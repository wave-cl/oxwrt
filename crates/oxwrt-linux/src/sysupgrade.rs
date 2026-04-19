//! Native replacement for OpenWrt's sysupgrade on mediatek/filogic eMMC
//! (GL-MT6000 specifically).
//!
//! Why native: the stock /sbin/sysupgrade is a shell script that calls
//! `ubus call system sysupgrade` to hand off to procd's stage2. When
//! oxwrtd replaces procd, no ubus broker is running and the hand-off
//! fails. Rather than ship ubusd + fake ubus shims just to satisfy a
//! shell script, we reimplement the ~200 lines of logic that actually
//! matter for this board in Rust.
//!
//! Scope (deliberately narrow — see FOLLOW-UPS at bottom of file):
//!   - **Target**: GL.iNet GL-MT6000 on OpenWrt 25.12.2 mediatek/filogic.
//!   - **Image format**: gzipped tar + fwtool `FWx0` trailer. No ucert
//!     signature verification. No FIT-fitblk variant.
//!   - **Flash path**: eMMC, partitions by GPT PARTLABEL. No NAND, no
//!     UBI, no NOR.
//!   - **Config preservation**: honored via /etc/sysupgrade.conf →
//!     files-list → tgz → append past rootfs. Clean flash (-n) zeros
//!     the marker byte so libfstools reformats the overlay.
//!
//! Flow (matches what `/lib/upgrade/emmc.sh` + `stage2` do on stock):
//!   1. Validate fwtool trailer: board name matches, compat_version
//!      major matches.
//!   2. Build /tmp/sysupgrade.tgz from /etc/sysupgrade.conf (only if
//!      `keep_settings`).
//!   3. Shut down our supervisor so nothing writes to disk during flash.
//!   4. `pivot_root` into a tmpfs root so /dev/mmcblk0pN is writable.
//!   5. Resolve `kernel` + `rootfs` partitions via /sys/class/block.
//!   6. Zero the first 4 KiB of `kernel` → makes the old bootloader
//!      fail-and-retry if we die mid-flash. Write `root` tar member to
//!      `rootfs`. Write `kernel` tar member to `kernel`.
//!   7. Either zero marker past rootfs (clean flash) or write tgz
//!      there (keep settings).
//!   8. `sync(2)` + `reboot(RB_AUTOBOOT)`.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

const BOARD_NAME: &str = "glinet,gl-mt6000";

/// Expected fwtool metadata compat_version major. Mediatek/filogic
/// uses compat_version "1.1" on OpenWrt 25.12; the MAJOR ("1") must
/// match. Bumping this in a new OpenWrt release means operators can
/// no longer sysupgrade from the old image without an explicit flag
/// (stock sysupgrade uses `-F` to force). We require major equality
/// and refuse to force.
const COMPAT_VERSION_MAJOR: &str = "1";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("image: {0}")]
    Image(String),
    #[error("partition: {0}")]
    Partition(String),
    #[error("io {ctx}: {source}")]
    Io {
        ctx: String,
        #[source]
        source: std::io::Error,
    },
    #[error("pivot_root: {0}")]
    Pivot(String),
    #[error("fwtool: {0}")]
    Fwtool(String),
}

fn io<S: Into<String>>(ctx: S) -> impl FnOnce(std::io::Error) -> Error {
    move |source| Error::Io {
        ctx: ctx.into(),
        source,
    }
}

/// Public entry point. Consumes the calling process: on success, the
/// device reboots; on failure, returns without modifying flash (best
/// effort — see per-step comments for where the guarantee weakens).
///
/// Preconditions:
///   - `image_path` exists and is a well-formed sysupgrade.bin for
///     this board.
///   - Caller has CAP_SYS_ADMIN (for pivot_root + mount + reboot) and
///     CAP_DAC_OVERRIDE (for /dev/mmcblk0pN writes).
///   - Caller has already stopped any non-essential services; we
///     don't re-implement procd's "signal everyone to stop" here,
///     assuming the supervisor already did.
pub fn apply(image_path: &Path, keep_settings: bool) -> Result<(), Error> {
    tracing::warn!(
        image = %image_path.display(),
        keep_settings,
        "sysupgrade: native flash starting"
    );

    // Step 1: validate fwtool trailer BEFORE we do anything destructive.
    // Stops a wrong-board image from getting as far as the pivot.
    let (tar_len, fwmeta) = parse_fwtool_trailer(image_path)?;
    fwmeta.check_board(BOARD_NAME)?;
    fwmeta.check_compat_major(COMPAT_VERSION_MAJOR)?;
    tracing::info!(
        supported = ?fwmeta.supported_devices,
        compat = %fwmeta.compat_version,
        "sysupgrade: fwtool metadata ok"
    );

    // Step 2: build the preserved-config tarball IN MEMORY. After the
    // pivot, any path in the old root is reachable only as /mnt/…
    // and we lazy-unmount /mnt, so a file written there disappears.
    // Build into a Vec<u8> that survives the pivot by virtue of being
    // in process memory.
    let backup_tgz: Option<Vec<u8>> = if keep_settings {
        Some(build_config_backup_in_memory()?)
    } else {
        None
    };

    // Step 3: Open TWO independent file handles before pivot. We need
    // one per tar-member-extraction pass in flash_image, since we can't
    // reliably assume the tar places `root` before `kernel` (on this
    // target the actual order is kernel, then root — the opposite of
    // what stock sysupgrade's emmc_upgrade_tar suggests). Streaming in
    // tar order would force us to write kernel first, which breaks
    // the "rootfs-before-kernel" safety property; two passes let us
    // write in the canonical order regardless of the archive's order.
    //
    // try_clone() shares the underlying file offset on Linux, so
    // independent offsets require independent open(2) calls. Files
    // open across pivot_root continue to work — only name lookups
    // break — so opening here is safe and survives the pivot.
    let img_for_root =
        File::open(image_path).map_err(io(format!("open {} (root pass)", image_path.display())))?;
    let img_for_kernel = File::open(image_path)
        .map_err(io(format!("open {} (kernel pass)", image_path.display())))?;

    // Pre-flight: walk the tar listing once BEFORE the destructive
    // writes in flash_image. Catches malformed images, missing
    // kernel/root members, etc. before we've committed any writes.
    preflight_tar(image_path)?;

    // Step 4: resolve partitions ahead of pivot. After the pivot,
    // /sys gets moved into the new root and is still present, but
    // doing this up-front keeps the error surface simpler.
    let kern_dev = resolve_partition("kernel")?;
    let root_dev = resolve_partition("rootfs")?;
    tracing::info!(
        kernel = %kern_dev.display(),
        rootfs = %root_dev.display(),
        "sysupgrade: eMMC partitions resolved"
    );

    // Step 5: pivot_root to tmpfs so we're not holding the rootfs
    // block device open when we write to it.
    pivot_to_ramfs()?;

    // Step 6-7: flash.
    flash_image(
        img_for_root,
        img_for_kernel,
        tar_len,
        &kern_dev,
        &root_dev,
        backup_tgz.as_deref(),
    )?;

    // Step 8: sync + reboot.
    tracing::warn!("sysupgrade: flash complete, rebooting");
    unsafe {
        libc::sync();
    }
    // Both: "ask nicely" via reboot(2), and fallback to sysrq if the
    // kernel doesn't honor the first. The fallback matches what stock
    // do_stage2 does at the end.
    let rc = unsafe { libc::reboot(libc::RB_AUTOBOOT) };
    if rc != 0 {
        // reboot(2) returns -1 on error; try sysrq as a backup.
        if let Ok(mut f) = OpenOptions::new().write(true).open("/proc/sysrq-trigger") {
            let _ = f.write_all(b"b");
        }
    }
    // If we somehow got here, hang so we don't return to a caller
    // that thinks "sysupgrade finished."
    loop {
        std::thread::sleep(std::time::Duration::from_secs(60));
    }
}

// ── fwtool trailer parsing ─────────────────────────────────────────

/// fwtool appends a 16-byte **big-endian** footer, preceded by a
/// variable-length metadata block. The layout observed on real
/// OpenWrt 25.12 mediatek/filogic sysupgrade.bin:
///
///     ... tar.gz bytes ...
///     [ metadata (size - 16 bytes) ]         # includes 8-byte pad + JSON
///     [ magic "FWx0"                4 bytes ]
///     [ crc32 (BE)                  4 bytes ]
///     [ type (BE, =1 "metadata")    4 bytes ]
///     [ size (BE, total trailer)    4 bytes ]
///
/// `size` is the length of the ENTIRE trailer including the 16-byte
/// fixed header — so the metadata bytes run from (EOF - size) through
/// (EOF - 16). An earlier version of this code assumed little-endian
/// and a 12-byte footer; that guess was wrong and the native
/// self-update path silently rejected every valid image with
/// `magic not found (got [0, 0, 1, 0x40])` — those four bytes are
/// the BE size field we should have been reading first.
///
/// CRC is not verified here — the sQUIC FwUpdate RPC already checks
/// a SHA-256 of the whole stream before writing FW_STAGING_PATH, so
/// a torn stream can't reach this code path.
#[derive(Debug)]
struct FwtoolMeta {
    supported_devices: Vec<String>,
    compat_version: String,
}

impl FwtoolMeta {
    fn check_board(&self, expected: &str) -> Result<(), Error> {
        if self.supported_devices.iter().any(|s| s == expected) {
            Ok(())
        } else {
            Err(Error::Fwtool(format!(
                "image does not support this board ({expected}); supported: {:?}",
                self.supported_devices
            )))
        }
    }

    fn check_compat_major(&self, expected_major: &str) -> Result<(), Error> {
        let major = self.compat_version.split('.').next().unwrap_or("");
        if major == expected_major {
            Ok(())
        } else {
            Err(Error::Fwtool(format!(
                "compat_version major mismatch: image={} expected={}.x",
                self.compat_version, expected_major
            )))
        }
    }
}

/// Returns (length of tar.gz data before the trailer, parsed metadata).
fn parse_fwtool_trailer(path: &Path) -> Result<(u64, FwtoolMeta), Error> {
    let mut f = File::open(path).map_err(io(format!("open {}", path.display())))?;
    let total = f.metadata().map_err(io("stat image"))?.len();
    if total < 16 {
        return Err(Error::Fwtool(
            "image too small to have 16-byte fwtool trailer".into(),
        ));
    }

    // Fixed 16-byte trailer: magic (4) + crc (4) + type (4) + size (4).
    f.seek(SeekFrom::Start(total - 16))
        .map_err(io("seek trailer"))?;
    let mut footer = [0u8; 16];
    f.read_exact(&mut footer).map_err(io("read trailer"))?;

    let magic = &footer[0..4];
    if magic != b"FWx0" {
        return Err(Error::Fwtool(format!(
            "fwtool magic not found (got {magic:?}); image not fwtool-wrapped"
        )));
    }

    // size is big-endian and covers the *entire* trailer from the
    // metadata-block start through the 16 trailer bytes.
    let total_trailer_size =
        u32::from_be_bytes([footer[12], footer[13], footer[14], footer[15]]) as u64;
    if !(16..=65_536).contains(&total_trailer_size) {
        return Err(Error::Fwtool(format!(
            "fwtool trailer size implausible: {total_trailer_size} bytes"
        )));
    }

    let tar_len = total
        .checked_sub(total_trailer_size)
        .ok_or_else(|| Error::Fwtool("fwtool trailer overruns image".into()))?;

    // Metadata block is (size - 16) bytes starting at tar_len.
    let meta_len = (total_trailer_size - 16) as usize;
    f.seek(SeekFrom::Start(tar_len)).map_err(io("seek meta"))?;
    let mut meta_bytes = vec![0u8; meta_len];
    f.read_exact(&mut meta_bytes).map_err(io("read meta"))?;

    // Metadata is JSON, but OpenWrt's fwtool prepends an 8-byte
    // zero-padding header (possibly a sub-type field). Find the first
    // '{' and parse from there.
    let json_start = meta_bytes
        .iter()
        .position(|&b| b == b'{')
        .ok_or_else(|| Error::Fwtool("fwtool metadata: no JSON opening '{' found".into()))?;
    let json_bytes = &meta_bytes[json_start..];

    #[derive(serde::Deserialize)]
    struct Raw {
        supported_devices: Vec<String>,
        #[serde(default)]
        compat_version: String,
    }
    let raw: Raw = serde_json::from_slice(json_bytes)
        .map_err(|e| Error::Fwtool(format!("metadata json: {e}")))?;
    Ok((
        tar_len,
        FwtoolMeta {
            supported_devices: raw.supported_devices,
            compat_version: if raw.compat_version.is_empty() {
                "1.0".to_string()
            } else {
                raw.compat_version
            },
        },
    ))
}

// ── config backup ──────────────────────────────────────────────────

/// Build a gzipped tar of every file referenced by
/// /etc/sysupgrade.conf and /lib/upgrade/keep.d/*, returned as an
/// in-memory Vec<u8>.
///
/// In memory (rather than writing to /tmp/sysupgrade.tgz) because
/// after pivot_root, /tmp is the empty new-root tmpfs — a file
/// written under /tmp pre-pivot is reachable only as /mnt/tmp/... ,
/// and we lazy-unmount /mnt. The Vec survives the pivot trivially
/// since it's process memory.
///
/// Implementation note: we don't do the full shell-driven file-list
/// resolution that stock sysupgrade does (uci conffiles, per-package
/// keep.d, etc.). Our image has a small, predictable list —
/// /etc/oxwrt/, /etc/dropbear/, /etc/oxwrt.toml. If operators need
/// to extend it, /etc/sysupgrade.conf is the hook and we read it.
/// Recursively archive a directory into a tar::Builder, skipping any
/// entry that isn't a regular file, directory, or symlink.
///
/// Why not `tb.append_dir_all(...)`: that method recurses via
/// `std::fs::metadata` + `fs::File::open`, and calls `append_path_with_
/// name` which tries to archive whatever it finds. UNIX domain sockets,
/// FIFOs, block/char devices all fail with "X can not be archived" from
/// the `tar` crate, and there's no filter hook — one unsupported entry
/// inside the walk aborts the whole backup.
///
/// Implementation mirrors append_dir_all's semantics for the cases we do
/// handle (regular + dir + symlink), logging + skipping the rest.
fn tar_append_dir_filtered<W: std::io::Write>(
    tb: &mut tar::Builder<W>,
    archive_path: &Path,
    disk_path: &Path,
) -> Result<(), Error> {
    // Add the directory entry itself first so empty dirs get preserved.
    tb.append_dir(archive_path, disk_path)
        .map_err(io(format!("tar dir {}", disk_path.display())))?;
    let rd =
        std::fs::read_dir(disk_path).map_err(io(format!("read_dir {}", disk_path.display())))?;
    for ent in rd {
        let ent = ent.map_err(io(format!("read_dir entry {}", disk_path.display())))?;
        let sub_disk = ent.path();
        let sub_archive = archive_path.join(ent.file_name());
        let ft = ent
            .file_type()
            .map_err(io(format!("file_type {}", sub_disk.display())))?;
        if ft.is_symlink() {
            // tar::Builder::append_path_with_name handles symlinks
            // correctly — records the link target without dereferencing.
            let target = std::fs::read_link(&sub_disk)
                .map_err(io(format!("readlink {}", sub_disk.display())))?;
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_size(0);
            header.set_mode(0o777);
            header.set_mtime(0);
            tb.append_link(&mut header, &sub_archive, &target)
                .map_err(io(format!("tar symlink {}", sub_disk.display())))?;
        } else if ft.is_dir() {
            tar_append_dir_filtered(tb, &sub_archive, &sub_disk)?;
        } else if ft.is_file() {
            let mut f =
                File::open(&sub_disk).map_err(io(format!("open {}", sub_disk.display())))?;
            tb.append_file(&sub_archive, &mut f)
                .map_err(io(format!("tar file {}", sub_disk.display())))?;
        } else {
            // Socket / FIFO / block / char / unknown — skip. Preserving
            // these across a reboot is meaningless (runtime-scoped).
            tracing::info!(
                path = %sub_disk.display(),
                "backup: skipping non-archivable entry (socket/fifo/device)"
            );
        }
    }
    Ok(())
}

fn build_config_backup_in_memory() -> Result<Vec<u8>, Error> {
    use flate2::Compression;
    use flate2::write::GzEncoder;

    let list = read_keep_list()?;
    let mut buf = Vec::<u8>::with_capacity(64 * 1024);
    {
        let gz = GzEncoder::new(&mut buf, Compression::default());
        let mut tb = tar::Builder::new(gz);
        for p in &list {
            let p = Path::new(p);
            if !p.exists() {
                tracing::debug!(path = %p.display(), "backup: path absent, skip");
                continue;
            }
            if p.is_dir() {
                // Manual walk instead of append_dir_all so we can filter
                // out non-regular/non-symlink entries (UNIX domain sockets,
                // FIFOs, device nodes) — tar can't archive those and the
                // whole backup fails if one is present. Seen in the wild:
                // hostapd's ctrl socket under /etc/oxwrt/hostapd-*-run/.
                let stripped: PathBuf = p.strip_prefix("/").unwrap_or(p).into();
                tar_append_dir_filtered(&mut tb, &stripped, p)?;
            } else {
                let mut f = File::open(p).map_err(io(format!("open {}", p.display())))?;
                let stripped: PathBuf = p.strip_prefix("/").unwrap_or(p).into();
                tb.append_file(&stripped, &mut f)
                    .map_err(io(format!("tar file {}", p.display())))?;
            }
        }
        tb.finish().map_err(io("tar finish"))?;
    }
    tracing::info!(
        entries = list.len(),
        bytes = buf.len(),
        "sysupgrade: config backup built in memory"
    );
    Ok(buf)
}

/// Read /etc/sysupgrade.conf + every /lib/upgrade/keep.d/* into a
/// deduplicated list of file paths. Comments (#) and blank lines
/// ignored.
fn read_keep_list() -> Result<Vec<String>, Error> {
    let mut seen = std::collections::BTreeSet::<String>::new();
    let mut push_from = |p: &Path| -> Result<(), Error> {
        let Ok(s) = std::fs::read_to_string(p) else {
            return Ok(());
        };
        for line in s.lines() {
            let t = line.trim();
            if t.is_empty() || t.starts_with('#') {
                continue;
            }
            seen.insert(t.to_string());
        }
        Ok(())
    };
    push_from(Path::new("/etc/sysupgrade.conf"))?;
    if let Ok(rd) = std::fs::read_dir("/lib/upgrade/keep.d") {
        for e in rd.flatten() {
            push_from(&e.path())?;
        }
    }
    Ok(seen.into_iter().collect())
}

// ── partition resolution ───────────────────────────────────────────

/// Walk /sys/class/block/mmcblk0p*/uevent looking for PARTNAME=<name>,
/// return the corresponding /dev/mmcblk0pN path.
///
/// Stock sysupgrade's `find_mmc_part` does the same scan — the name
/// is the GPT PARTLABEL assigned at image build time via the mediatek
/// filogic DTS. For GL-MT6000 the labels are fixed: bl2, u-boot-env,
/// factory, fip, kernel, rootfs, rootfs_data.
pub fn resolve_partition(name: &str) -> Result<PathBuf, Error> {
    let rd = std::fs::read_dir("/sys/class/block").map_err(io("read /sys/class/block"))?;
    for e in rd.flatten() {
        let dev_name = e.file_name();
        let Some(dev_name) = dev_name.to_str() else {
            continue;
        };
        if !dev_name.starts_with("mmcblk0p") {
            continue;
        }
        let uevent = e.path().join("uevent");
        let Ok(content) = std::fs::read_to_string(&uevent) else {
            continue;
        };
        let matched = content
            .lines()
            .any(|l| l.trim() == format!("PARTNAME={name}"));
        if matched {
            return Ok(PathBuf::from(format!("/dev/{dev_name}")));
        }
    }
    Err(Error::Partition(format!(
        "no mmcblk0p* with PARTNAME={name}"
    )))
}

// ── pivot_root to tmpfs ────────────────────────────────────────────

/// Move the process root into a freshly-minted tmpfs so that subsequent
/// writes to /dev/mmcblk0pN don't race against reads from the same
/// blocks via the mounted rootfs. Matches stock stage2's switch_to_ramfs.
///
/// Steps:
///   1. Set up a new root directory backed by tmpfs.
///   2. Bind-mount it on itself (pivot_root needs a mount point).
///   3. Move /proc, /sys, /dev, /tmp, /overlay into the new root.
///   4. pivot_root: new root becomes /, old root becomes /mnt.
///   5. Remount old root read-only, lazy-unmount it + /overlay to
///      release the underlying block devices.
fn pivot_to_ramfs() -> Result<(), Error> {
    use rustix::mount::{MountFlags, UnmountFlags, mount_bind, mount_move, mount_remount, unmount};

    let new_root = Path::new("/tmp/sysupgrade-root");
    std::fs::create_dir_all(new_root).map_err(io("mkdir new_root"))?;

    // mount --bind new_root on itself so pivot_root accepts it as a
    // mount point. On Linux this works even though the underlying fs
    // is already tmpfs: the bind creates a new mount entry.
    mount_bind(new_root, new_root).map_err(|e| Error::Pivot(format!("bind new_root: {e}")))?;

    // Prepare mount point directories inside the new root.
    for sub in ["proc", "sys", "dev", "tmp", "overlay", "mnt"] {
        let p = new_root.join(sub);
        std::fs::create_dir_all(&p).map_err(io(format!("mkdir new_root/{sub}")))?;
    }

    // Move the filesystems we need to carry across. MS_MOVE preserves
    // the mount subtree — binds, tmpfs contents, everything.
    for sub in ["/proc", "/sys", "/dev", "/overlay"] {
        let from = Path::new(sub);
        let to = new_root.join(sub.trim_start_matches('/'));
        // /overlay may not be present if the rootfs has no overlay —
        // that's actually the case right after first boot on an image
        // where libfstools hasn't attached the overlay yet. Tolerate.
        if !from.exists() {
            continue;
        }
        mount_move(from, &to).map_err(|e| Error::Pivot(format!("move {sub}: {e}")))?;
    }
    // /tmp is special — it's the parent of our new_root, so we can't
    // move it without surgery. Instead, bind-mount it into the new
    // tree; the original /tmp mount keeps our flash artifacts
    // (/tmp/fw_update.bin + /tmp/sysupgrade.tgz) accessible at
    // /mnt/tmp after the pivot, but they're also visible at /tmp via
    // the bind.
    // Actually the simpler approach is: after pivot, /mnt/tmp still
    // works, and we refer to /mnt/tmp/fw_update.bin from post-pivot
    // code. Nothing to do here — the pivot itself preserves access
    // via /mnt/*.

    // pivot_root(2): syscall has no libc wrapper in older musl, but
    // rustix exposes it. new_root becomes /, old root is parked under
    // new_root/mnt (which we created above).
    let old_root_in_new = new_root.join("mnt");
    rustix::process::pivot_root(new_root, &old_root_in_new)
        .map_err(|e| Error::Pivot(format!("pivot_root: {e}")))?;

    // Post-pivot: we're in the new root. Chdir to / so relative paths
    // work, and release the old root so the block device is freed.
    std::env::set_current_dir("/").map_err(io("chdir / after pivot"))?;

    // Remount old root read-only, then lazy-unmount. Both must happen
    // or we can't write to the partition. Lazy because we may still
    // have file descriptors from the pre-pivot world (the FwUpdate
    // RPC handler opened /tmp/fw_update.bin, etc.).
    if let Err(e) = mount_remount("/mnt", MountFlags::RDONLY, "") {
        tracing::warn!(error = %e, "sysupgrade: remount /mnt ro failed (non-fatal)");
    }
    for target in ["/mnt", "/overlay"] {
        if Path::new(target).exists() {
            if let Err(e) = unmount(target, UnmountFlags::DETACH) {
                tracing::warn!(target, error = %e, "sysupgrade: lazy unmount failed");
            }
        }
    }

    // Final kick to the page cache so reads of the flashing partition
    // don't return stale data if anything happens to read it.
    if let Ok(mut f) = OpenOptions::new()
        .write(true)
        .open("/proc/sys/vm/drop_caches")
    {
        let _ = f.write_all(b"3\n");
    }

    tracing::info!("sysupgrade: pivot to tmpfs complete");
    Ok(())
}

// ── pre-flight validation ──────────────────────────────────────────

/// Walk the tar members once, verify `root` and `kernel` are both
/// present and reachable, and that the tar parses cleanly. Opens an
/// independent File (not a clone of the flash-time fd) so the scan
/// has its own read offset — try_clone shares offset on Linux, which
/// would empty the flash-time stream before it starts.
fn preflight_tar(image_path: &Path) -> Result<(), Error> {
    let f =
        File::open(image_path).map_err(io(format!("preflight: open {}", image_path.display())))?;
    // Note: no tar_len cap here — we don't need one for preflight.
    // Reading past the fwtool trailer will cause tar to hit "bad
    // archive" eventually, but we'll have already seen both members
    // by then. Be defensive: break out of iteration on the first
    // error, not mid-scan.
    let mut ar = tar::Archive::new(f);

    let mut have_root = false;
    let mut have_kernel = false;
    for entry in ar.entries().map_err(io("preflight: tar entries"))? {
        let entry = match entry {
            Ok(e) => e,
            // Hitting the fwtool trailer past tar_len will surface as
            // a tar parse error. If we already have both members by
            // then, short-circuit — no point propagating.
            Err(_) if have_root && have_kernel => break,
            Err(e) => return Err(io("preflight: tar entry")(e)),
        };
        let path = entry
            .path()
            .map_err(io("preflight: tar entry path"))?
            .into_owned();
        match path.file_name().and_then(|s| s.to_str()).unwrap_or("") {
            "root" => have_root = true,
            "kernel" => have_kernel = true,
            _ => {}
        }
        if have_root && have_kernel {
            break;
        }
    }
    if !have_root {
        return Err(Error::Image("preflight: tar missing root member".into()));
    }
    if !have_kernel {
        // Kernel-less update is accepted by flash_image, but we log
        // at warn level because it's unusual enough that operators
        // probably wanted to include one and something broke upstream.
        tracing::warn!("preflight: tar has no kernel member (rootfs-only update)");
    }
    Ok(())
}

// ── per-member extract helper ──────────────────────────────────────

/// Stream a single tar member (by basename) from `image_file` to
/// `out_dev`. Returns the number of bytes written. Consumes
/// `image_file`. Used twice from flash_image — once for "root", once
/// for "kernel". Each call uses an independent File handle so the
/// tar iteration offsets don't collide.
fn extract_and_write(
    image_file: File,
    tar_len: u64,
    member_basename: &str,
    out_dev: &Path,
) -> Result<u64, Error> {
    let limited = image_file.take(tar_len);
    let mut ar = tar::Archive::new(limited);
    for entry in ar.entries().map_err(io("tar entries"))? {
        let mut entry = match entry {
            Ok(e) => e,
            // Past tar_len we hit the fwtool trailer; if we already
            // found the member we'd have returned, so this is a
            // genuine "not found" case. Let the "missing member"
            // error below fire.
            Err(_) => break,
        };
        let path = entry.path().map_err(io("tar entry path"))?.into_owned();
        let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if name != member_basename {
            continue;
        }
        let mut out = OpenOptions::new()
            .write(true)
            .open(out_dev)
            .map_err(io(format!("open {}", out_dev.display())))?;
        let n =
            std::io::copy(&mut entry, &mut out).map_err(io(format!("write {member_basename}")))?;
        out.sync_all()
            .map_err(io(format!("fsync {member_basename}")))?;
        return Ok(n);
    }
    Err(Error::Image(format!(
        "tar missing {member_basename} member"
    )))
}

// ── flash ──────────────────────────────────────────────────────────

/// Stream `image_path`'s root and kernel tar members to the eMMC
/// partitions, in the order that stock `emmc_upgrade_tar` uses (so a
/// power cut at any point leaves the bootloader with EITHER an old
/// valid kernel or a zeroed kernel — never a valid-looking kernel
/// pointing at a half-flashed rootfs).
fn flash_image(
    img_for_root: File,
    img_for_kernel: File,
    tar_len: u64,
    kern_dev: &Path,
    root_dev: &Path,
    backup_tgz: Option<&[u8]>,
) -> Result<(), Error> {
    // Canonical write order (matches stock emmc.sh's safety model):
    //
    //   1. Zero first 4 KiB of kernel partition — invalidates the FIT
    //      magic so U-Boot won't try to boot the old kernel if we die
    //      between here and step 3.
    //   2. Write rootfs in full.
    //   3. Write kernel in full.
    //
    // A power cut at ANY point between steps 1 and 3 leaves the board
    // in a "kernel unbootable, recovery needed" state — never a
    // "valid-looking kernel pointing at half-flashed rootfs" state.
    // That's worth the occasional recovery over a silent brick.
    //
    // We extract root and kernel via TWO independent passes because
    // the actual tar archive on mediatek/filogic interleaves them in
    // the order (CONTROL, kernel, root) — streaming in tar order
    // would force kernel-first. Two passes with independent File
    // handles keeps the safety ordering.

    // Step 1.
    {
        let mut f = OpenOptions::new()
            .write(true)
            .open(kern_dev)
            .map_err(io(format!("open {}", kern_dev.display())))?;
        let zeros = [0u8; 4096];
        f.write_all(&zeros).map_err(io("zero kernel head"))?;
        f.sync_all().map_err(io("fsync kernel"))?;
    }
    tracing::info!(dev = %kern_dev.display(), "sysupgrade: kernel head zeroed");

    // Step 2: extract and write rootfs.
    tracing::info!(dev = %root_dev.display(), "sysupgrade: writing rootfs");
    let root_bytes_written = extract_and_write(img_for_root, tar_len, "root", root_dev)?;
    tracing::info!(bytes = root_bytes_written, "sysupgrade: rootfs written");

    // Step 3: extract and write kernel.
    tracing::info!(dev = %kern_dev.display(), "sysupgrade: writing kernel");
    let kernel_bytes_written = extract_and_write(img_for_kernel, tar_len, "kernel", kern_dev)?;
    tracing::info!(bytes = kernel_bytes_written, "sysupgrade: kernel written");

    // Step 3: write the backup tgz past the rootfs, or zero a marker
    // there to force overlay reformat.
    //
    // Calculation (matches libfstools): the overlay starts at
    //   rootfs_offset + align_up(rootfs_blocks, 128) * 512
    // where rootfs_blocks = ceil(root_bytes_written / 512). The 128-
    // block (64 KiB) alignment is load-bearing — libfstools looks
    // there for either an f2fs magic (continue with existing overlay)
    // or any other bytes (reformat on first boot).
    let rootfs_blocks = root_bytes_written.div_ceil(512);
    let aligned_blocks = (rootfs_blocks + 127) & !127;
    let overlay_off: u64 = aligned_blocks * 512;

    let mut f = OpenOptions::new()
        .write(true)
        .open(root_dev)
        .map_err(io(format!("open {} for marker", root_dev.display())))?;
    f.seek(SeekFrom::Start(overlay_off))
        .map_err(io("seek overlay marker"))?;

    match backup_tgz {
        Some(bytes) => {
            tracing::info!(
                off = overlay_off,
                size = bytes.len(),
                "sysupgrade: writing config backup past rootfs"
            );
            f.write_all(bytes).map_err(io("write backup"))?;
            f.sync_all().map_err(io("fsync backup"))?;
            tracing::info!(bytes = bytes.len(), "sysupgrade: backup written");
        }
        None => {
            // Clean flash: zero 4 KiB at the overlay start so
            // libfstools sees garbage and reformats.
            let zeros = [0u8; 4096];
            f.write_all(&zeros).map_err(io("zero overlay marker"))?;
            f.sync_all().map_err(io("fsync marker"))?;
            tracing::info!(
                off = overlay_off,
                "sysupgrade: overlay marker zeroed (clean flash)"
            );
        }
    }

    Ok(())
}

// ── FOLLOW-UPS (not in scope yet) ─────────────────────────────────
//
// - ucert signature verification. Stock sysupgrade's fwtool verifies
//   an optional ucert chain if the image is signed; we currently
//   ignore it. Adding it means pulling in a small ed25519 / ECDSA
//   verifier and the ucert format spec.
//
// - FIT-fitblk variant. Some mediatek/filogic devices (ubootmod
//   variants, future GL-MT6000 firmware lines) use fit_do_upgrade +
//   fitblk. The kernel member is a FIT image written to a fitblk
//   device, not a raw kernel partition. GL-MT6000 current firmware
//   doesn't need this.
//
// - NAND + UBI. If we ever target ramips or ath79, the partition
//   abstraction changes (mtd write, ubi attach/detach, etc.).
//
// - save_partitions / add_provisioning / use_curr_part options from
//   stock's `ubus call system sysupgrade`. Not exposed in our
//   FwApply RPC yet.

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a synthetic sysupgrade.bin with a minimal fwtool trailer
    /// (big-endian, matching real OpenWrt fwtool output). Not a valid
    /// tar — only parse_fwtool_trailer is exercised here.
    ///
    /// Layout: payload || 8-byte pad || JSON || "FWx0" || crc(BE) ||
    ///         type(BE=1) || size(BE)
    /// where size counts magic onward PLUS the metadata that precedes.
    fn synth_image(payload: &[u8], meta_json: &str) -> tempfile::NamedTempFile {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(payload).unwrap();
        // Metadata section: 8-byte pad + JSON
        let pad = [0u8; 8];
        tmp.write_all(&pad).unwrap();
        tmp.write_all(meta_json.as_bytes()).unwrap();
        let meta_section_len = pad.len() + meta_json.len();
        // Fixed 16-byte trailer: magic + crc + type + size (all BE u32).
        tmp.write_all(b"FWx0").unwrap();
        tmp.write_all(&0u32.to_be_bytes()).unwrap(); // crc (unchecked)
        tmp.write_all(&1u32.to_be_bytes()).unwrap(); // type = metadata
        let total_trailer_size = (meta_section_len + 16) as u32;
        tmp.write_all(&total_trailer_size.to_be_bytes()).unwrap();
        tmp.flush().unwrap();
        tmp
    }

    #[test]
    fn rejects_image_without_fwtool_trailer() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(b"not an fwtool image").unwrap();
        let e = parse_fwtool_trailer(tmp.path()).unwrap_err();
        assert!(matches!(e, Error::Fwtool(_)), "{e:?}");
    }

    #[test]
    fn parses_valid_trailer_and_checks_board() {
        let meta = r#"{"supported_devices":["glinet,gl-mt6000"],"compat_version":"1.1"}"#;
        let img = synth_image(b"tar-bytes-go-here", meta);
        let (tar_len, parsed) = parse_fwtool_trailer(img.path()).unwrap();
        assert_eq!(tar_len, b"tar-bytes-go-here".len() as u64);
        assert!(parsed.check_board("glinet,gl-mt6000").is_ok());
        assert!(parsed.check_compat_major("1").is_ok());
    }

    #[test]
    fn rejects_wrong_board() {
        let meta = r#"{"supported_devices":["tplink,archer-ax80"],"compat_version":"1.0"}"#;
        let img = synth_image(b"tar", meta);
        let (_, parsed) = parse_fwtool_trailer(img.path()).unwrap();
        let e = parsed.check_board("glinet,gl-mt6000").unwrap_err();
        assert!(matches!(e, Error::Fwtool(_)));
    }

    #[test]
    fn rejects_compat_major_mismatch() {
        let meta = r#"{"supported_devices":["glinet,gl-mt6000"],"compat_version":"2.0"}"#;
        let img = synth_image(b"tar", meta);
        let (_, parsed) = parse_fwtool_trailer(img.path()).unwrap();
        assert!(parsed.check_compat_major("1").is_err());
        assert!(parsed.check_compat_major("2").is_ok());
    }

    #[test]
    fn rejects_implausible_metadata_length() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(b"tar-bytes").unwrap();
        // Trailer: magic + crc + type + size=100_000_000 (BE). Parser
        // should refuse — no legit metadata is that big.
        tmp.write_all(b"FWx0").unwrap();
        tmp.write_all(&0u32.to_be_bytes()).unwrap();
        tmp.write_all(&1u32.to_be_bytes()).unwrap();
        tmp.write_all(&(100_000_000u32).to_be_bytes()).unwrap();
        tmp.flush().unwrap();
        let e = parse_fwtool_trailer(tmp.path()).unwrap_err();
        assert!(matches!(e, Error::Fwtool(_)));
    }

    /// Sanity-check against a real OpenWrt-produced sysupgrade.bin.
    /// Skipped if the file isn't available (only the dev host that
    /// ran `make imagebuilder-image-pid1` has it staged).
    #[test]
    fn parses_real_sysupgrade_bin() {
        let candidates = [
            "imagebuilder/openwrt-imagebuilder-25.12.2-mediatek-filogic.Linux-x86_64/bin/targets/mediatek/filogic/openwrt-25.12.2-mediatek-filogic-glinet_gl-mt6000-squashfs-sysupgrade.bin",
            "../imagebuilder/openwrt-imagebuilder-25.12.2-mediatek-filogic.Linux-x86_64/bin/targets/mediatek/filogic/openwrt-25.12.2-mediatek-filogic-glinet_gl-mt6000-squashfs-sysupgrade.bin",
        ];
        let real = candidates.iter().find(|p| Path::new(p).exists());
        let Some(real) = real else {
            eprintln!("parses_real_sysupgrade_bin: image not staged, skipping");
            return;
        };
        let (_, meta) =
            parse_fwtool_trailer(Path::new(real)).expect("real sysupgrade.bin should parse");
        meta.check_board("glinet,gl-mt6000")
            .expect("real image should advertise gl-mt6000");
    }
}
