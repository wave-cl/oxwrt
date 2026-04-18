//! Native replacement for OpenWrt's sysupgrade on mediatek/filogic eMMC
//! (GL-MT6000 specifically).
//!
//! Why native: the stock /sbin/sysupgrade is a shell script that calls
//! `ubus call system sysupgrade` to hand off to procd's stage2. When
//! oxwrtctl replaces procd, no ubus broker is running and the hand-off
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

    // Step 2: build the preserved-config tarball. If this fails, abort
    // — flashing without the config we promised to keep is worse than
    // not flashing at all.
    let backup_path: Option<PathBuf> = if keep_settings {
        let p = PathBuf::from("/tmp/sysupgrade.tgz");
        build_config_backup(&p)?;
        Some(p)
    } else {
        None
    };

    // Step 3: resolve partitions ahead of pivot. After the pivot, /sys
    // and /dev are moved but still present; doing this up-front keeps
    // the error surface simpler.
    let kern_dev = resolve_partition("kernel")?;
    let root_dev = resolve_partition("rootfs")?;
    tracing::info!(
        kernel = %kern_dev.display(),
        rootfs = %root_dev.display(),
        "sysupgrade: eMMC partitions resolved"
    );

    // Step 4: pivot_root to tmpfs so we're not holding the rootfs
    // block device open when we write to it.
    pivot_to_ramfs()?;

    // Step 5-7: flash.
    flash_image(image_path, tar_len, &kern_dev, &root_dev, backup_path.as_deref())?;

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

/// fwtool appends a 12-byte little-endian footer plus a variable-length
/// JSON metadata block to the end of the tar.gz stream:
///
///     ... tar.gz bytes ...
///     [ metadata JSON (N bytes) ]
///     [ crc32: 4 bytes LE ] [ length-of-json: 4 bytes LE ] [ magic: "FWx0" 4 bytes ]
///
/// We extract the length, seek back, read the JSON, and deserialize.
/// The CRC check is omitted — if it matters to us it'll fail JSON
/// parse anyway; stock sysupgrade's fwtool only uses the CRC to
/// detect truncation during `wget`, which doesn't apply here (we
/// already have the full file via FwUpdate SHA-256 check).
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
    let total = f
        .metadata()
        .map_err(io("stat image"))?
        .len();
    if total < 12 {
        return Err(Error::Fwtool("image too small to have fwtool trailer".into()));
    }

    f.seek(SeekFrom::Start(total - 12)).map_err(io("seek trailer"))?;
    let mut footer = [0u8; 12];
    f.read_exact(&mut footer).map_err(io("read trailer"))?;

    let magic = &footer[8..12];
    if magic != b"FWx0" {
        return Err(Error::Fwtool(format!(
            "fwtool magic not found (got {magic:?}); image not fwtool-wrapped"
        )));
    }
    let meta_len = u32::from_le_bytes([footer[4], footer[5], footer[6], footer[7]]) as u64;
    if meta_len == 0 || meta_len > 65536 {
        return Err(Error::Fwtool(format!(
            "fwtool metadata length implausible: {meta_len} bytes"
        )));
    }

    let tar_len = total
        .checked_sub(12 + meta_len)
        .ok_or_else(|| Error::Fwtool("fwtool metadata overruns image".into()))?;

    f.seek(SeekFrom::Start(tar_len)).map_err(io("seek meta"))?;
    let mut meta_bytes = vec![0u8; meta_len as usize];
    f.read_exact(&mut meta_bytes).map_err(io("read meta"))?;

    #[derive(serde::Deserialize)]
    struct Raw {
        supported_devices: Vec<String>,
        #[serde(default)]
        compat_version: String,
    }
    let raw: Raw = serde_json::from_slice(&meta_bytes)
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

/// Build a gzipped tar at `out` containing every file referenced by
/// /etc/sysupgrade.conf and /lib/upgrade/keep.d/* (same convention as
/// stock sysupgrade). Paths may be directories (recursed) or files.
///
/// Implementation note: we do not do the full shell-driven file-list
/// resolution that stock does (uci conffiles, packaging hooks, etc.).
/// For our image the list is short and predictable — /etc/oxwrt/,
/// /etc/dropbear/, maybe /etc/oxwrt.toml. If operators need to
/// extend it, /etc/sysupgrade.conf is still the hook.
fn build_config_backup(out: &Path) -> Result<(), Error> {
    use flate2::Compression;
    use flate2::write::GzEncoder;

    let list = read_keep_list()?;
    if list.is_empty() {
        // Still emit an empty archive so later stages can rely on it
        // existing (clean error if file is missing vs. "0-sized is
        // fine, nothing to restore").
        let f = File::create(out).map_err(io(format!("create {}", out.display())))?;
        let gz = GzEncoder::new(f, Compression::default());
        let mut tb = tar::Builder::new(gz);
        tb.finish().map_err(io("tar finish (empty)"))?;
        return Ok(());
    }

    let f = File::create(out).map_err(io(format!("create {}", out.display())))?;
    let gz = GzEncoder::new(f, Compression::default());
    let mut tb = tar::Builder::new(gz);
    for p in &list {
        let p = Path::new(p);
        if !p.exists() {
            tracing::debug!(path = %p.display(), "backup: path absent, skip");
            continue;
        }
        if p.is_dir() {
            // append_dir_all prepends the path as-is — strip leading
            // '/' so the tar looks like "etc/oxwrt/" not "/etc/oxwrt/"
            // (stock sysupgrade's restore expects leading-slash-relative).
            let stripped: PathBuf = p.strip_prefix("/").unwrap_or(p).into();
            tb.append_dir_all(&stripped, p)
                .map_err(io(format!("tar dir {}", p.display())))?;
        } else {
            let mut f = File::open(p).map_err(io(format!("open {}", p.display())))?;
            let stripped: PathBuf = p.strip_prefix("/").unwrap_or(p).into();
            tb.append_file(&stripped, &mut f)
                .map_err(io(format!("tar file {}", p.display())))?;
        }
    }
    tb.finish().map_err(io("tar finish"))?;
    tracing::info!(
        out = %out.display(),
        entries = list.len(),
        "sysupgrade: config backup written"
    );
    Ok(())
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
fn resolve_partition(name: &str) -> Result<PathBuf, Error> {
    let rd = std::fs::read_dir("/sys/class/block")
        .map_err(io("read /sys/class/block"))?;
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
    use rustix::mount::{
        MountFlags, UnmountFlags, mount_bind, mount_move, mount_remount, unmount,
    };

    let new_root = Path::new("/tmp/sysupgrade-root");
    std::fs::create_dir_all(new_root).map_err(io("mkdir new_root"))?;

    // mount --bind new_root on itself so pivot_root accepts it as a
    // mount point. On Linux this works even though the underlying fs
    // is already tmpfs: the bind creates a new mount entry.
    mount_bind(new_root, new_root)
        .map_err(|e| Error::Pivot(format!("bind new_root: {e}")))?;

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
        mount_move(from, &to)
            .map_err(|e| Error::Pivot(format!("move {sub}: {e}")))?;
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
    std::env::set_current_dir("/")
        .map_err(io("chdir / after pivot"))?;

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
    if let Ok(mut f) = OpenOptions::new().write(true).open("/proc/sys/vm/drop_caches") {
        let _ = f.write_all(b"3\n");
    }

    tracing::info!("sysupgrade: pivot to tmpfs complete");
    Ok(())
}

// ── flash ──────────────────────────────────────────────────────────

/// Stream `image_path`'s root and kernel tar members to the eMMC
/// partitions, in the order that stock `emmc_upgrade_tar` uses (so a
/// power cut at any point leaves the bootloader with EITHER an old
/// valid kernel or a zeroed kernel — never a valid-looking kernel
/// pointing at a half-flashed rootfs).
fn flash_image(
    image_path: &Path,
    tar_len: u64,
    kern_dev: &Path,
    root_dev: &Path,
    backup: Option<&Path>,
) -> Result<(), Error> {
    use flate2::read::GzDecoder;

    // Step 1: zero the first 4 KiB of the kernel partition. Invalidates
    // the existing FIT header so U-Boot refuses to boot the old kernel
    // if we die before writing the new one.
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

    // Open the image file and size-limit the gzip/tar to the
    // pre-trailer length — otherwise tar will see the fwtool FWx0
    // footer as garbage past EOF.
    let img = File::open(image_path).map_err(io(format!("open {}", image_path.display())))?;
    let limited = img.take(tar_len);
    let gz = GzDecoder::new(limited);
    let mut ar = tar::Archive::new(gz);

    // Walk the tar once. We need both `root` and `kernel` members;
    // tar doesn't support random access so we stream each member as
    // we encounter it.
    //
    // Invariant: `root` MUST be written before `kernel` (see emmc.sh
    // ordering comment above). The stock tar places them root-first
    // already, but we defensively check and fail loudly if the order
    // is reversed.
    let mut root_bytes_written: u64 = 0;
    let mut kernel_seen = false;
    let mut root_seen = false;

    for entry in ar.entries().map_err(io("tar entries"))? {
        let mut entry = entry.map_err(io("tar entry"))?;
        let path = entry.path().map_err(io("tar entry path"))?.into_owned();
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("");

        match name {
            "root" => {
                if kernel_seen {
                    return Err(Error::Image(
                        "tar order: kernel precedes root (dangerous)".into(),
                    ));
                }
                tracing::info!(dev = %root_dev.display(), "sysupgrade: writing rootfs");
                let mut f = OpenOptions::new()
                    .write(true)
                    .open(root_dev)
                    .map_err(io(format!("open {}", root_dev.display())))?;
                root_bytes_written = std::io::copy(&mut entry, &mut f)
                    .map_err(io("write rootfs"))?;
                f.sync_all().map_err(io("fsync rootfs"))?;
                root_seen = true;
                tracing::info!(bytes = root_bytes_written, "sysupgrade: rootfs written");
            }
            "kernel" => {
                if !root_seen {
                    // We can still continue — we just might lose the
                    // "atomic" property. Don't abort: a sysupgrade.bin
                    // shipping only a kernel is a valid operator
                    // choice in some workflows.
                    tracing::warn!("sysupgrade: kernel member without preceding root");
                }
                tracing::info!(dev = %kern_dev.display(), "sysupgrade: writing kernel");
                let mut f = OpenOptions::new()
                    .write(true)
                    .open(kern_dev)
                    .map_err(io(format!("open {}", kern_dev.display())))?;
                let n = std::io::copy(&mut entry, &mut f)
                    .map_err(io("write kernel"))?;
                f.sync_all().map_err(io("fsync kernel after write"))?;
                kernel_seen = true;
                tracing::info!(bytes = n, "sysupgrade: kernel written");
            }
            _ => {
                // CONTROL, directories, dtb (unused on GL-MT6000) — skip.
            }
        }
    }

    if !root_seen {
        return Err(Error::Image("tar missing root member".into()));
    }

    // Step 3: write the backup tgz past the rootfs, or zero a marker
    // there to force overlay reformat.
    //
    // Calculation (matches libfstools): the overlay starts at
    //   rootfs_offset + align_up(rootfs_blocks, 128) * 512
    // where rootfs_blocks = ceil(root_bytes_written / 512). The 128-
    // block (64 KiB) alignment is load-bearing — libfstools looks
    // there for either an f2fs magic (continue with existing overlay)
    // or any other bytes (reformat on first boot).
    let rootfs_blocks = (root_bytes_written + 511) / 512;
    let aligned_blocks = (rootfs_blocks + 127) & !127;
    let overlay_off: u64 = aligned_blocks * 512;

    let mut f = OpenOptions::new()
        .write(true)
        .open(root_dev)
        .map_err(io(format!("open {} for marker", root_dev.display())))?;
    f.seek(SeekFrom::Start(overlay_off))
        .map_err(io("seek overlay marker"))?;

    match backup {
        Some(p) => {
            tracing::info!(off = overlay_off, src = %p.display(), "sysupgrade: writing config backup past rootfs");
            let mut b = File::open(p).map_err(io(format!("open backup {}", p.display())))?;
            let n = std::io::copy(&mut b, &mut f).map_err(io("write backup"))?;
            f.sync_all().map_err(io("fsync backup"))?;
            tracing::info!(bytes = n, "sysupgrade: backup written");
        }
        None => {
            // Clean flash: zero 4 KiB at the overlay start so
            // libfstools sees garbage and reformats.
            let zeros = [0u8; 4096];
            f.write_all(&zeros).map_err(io("zero overlay marker"))?;
            f.sync_all().map_err(io("fsync marker"))?;
            tracing::info!(off = overlay_off, "sysupgrade: overlay marker zeroed (clean flash)");
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
    use std::io::Write as _;

    /// Build a synthetic sysupgrade.bin with a minimal fwtool trailer
    /// around a given payload. Not a valid tar — only parse_fwtool_trailer
    /// is exercised here.
    fn synth_image(payload: &[u8], meta_json: &str) -> tempfile::NamedTempFile {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(payload).unwrap();
        tmp.write_all(meta_json.as_bytes()).unwrap();
        // crc (unchecked by our parser) + len + magic
        let meta_len = meta_json.len() as u32;
        tmp.write_all(&0u32.to_le_bytes()).unwrap();
        tmp.write_all(&meta_len.to_le_bytes()).unwrap();
        tmp.write_all(b"FWx0").unwrap();
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
        // Pretend the metadata is 100 MB long — should reject.
        tmp.write_all(&0u32.to_le_bytes()).unwrap();
        tmp.write_all(&(100_000_000u32).to_le_bytes()).unwrap();
        tmp.write_all(b"FWx0").unwrap();
        tmp.flush().unwrap();
        let e = parse_fwtool_trailer(tmp.path()).unwrap_err();
        assert!(matches!(e, Error::Fwtool(_)));
    }
}
