//! Preinit: early filesystem mounts, devtmpfs fallback, mount_root
//! hot path, overlay probing, config-backup restore, DHCP lease DB reset,
//! uci-defaults runner.
//! Split out of init.rs in step 6.

use super::*;

fn populate_dev_from_sys() {
    use std::ffi::CString;
    for (kind, mode_bits) in [("block", libc::S_IFBLK), ("char", libc::S_IFCHR)] {
        let dir = format!("/sys/dev/{kind}");
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        for entry in rd.flatten() {
            let name = entry.file_name();
            let Some(_mm) = name.to_str() else { continue };
            // entry.path() here is the symlink (e.g.,
            // /sys/dev/block/179:7 → ../../devices/...), which we
            // can still read uevent from.
            let uevent_path = entry.path().join("uevent");
            let Ok(content) = std::fs::read_to_string(&uevent_path) else { continue };
            let mut major: Option<u32> = None;
            let mut minor: Option<u32> = None;
            let mut devname: Option<&str> = None;
            for line in content.lines() {
                if let Some(v) = line.strip_prefix("MAJOR=") {
                    major = v.parse().ok();
                } else if let Some(v) = line.strip_prefix("MINOR=") {
                    minor = v.parse().ok();
                } else if let Some(v) = line.strip_prefix("DEVNAME=") {
                    devname = Some(v);
                }
            }
            let (Some(major), Some(minor), Some(devname)) = (major, minor, devname) else {
                continue;
            };
            let devpath = format!("/dev/{devname}");
            // Create parent dirs if the DEVNAME contains "/" (e.g.
            // "bus/usb/001/001").
            if let Some(parent) = std::path::Path::new(&devpath).parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let Ok(cpath) = CString::new(devpath.as_bytes()) else { continue };
            let dev = unsafe { libc::makedev(major, minor) };
            let rc = unsafe { libc::mknod(cpath.as_ptr(), mode_bits | 0o600, dev) };
            if rc != 0 {
                let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                if errno != libc::EEXIST {
                    tracing::debug!(path = devpath, errno, "mknod failed");
                }
            }
        }
    }
}

/// Rename network interfaces so their kernel name matches the
/// DTS-declared label (or `openwrt,netdev-name` property). Equivalent
/// of the target's /lib/preinit/04_set_netdev_label shell hook.
///
/// Walks `/sys/class/net/*/of_node/label` — each entry is one name.
/// If the current ifname differs from the label, issue RTM_SETLINK
/// (IFLA_IFNAME) via rtnetlink. Interface must be DOWN for the kernel
/// to accept a rename; during preinit all interfaces ARE down
/// (netifd hasn't brought anything up yet), so this is safe before
/// `net::Net::bring_up`.
///
/// Spins its own tokio current-thread runtime — init::run() is sync
/// and the async main runtime hasn't started yet. Best-effort: a
/// single bad rename doesn't block the others, and a complete failure
/// is logged but not propagated.
///
/// In coexist, procd-init's preinit already ran this and every
/// netdev already has its final name. Every iteration here finds

pub(super) fn mount_root_if_needed() -> Result<(), Error> {
    if overlay_is_attached()? {
        tracing::info!(
            "mount_root: rootfs overlay already attached upstream; skipping"
        );
        return Ok(());
    }

    tracing::warn!("mount_root: no upstream overlay; engaging hot path");
    mount_root_hot_path()
}

/// The actual libfstools-in-Rust path. Assumes we're pid 1 with the
/// rootfs mounted read-only on `/` (kernel's default from `root=` on
/// the cmdline), /proc, /sys, /dev, /tmp already set up by
/// `early_mounts`, and nobody else has touched the overlay region.
///
/// Steps (matches fstools `rootdisk.c` + `mount.c` + `overlay.c`):
///  1. Find rootfs block device from GPT PARTLABEL=rootfs.
///  2. Parse squashfs superblock magic + bytes_used; align to 64 KiB
///     → overlay_off.
///  3. Detect what's at overlay_off:
///      - f2fs superblock magic at +0x400 → existing overlay, just
///        mount it.
///      - DEADCODE or ones/junk → unformatted. Scan forward ≤256 KiB
///        for a gzip-wrapped config backup (from sysupgrade) and
///        stash it in RAM if present.
///  4. Create /dev/loopN (LOOP_CTL_GET_FREE), bind to rootfs fd with
///     lo_offset = overlay_off. **Leak the rootfs fd.**
///  5. mkfs.f2fs the loop device if needed (shell out — writing an
///     f2fs formatter in Rust is a hundred times more code than
///     shelling out).
///  6. Mount f2fs on the loop device at /overlay.
///  7. Build /overlay/upper + /overlay/work, stack overlayfs at /mnt
///     with lowerdir=/.
///  8. pivot_root: /mnt → /, old / → /mnt/rom.
///  9. mount_move /rom/{proc,sys,dev,tmp,overlay} into the new root.
/// 10. If step 3 found a backup, tar-extract it over the new /.
fn mount_root_hot_path() -> Result<(), Error> {
    use rustix::mount::{MountFlags, mount, mount_move};
    use std::io::{Read, Seek, SeekFrom};
    use std::os::fd::AsRawFd;

    // 1. Rootfs partition.
    let rootfs_dev = crate::sysupgrade::resolve_partition("rootfs")
        .map_err(|e| Error::Runtime(format!("mount_root: resolve_partition: {e}")))?;
    tracing::info!(dev = %rootfs_dev.display(), "mount_root: using rootfs device");

    // 2. Parse squashfs superblock for bytes_used. Keep the fd — we
    // later reuse it as the loop backing.
    let mut rootfs_file = std::fs::File::options()
        .read(true)
        .write(true)
        .open(&rootfs_dev)
        .map_err(Error::Io)?;
    let mut sb = [0u8; 96];
    rootfs_file.read_exact(&mut sb).map_err(Error::Io)?;
    if &sb[..4] != b"hsqs" {
        return Err(Error::Runtime(format!(
            "mount_root: {} is not squashfs (magic {:02x?})",
            rootfs_dev.display(),
            &sb[..4]
        )));
    }
    let bytes_used = u64::from_le_bytes(sb[40..48].try_into().unwrap());
    // Align UP to 64 KiB — matches libfstools ROOTDEV_OVERLAY_ALIGN.
    let overlay_off = (bytes_used + 0xFFFF) & !0xFFFF;
    tracing::info!(
        bytes_used,
        overlay_off,
        "mount_root: squashfs header parsed"
    );

    // 3. Check what's at overlay_off.
    let mut probe = [0u8; 0x420];
    rootfs_file
        .seek(SeekFrom::Start(overlay_off))
        .map_err(Error::Io)?;
    rootfs_file.read_exact(&mut probe).map_err(Error::Io)?;
    const F2FS_MAGIC: u32 = 0xF2F5_2010;
    let f2fs_at = u32::from_le_bytes(probe[0x400..0x404].try_into().unwrap());
    let first_le = u32::from_le_bytes(probe[0..4].try_into().unwrap());

    // Gzip magic `1f 8b 08 00` as LE u32 = 0x00088b1f. Our native
    // sysupgrade writes the config-backup tgz directly at overlay_off
    // (no preceding DEADCODE marker, which stock libfstools uses).
    // Accept that case too.
    const GZIP_MAGIC_LE: u32 = 0x00088b1f;

    let (needs_format, backup_tgz): (bool, Option<Vec<u8>>) = if f2fs_at == F2FS_MAGIC {
        tracing::info!("mount_root: existing f2fs overlay detected");
        (false, None)
    } else if first_le == 0xDEADC0DE || first_le == 0xFFFFFFFF {
        // Stock sysupgrade convention: DEADCODE or FFFFFFFF marker,
        // gzip backup ≤256 KiB forward.
        tracing::info!(marker = format!("{first_le:#010x}"), "mount_root: unformatted marker; scanning for config backup");
        let backup = scan_for_backup_tgz(&mut rootfs_file, overlay_off)
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "mount_root: backup scan failed");
                None
            });
        (true, backup)
    } else if first_le == GZIP_MAGIC_LE {
        // Our native sysupgrade's convention: gzip backup starts
        // directly at overlay_off. Read it and treat overlay as
        // unformatted.
        tracing::info!("mount_root: gzip backup at overlay_off; unformatted overlay");
        let backup = scan_for_backup_tgz(&mut rootfs_file, overlay_off)
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "mount_root: backup read failed");
                None
            });
        (true, backup)
    } else if first_le == 0x00000000 && f2fs_at == 0x00000000 {
        // Freshly-flashed region (U-Boot HTTP recovery writes zeros
        // past the rootfs — no marker, no backup, no filesystem).
        // Treat as unformatted, no backup.
        tracing::info!("mount_root: zero region (fresh flash); will format f2fs");
        (true, None)
    } else {
        // Something in the overlay region but not f2fs — bail loudly
        // rather than format and potentially destroy user data.
        return Err(Error::Runtime(format!(
            "mount_root: overlay region has unknown content \
             (first_le={first_le:#010x}, f2fs_probe={f2fs_at:#010x})"
        )));
    };

    // 4. Create loop device.
    let loop_dev = create_loop_device(&rootfs_file, overlay_off)?;
    tracing::info!(loop_dev = %loop_dev.display(), "mount_root: loop device attached");
    // CRUCIAL: leak the rootfs_file so its fd stays alive for the
    // loop device's lifetime. If dropped, LO_FLAGS_AUTOCLEAR fires
    // and the loop detaches the next time we umount — meaning the
    // next sysupgrade will fail with "device busy" at best and
    // silent corruption at worst.
    std::mem::forget(rootfs_file);

    // 5. Format if needed. Shell out to mkfs.f2fs — implementing
    // f2fs formatting in Rust is way too much for one firmware
    // feature.
    if needs_format {
        tracing::info!(dev = %loop_dev.display(), "mount_root: formatting f2fs");
        let status = std::process::Command::new("/usr/sbin/mkfs.f2fs")
            .args(["-q", "-f", "-l", "rootfs_data"])
            .arg(&loop_dev)
            .status()
            .map_err(Error::Io)?;
        if !status.success() {
            return Err(Error::Runtime(format!(
                "mount_root: mkfs.f2fs exited {status}"
            )));
        }
    }

    // 6. Mount f2fs at /overlay.
    std::fs::create_dir_all("/overlay").map_err(Error::Io)?;
    mount(&loop_dev, "/overlay", "f2fs", MountFlags::NOATIME, None::<&std::ffi::CStr>)
        .map_err(|e| Error::Runtime(format!("mount_root: mount f2fs: {e}")))?;

    // 7. Stack overlayfs.
    std::fs::create_dir_all("/overlay/upper").map_err(Error::Io)?;
    std::fs::create_dir_all("/overlay/work").map_err(Error::Io)?;
    std::fs::create_dir_all("/mnt").map_err(Error::Io)?;
    let overlay_opts = std::ffi::CString::new(
        "lowerdir=/,upperdir=/overlay/upper,workdir=/overlay/work",
    )
    .expect("no NUL in overlay opts");
    mount(
        "overlayfs:/overlay",
        "/mnt",
        "overlay",
        MountFlags::NOATIME,
        Some(overlay_opts.as_c_str()),
    )
    .map_err(|e| Error::Runtime(format!("mount_root: mount overlay: {e}")))?;

    // 8. pivot_root. `/mnt/rom` must exist BEFORE the call.
    std::fs::create_dir_all("/mnt/rom").map_err(Error::Io)?;
    // fstools moves /proc BEFORE pivot_root — if /proc isn't in the
    // new root, pivot_root can fail with EINVAL ("shared parent").
    mount_move("/proc", "/mnt/proc")
        .map_err(|e| Error::Runtime(format!("mount_root: move /proc: {e}")))?;
    rustix::process::pivot_root("/mnt", "/mnt/rom")
        .map_err(|e| Error::Runtime(format!("mount_root: pivot_root: {e}")))?;
    std::env::set_current_dir("/").map_err(Error::Io)?;

    // 9. Move the rest. sys/dev/overlay — in that order. /overlay
    // must move last because we depend on the original /overlay bind
    // until we unmount /rom.
    //
    // /tmp is intentionally NOT in this list: early_mounts doesn't
    // mount a tmpfs on /tmp, so /rom/tmp is just a directory on the
    // old rootfs — `mount_move` returns EINVAL on non-mountpoints.
    // Instead, mount a fresh tmpfs on the new /tmp below (step 9b).
    for (src, dst) in [
        ("/rom/sys", "/sys"),
        ("/rom/dev", "/dev"),
        ("/rom/overlay", "/overlay"),
    ] {
        if std::path::Path::new(src).exists() {
            if let Err(e) = mount_move(src, dst) {
                tracing::warn!(src, dst, error = %e, "mount_root: move failed");
            }
        }
    }

    // 9b. Fresh tmpfs on /tmp. Stock OpenWrt does this via preinit's
    // `/lib/preinit/10_indicate_preinit`; we own that responsibility
    // now. Standard size (half of RAM) matches procd's default.
    if let Err(e) = mount(
        "tmpfs",
        "/tmp",
        "tmpfs",
        MountFlags::NOSUID | MountFlags::NODEV,
        Some(std::ffi::CString::new("mode=1777").unwrap().as_c_str()),
    ) {
        tracing::warn!(error = %e, "mount_root: tmpfs /tmp failed");
    }

    // 10. Restore backup.
    if let Some(tgz) = backup_tgz {
        tracing::info!(bytes = tgz.len(), "mount_root: restoring config backup");
        if let Err(e) = extract_tgz_over_root(&tgz) {
            tracing::warn!(error = %e, "mount_root: backup restore failed");
        }
    }

    // Keep a note that we did this, for the logs.
    tracing::info!("mount_root: hot path complete, overlay live");
    Ok(())
}

/// Scan forward from `overlay_off` up to 256 KiB looking for a gzip
/// header (1f 8b 08 00). If found, return the bytes from there to
/// end-of-scan (gzip is self-delimiting so the tail after the gzip
/// trailer is ignored by gunzip).
fn scan_for_backup_tgz(
    f: &mut std::fs::File,
    overlay_off: u64,
) -> Result<Option<Vec<u8>>, Error> {
    use std::io::{Read, Seek, SeekFrom};
    const MAX_SCAN: usize = 256 * 1024;
    f.seek(SeekFrom::Start(overlay_off)).map_err(Error::Io)?;
    let mut buf = vec![0u8; MAX_SCAN];
    let n = f.read(&mut buf).map_err(Error::Io)?;
    buf.truncate(n);
    // Gzip magic with exact FLG=0 byte — matches fstools'
    // cpu_to_le32(0x88b1f) expectation.
    let needle: [u8; 4] = [0x1f, 0x8b, 0x08, 0x00];
    for i in 0..buf.len().saturating_sub(4) {
        if buf[i..i + 4] == needle {
            tracing::info!(offset = i, "mount_root: gzip magic located in overlay region");
            return Ok(Some(buf[i..].to_vec()));
        }
    }
    Ok(None)
}

/// Create a loop device bound to `backing`'s fd at `offset`. Returns
/// the `/dev/loopN` path. Leaves the backing fd OPEN (caller must
/// `std::mem::forget` it or otherwise keep it alive).
fn create_loop_device(backing: &std::fs::File, offset: u64) -> Result<PathBuf, Error> {
    use std::os::fd::AsRawFd;

    // Constants lifted from <linux/loop.h>. Use `_` as the ioctl
    // request type — libc has it as c_int on some arches and c_ulong
    // on others, and letting inference pick avoids a per-arch cfg.
    const LOOP_CTL_GET_FREE: u32 = 0x4C82;
    const LOOP_SET_FD: u32 = 0x4C00;
    const LOOP_SET_STATUS64: u32 = 0x4C04;
    const LO_FLAGS_AUTOCLEAR: u32 = 4;

    // loop_info64 layout — matches <linux/loop.h>. 232 bytes on
    // most arches. We only need lo_offset; the rest stays zero.
    #[repr(C)]
    struct LoopInfo64 {
        lo_device: u64,
        lo_inode: u64,
        lo_rdevice: u64,
        lo_offset: u64,
        lo_sizelimit: u64,
        lo_number: u32,
        lo_encrypt_type: u32,
        lo_encrypt_key_size: u32,
        lo_flags: u32,
        lo_file_name: [u8; 64],
        lo_crypt_name: [u8; 64],
        lo_encrypt_key: [u8; 32],
        lo_init: [u64; 2],
    }

    // Get a free loop number via the control device.
    let ctl = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/loop-control")
        .map_err(Error::Io)?;
    let num = unsafe { libc::ioctl(ctl.as_raw_fd(), LOOP_CTL_GET_FREE as _) };
    if num < 0 {
        return Err(Error::Runtime(format!(
            "LOOP_CTL_GET_FREE: {}",
            std::io::Error::last_os_error()
        )));
    }
    let loop_dev = PathBuf::from(format!("/dev/loop{num}"));
    let lf = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&loop_dev)
        .map_err(Error::Io)?;
    // Associate backing fd.
    if unsafe { libc::ioctl(lf.as_raw_fd(), LOOP_SET_FD as _, backing.as_raw_fd() as libc::c_ulong) } < 0 {
        return Err(Error::Runtime(format!(
            "LOOP_SET_FD: {}",
            std::io::Error::last_os_error()
        )));
    }
    // Set offset + autoclear flag.
    let mut info: LoopInfo64 = unsafe { std::mem::zeroed() };
    info.lo_offset = offset;
    info.lo_flags = LO_FLAGS_AUTOCLEAR;
    if unsafe { libc::ioctl(lf.as_raw_fd(), LOOP_SET_STATUS64 as _, &info as *const _ as libc::c_ulong) } < 0 {
        return Err(Error::Runtime(format!(
            "LOOP_SET_STATUS64: {}",
            std::io::Error::last_os_error()
        )));
    }
    // Intentionally leak the loop fd too — keeping it open guards
    // against another process opening the loop device with a
    // different offset. Matches fstools rootdisk.c lifetime model.
    std::mem::forget(lf);
    Ok(loop_dev)
}

/// Extract a gzipped tar over `/`. Used to restore a sysupgrade
/// config backup that was embedded in the overlay region.
///
/// Does NOT merge passwd/group/shadow (which stock does) — our
/// image has a fixed /etc/passwd and the backup only needs to
/// restore /etc/oxwrt/, /etc/dropbear/authorized_keys etc.
fn extract_tgz_over_root(bytes: &[u8]) -> Result<(), Error> {
    use flate2::read::GzDecoder;
    let gz = GzDecoder::new(bytes);
    let mut ar = tar::Archive::new(gz);
    ar.unpack("/").map_err(Error::Io)
}

/// Parse /proc/mounts looking for an overlayfs mount on `/`. That's

/// Parse /proc/mounts looking for an overlayfs mount on `/`. That's
/// what fstools leaves us with after its pivot_root: root filesystem
/// is of type "overlay" with `lowerdir=/,upperdir=/overlay/upper,...`.
///
/// We could also look at the `/overlay` entry (f2fs on loop0), but
/// the overlay-on-/ signal is the definitive "the whole stack is
/// set up" marker.
fn overlay_is_attached() -> Result<bool, Error> {
    let mounts = std::fs::read_to_string("/proc/mounts")
        .map_err(Error::Io)?;
    for line in mounts.lines() {
        // Each line: "<src> <mountpoint> <fstype> <opts> <dump> <pass>"
        let mut it = line.split_whitespace();
        let _src = it.next();
        let Some(mp) = it.next() else { continue };
        let Some(fstype) = it.next() else { continue };
        if mp == "/" && fstype == "overlay" {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Load kernel modules from /etc/modules-boot.d/ and /etc/modules.d/.
///
/// Equivalent of upstream OpenWrt `ubox/kmodloader.c`, trimmed to
/// what we actually need: boot-time modules (for things procd-init
/// would have loaded before our pid-1 entry) and runtime modules
/// (for drivers needed once the supervisor is up — e.g. `kmod-veth`
/// for container netns peers, `kmod-nft-nat` for the firewall).
///
/// Flow: walk each directory in sorted order, read each file, parse
/// each non-comment non-empty line as `<module_name> [params...]`.
/// For each module, recursively glob /lib/modules/<uname>/ for the
/// `.ko`, call finit_module(2). EEXIST (already loaded) counts as
/// success and is logged at debug, not warn — this is the normal
/// case when running in coexist with procd-init, which already
/// loaded everything during its preinit phase.
///
/// Best-effort: a missing .ko file or a genuine finit_module error
/// is logged at warn level and the loop continues. A missing
/// kernel module is almost never fatal for oxwrtd's own needs,
/// and a panicked init makes diagnosis much harder than a running
/// init with one missing driver.
///
/// Stage 1 of the procd-init takeover; safe under current (coexist)
/// configuration where procd-init loads modules before us —
/// every finit_module returns EEXIST.
/// Create AP-mode netdevs on every available wifi phy. Names follow
/// OpenWrt's convention: `phy<N>-ap0` on `phy<N>`. Uses the bundled
/// `iw` binary (staged into /usr/bin by the imagebuilder) because
/// rolling our own nl80211 client is a lot of code for one ioctl
/// equivalent. Fully idempotent — existing interfaces are left alone.
/// Wipe /etc/oxwrt/coredhcp/leases.txt on LAN subnet change.
///
/// coredhcp's range plugin persists leases as a **SQLite database**
/// (despite the `.txt` extension) and refuses to start — fatal error —
/// if any persisted lease falls outside the currently-configured pool.
/// Renumbering the LAN (e.g. 192.168.1.0/24 → 192.168.50.0/24) bricks
/// DHCPv4 forever without intervention.
///
/// Reliable strategy: keep a plaintext marker file at
/// /etc/oxwrt/coredhcp/.lan recording the last-booted LAN subnet in
/// canonical form (`A.B.C.D/NN`). On every boot, compare to the
/// configured LAN. If they differ, wipe the SQLite DB and refresh the
/// marker. Losing DHCP lease persistence on a subnet change is an
/// acceptable trade — clients re-DISCOVER within seconds.
///
/// Byte-scanning the SQLite file directly is unreliable because the
/// engine may store string values in non-contiguous pages or in
/// overflow chains, so literal IP bytes don't always appear in-file.
pub(super) fn truncate_stale_dhcp_leases(cfg: &Config) {
    use crate::config::Network;

    let Some(Network::Lan { address, prefix, .. }) = cfg.lan() else {
        return;
    };
    let cur = format!("{address}/{prefix}");
    let marker_path = "/etc/oxwrt/coredhcp/.lan";
    let prev = std::fs::read_to_string(marker_path)
        .ok()
        .map(|s| s.trim().to_string());
    if prev.as_deref() == Some(cur.as_str()) {
        return; // no change since last boot
    }
    tracing::warn!(
        prev = ?prev,
        current = %cur,
        "LAN subnet changed since last boot; wiping coredhcp lease database"
    );
    let lease_path = "/etc/oxwrt/coredhcp/leases.txt";
    // Truncate to 0 bytes rather than removing. The file must exist
    // because it's a bind-mount source for the dhcp container; removing
    // it makes container spawn fail with ENOENT and the service can
    // never start. SQLite with OPEN_CREATE on a 0-byte file initializes
    // a fresh database on first write, which is exactly what we want.
    if let Err(e) = std::fs::write(lease_path, b"") {
        tracing::warn!(error = %e, "failed to truncate stale leases file");
    }
    // Also update the marker so next boot is a no-op.
    if let Some(parent) = std::path::Path::new(marker_path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(marker_path, &cur);
}

pub(super) fn run_uci_defaults() {
    const DIR: &str = "/etc/uci-defaults";
    let rd = match std::fs::read_dir(DIR) {
        Ok(rd) => rd,
        Err(e) => {
            // ENOENT is normal on an image with no first-boot scripts
            // (or on the second boot after the first-boot scripts have
            // all been cleared).
            if e.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(error = %e, "uci-defaults: read_dir failed");
            }
            return;
        }
    };

    let mut entries: Vec<_> = rd
        .filter_map(|r| r.ok())
        .map(|e| e.path())
        .filter(|p| {
            if !p.is_file() {
                return false;
            }
            let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
            // Reject hidden files + stock OpenWrt scripts (see
            // doc comment above). "oxwrt" must appear in the name.
            !name.starts_with('.') && name.contains("oxwrt")
        })
        .collect();
    entries.sort();

    for script in entries {
        tracing::info!(script = %script.display(), "uci-defaults: running");
        // Ensure the script is executable — at image-stage time we chmod
        // 755 these, but defensive `chmod +x` via the shell works for
        // hand-dropped operator scripts too. Invoke through /bin/sh so
        // scripts without a shebang still work.
        let status = std::process::Command::new("/bin/sh")
            .arg(&script)
            .status();
        match status {
            Ok(s) if s.success() => {
                if let Err(e) = std::fs::remove_file(&script) {
                    tracing::warn!(
                        script = %script.display(),
                        error = %e,
                        "uci-defaults: remove after success failed"
                    );
                }
            }
            Ok(s) => {
                tracing::warn!(
                    script = %script.display(),
                    status = ?s,
                    "uci-defaults: script failed; will retry next boot"
                );
            }
            Err(e) => {
                tracing::warn!(
                    script = %script.display(),
                    error = %e,
                    "uci-defaults: spawn failed"
                );
            }
        }
    }
}

pub(super) fn early_mounts() -> Result<(), Error> {
    use rustix::ffi::CStr;
    use rustix::mount::{MountFlags, mount};

    let nsnd = MountFlags::NOSUID | MountFlags::NOEXEC | MountFlags::NODEV;
    // /dev is attempted as devtmpfs first; if the kernel lacks
    // CONFIG_DEVTMPFS (confirmed on the mediatek/filogic image
    // we ship) the mount returns ENODEV and we retry with tmpfs +
    // populate_dev_from_sys(). That fallback does what procd's
    // `early_dev()` does: walks /sys/dev/{block,char}/M:N/uevent for
    // each device, mknod's the corresponding /dev/<name>.
    // devpts needs ptmxmode=666,gid=5 so /dev/pts/ptmx is usable
    // outside root (dropbear drops to logged-in user before calling
    // openpty). Without these options the kernel defaults ptmxmode to
    // 0000 and ptmx opens return EACCES — the exact failure mode seen
    // in the debug-ssh container ("PTY allocation request failed").
    let devpts_opts = std::ffi::CString::new("ptmxmode=666,gid=5").unwrap();
    let mounts: &[(&str, &str, &str, MountFlags, Option<&CStr>)] = &[
        ("proc", "/proc", "proc", nsnd, None),
        ("sysfs", "/sys", "sysfs", nsnd, None),
        ("devtmpfs", "/dev", "devtmpfs", MountFlags::NOSUID, None),
        (
            "devpts", "/dev/pts", "devpts",
            MountFlags::NOSUID | MountFlags::NOEXEC,
            Some(devpts_opts.as_c_str()),
        ),
        ("cgroup2", "/sys/fs/cgroup", "cgroup2", nsnd, None),
    ];

    for (source, target, fstype, flags, data) in mounts {
        // mkdir the target. Two tolerant cases:
        //   AlreadyExists: fine.
        //   EROFS (no such dir on the ro squashfs): log + try mount
        //       anyway. On real hardware the kernel auto-mounts
        //       devtmpfs on /dev (CONFIG_DEVTMPFS_MOUNT=y) before we
        //       run, so /dev exists even if the squashfs didn't
        //       provide it. /proc similarly gets mounted by the
        //       kernel command line on some configs. When it really
        //       doesn't exist, the mount call below fails with a
        //       clearer error than mkdir's EROFS.
        if let Err(e) = std::fs::create_dir_all(target) {
            match e.kind() {
                std::io::ErrorKind::AlreadyExists => {}
                _ if e.raw_os_error() == Some(libc::EROFS) => {
                    tracing::warn!(
                        target = target,
                        "early_mounts: mountpoint missing on ro rootfs; relying on pre-existing mount"
                    );
                }
                _ => return Err(Error::Io(e)),
            }
        }
        match mount(*source, *target, *fstype, *flags, *data) {
            Ok(()) => {
                tracing::info!(target = target, fstype = fstype, "early_mounts: mounted");
            }
            // EBUSY = target already mounted (upstream or prior run).
            Err(rustix::io::Errno::BUSY) => {
                tracing::info!(target = target, "early_mounts: already mounted (EBUSY)");
            }
            // ENODEV = fs type can't be mounted on this target, e.g.,
            // devtmpfs when the kernel lacks CONFIG_DEVTMPFS. This is
            // a real problem for /dev — without devtmpfs we'd need to
            // mknod the device nodes by hand. Log loudly.
            Err(rustix::io::Errno::NODEV) => {
                // Fallback for /dev: mount tmpfs + populate via mknod.
                if *target == "/dev" && *fstype == "devtmpfs" {
                    tracing::warn!("early_mounts: devtmpfs unavailable; falling back to tmpfs + mknod");
                    let tmpfs_opts = std::ffi::CString::new("mode=0755,size=512K").unwrap();
                    match mount(
                        "tmpfs",
                        "/dev",
                        "tmpfs",
                        MountFlags::NOSUID,
                        Some(tmpfs_opts.as_c_str()),
                    ) {
                        Ok(()) => {
                            populate_dev_from_sys();
                            tracing::info!("early_mounts: /dev populated via mknod");
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "early_mounts: tmpfs fallback on /dev failed");
                        }
                    }
                } else {
                    tracing::warn!(target = target, fstype = fstype, "early_mounts: ENODEV (kernel lacks fstype?)");
                }
            }
            // ENOENT = target path doesn't exist AND nothing is
            // mounted there. Can happen for /dev/pts or /sys/fs/cgroup
            // if their parent tmpfs/sysfs doesn't have them yet.
            Err(rustix::io::Errno::NOENT) => {
                tracing::warn!(
                    target = target,
                    "early_mounts: mount target does not exist; skipping"
                );
            }
            Err(source) => {
                return Err(Error::Mount {
                    target: (*target).to_string(),
                    source,
                });
            }
        }
    }
    Ok(())
}

