//! Watchdog: inherit an fd if procd-init left one, else open
//! /dev/watchdog and pet it every 5s.
//! Split out of init.rs in step 6.

fn find_inherited_watchdog_fd() -> Option<std::fs::File> {
    use std::os::fd::FromRawFd;
    let rd = std::fs::read_dir("/proc/self/fd").ok()?;
    for entry in rd.flatten() {
        let Ok(target) = std::fs::read_link(entry.path()) else {
            continue;
        };
        let s = target.to_string_lossy();
        if s == "/dev/watchdog" || s.starts_with("/dev/watchdog ") {
            let fd_name = entry.file_name();
            let Some(fd_str) = fd_name.to_str() else {
                continue;
            };
            let Ok(fd) = fd_str.parse::<i32>() else {
                continue;
            };
            // Don't steal stdio (0/1/2) even if some weirdness has those
            // pointing at /dev/watchdog — that'd deadlock logging.
            if fd < 3 {
                continue;
            }
            tracing::info!(fd = fd, "reusing inherited /dev/watchdog fd");
            // SAFETY: the fd is open in our process (we just verified
            // via /proc/self/fd), and we're taking ownership — nothing
            // else will close it.
            return Some(unsafe { std::fs::File::from_raw_fd(fd) });
        }
    }
    None
}

/// Pet the hardware watchdog in a background task.
///
/// Every OpenWrt board with a hardware watchdog (almost all of them,
/// including mediatek/filogic which this firmware targets) expects
/// userspace to write to /dev/watchdog periodically, or the watchdog
/// fires and the SoC reboots. On the GL-MT6000 the default timeout is
/// 31s. Stock procd runs a watchdog.c thread that writes every 5s.
///
/// We need to do the same. If /dev/watchdog doesn't exist (QEMU,
/// non-watchdog boards, --services-only side-binary), this logs at
/// debug level and returns — the loop only runs when the device is
/// actually there.
pub(super) fn spawn_watchdog_pet() {
    use std::io::Write;

    // /sbin/init (procd-init) opens /dev/watchdog during preinit and
    // execve's /sbin/procd (us) with the fd still open — file
    // descriptors survive execve unless FD_CLOEXEC is set, which
    // procd-init intentionally doesn't set on the watchdog fd.
    //
    // The kernel only allows one open() on /dev/watchdog at a time
    // (EBUSY on the second), so we CAN'T just open it ourselves — we
    // have to find the inherited fd. Real procd does the same trick
    // (see procd.git watchdog.c). Scan /proc/self/fd, find the entry
    // whose readlink target is "/dev/watchdog", and keep petting it.
    let wd = match find_inherited_watchdog_fd() {
        Some(f) => f,
        None => {
            // No inherited fd — either we're not pid 1 yet (side-binary
            // mode / tests) or /sbin/init didn't open one. Fall back to
            // opening fresh, which works in QEMU / test envs.
            match std::fs::OpenOptions::new()
                .write(true)
                .open("/dev/watchdog")
            {
                Ok(f) => f,
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::NotFound {
                        tracing::debug!("no /dev/watchdog; skipping");
                    } else {
                        tracing::warn!(error = %e, "open /dev/watchdog failed");
                    }
                    return;
                }
            }
        }
    };
    tracing::info!("watchdog petting loop started (5s interval)");

    std::thread::Builder::new()
        .name("watchdog".to_string())
        .spawn(move || {
            let mut wd = wd;
            loop {
                if let Err(e) = wd.write_all(b"\0") {
                    tracing::warn!(error = %e, "watchdog write failed");
                }
                let _ = wd.flush();
                std::thread::sleep(std::time::Duration::from_secs(5));
            }
        })
        .expect("spawn watchdog thread");
}
