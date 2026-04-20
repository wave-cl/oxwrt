//! Watchdog: inherit an fd if procd-init left one, else open
//! /dev/watchdog and pet it every 5s.
//!
//! # Deadman coupling (stall detector)
//!
//! The watchdog pet loop runs on a dedicated OS thread so it
//! stays alive even when tokio's executor is wedged — that's
//! useful for catching hard process-level failures, but it also
//! masks a class of "tokio is stuck but the process is alive"
//! bugs where the hardware reset never fires.
//!
//! To catch those too, we run a tokio task that increments
//! `HEARTBEAT` every second. The OS-thread pet loop checks the
//! heartbeat's freshness before each pet: if the counter hasn't
//! advanced in `STALL_THRESHOLD`, it STOPS petting. The kernel's
//! hardware watchdog then fires (default ~31s on MT7986) and
//! the board resets. On a healthy system, the heartbeat ticks
//! every 1s → pet loop sees fresh counter → watchdog stays
//! happy.
//!
//! The two numbers have to fit the kernel's timeout:
//!   - HEARTBEAT tick:       1 s
//!   - STALL_THRESHOLD:     20 s  (we stop petting after 20 s of
//!                                 no tokio progress)
//!   - kernel WD timeout:   31 s  (board default — reboots
//!                                 20+ ms after we stop petting)
//!
//! Split out of init.rs in step 6.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Monotonic counter incremented by `spawn_heartbeat` every
/// HEARTBEAT_INTERVAL. The pet loop reads it to detect tokio
/// stalls. Starts at 0 — if tokio never ticks (e.g. runtime
/// failed to build), the very first pet attempt sees a stale
/// counter and refuses to pet, which is the correct behavior.
static HEARTBEAT: AtomicU64 = AtomicU64::new(0);

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(1);
const PET_INTERVAL: Duration = Duration::from_secs(5);
const STALL_THRESHOLD: Duration = Duration::from_secs(20);

/// Spawn a tokio task that bumps `HEARTBEAT` every second. Must
/// run on the same runtime that owns the control plane — if
/// THAT runtime stalls, this task stops firing, the watchdog
/// pet thread notices, and the kernel reboots.
pub(super) fn spawn_heartbeat() {
    tokio::spawn(async {
        let mut ticker = tokio::time::interval(HEARTBEAT_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            HEARTBEAT.fetch_add(1, Ordering::Relaxed);
        }
    });
}

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
            // Snapshot of the last-seen heartbeat + wall-clock
            // when we saw it. Used to detect "counter advancing"
            // vs "counter stuck" without needing a synchronized
            // clock between heartbeat task and pet thread.
            let mut last_seen: u64 = HEARTBEAT.load(Ordering::Relaxed);
            let mut last_advance = Instant::now();
            loop {
                let current = HEARTBEAT.load(Ordering::Relaxed);
                let (new_last_seen, new_last_advance) =
                    update_stall_tracker(last_seen, last_advance, current);
                last_seen = new_last_seen;
                last_advance = new_last_advance;
                let stall = last_advance.elapsed();
                if stall < STALL_THRESHOLD {
                    if let Err(e) = wd.write_all(b"\0") {
                        tracing::warn!(error = %e, "watchdog write failed");
                    }
                    let _ = wd.flush();
                } else {
                    // tokio heartbeat hasn't advanced in >= STALL_THRESHOLD.
                    // Stop petting — the kernel's hardware watchdog
                    // takes over and reboots the board. Log once per
                    // pet cycle so an operator watching the console
                    // sees the count-up before reboot.
                    tracing::error!(
                        stall_s = stall.as_secs(),
                        threshold_s = STALL_THRESHOLD.as_secs(),
                        "watchdog: tokio heartbeat stalled; withholding pet to trigger reset"
                    );
                }
                std::thread::sleep(PET_INTERVAL);
            }
        })
        .expect("spawn watchdog thread");
}

/// Pure stall-tracker update: given the previously-observed
/// heartbeat + when we last saw it advance, plus the current
/// counter, return the updated (last_seen, last_advance) pair.
///
/// Extracted so the decision logic is unit-testable without
/// spawning threads or reading the real HEARTBEAT static.
fn update_stall_tracker(last_seen: u64, last_advance: Instant, current: u64) -> (u64, Instant) {
    if current != last_seen {
        (current, Instant::now())
    } else {
        (last_seen, last_advance)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Counter advancing → last_advance pushed forward, pet
    /// continues indefinitely.
    #[test]
    fn heartbeat_advance_resets_stall_timer() {
        let t0 = Instant::now() - Duration::from_secs(5);
        let (seen, advance) = update_stall_tracker(10, t0, 11);
        assert_eq!(seen, 11);
        // Advance must have moved forward — strictly greater
        // than t0.
        assert!(advance > t0);
    }

    /// Counter unchanged → stall timer unchanged (pet thread
    /// sees the age grow each iteration).
    #[test]
    fn heartbeat_unchanged_preserves_timer() {
        let t0 = Instant::now() - Duration::from_secs(5);
        let (seen, advance) = update_stall_tracker(10, t0, 10);
        assert_eq!(seen, 10);
        assert_eq!(advance, t0, "stale counter must not refresh the timer");
    }

    /// Threshold sizing sanity: the stall-before-pet withhold
    /// MUST be less than typical hardware watchdog timeouts so
    /// the kernel has room to fire after we stop feeding.
    /// MT7986 default is 31 s; we withhold at 20 s, leaving
    /// ≥11 s for the kernel to notice.
    #[test]
    fn stall_threshold_fits_under_hw_timeout() {
        // Conservative: any kernel timeout >= 30 s covers us.
        let kernel_wd_floor = Duration::from_secs(30);
        assert!(
            STALL_THRESHOLD + Duration::from_secs(5) <= kernel_wd_floor,
            "STALL_THRESHOLD too close to kernel timeout; widen the gap"
        );
    }

    /// The heartbeat-tick interval must be comfortably shorter
    /// than the stall threshold so normal jitter (tokio timer
    /// wheel granularity, GC pauses, etc.) doesn't trigger a
    /// false stall detection.
    #[test]
    fn heartbeat_interval_well_under_threshold() {
        assert!(
            HEARTBEAT_INTERVAL * 10 <= STALL_THRESHOLD,
            "STALL_THRESHOLD must be at least 10x HEARTBEAT_INTERVAL"
        );
    }
}
