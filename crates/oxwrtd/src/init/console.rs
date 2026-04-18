//! Console hand-off: dup /dev/console to fd 0/1/2 and install a
//! /dev/kmsg-writing panic hook.
//!
//! Moved out of main.rs in step 6. Kept `pub` (not `pub(super)`) so
//! main.rs can call it from the pre-runtime bootstrap — we have to
//! attach the console BEFORE `init::run()` spins up a tokio runtime
//! or the kernel panics in a runtime thread leave no trace.

/// Open /dev/console and dup it to stdin/stdout/stderr. When the
/// kernel execs /sbin/init as pid 1 directly, fds 0/1/2 may be
/// closed or pointed at the wrong place depending on kernel config.
/// Without this step every eprintln / tracing::error goes into the
/// void — and a panicking init loses its backtrace, making bootloop
/// diagnosis impossible.
///
/// Procd-init's `early_console()` in procd/initd/early.c does the
/// equivalent. Best-effort: if /dev/console is missing (early
/// boot, /dev not yet populated by devtmpfs), silently continue —
/// the rest of the boot may still succeed and we can read logs via
/// /dev/kmsg later.
#[cfg(target_os = "linux")]
pub fn early_console() {
    use std::os::fd::{AsRawFd, IntoRawFd};
    let Ok(console) = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/console")
    else {
        return;
    };
    let fd = console.as_raw_fd();
    // dup3 to get each target fd (0, 1, 2). Safe because the target
    // fds are either closed or ones we can clobber (we're pid 1,
    // there's nothing else running to care).
    for target in 0..=2 {
        if target != fd {
            unsafe {
                // Use dup2 — simpler than dup3, no O_CLOEXEC needed
                // (we want these to survive execve into children).
                let _ = libc::dup2(fd, target);
            }
        }
    }
    // Intentionally leak the console file so the original fd stays
    // open even if the temporary File is dropped. Without this, the
    // console fd can close underneath our stdio.
    let _ = console.into_raw_fd();
}

#[cfg(not(target_os = "linux"))]
pub fn early_console() {}

/// Install a panic hook that prints the panic to stderr (now
/// console-attached) AND writes to /dev/kmsg so a bootloop's UART
/// output has the panic details. Without this hook, a Rust panic
/// in pid 1 produces just "panicked at ..." to stderr and the
/// kernel immediately reboots without dmesg capturing anything.
#[cfg(target_os = "linux")]
pub fn install_panic_hook() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        // Write to stderr first (our console).
        eprintln!("===== OXWRTD PANIC =====");
        default_hook(info);
        eprintln!("===== /OXWRTD PANIC =====");
        // Then try /dev/kmsg so dmesg captures it too.
        use std::io::Write as _;
        if let Ok(mut kmsg) = std::fs::OpenOptions::new().write(true).open("/dev/kmsg") {
            let _ = writeln!(kmsg, "oxwrtd PANIC: {info}");
        }
    }));
}

#[cfg(not(target_os = "linux"))]
pub fn install_panic_hook() {}
