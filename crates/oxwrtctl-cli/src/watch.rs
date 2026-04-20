//! `oxctl watch` — live-updating RPC display.
//!
//! Re-issues an inner command (defaults to `status`) on a timer,
//! clears the terminal between ticks, and prints the latest
//! response. Runs until Ctrl-C.
//!
//! Client-local: parses + dispatches before the normal
//! `client::run` path. Every tick opens a fresh sQUIC connection
//! via `client::run` — LAN connection overhead is ~20-50 ms so the
//! 1s default interval stays well inside the budget. If we ever
//! need sub-second refresh we can switch to a reused connection
//! with one stream per tick, but that complicates this module for
//! no v1 benefit.
//!
//! Usage:
//!   oxctl <host> watch                        # default: status every 1s
//!   oxctl <host> watch --interval 2 status
//!   oxctl <host> watch diag links             # any inner cmd works

use std::time::{Duration, Instant};

/// Entry point. `args` is everything after `watch` on the command
/// line — so `oxctl 192.168.50.1:51820 watch --interval 2 status`
/// hands us `["192.168.50.1:51820", "--interval", "2", "status"]`.
pub fn run(args: Vec<String>) -> Result<(), String> {
    let (remote, interval, inner) = parse_args(args)?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("build tokio runtime: {e}"))?;

    // Ctrl-C should drop us out of the loop cleanly rather than
    // dumping a scary tokio panic. Register once, check the flag
    // between ticks.
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    {
        let stop = stop.clone();
        ctrlc_once(move || {
            stop.store(true, std::sync::atomic::Ordering::SeqCst);
        });
    }

    let mut tick = 0u64;
    while !stop.load(std::sync::atomic::Ordering::SeqCst) {
        let t0 = Instant::now();
        clear_screen();
        print_header(&remote, &inner, interval, tick);
        // Each tick rebuilds the argv for client::run. Host + cmd
        // + cmd-args in that order; client::run does the usual
        // parse + dial + single-RPC-and-exit.
        let mut argv = vec![remote.clone()];
        argv.extend(inner.iter().cloned());
        if let Err(e) = rt.block_on(crate::client::run(argv)) {
            // Don't exit on a transient error — the router might
            // be rebooting from a reload we just watched. Show
            // the error in the header-area and keep ticking.
            eprintln!("\n[tick {tick}] error: {e}");
        }
        tick += 1;
        // Sleep the remainder of the interval; never oversleep.
        let elapsed = t0.elapsed();
        if elapsed < interval && !stop.load(std::sync::atomic::Ordering::SeqCst) {
            std::thread::sleep(interval - elapsed);
        }
    }
    // Leave the cursor at a sensible place on exit.
    println!();
    Ok(())
}

/// Parse `args` into (remote, interval, inner_argv).
/// Default inner cmd is `["status"]`. Accepts `--interval N` or
/// `--interval=N` anywhere before the inner cmd.
fn parse_args(args: Vec<String>) -> Result<(String, Duration, Vec<String>), String> {
    let mut it = args.into_iter();
    let remote = it
        .next()
        .ok_or_else(|| "watch: missing <remote>".to_string())?;
    let mut interval_s: u64 = 1;
    let mut inner: Vec<String> = Vec::new();
    let mut in_inner = false;
    while let Some(a) = it.next() {
        if in_inner {
            inner.push(a);
            continue;
        }
        match a.as_str() {
            "--interval" => {
                let v = it
                    .next()
                    .ok_or_else(|| "watch: --interval needs a value".to_string())?;
                interval_s = parse_interval(&v)?;
            }
            s if s.starts_with("--interval=") => {
                interval_s = parse_interval(&s["--interval=".len()..])?;
            }
            other => {
                inner.push(other.to_string());
                in_inner = true;
            }
        }
    }
    if inner.is_empty() {
        inner.push("status".to_string());
    }
    Ok((remote, Duration::from_secs(interval_s), inner))
}

fn parse_interval(s: &str) -> Result<u64, String> {
    let v: u64 = s
        .parse()
        .map_err(|_| format!("watch: --interval {s:?} is not a non-negative integer"))?;
    if v == 0 {
        return Err("watch: --interval must be >= 1".to_string());
    }
    Ok(v)
}

/// ANSI cursor+screen reset. `\x1b[2J` clears the whole screen;
/// `\x1b[H` moves the cursor to 1,1. Stdout-flushed so the next
/// `println!` lands at the top.
fn clear_screen() {
    use std::io::Write;
    let mut out = std::io::stdout().lock();
    let _ = out.write_all(b"\x1b[2J\x1b[H");
    let _ = out.flush();
}

fn print_header(remote: &str, inner: &[String], interval: Duration, tick: u64) {
    let inner_pretty = inner.join(" ");
    // Underline via ANSI; most terminals support it. Fall back is
    // ugly (`^[[4m…^[[0m` visible) but not wrong.
    println!(
        "\x1b[1moxctl watch\x1b[0m {remote} — \x1b[4m{inner_pretty}\x1b[0m \
         every {}s (tick {tick}; Ctrl-C to quit)\n",
        interval.as_secs()
    );
}

/// Best-effort Ctrl-C handler. Spawns a thread because neither
/// `ctrlc` (crate) nor `tokio::signal` is worth pulling in for
/// one shared boolean. `libc::signal` with a C-ABI handler
/// function is a little unsightly but lets us set + forget.
fn ctrlc_once<F: FnMut() + Send + 'static>(f: F) {
    // Box + leak the callback so the signal handler can reach it
    // without a `static mut`. The leak is a single allocation at
    // program start — not a loop.
    let boxed: Box<dyn FnMut() + Send> = Box::new(f);
    let cb_ptr: &'static mut Box<dyn FnMut() + Send> = Box::leak(Box::new(boxed));
    // SAFETY: cb_ptr is 'static (leaked above), and the signal
    // handler runs single-threaded from the process POV (signal
    // delivery to the main thread). Setting CB via atomic pointer
    // would be more robust, but the leak-and-call pattern is
    // standard for single-signal apps and we only install once.
    unsafe {
        CB_PTR = cb_ptr as *mut _ as *mut ();
        libc::signal(
            libc::SIGINT,
            sigint_trampoline as *const () as libc::sighandler_t,
        );
    }
}

// Static holding a pointer to the boxed callback. Only written
// once (in ctrlc_once) and only read from the signal handler.
static mut CB_PTR: *mut () = std::ptr::null_mut();

extern "C" fn sigint_trampoline(_signum: libc::c_int) {
    unsafe {
        if !CB_PTR.is_null() {
            let cb = CB_PTR as *mut Box<dyn FnMut() + Send>;
            (*cb)();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_inner_is_status_every_1s() {
        let (r, i, inner) = parse_args(vec!["1.2.3.4:51820".into()]).unwrap();
        assert_eq!(r, "1.2.3.4:51820");
        assert_eq!(i, Duration::from_secs(1));
        assert_eq!(inner, vec!["status"]);
    }

    #[test]
    fn interval_flag_space_form() {
        let (_, i, _) = parse_args(vec![
            "1.2.3.4:51820".into(),
            "--interval".into(),
            "5".into(),
            "status".into(),
        ])
        .unwrap();
        assert_eq!(i, Duration::from_secs(5));
    }

    #[test]
    fn interval_flag_equals_form() {
        let (_, i, _) = parse_args(vec![
            "1.2.3.4:51820".into(),
            "--interval=3".into(),
            "status".into(),
        ])
        .unwrap();
        assert_eq!(i, Duration::from_secs(3));
    }

    #[test]
    fn inner_command_passes_through_with_args() {
        let (_, _, inner) =
            parse_args(vec!["1.2.3.4:51820".into(), "diag".into(), "links".into()]).unwrap();
        assert_eq!(inner, vec!["diag", "links"]);
    }

    #[test]
    fn missing_remote_errors() {
        let err = parse_args(vec![]).unwrap_err();
        assert!(err.contains("missing"));
    }

    #[test]
    fn zero_interval_rejected() {
        let err = parse_args(vec![
            "1.2.3.4:51820".into(),
            "--interval".into(),
            "0".into(),
        ])
        .unwrap_err();
        assert!(err.contains(">= 1"));
    }

    #[test]
    fn non_numeric_interval_rejected() {
        let err = parse_args(vec![
            "1.2.3.4:51820".into(),
            "--interval".into(),
            "slow".into(),
        ])
        .unwrap_err();
        assert!(err.contains("not a non-negative integer"));
    }

    #[test]
    fn interval_flag_after_inner_is_treated_as_inner_arg() {
        // Once we've seen a non-flag token, everything after it is
        // forwarded — `--interval` there is an argument to the
        // inner command, not a watch-level flag.
        let (_, i, inner) = parse_args(vec![
            "1.2.3.4:51820".into(),
            "diag".into(),
            "--interval".into(),
            "5".into(),
        ])
        .unwrap();
        assert_eq!(i, Duration::from_secs(1)); // default
        assert_eq!(inner, vec!["diag", "--interval", "5"]);
    }
}
