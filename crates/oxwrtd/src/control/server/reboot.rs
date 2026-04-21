//! Graceful reboot handler.
//!
//! Wire shape: `Request::Reboot { confirm: true }` → this function
//! → (Response::Ok, then the process calls `reboot(2)` and the
//! kernel restarts). The sQUIC connection drops as the network
//! stack tears down; the client treats that as confirmation.
//!
//! Why a real reboot RPC instead of `ssh -p 2222 ... reboot`:
//!
//! 1. The ssh dropbear container lacks CAP_SYS_BOOT, so a reboot
//!    from there either requires sysrq-trigger hacks or doesn't
//!    work at all (we hit the latter during live verify).
//! 2. Going through oxwrtd lets us flush one more urandom seed
//!    and shut down supervisor children cleanly — dropbear-reboot
//!    leaves zombie containers and a stale seed file.
//! 3. Auth: the RPC reuses the sQUIC ed25519 key gate, so the
//!    operator doesn't need a separate ssh key for reboot.

use super::*;

pub(super) async fn handle_reboot(state: &ControlState, confirm: bool) -> Response {
    if !confirm {
        return Response::Err {
            message: "reboot: refused without confirm=true".to_string(),
        };
    }

    // 1. One last urandom seed save so the next boot's preinit
    //    finds the freshest possible seed. The periodic saver
    //    runs every 30 min; a reboot in the 29th minute would
    //    otherwise lose 30 min of freshness.
    if let Err(e) = crate::urandom_seed::save() {
        tracing::warn!(error = %e, "reboot: final urandom seed save failed");
    } else {
        tracing::info!("reboot: urandom seed saved");
    }

    // 2. Stop supervisor children. Reverse-dep order + reap. Idle
    //    for ~1 s per service then rmdir the cgroup leaf.
    if let Ok(mut sup) = state.supervisor.lock() {
        tracing::info!("reboot: shutting down supervisor");
        sup.shutdown();
    } else {
        tracing::warn!("reboot: supervisor mutex poisoned; skipping clean shutdown");
    }

    // 3. sync(2) — flush every pending filesystem write so the
    //    overlay/f2fs upper layer is on disk before the kernel
    //    cuts power to the eMMC. Without this, a reboot 100 ms
    //    after a config-push can leave /etc/oxwrt/oxwrt.toml empty
    //    (dirty pages never flushed).
    //
    //    Two syncs with a short gap — the first commits the
    //    overlay, the second catches anything the commit
    //    triggered (F2FS checkpoint journal, etc).
    unsafe {
        libc::sync();
    }
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    unsafe {
        libc::sync();
    }

    // 4. Send Ok to the client BEFORE the reboot syscall so the
    //    caller sees "ok" and interprets the subsequent
    //    connection drop as "reboot in flight," not an error.
    //    The caller discards the response via `send.finish()`;
    //    we return Ok here and the caller dispatches it, then
    //    we spawn the reboot after a small delay.
    //
    //    The delay matters: the sQUIC write_frame above returns
    //    after the local send buffer is flushed, but the
    //    packet may still be in the kernel's UDP tx queue when
    //    reboot(2) fires. 200 ms gives QUIC time to actually
    //    transmit the frame + ack before the NIC stops.
    tokio::spawn(async {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        tracing::info!("reboot: calling reboot(LINUX_REBOOT_CMD_RESTART)");
        // We're PID 1 — the kernel restarts on this syscall. The
        // per-file fsync + parent-dir fsync in urandom_seed::save
        // + the pair of sync() calls above ensure the overlay's
        // upper-layer writes hit eMMC before the kernel cuts
        // power.
        unsafe {
            libc::reboot(libc::LINUX_REBOOT_CMD_RESTART);
        }
        // If we got here, the syscall refused (EPERM on non-root
        // oxwrtd — shouldn't happen in init mode).
        tracing::error!("reboot: reboot(2) returned — kernel did not restart (EPERM?)");
        std::process::exit(1);
    });

    Response::Ok
}
