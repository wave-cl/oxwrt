//! Log streaming + tailing. Split out in step 7.

use super::*;

pub(super) async fn stream_follow_logs(
    state: &ControlState,
    send: &mut quinn::SendStream,
    service: &str,
) -> Result<(), Error> {
    // First replay the last-N buffered lines so the client sees recent
    // context, then subscribe to the live channel for anything new.
    for entry in state.logd.tail(service, LOG_TAIL_LIMIT) {
        let resp = Response::LogLine { line: entry.line };
        write_frame(send, &resp).await?;
    }
    let mut subscription = state.logd.subscribe();
    loop {
        match subscription.recv().await {
            Ok(entry) if entry.service == service => {
                let resp = Response::LogLine { line: entry.line };
                if write_frame(send, &resp).await.is_err() {
                    break;
                }
            }
            Ok(_) => continue,
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                // Client fell behind; send a marker and keep going.
                let resp = Response::LogLine {
                    line: "[…lagged, some lines dropped…]".to_string(),
                };
                if write_frame(send, &resp).await.is_err() {
                    break;
                }
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
        }
    }
    Ok(())
}

const LOG_TAIL_LIMIT: usize = 200;

pub(super) fn handle_logs(state: &ControlState, service: &str, follow: bool) -> Vec<Response> {
    // `follow = true` is special-cased upstream in `handle_incoming` so the
    // bi stream can stay open. This path only services non-follow logs.
    let _ = follow;
    let mut out: Vec<Response> = state
        .logd
        .tail(service, LOG_TAIL_LIMIT)
        .into_iter()
        .map(|l| Response::LogLine { line: l.line })
        .collect();
    out.push(Response::Ok);
    out
}

// ── Firmware update ──────────────────────────────────────────────────

/// Staging path for the uploaded firmware image. Lives on tmpfs so it
/// survives the write but not a reboot (which is fine — we apply it
/// immediately after staging, or the operator re-uploads next boot).
const FW_STAGING_PATH: &str = "/tmp/fw_update.bin";
const FW_STAGING_TMP: &str = "/tmp/fw_update.bin.tmp";
/// Max firmware image size: 64 MiB. Sane upper bound for an OpenWrt
/// sysupgrade image (typical: 10-30 MiB). Rejects obviously-wrong sizes
/// before any I/O.
const FW_MAX_SIZE: u64 = 64 * 1024 * 1024;
/// Chunk size for reading the raw byte stream. 64 KiB balances syscall
/// overhead against memory usage.
const FW_CHUNK_SIZE: usize = 64 * 1024;
/// Send a progress frame every N bytes received.
const FW_PROGRESS_INTERVAL: u64 = 1024 * 1024; // 1 MiB
