//! Firmware update upload + apply RPCs. Split out in step 7.

use super::*;

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

/// Receive a firmware image over the sQUIC bi-stream, hash it, stage it.
///
/// Protocol: the client has already sent the `FwUpdate { size, sha256 }`
/// metadata frame (already read by the dispatch loop). Next, the client
/// writes `size` raw bytes directly on the same stream (no framing),
/// then calls `send.finish()`. We read, hash with SHA-256, write to a
/// temp file, verify the hash, and rename to the staging path.
///
/// Progress frames (`FwProgress { bytes_received }`) are sent back on
/// the send side periodically so the client can display a progress bar.
pub(super) async fn handle_fw_update(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    size: u64,
    expected_sha256: &str,
) -> Response {
    use sha2::{Sha256, Digest};

    if size == 0 || size > FW_MAX_SIZE {
        return Response::Err {
            message: format!(
                "fw_update: size {size} out of range (1..{FW_MAX_SIZE})"
            ),
        };
    }

    // Validate the expected hash is a valid hex string.
    if expected_sha256.len() != 64
        || !expected_sha256.chars().all(|c| c.is_ascii_hexdigit())
    {
        return Response::Err {
            message: "fw_update: sha256 must be 64 hex chars".to_string(),
        };
    }

    // Open temp file for writing.
    let mut file = match tokio::fs::File::create(FW_STAGING_TMP).await {
        Ok(f) => f,
        Err(e) => {
            return Response::Err {
                message: format!("fw_update: create staging tmp: {e}"),
            };
        }
    };

    let mut hasher = Sha256::new();
    let mut received: u64 = 0;
    let mut buf = vec![0u8; FW_CHUNK_SIZE];
    let mut last_progress: u64 = 0;

    // Read raw bytes from the stream (no framing).
    while received < size {
        let want = std::cmp::min(FW_CHUNK_SIZE as u64, size - received) as usize;
        let n = match recv.read(&mut buf[..want]).await {
            Ok(Some(n)) if n > 0 => n,
            Ok(_) => {
                // Stream closed before we got all bytes.
                let _ = tokio::fs::remove_file(FW_STAGING_TMP).await;
                return Response::Err {
                    message: format!(
                        "fw_update: stream closed after {received}/{size} bytes"
                    ),
                };
            }
            Err(e) => {
                let _ = tokio::fs::remove_file(FW_STAGING_TMP).await;
                return Response::Err {
                    message: format!("fw_update: read error: {e}"),
                };
            }
        };

        hasher.update(&buf[..n]);
        if let Err(e) = tokio::io::AsyncWriteExt::write_all(&mut file, &buf[..n]).await {
            let _ = tokio::fs::remove_file(FW_STAGING_TMP).await;
            return Response::Err {
                message: format!("fw_update: write error: {e}"),
            };
        }

        received += n as u64;

        // Send progress every FW_PROGRESS_INTERVAL bytes.
        if received - last_progress >= FW_PROGRESS_INTERVAL || received == size {
            let progress = Response::FwProgress {
                bytes_received: received,
            };
            // Best-effort: if the progress frame fails to send, continue
            // — the upload itself is more important than the progress bar.
            let _ = write_frame(send, &progress).await;
            last_progress = received;
        }
    }

    // Flush and close the file.
    if let Err(e) = tokio::io::AsyncWriteExt::flush(&mut file).await {
        let _ = tokio::fs::remove_file(FW_STAGING_TMP).await;
        return Response::Err {
            message: format!("fw_update: flush: {e}"),
        };
    }
    drop(file);

    // Verify the hash.
    let computed = hex::encode(hasher.finalize());
    if computed != expected_sha256 {
        let _ = tokio::fs::remove_file(FW_STAGING_TMP).await;
        return Response::Err {
            message: format!(
                "fw_update: SHA-256 mismatch: expected {expected_sha256}, got {computed}"
            ),
        };
    }

    // Atomic rename to the staging path.
    if let Err(e) = tokio::fs::rename(FW_STAGING_TMP, FW_STAGING_PATH).await {
        let _ = tokio::fs::remove_file(FW_STAGING_TMP).await;
        return Response::Err {
            message: format!("fw_update: rename to staging: {e}"),
        };
    }

    tracing::info!(
        size,
        sha256 = %expected_sha256,
        "firmware image staged at {FW_STAGING_PATH}"
    );
    Response::Ok
}

/// Apply the staged firmware image. Triggers `sysupgrade -n` (or the
/// platform-appropriate flash command) and reboots. The sQUIC
/// connection drops on reboot — the client detects this as success.
///
/// `confirm` must be true (same safety gate as Reset). Rejects if no
/// staged image exists.
pub(super) fn handle_fw_apply(confirm: bool, keep_settings: bool) -> Response {
    if !confirm {
        return Response::Err {
            message: "fw_apply: pass --confirm to proceed".to_string(),
        };
    }

    let meta = match std::fs::metadata(FW_STAGING_PATH) {
        Ok(m) => m,
        Err(e) => {
            return Response::Err {
                message: format!(
                    "fw_apply: no staged image at {FW_STAGING_PATH}: {e}"
                ),
            };
        }
    };

    tracing::warn!(
        size = meta.len(),
        keep_settings,
        "fw_apply: applying firmware via native sysupgrade"
    );

    // Detach the actual flash to a background thread so we can reply
    // "ok" to the client before tearing down the world. The client
    // should interpret the upcoming connection drop (reboot) as
    // success. Without this detach, we'd block the RPC handler
    // through pivot_root + reboot and the reply would never flush.
    //
    // We deliberately do NOT use tokio::spawn — the sysupgrade code
    // path calls pivot_root which would upset every tokio task's
    // open fds. A plain OS thread is cleaner.
    let path = std::path::PathBuf::from(FW_STAGING_PATH);
    std::thread::Builder::new()
        .name("sysupgrade".to_string())
        .spawn(move || {
            // Small delay so the RPC response has time to flush over
            // sQUIC before we start tearing down tokio.
            std::thread::sleep(std::time::Duration::from_millis(500));
            if let Err(e) = crate::sysupgrade::apply(&path, keep_settings) {
                // This path only reachable if flash fails BEFORE reboot;
                // on success, apply() loops forever waiting for reboot.
                tracing::error!(error = %e, "sysupgrade: native flash failed");
            }
        })
        .expect("spawn sysupgrade thread");

    Response::Ok
}
