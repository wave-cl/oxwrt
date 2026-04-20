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
/// Path to the baked-in release-signing pubkey. Present when the
/// image was built with a signing key; absent on self-built /
/// dev images. Shape: raw 32 bytes (the ed25519 VerifyingKey's
/// byte representation).
const RELEASE_PUBKEY_PATH: &str = "/etc/oxwrt/release-pubkey.ed25519";

pub(super) async fn handle_fw_update(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    size: u64,
    expected_sha256: &str,
    sig_hex: Option<&str>,
) -> Response {
    use sha2::{Digest, Sha256};

    if size == 0 || size > FW_MAX_SIZE {
        return Response::Err {
            message: format!("fw_update: size {size} out of range (1..{FW_MAX_SIZE})"),
        };
    }

    // Validate the expected hash is a valid hex string.
    if expected_sha256.len() != 64 || !expected_sha256.chars().all(|c| c.is_ascii_hexdigit()) {
        return Response::Err {
            message: "fw_update: sha256 must be 64 hex chars".to_string(),
        };
    }

    // Gate the release-signing policy before we start streaming
    // bytes: cheap fail-fast if the client forgot the .sig or
    // sent a malformed one. Actual signature verification runs
    // AFTER the hash is computed (can't verify a sig over a hash
    // that doesn't exist yet).
    let pubkey = load_release_pubkey();
    match (&pubkey, sig_hex) {
        (Some(_), None) => {
            return Response::Err {
                message: format!(
                    "fw_update: router has a release pubkey at {RELEASE_PUBKEY_PATH} \
                     but the update request carries no .sig. Pass a signed image \
                     (run `oxctl --sign <image>` on your build host, or rebuild \
                     without the pubkey for dev-mode acceptance)."
                ),
            };
        }
        (Some(_), Some(s)) if s.len() != 128 || !s.chars().all(|c| c.is_ascii_hexdigit()) => {
            return Response::Err {
                message: "fw_update: sig must be 128 hex chars (ed25519 detached sig)"
                    .to_string(),
            };
        }
        (None, Some(_)) => {
            tracing::warn!(
                "fw_update: .sig received but no {RELEASE_PUBKEY_PATH} on router; \
                 accepting unsigned (dev-mode image)"
            );
        }
        _ => {}
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
                    message: format!("fw_update: stream closed after {received}/{size} bytes"),
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
    let digest = hasher.finalize();
    let computed = hex::encode(digest);
    if computed != expected_sha256 {
        let _ = tokio::fs::remove_file(FW_STAGING_TMP).await;
        return Response::Err {
            message: format!(
                "fw_update: SHA-256 mismatch: expected {expected_sha256}, got {computed}"
            ),
        };
    }

    // Signature verification. Gate condition from the pre-stream
    // check above guarantees (pubkey.is_some() ↔ sig_hex.is_some()
    // AND well-formed) by the time we reach here, so the only
    // remaining path is "verify the bytes match the claimed
    // signature."
    if let (Some(pk), Some(sig_s)) = (&pubkey, sig_hex) {
        if let Err(e) = verify_release_signature(pk, &digest[..], sig_s) {
            let _ = tokio::fs::remove_file(FW_STAGING_TMP).await;
            return Response::Err {
                message: format!("fw_update: signature verify failed: {e}"),
            };
        }
        tracing::info!("fw_update: release signature verified");
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
                message: format!("fw_apply: no staged image at {FW_STAGING_PATH}: {e}"),
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

/// Read the baked-in release pubkey from
/// `/etc/oxwrt/release-pubkey.ed25519`. Returns None on any error
/// (missing file, wrong length, unreadable) — those are logged
/// but not fatal; the caller falls through to the dev-mode path.
fn load_release_pubkey() -> Option<ed25519_dalek::VerifyingKey> {
    let bytes = match std::fs::read(RELEASE_PUBKEY_PATH) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            tracing::warn!(error = %e, "fw_update: release pubkey unreadable at {RELEASE_PUBKEY_PATH}");
            return None;
        }
    };
    let arr: [u8; 32] = match bytes.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => {
            tracing::warn!(
                len = bytes.len(),
                "fw_update: release pubkey at {RELEASE_PUBKEY_PATH} wrong length (expected 32 bytes)"
            );
            return None;
        }
    };
    ed25519_dalek::VerifyingKey::from_bytes(&arr).ok()
}

/// Verify that `sig_hex` is a valid ed25519 signature of
/// `digest` bytes under `pubkey`. The signing protocol is
/// "sign the 32 raw hash bytes" — stable, replay-safe, and
/// cheap to compute offline via `oxctl --sign`.
fn verify_release_signature(
    pubkey: &ed25519_dalek::VerifyingKey,
    digest: &[u8],
    sig_hex: &str,
) -> Result<(), String> {
    use ed25519_dalek::Verifier;
    let sig_bytes: [u8; 64] = hex::decode(sig_hex)
        .map_err(|e| format!("decode: {e}"))?
        .as_slice()
        .try_into()
        .map_err(|_| "sig must decode to 64 bytes".to_string())?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    pubkey
        .verify(digest, &sig)
        .map_err(|e| format!("verify: {e}"))
}

#[cfg(test)]
mod signed_update_tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn sign_verify_round_trip() {
        let seed = [42u8; 32];
        let sk = SigningKey::from_bytes(&seed);
        let vk = sk.verifying_key();
        let digest = [0xabu8; 32];
        let sig = sk.sign(&digest);
        let sig_hex = hex::encode(sig.to_bytes());
        verify_release_signature(&vk, &digest, &sig_hex).expect("valid sig verifies");
    }

    #[test]
    fn wrong_pubkey_rejects() {
        let sk_a = SigningKey::from_bytes(&[1u8; 32]);
        let sk_b = SigningKey::from_bytes(&[2u8; 32]);
        let digest = [0xabu8; 32];
        let sig = sk_a.sign(&digest);
        let sig_hex = hex::encode(sig.to_bytes());
        let err = verify_release_signature(&sk_b.verifying_key(), &digest, &sig_hex)
            .unwrap_err();
        assert!(err.contains("verify"));
    }

    #[test]
    fn tampered_digest_rejects() {
        let sk = SigningKey::from_bytes(&[3u8; 32]);
        let vk = sk.verifying_key();
        let digest = [0xabu8; 32];
        let sig = sk.sign(&digest);
        let sig_hex = hex::encode(sig.to_bytes());
        let mut tampered = digest;
        tampered[0] ^= 1;
        assert!(verify_release_signature(&vk, &tampered, &sig_hex).is_err());
    }

    #[test]
    fn malformed_sig_hex_rejected() {
        let vk = SigningKey::from_bytes(&[4u8; 32]).verifying_key();
        let digest = [0u8; 32];
        // Not hex.
        assert!(verify_release_signature(&vk, &digest, "zzz").is_err());
        // Hex, wrong length (32 bytes, not 64).
        assert!(verify_release_signature(&vk, &digest, &"aa".repeat(32)).is_err());
    }
}
