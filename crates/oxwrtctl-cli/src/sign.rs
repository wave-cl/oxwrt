//! `oxctl --sign <image>` — produce `<image>.sig` next to a
//! firmware image so the daemon's signed-update path accepts it.
//!
//! Signs the SHA-256 digest of the image bytes (NOT the full
//! bytes) with an offline ed25519 key. The protocol matches
//! `sysupgrade::verify_release_signature` on the server —
//! operators don't have to reason about signature subtleties.
//!
//! Key material:
//! - Reads the 32-byte seed from `$OXWRT_SIGNING_KEY_PATH`
//!   (default `./release-signing.key`).
//! - Or, for one-shot CI use, reads hex from
//!   `$OXWRT_SIGNING_KEY` directly (64 hex chars = 32-byte seed).
//!
//! Emit the companion pubkey via:
//!   oxctl --sign --print-pubkey
//! Bake the output as `provisioning/release-pubkey.ed25519` in
//! the image-builder overlay; subsequent image builds install it
//! at `/etc/oxwrt/release-pubkey.ed25519` on-device.

use std::process::ExitCode;

pub fn run(args: Vec<String>) -> ExitCode {
    // Flags:
    //   oxctl --sign <image>          → write <image>.sig
    //   oxctl --sign --print-pubkey   → hex pubkey to stdout
    let print_pubkey = args.iter().any(|a| a == "--print-pubkey");
    let image_path = args.iter().find(|a| !a.starts_with("--"));

    let seed = match load_seed() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("oxctl --sign: {e}");
            return ExitCode::FAILURE;
        }
    };
    let signing = ed25519_dalek::SigningKey::from_bytes(&seed);

    if print_pubkey {
        let pubkey = signing.verifying_key();
        println!("{}", hex::encode(pubkey.to_bytes()));
        return ExitCode::SUCCESS;
    }

    let Some(image_path) = image_path else {
        eprintln!(
            "usage: oxctl --sign <image>\n\
             or:    oxctl --sign --print-pubkey\n\
             (signing key loaded from OXWRT_SIGNING_KEY_PATH or OXWRT_SIGNING_KEY env)"
        );
        return ExitCode::FAILURE;
    };

    match write_signature(&signing, image_path) {
        Ok(sig_path) => {
            eprintln!("oxctl --sign: wrote {sig_path}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("oxctl --sign: {e}");
            ExitCode::FAILURE
        }
    }
}

fn load_seed() -> Result<[u8; 32], String> {
    // Env hex path wins (CI-friendly). Else fall back to a file.
    if let Ok(hex_str) = std::env::var("OXWRT_SIGNING_KEY") {
        let bytes = hex::decode(hex_str.trim())
            .map_err(|e| format!("OXWRT_SIGNING_KEY: decode hex: {e}"))?;
        return bytes
            .as_slice()
            .try_into()
            .map_err(|_| format!("OXWRT_SIGNING_KEY: need 32 bytes, got {}", bytes.len()));
    }
    let path = std::env::var("OXWRT_SIGNING_KEY_PATH")
        .unwrap_or_else(|_| "release-signing.key".to_string());
    let bytes = std::fs::read(&path).map_err(|e| format!("read {path}: {e}"))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("{path}: need 32 raw bytes, got {}", bytes.len()))
}

fn write_signature(
    signing: &ed25519_dalek::SigningKey,
    image_path: &str,
) -> Result<String, String> {
    use ed25519_dalek::Signer;
    use sha2::{Digest, Sha256};

    let mut file = std::fs::File::open(image_path)
        .map_err(|e| format!("open {image_path}: {e}"))?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher).map_err(|e| format!("read {image_path}: {e}"))?;
    let digest = hasher.finalize();

    let sig = signing.sign(&digest);
    let sig_hex = hex::encode(sig.to_bytes());

    let sig_path = format!("{image_path}.sig");
    std::fs::write(&sig_path, format!("{sig_hex}\n"))
        .map_err(|e| format!("write {sig_path}: {e}"))?;
    Ok(sig_path)
}
