//! `oxctl dump-config` — emit the merged running config with every
//! secret leaf replaced by `<redacted>`. Safe to paste into a bug
//! report or an operator support thread.
//!
//! Default paths match the daemon's on-device locations:
//!   /etc/oxwrt/oxwrt.toml         (public)
//!   /etc/oxwrt/oxwrt.secrets.toml (overlay, mode 0600)
//!
//! Override with `--public PATH` / `--secrets PATH`. The tool also
//! applies `OXWRT_SECRET__…` env overrides the same way the daemon
//! does on boot, so the printed view reflects exactly what the
//! daemon would see — with the caveat that every secret-leaf has
//! been replaced by `<redacted>`.
//!
//! Runs client-side only: no sQUIC, no `<remote>` needed. Files
//! must be readable by the invoking user (typically root on the
//! device, or a dev copy on a workstation).

use oxwrt_api::{
    config::{self, merge_toml},
    secrets::{count_entries, redact_document},
};

pub fn run(args: Vec<String>) -> Result<(), String> {
    let mut public: Option<String> = None;
    let mut secrets: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--public" => {
                public = Some(args.get(i + 1).cloned().ok_or("--public needs PATH")?);
                i += 2;
            }
            "--secrets" => {
                secrets = Some(args.get(i + 1).cloned().ok_or("--secrets needs PATH")?);
                i += 2;
            }
            "--help" | "-h" => {
                eprintln!("usage: oxctl dump-config [--public PATH] [--secrets PATH]");
                return Ok(());
            }
            other => return Err(format!("unknown arg {other:?}")),
        }
    }
    let public_path: std::path::PathBuf = public
        .map(Into::into)
        .unwrap_or_else(|| config::DEFAULT_PATH.into());
    let secrets_path: std::path::PathBuf = secrets
        .map(Into::into)
        .unwrap_or_else(|| public_path.with_file_name("oxwrt.secrets.toml"));

    // Re-implement what Config::load_with_secrets does, but at the
    // toml_edit / toml::Value level so we keep redact-friendly
    // structure — Config's Rust types would force us to serialize
    // after redaction, losing operator-facing field order.
    let public_text = std::fs::read_to_string(&public_path)
        .map_err(|e| format!("read {}: {e}", public_path.display()))?;
    let mut base: toml::Value = toml::from_str(&public_text)
        .map_err(|e| format!("parse {}: {e}", public_path.display()))?;
    let secrets_present = secrets_path.exists();
    if secrets_present {
        let sec_text = std::fs::read_to_string(&secrets_path)
            .map_err(|e| format!("read {}: {e}", secrets_path.display()))?;
        let overlay: toml::Value = toml::from_str(&sec_text)
            .map_err(|e| format!("parse {}: {e}", secrets_path.display()))?;
        merge_toml(&mut base, overlay, "");
    }
    // Env overlay uses the real process environment — same as the
    // daemon would see on boot.
    config::apply_env_overlay(&mut base);

    // Serialize the merged toml::Value → TOML string → DocumentMut
    // so we can apply the redactor (which works on toml_edit types).
    let merged_text = toml::to_string_pretty(&base).map_err(|e| format!("serialize: {e}"))?;
    let mut doc: toml_edit::DocumentMut = merged_text
        .parse()
        .map_err(|e| format!("re-parse merged: {e}"))?;
    let redacted_count = count_entries(&{
        let mut copy = doc.clone();
        oxwrt_api::secrets::split_document(&mut copy)
    });
    redact_document(&mut doc);

    // Header: provenance summary so the operator (and anyone reading
    // the pasted output) sees what was merged.
    println!("# oxctl dump-config — merged view with secrets redacted.");
    println!("# public:  {}", public_path.display());
    if secrets_present {
        println!("# secrets: {} (present)", secrets_path.display());
    } else {
        println!("# secrets: {} (NOT present)", secrets_path.display());
    }
    println!("# redacted leaves: {redacted_count}");
    println!();
    print!("{doc}");
    Ok(())
}
