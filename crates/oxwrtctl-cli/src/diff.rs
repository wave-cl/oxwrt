//! `oxctl <host> diff <local.toml>` — show what a `config-push`
//! followed by `reload` would change.
//!
//! Reads the local TOML, fetches the router's running config via
//! the existing `ConfigDump` RPC, renders a unified-line diff
//! (similar-style `@@` hunks with context lines). Client-local
//! with one sQUIC round-trip; server-side is unchanged.
//!
//! Intentional non-goals v1:
//! - Semantic diff at the TOML AST level (additions/removals/
//!   value-changes grouped by section). Line diff is operator-
//!   readable and matches `git diff` muscle memory.
//! - Side-by-side rendering. Unified is the CLI-native shape.
//! - Auto-redaction of secrets. The local file is the operator's
//!   oxwrt.toml (publishable by design post-absorption); the
//!   server-side dump is already post-split-safe.

use std::net::SocketAddr;

use oxwrt_api::rpc::{Request, Response};
use oxwrt_proto::{format_response, read_frame, write_frame};
use similar::{ChangeTag, TextDiff};

/// Entry point. `args` is everything after `diff` — so
/// `oxctl 192.168.50.1:51820 diff oxwrt.toml` hands us
/// `["192.168.50.1:51820", "oxwrt.toml"]`.
pub fn run(args: Vec<String>) -> Result<(), String> {
    let mut it = args.into_iter();
    let remote = it
        .next()
        .ok_or_else(|| "diff: missing <remote>".to_string())?;
    let local_path = it
        .next()
        .ok_or_else(|| "diff: missing <local.toml>".to_string())?;
    if let Some(extra) = it.next() {
        return Err(format!("diff: unexpected arg {extra:?}"));
    }

    let local_text = std::fs::read_to_string(&local_path)
        .map_err(|e| format!("diff: read {local_path}: {e}"))?;

    let addr: SocketAddr = remote
        .parse()
        .map_err(|e| format!("diff: invalid <remote> {remote:?}: {e}"))?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("diff: build tokio runtime: {e}"))?;

    let live_text = rt.block_on(fetch_live_config(addr))?;

    print_diff(&local_path, &local_text, &live_text);
    Ok(())
}

/// Open a sQUIC connection, issue `ConfigDump`, collect the
/// single `Response::Value` the server replies with.
async fn fetch_live_config(addr: SocketAddr) -> Result<String, String> {
    let server_key_hex = std::env::var("SQUIC_SERVER_KEY")
        .map_err(|_| "diff: SQUIC_SERVER_KEY not set".to_string())?;
    let server_key = parse_pubkey(&server_key_hex)?;

    let mut config = squic::Config::default();
    if let Ok(client_key) = std::env::var("SQUIC_CLIENT_KEY") {
        config.client_key = Some(client_key);
    }
    let conn = squic::dial(addr, &server_key, config)
        .await
        .map_err(|e| format!("diff: dial: {e}"))?;
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| format!("diff: open_bi: {e}"))?;
    write_frame(&mut send, &Request::ConfigDump)
        .await
        .map_err(|e| format!("diff: write: {e}"))?;
    send.finish().map_err(|e| format!("diff: finish: {e}"))?;

    // ConfigDump returns exactly one Response::Value frame. We
    // keep reading until we see it or the stream closes.
    loop {
        match read_frame::<_, Response>(&mut recv).await {
            Ok(Response::Value { value }) => return Ok(value),
            Ok(Response::Err { message }) => return Err(format!("diff: server: {message}")),
            Ok(other) => {
                // Not the frame we want; skip + keep looking.
                let _ = format_response(&other);
            }
            Err(e) => return Err(format!("diff: read: {e}")),
        }
    }
}

/// Parse a 64-hex-char server pubkey. Matches `client::parse_pubkey`
/// (not pub) — duplicate the impl rather than expose that private.
fn parse_pubkey(hex_str: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("SQUIC_SERVER_KEY: {e}"))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("SQUIC_SERVER_KEY: expected 32 bytes, got {}", bytes.len()))
}

/// Render a unified diff. Silent when the two sides are equal
/// (exit 0 with an empty print) so operators can chain this
/// with `&&` / `||` and react to the shell's exit code.
fn print_diff(local_path: &str, local: &str, live: &str) {
    if local == live {
        eprintln!("oxctl diff: no changes between {local_path} and live config");
        return;
    }
    let diff = TextDiff::from_lines(live, local);
    println!("--- live (on router)");
    println!("+++ {local_path}");
    for change in diff.iter_all_changes() {
        let sigil = match change.tag() {
            ChangeTag::Delete => "-",
            ChangeTag::Insert => "+",
            ChangeTag::Equal => " ",
        };
        // Strip the trailing newline from the line value before
        // emitting our own, so we don't double it.
        let value = change.value();
        let value = value.strip_suffix('\n').unwrap_or(value);
        println!("{sigil}{value}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pubkey_parse_32_bytes() {
        let hex = "a".repeat(64);
        let key = parse_pubkey(&hex).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn pubkey_parse_wrong_length() {
        let err = parse_pubkey(&"a".repeat(62)).unwrap_err();
        assert!(err.contains("expected 32 bytes"));
    }

    #[test]
    fn pubkey_parse_non_hex() {
        assert!(parse_pubkey("zzz").is_err());
    }
}
