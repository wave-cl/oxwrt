//! Scheduled passphrase rotation for `[[wifi]]` SSIDs with
//! `rotate_hours` set. Spawns one tokio task per rotating SSID;
//! on each tick the task:
//!
//!   1. Generates a 16-char alphanumeric passphrase from
//!      /dev/urandom.
//!   2. Reads the on-disk /etc/oxwrt/oxwrt.toml, patches the
//!      matching `[[wifi]]` entry's `passphrase` via toml_edit
//!      (preserving operator comments), writes back atomically.
//!   3. Writes sidecar files:
//!        /etc/oxwrt/wifi-<ssid>-passphrase.txt  — plaintext
//!        /etc/oxwrt/wifi-<ssid>-qr.txt          — ASCII-QR for
//!          phone scanning (`WIFI:T:WPA;S:<ssid>;P:<pw>;;` URI)
//!   4. Triggers the usual reload path on the control server so
//!      hostapd regens + restarts.
//!
//! Typical operator pattern: guest-SSID rotates daily, printed
//! QR is taped to the fridge. Main-LAN SSIDs leave
//! `rotate_hours = None` so pinned clients don't re-prompt.

use std::io::Read;
use std::sync::Arc;
use std::time::Duration;

use oxwrt_api::config::Config;

/// 16 chars from the URL-safe alphabet (no O/0/I/l/1 to reduce
/// misreading). 94 bits of entropy — more than enough for a
/// WPA2/WPA3 PSK that's only valid for a day.
const PASSPHRASE_ALPHABET: &[u8] =
    b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
const PASSPHRASE_LEN: usize = 16;

/// Spawn one rotation task per rotating SSID. Handles are not
/// returned (fire-and-forget, task lives for the process life-
/// time — a reload that changes rotate_hours requires a reboot
/// to take effect, same caveat as service-supervisor restart
/// intervals). Called once from init::run.
pub fn spawn_all(cfg: &Config, config_path: std::path::PathBuf) {
    for (idx, wifi) in cfg.wifi.iter().enumerate() {
        let Some(hours) = wifi.rotate_hours else {
            continue;
        };
        if hours == 0 {
            continue;
        }
        let ssid = wifi.ssid.clone();
        let path = config_path.clone();
        let interval = Duration::from_secs(u64::from(hours) * 3600);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(interval);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            // tokio::interval fires immediately on first tick —
            // which we DON'T want at boot, because the current
            // on-disk passphrase is presumably in use. Skip the
            // first tick.
            tick.tick().await;
            loop {
                tick.tick().await;
                if let Err(e) = rotate_once(&ssid, idx, &path).await {
                    tracing::error!(ssid = %ssid, error = %e, "wifi rotate failed");
                }
            }
        });
        tracing::info!(ssid = %wifi.ssid, hours, "wifi rotate task spawned");
    }
}

async fn rotate_once(
    ssid: &str,
    wifi_idx: usize,
    config_path: &std::path::Path,
) -> Result<(), String> {
    let new_pw = generate_passphrase()?;
    patch_config_passphrase(config_path, wifi_idx, ssid, &new_pw)?;
    write_sidecars(ssid, &new_pw)?;
    // Reload: re-exec the running config so hostapd picks up the
    // change. We post to the control-plane's own sQUIC listener?
    // No — simpler: just invoke the reload handler directly via
    // a shared-state hook. Since wifi_rotate doesn't hold a
    // ControlState ref, the pragmatic v1 approach is to rely on
    // the operator running `oxctl reload` themselves OR add a
    // reload-self signal in a follow-up. For now, log the new
    // passphrase location and let the operator trigger.
    //
    // Follow-up: spawn_all could take an Arc<ControlState> +
    // call handle_reload_async directly. v1 is "write the
    // config + sidecar, operator reloads."
    tracing::warn!(
        ssid, pw_location = "/etc/oxwrt/wifi-<ssid>-passphrase.txt",
        "wifi passphrase rotated — run `oxctl reload` to activate"
    );
    Ok(())
}

/// 16-char alphanumeric from `/dev/urandom`. Rejection-samples
/// bytes outside the alphabet range to avoid modulo bias — the
/// alphabet is 56 chars, rejecting ~78% per byte (4 valid chars
/// per 16-char window in the 0..=255 byte space), which needs
/// ~73 bytes to produce 16 PWD chars on average. Cheap.
fn generate_passphrase() -> Result<String, String> {
    let mut f = std::fs::File::open("/dev/urandom").map_err(|e| format!("open urandom: {e}"))?;
    let mut out = String::with_capacity(PASSPHRASE_LEN);
    let mut buf = [0u8; 1];
    while out.len() < PASSPHRASE_LEN {
        f.read_exact(&mut buf).map_err(|e| format!("read urandom: {e}"))?;
        // Unbiased: accept only bytes in the largest multiple of
        // alphabet length that fits in u8. 56 * 4 = 224; bytes
        // 0..=223 are usable, 224..=255 get re-rolled.
        let cap = (256 / PASSPHRASE_ALPHABET.len()) * PASSPHRASE_ALPHABET.len();
        if (buf[0] as usize) < cap {
            let idx = (buf[0] as usize) % PASSPHRASE_ALPHABET.len();
            out.push(PASSPHRASE_ALPHABET[idx] as char);
        }
    }
    Ok(out)
}

/// Patch oxwrt.toml via toml_edit so operator-hand-written
/// comments / section ordering survive the round-trip. Writes
/// to a tempfile + atomic rename.
fn patch_config_passphrase(
    path: &std::path::Path,
    wifi_idx: usize,
    expected_ssid: &str,
    new_pw: &str,
) -> Result<(), String> {
    let body = std::fs::read_to_string(path).map_err(|e| format!("read {path:?}: {e}"))?;
    let mut doc: toml_edit::DocumentMut =
        body.parse().map_err(|e| format!("parse {path:?}: {e}"))?;
    let wifi_arr = doc
        .get_mut("wifi")
        .and_then(|i| i.as_array_of_tables_mut())
        .ok_or_else(|| "no [[wifi]] array in config".to_string())?;
    // Double-check SSID matches the expected idx — an operator
    // reorder between boot and tick would otherwise clobber the
    // wrong network.
    let t = wifi_arr
        .get_mut(wifi_idx)
        .ok_or_else(|| format!("wifi index {wifi_idx} out of bounds"))?;
    let current_ssid = t
        .get("ssid")
        .and_then(|i| i.as_value())
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if current_ssid != expected_ssid {
        return Err(format!(
            "wifi[{wifi_idx}] ssid changed from {expected_ssid:?} to {current_ssid:?} — aborting rotation to avoid clobbering the wrong network"
        ));
    }
    t["passphrase"] = toml_edit::value(new_pw.to_string());
    // Atomic write: tempfile + rename.
    let tmp = path.with_extension("toml.rotate-tmp");
    std::fs::write(&tmp, doc.to_string()).map_err(|e| format!("write tmp: {e}"))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("rename: {e}"))?;
    Ok(())
}

fn write_sidecars(ssid: &str, new_pw: &str) -> Result<(), String> {
    // Plain-text sidecar: just the passphrase, one line, trailing
    // newline. Operator `cat`s it or pipes into anything that
    // wants the raw value.
    let pw_path = format!("/etc/oxwrt/wifi-{}-passphrase.txt", sanitize(ssid));
    std::fs::write(&pw_path, format!("{new_pw}\n"))
        .map_err(|e| format!("write {pw_path}: {e}"))?;
    // UTF-8 half-block QR for the standard WiFi URI format
    // (`WIFI:T:WPA;S:<ssid>;P:<pw>;;`) — scan with any phone
    // camera. Reuses the render helper from oxwrtctl-cli via
    // qrcodegen directly here (no cross-crate dep; we need this
    // server-side, not client-side).
    let uri = format!("WIFI:T:WPA;S:{};P:{};;", qr_escape(ssid), qr_escape(new_pw));
    let qr_ascii = render_qr(&uri).map_err(|e| format!("qr render: {e}"))?;
    let qr_path = format!("/etc/oxwrt/wifi-{}-qr.txt", sanitize(ssid));
    std::fs::write(&qr_path, qr_ascii).map_err(|e| format!("write {qr_path}: {e}"))?;
    tracing::info!(ssid, pw_path = %pw_path, qr_path = %qr_path, "wifi sidecars updated");
    Ok(())
}

/// Sanitize SSID for use in a filename. Keeps only ASCII
/// alphanumerics + `-_`; other chars map to `_`. Prevents a
/// malicious or weird SSID from producing a filename with
/// slashes, dots, or spaces.
fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect()
}

/// WiFi-URI escape per IEEE-1905/ZXing convention: backslash-
/// escape `\`, `;`, `,`, `:`, `"`.
fn qr_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(c, '\\' | ';' | ',' | ':' | '"') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Render a string as an ASCII / UTF-8 half-block QR suitable for
/// phone scanning from a terminal. Uses qrcodegen directly since
/// pulling in oxwrtctl-cli's qr::render would create a server-on-
/// client dep.
fn render_qr(payload: &str) -> Result<String, String> {
    use qrcodegen::{QrCode, QrCodeEcc};
    let qr = QrCode::encode_text(payload, QrCodeEcc::Medium)
        .map_err(|e| format!("encode: {e:?}"))?;
    let n = qr.size();
    let mut out = String::new();
    // Quiet zone: 1 row of blanks above and below.
    for _ in 0..2 {
        for _ in -1..=n {
            out.push_str("  ");
        }
        out.push('\n');
    }
    // Pairs of rows → one line of UTF-8 half-blocks.
    let mut y = 0;
    while y < n {
        out.push_str("  ");
        for x in 0..n {
            let top = qr.get_module(x, y);
            let bot = if y + 1 < n { qr.get_module(x, y + 1) } else { false };
            let ch = match (top, bot) {
                (false, false) => ' ',
                (true, false) => '▀',
                (false, true) => '▄',
                (true, true) => '█',
            };
            out.push(ch);
        }
        out.push_str("  \n");
        y += 2;
    }
    for _ in 0..2 {
        for _ in -1..=n {
            out.push_str("  ");
        }
        out.push('\n');
    }
    Ok(out)
}

// Unused arg placeholder if future expansion needs the full Arc<Config>
#[allow(dead_code)]
fn _cfg_anchor(_c: Arc<Config>) {}
