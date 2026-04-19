//! ASCII QR rendering for `wg-enroll --qr`. Each QR module (pixel)
//! maps to one Unicode half-block so a 25x25 QR becomes a
//! 25-column x 13-row block — fits in any 80-column terminal with
//! room to spare, still scans from a phone camera held about
//! 30 cm from the screen.
//!
//! Two rows of QR modules pack into one output row:
//!
//! ```text
//! light/light -> ' '     (space)
//! light/dark  -> '▄'     (lower-half block, fg=dark)
//! dark/light  -> '▀'     (upper-half block)
//! dark/dark   -> '█'     (full block)
//! ```
//!
//! Uses the default fg (light) terminal color + '█' as the "dark"
//! pixel. Inverted vs the QR spec's "black on white" because most
//! terminals are dark-themed — phone cameras handle either
//! polarity. The quiet zone (4-module white border) is required
//! by ISO/IEC 18004; we emit it as extra blank rows + prefix
//! spaces.
//!
//! Error correction: ECC::Medium (~15%) balances size against
//! partial-occlusion tolerance (finger over the screen, glare
//! spots). wg-quick configs fit in M-level up to ~300 bytes at
//! QR version ~10; a typical enroll .conf is ~280 bytes.

use qrcodegen::{QrCode, QrCodeEcc};

/// Render `data` as a UTF-8 half-block QR code. Returns the block
/// string suitable for stdout; includes the mandatory 4-module
/// quiet zone on all sides.
pub fn render(data: &str) -> Result<String, String> {
    let qr = QrCode::encode_text(data, QrCodeEcc::Medium).map_err(|e| format!("qrcode: {e}"))?;
    Ok(render_qr(&qr))
}

fn render_qr(qr: &QrCode) -> String {
    let size = qr.size();
    let border = 4;
    let total = size + 2 * border;

    // Pack two QR rows into one terminal row. Each output row y
    // covers input rows (2y, 2y+1) — the extra row is "bottom
    // quiet zone" when we're on the last iteration.
    let mut out = String::with_capacity(((total as usize) * ((total as usize) / 2 + 1)) * 3);

    for y in (0..total).step_by(2) {
        for x in 0..total {
            let top_dark = get_module(qr, x - border, y - border);
            let bot_dark = if y + 1 < total {
                get_module(qr, x - border, (y + 1) - border)
            } else {
                false
            };
            out.push(match (top_dark, bot_dark) {
                (false, false) => ' ',
                (false, true) => '▄',
                (true, false) => '▀',
                (true, true) => '█',
            });
        }
        out.push('\n');
    }
    out
}

fn get_module(qr: &QrCode, x: i32, y: i32) -> bool {
    if x < 0 || y < 0 || x >= qr.size() || y >= qr.size() {
        false // quiet zone
    } else {
        qr.get_module(x, y)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_returns_nonempty_for_short_payload() {
        let out = render("hello").unwrap();
        assert!(!out.is_empty());
        // At least 20 rows covering the quiet zone + a V1 21x21 QR.
        let rows: Vec<&str> = out.lines().collect();
        assert!(rows.len() >= 10, "too few rows: {}", rows.len());
    }

    #[test]
    fn render_fits_realistic_wg_conf() {
        // A typical wg-enroll .conf is ~280 bytes: Interface
        // block (name, privkey, address, dns) + Peer block
        // (pubkey, psk, endpoint, allowedips, keepalive).
        let conf = "[Interface]\n\
                    PrivateKey = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=\n\
                    Address = 10.8.0.2/32\n\
                    DNS = 192.168.50.1\n\
                    \n\
                    [Peer]\n\
                    PublicKey = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb=\n\
                    PresharedKey = ccccccccccccccccccccccccccccccccccccccccccc=\n\
                    AllowedIPs = 0.0.0.0/0\n\
                    Endpoint = vpn.example.com:51820\n\
                    PersistentKeepalive = 25\n";
        let out = render(conf).unwrap();
        // Real wg-quick configs encode at QR version ~10-11 with
        // ECC-M (53x53 modules = 27 terminal rows plus 4-module
        // quiet zone top and bottom). Width counts UTF-8 chars,
        // not bytes, so use chars() to match how the terminal
        // sees it.
        let cols = out.lines().next().unwrap().chars().count();
        assert!(
            cols >= 21 + 8 && cols <= 200,
            "unexpected col count: {cols}"
        );
    }

    #[test]
    fn render_errors_on_oversized_payload() {
        // QR has an upper bound — huge binary blobs don't fit
        // even in version-40 ECC-L. 10 KiB is safely over that.
        let huge = "X".repeat(10 * 1024);
        let r = render(&huge);
        assert!(r.is_err(), "should reject oversized payload");
    }
}
