//! Prometheus-format `/metrics` endpoint. Optional — only runs when
//! `[metrics] listen = "..."` is set in the config. Hand-written HTTP
//! (no hyper dep) because the surface area is tiny: one URL, one
//! method, plain text response. Reusing reqwest's server side would
//! pull in hyper + several hundred kB of musl-linked deps for zero
//! operational win.
//!
//! Why run at all: `oxctl status` already exposes the same data, but
//! that's a pull over sQUIC + ed25519 — great for operators, awkward
//! for a Prometheus scraper on the LAN. This endpoint is plain HTTP
//! with no auth, intended to be firewalled to the LAN zone via the
//! normal `[[rules]]` mechanism (or bound to `127.0.0.1` + scraped
//! over an SSH tunnel). No TLS on purpose — inside a trust boundary.
//!
//! Metrics exported (Prometheus text format 0.0.4):
//!   - `oxwrt_supervisor_uptime_seconds`
//!   - `oxwrt_service_state{service,pid}` — 0=stopped 1=starting
//!     2=running 3=crashed
//!   - `oxwrt_service_restarts_total{service}`
//!   - `oxwrt_service_uptime_seconds{service}`
//!   - `oxwrt_ap_up{ssid,iface,phy,band}` — 1 if operstate=="up"
//!   - `oxwrt_wan_lease_seconds{iface}` — full lease length
//!   - `oxwrt_firewall_rules`
//!   - `oxwrt_wg_peer_last_handshake_seconds{iface,peer,pubkey}`
//!   - `oxwrt_wg_peer_rx_bytes_total{iface,peer}`
//!   - `oxwrt_wg_peer_tx_bytes_total{iface,peer}`
//!
//! The collect_* functions already sit in `control::server`, so this
//! module is ~80% formatting.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::control::ControlState;

/// Spawn the metrics HTTP listener. If `cfg.metrics` is None the
/// function returns immediately without spawning anything. On bind
/// failure we log an error and keep going — a broken metrics
/// endpoint should never block boot.
pub fn spawn(state: Arc<ControlState>) {
    let cfg = state.config_snapshot();
    let Some(m) = cfg.metrics.as_ref() else {
        tracing::info!("metrics: disabled (no [metrics] in config)");
        return;
    };
    let listen = m.listen.clone();
    tokio::spawn(async move {
        let listener = match TcpListener::bind(&listen).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(listen = %listen, error = %e, "metrics: bind failed; disabling");
                return;
            }
        };
        tracing::info!(listen = %listen, "metrics: listening");
        loop {
            let (mut sock, peer) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %e, "metrics: accept failed");
                    continue;
                }
            };
            let state = state.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_conn(&mut sock, &state).await {
                    tracing::debug!(peer = %peer, error = %e, "metrics: conn error");
                }
            });
        }
    });
}

/// Minimal HTTP/1.1 handler. Reads until the end of headers (blank
/// line), ignores everything about the request except that we got
/// one, and writes a Prometheus text body. Connection: close, so
/// the scraper has to reconnect each scrape — fine at 15s cadence.
async fn handle_conn(
    sock: &mut tokio::net::TcpStream,
    state: &Arc<ControlState>,
) -> std::io::Result<()> {
    // Read the request headers. Cap at 4 KiB — scrapers send ~200 B.
    let mut buf = [0u8; 4096];
    let mut n = 0;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Ok(()); // read timeout — client went away
        }
        let read = tokio::time::timeout(remaining, sock.read(&mut buf[n..])).await;
        let r = match read {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => return Err(e),
            Err(_) => return Ok(()),
        };
        if r == 0 {
            break;
        }
        n += r;
        if buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if n == buf.len() {
            break;
        }
    }

    let body = render(state);
    let resp = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: text/plain; version=0.0.4\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n{}",
        body.len(),
        body
    );
    sock.write_all(resp.as_bytes()).await?;
    sock.shutdown().await.ok();
    Ok(())
}

/// Build the Prometheus text body. Pure function of `state` — all
/// I/O happens in the collect_* helpers it calls (sysfs reads,
/// `wg show` subprocess). Kept free of async so unit tests can
/// exercise the formatter without a runtime.
fn render(state: &ControlState) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(2048);

    // Supervisor uptime ─────────────────────────────────────────────
    let _ = writeln!(
        out,
        "# HELP oxwrt_supervisor_uptime_seconds Seconds since ControlState init.\n\
         # TYPE oxwrt_supervisor_uptime_seconds gauge\n\
         oxwrt_supervisor_uptime_seconds {}",
        state.boot_time.elapsed().as_secs()
    );

    // Per-service state ─────────────────────────────────────────────
    let services = crate::control::server::collect_status(state);
    let _ = writeln!(
        out,
        "# HELP oxwrt_service_state 0=stopped 1=starting 2=running 3=crashed.\n\
         # TYPE oxwrt_service_state gauge"
    );
    for s in &services {
        let v = match s.state {
            crate::rpc::ServiceState::Stopped => 0,
            crate::rpc::ServiceState::Starting => 1,
            crate::rpc::ServiceState::Running => 2,
            crate::rpc::ServiceState::Crashed => 3,
        };
        let pid = s.pid.map(|p| p.to_string()).unwrap_or_else(|| "0".into());
        let _ = writeln!(
            out,
            "oxwrt_service_state{{service=\"{}\",pid=\"{}\"}} {}",
            esc(&s.name),
            pid,
            v
        );
    }
    let _ = writeln!(
        out,
        "# HELP oxwrt_service_restarts_total Cumulative restart count.\n\
         # TYPE oxwrt_service_restarts_total counter"
    );
    for s in &services {
        let _ = writeln!(
            out,
            "oxwrt_service_restarts_total{{service=\"{}\"}} {}",
            esc(&s.name),
            s.restarts
        );
    }
    let _ = writeln!(
        out,
        "# HELP oxwrt_service_uptime_seconds Seconds since the current spawn.\n\
         # TYPE oxwrt_service_uptime_seconds gauge"
    );
    for s in &services {
        let _ = writeln!(
            out,
            "oxwrt_service_uptime_seconds{{service=\"{}\"}} {}",
            esc(&s.name),
            s.uptime_secs
        );
    }

    // APs ───────────────────────────────────────────────────────────
    let cfg = state.config_snapshot();
    let aps = crate::control::server::collect_ap_status(&cfg);
    let _ = writeln!(
        out,
        "# HELP oxwrt_ap_up 1 if the AP iface is up, 0 otherwise.\n\
         # TYPE oxwrt_ap_up gauge"
    );
    for ap in &aps {
        let up = if ap.operstate == "up" { 1 } else { 0 };
        let _ = writeln!(
            out,
            "oxwrt_ap_up{{ssid=\"{}\",iface=\"{}\",phy=\"{}\",band=\"{}\"}} {}",
            esc(&ap.ssid),
            esc(&ap.iface),
            esc(&ap.radio_phy),
            esc(&ap.band),
            up
        );
    }

    // WAN lease ─────────────────────────────────────────────────────
    let _ = writeln!(
        out,
        "# HELP oxwrt_wan_lease_seconds Full lease length from the DHCP ACK (gauge).\n\
         # TYPE oxwrt_wan_lease_seconds gauge"
    );
    if let Ok(guard) = state.wan_lease.read() {
        if let Some(l) = guard.as_ref() {
            let _ = writeln!(out, "oxwrt_wan_lease_seconds {}", l.lease_seconds);
        }
    }

    // Firewall rules ────────────────────────────────────────────────
    let fw_rules = state.firewall_dump.read().map(|g| g.len()).unwrap_or(0);
    let _ = writeln!(
        out,
        "# HELP oxwrt_firewall_rules Number of rules installed at last firewall reload.\n\
         # TYPE oxwrt_firewall_rules gauge\n\
         oxwrt_firewall_rules {}",
        fw_rules
    );

    // WireGuard peers ───────────────────────────────────────────────
    let wg_ifaces = crate::control::server::collect_wg_status(&cfg);
    let _ = writeln!(
        out,
        "# HELP oxwrt_wg_peer_last_handshake_seconds Seconds since last handshake; -1 = never.\n\
         # TYPE oxwrt_wg_peer_last_handshake_seconds gauge\n\
         # HELP oxwrt_wg_peer_rx_bytes_total Bytes received from this peer.\n\
         # TYPE oxwrt_wg_peer_rx_bytes_total counter\n\
         # HELP oxwrt_wg_peer_tx_bytes_total Bytes sent to this peer.\n\
         # TYPE oxwrt_wg_peer_tx_bytes_total counter"
    );
    for wif in &wg_ifaces {
        for p in &wif.peers {
            let hs: i64 = p.last_handshake_secs_ago.map(|v| v as i64).unwrap_or(-1);
            let labels = format!(
                "iface=\"{}\",peer=\"{}\",pubkey=\"{}\"",
                esc(&wif.iface),
                esc(&p.name),
                esc(&p.pubkey)
            );
            let _ = writeln!(
                out,
                "oxwrt_wg_peer_last_handshake_seconds{{{}}} {}",
                labels, hs
            );
            let _ = writeln!(
                out,
                "oxwrt_wg_peer_rx_bytes_total{{iface=\"{}\",peer=\"{}\"}} {}",
                esc(&wif.iface),
                esc(&p.name),
                p.rx_bytes
            );
            let _ = writeln!(
                out,
                "oxwrt_wg_peer_tx_bytes_total{{iface=\"{}\",peer=\"{}\"}} {}",
                esc(&wif.iface),
                esc(&p.name),
                p.tx_bytes
            );
        }
    }

    out
}

/// Escape a label value per Prometheus text format: `\`, `"` and
/// newline are the only chars that must be quoted. Everything else
/// (UTF-8 included) passes through unchanged.
fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn esc_handles_specials() {
        assert_eq!(esc("plain"), "plain");
        assert_eq!(esc("a\"b"), "a\\\"b");
        assert_eq!(esc("a\\b"), "a\\\\b");
        assert_eq!(esc("a\nb"), "a\\nb");
        // UTF-8 unchanged
        assert_eq!(esc("αβ"), "αβ");
    }
}
