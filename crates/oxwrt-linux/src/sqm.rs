//! Smart Queue Management (SQM) via the Linux CAKE qdisc.
//!
//! For each WAN iface that declares `sqm`:
//!   - Upload (egress): `tc qdisc replace dev <wan> root cake bandwidth
//!     <up>kbit <extra>`
//!   - Download (ingress): create an IFB iface (`ifb-<wan>`), mirror the
//!     WAN's ingress to it via a tc-filter match-all mirred redirect,
//!     and run CAKE on the IFB's egress with the download bandwidth.
//!
//! Why IFB: Linux ingress qdiscs can only CLASSIFY + DROP, they can't
//! SHAPE. The canonical workaround is to redirect ingress traffic to
//! a virtual Intermediate Functional Block (IFB) iface where it
//! becomes "egress" and can be queued / shaped. This is the same
//! trick OpenWrt's sqm-scripts package uses.
//!
//! External-binary pattern: `tc` + `ip` from iproute2, both always
//! present in the image (iproute2 is a hard dep of kmod-sched-cake).
//! Matches how we already call `iw`, `wg`, `ip link add wireguard`
//! elsewhere — rtnetlink doesn't have a first-class API for qdisc
//! mutation yet.

use std::process::Command;

use oxwrt_api::config::{Config, Network};

use crate::net::Error;

/// Apply SQM (CAKE) shaping for every WAN iface that declares
/// `sqm`. Idempotent — uses `tc qdisc replace` which creates or
/// overwrites. Called on boot and on reload.
pub fn setup_sqm(cfg: &Config) -> Result<(), Error> {
    for net in &cfg.networks {
        let Network::Wan { iface, sqm, .. } = net else {
            continue;
        };
        let Some(sqm) = sqm.as_ref() else {
            // No SQM declared — actively remove any stale qdisc from a
            // previous reload so the iface falls back to the kernel
            // default (pfifo_fast). Ignore errors — a fresh iface has
            // no root qdisc to clear.
            let _ = Command::new("tc")
                .args(["qdisc", "del", "dev", iface, "root"])
                .status();
            let ifb = ifb_name(iface);
            let _ = Command::new("ip")
                .args(["link", "del", "dev", &ifb])
                .status();
            continue;
        };
        if let Err(e) = apply_one(iface, sqm) {
            tracing::error!(iface, error = %e, "sqm: apply failed");
        }
    }
    Ok(())
}

fn apply_one(wan_iface: &str, sqm: &oxwrt_api::config::SqmConfig) -> Result<(), String> {
    // ── Upload / egress ────────────────────────────────────────────
    if let Some(up) = sqm.bandwidth_up_kbps {
        let mut args: Vec<String> = vec![
            "qdisc".into(),
            "replace".into(),
            "dev".into(),
            wan_iface.into(),
            "root".into(),
            "cake".into(),
            "bandwidth".into(),
            format!("{up}kbit"),
        ];
        if let Some(extra) = sqm.extra_args.as_deref() {
            for tok in extra.split_whitespace() {
                args.push(tok.to_string());
            }
        }
        run("tc", &args).map_err(|e| format!("egress cake install: {e}"))?;
        tracing::info!(iface = wan_iface, kbps = up, "sqm: egress CAKE installed");
    } else {
        // Explicit up=unset + down=set: remove any stale root qdisc
        // so the existing shaping doesn't stick around.
        let _ = Command::new("tc")
            .args(["qdisc", "del", "dev", wan_iface, "root"])
            .status();
    }

    // ── Download / ingress via IFB ────────────────────────────────
    let ifb = ifb_name(wan_iface);
    if let Some(down) = sqm.bandwidth_down_kbps {
        // Ensure the IFB iface exists + is up.
        let present = Command::new("ip")
            .args(["link", "show", &ifb])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !present {
            run("ip", &["link", "add", &ifb, "type", "ifb"])
                .map_err(|e| format!("ifb add: {e}"))?;
        }
        run("ip", &["link", "set", "dev", &ifb, "up"]).map_err(|e| format!("ifb up: {e}"))?;

        // Mirror WAN's ingress → IFB egress. Replace the filter
        // parent (the clsact qdisc) so a reload doesn't stack up
        // N copies of the filter.
        let _ = Command::new("tc")
            .args(["qdisc", "del", "dev", wan_iface, "ingress"])
            .status();
        run(
            "tc",
            &[
                "qdisc", "add", "dev", wan_iface, "handle", "ffff:", "ingress",
            ],
        )
        .map_err(|e| format!("wan ingress qdisc: {e}"))?;
        run(
            "tc",
            &[
                "filter", "add", "dev", wan_iface, "parent", "ffff:", "protocol", "all",
                "matchall", "action", "mirred", "egress", "redirect", "dev", &ifb,
            ],
        )
        .map_err(|e| format!("wan ingress mirred: {e}"))?;

        // CAKE on the IFB iface.
        let mut args: Vec<String> = vec![
            "qdisc".into(),
            "replace".into(),
            "dev".into(),
            ifb.clone(),
            "root".into(),
            "cake".into(),
            "bandwidth".into(),
            format!("{down}kbit"),
        ];
        if let Some(extra) = sqm.extra_args.as_deref() {
            for tok in extra.split_whitespace() {
                args.push(tok.to_string());
            }
        }
        run("tc", &args).map_err(|e| format!("ingress cake install: {e}"))?;
        tracing::info!(
            iface = wan_iface,
            ifb = ifb.as_str(),
            kbps = down,
            "sqm: ingress CAKE installed via IFB"
        );
    } else {
        // No download shaping requested — tear down any leftover
        // IFB + ingress filter.
        let _ = Command::new("tc")
            .args(["qdisc", "del", "dev", wan_iface, "ingress"])
            .status();
        let _ = Command::new("ip")
            .args(["link", "del", "dev", &ifb])
            .status();
    }

    Ok(())
}

/// Name of the IFB iface used for a WAN's ingress shaping. Hashed
/// down to 15 chars if needed (IFNAMSIZ is 16 including NUL).
fn ifb_name(wan: &str) -> String {
    let raw = format!("ifb-{wan}");
    if raw.len() <= 15 {
        raw
    } else {
        format!("ifb-{}", &wan[..11])
    }
}

/// Thin wrapper over std::process::Command that stringifies any
/// non-zero exit or spawn error into a human-readable message with
/// the failed command echoed.
fn run<S: AsRef<str>>(prog: &str, args: &[S]) -> Result<(), String> {
    let args_vec: Vec<&str> = args.iter().map(|s| s.as_ref()).collect();
    let out = Command::new(prog)
        .args(&args_vec)
        .output()
        .map_err(|e| format!("{prog} spawn: {e}"))?;
    if !out.status.success() {
        let cmd = args_vec.join(" ");
        return Err(format!(
            "{prog} {cmd}: exit {} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ifb_name_short_wan() {
        assert_eq!(ifb_name("eth1"), "ifb-eth1");
        assert_eq!(ifb_name("wan"), "ifb-wan");
    }

    #[test]
    fn ifb_name_long_wan_truncates() {
        // 16-char wan iface would produce 20-char IFB, exceeds
        // IFNAMSIZ. We truncate to 11 chars of wan + "ifb-" = 15.
        assert_eq!(ifb_name("abcdefghijklmnop"), "ifb-abcdefghijk");
        assert_eq!(ifb_name("abcdefghijk"), "ifb-abcdefghijk"); // exact 11
    }
}
