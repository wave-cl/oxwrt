//! Reload: re-parse config, reconcile netlink addrs + firewall +
//! supervisor + wifi conf. Split out in step 7.

use super::*;

pub async fn handle_reload_async(state: &ControlState) -> Response {
    use crate::config::Config;
    use crate::container::Supervisor;
    use std::path::Path;

    // Phase 1: parse.
    let path = Path::new(crate::config::DEFAULT_PATH);
    let new_cfg = match Config::load(path) {
        Ok(c) => c,
        Err(e) => {
            return Response::Err {
                message: format!("reload: {e}"),
            };
        }
    };

    // Control-only mode short-circuit: re-parse + swap the in-memory
    // config but skip every reconcile phase (netlink, sethostname,
    // firewall, supervisor). This preserves the ability to hand-edit
    // /etc/oxwrt.toml and have `reload` validate + publish the result
    // for subsequent Get/CRUD reads, without violating the
    // --control-only contract of "don't touch live network state."
    if state.control_only {
        let Ok(mut cfg) = state.config.write() else {
            return Response::Err {
                message: "reload: config lock poisoned".to_string(),
            };
        };
        *cfg = std::sync::Arc::new(new_cfg);
        tracing::info!("control-only reload: config re-parsed and swapped (no reconcile)");
        return Response::Ok;
    }

    // Phase 2: reconcile netlink address state. We compare against the
    // KERNEL's current state, not the in-memory `state.config` —
    // because `Set` already updated the in-memory config and any two
    // snapshots of it are guaranteed equal at this point. The kernel
    // is the source of truth for "what's actually on the bridge."
    //
    // Bridge rename is still refused — creating the new bridge and
    // moving ports is substantially more work than an address swap.
    let old_cfg = state.config_snapshot();
    let old_lan_iface = old_cfg.lan().map(|n| n.iface().to_string());
    let new_lan_iface = new_cfg.lan().map(|n| n.iface().to_string());
    if old_lan_iface != new_lan_iface {
        return Response::Err {
            message: format!(
                "reload: lan bridge changed from {:?} to {:?}; bridge rename is not \
                 supported over reload, reboot required",
                old_lan_iface, new_lan_iface
            ),
        };
    }
    if let Some(crate::config::Network::Lan {
        bridge,
        address,
        prefix,
        ..
    }) = new_cfg.lan()
    {
        if let Err(e) = reconcile_iface_address(bridge, *address, *prefix, "lan").await {
            return Response::Err {
                message: format!("reload: lan address reconcile failed: {e}"),
            };
        }
    }

    // WAN static mode: same reconcile against the WAN iface. DHCP mode
    // is handled by the renewal loop (which runs DISCOVER → REQUEST →
    // ACK and applies the lease independently of reload). Pppoe has
    // its own setup path and isn't reconciled here.
    if let Some(crate::config::Network::Wan {
        iface,
        wan: crate::config::WanConfig::Static {
            address, prefix, ..
        },
        ..
    }) = new_cfg.primary_wan()
    {
        if let Err(e) = reconcile_iface_address(iface, *address, *prefix, "wan").await {
            return Response::Err {
                message: format!("reload: wan static address reconcile failed: {e}"),
            };
        }
    }

    // Hostname change: apply via sethostname(2) so the live kernel
    // agrees with the new config. No-op if the hostname didn't change
    // (sethostname is idempotent and cheap). Failure is logged but not
    // fatal — a hostname mismatch is a UX quirk, not a router outage.
    if let Err(e) = rustix::system::sethostname(new_cfg.hostname.as_bytes()) {
        tracing::warn!(
            error = %e,
            hostname = %new_cfg.hostname,
            "reload: sethostname failed"
        );
    }

    // Phase 3: reinstall firewall.
    if let Err(e) = crate::net::install_firewall(&new_cfg) {
        return Response::Err {
            message: format!("reload: firewall install failed: {e}"),
        };
    }
    let new_firewall_dump = crate::net::format_firewall_dump(&new_cfg);

    // Phase 3a: re-apply wireguard config. Picks up new/removed
    // [[wireguard]] entries and peer-list updates made via CRUD
    // since the last install — without this, `oxctl wg-peer add …`
    // + `reload` would persist the peer in oxwrt.toml but never
    // push it to the running wg iface, so the tunnel stays silently
    // broken until the next reboot.
    if let Err(e) = crate::wireguard::setup_wireguard(&new_cfg) {
        tracing::error!(error = %e, "reload: wireguard reapply failed");
        // Non-fatal: the rest of the reload continues so a bad wg
        // config doesn't knock the router offline.
    }

    // Phase 3b: regenerate per-phy hostapd.conf files at
    // /etc/oxwrt/hostapd/. Must run BEFORE phase 4 (supervisor rebuild)
    // so when the new hostapd-5g / hostapd-2g services come up they
    // read the freshly-generated config rather than stale content from
    // the previous boot. Failure is logged, not fatal — the services
    // might start with an old config or fail to start entirely, but we
    // don't want to block the rest of reload on it.
    if let Err(e) = crate::wifi::write_all(&new_cfg) {
        tracing::error!(error = %e, "reload: wifi::write_all failed");
    }

    // Phase 4: rebuild supervisor.
    {
        let Ok(mut sup) = state.supervisor.lock() else {
            return Response::Err {
                message: "reload: supervisor mutex poisoned".to_string(),
            };
        };
        sup.shutdown();
        *sup = Supervisor::from_config(&new_cfg.services);
    }

    // Phase 5: publish new state.
    {
        let Ok(mut cfg) = state.config.write() else {
            return Response::Err {
                message: "reload: config lock poisoned".to_string(),
            };
        };
        *cfg = std::sync::Arc::new(new_cfg);
    }
    {
        let Ok(mut dump) = state.firewall_dump.write() else {
            return Response::Err {
                message: "reload: firewall_dump lock poisoned".to_string(),
            };
        };
        *dump = new_firewall_dump;
    }

    tracing::info!("config reloaded, firewall reinstalled, supervisor rebuilt");
    Response::Ok
}

/// Bring the IPv4 addresses on `iface` into agreement with
/// `new_ip/new_prefix`. Compares the KERNEL's current state (not any
/// in-memory Config) because `Set` already updated the config before
/// `reload` ran — the kernel is the only source of truth for "what's
/// actually on the iface right now." Used for both the LAN bridge and
/// the WAN iface (in static mode); previously this was LAN-specific.
///
/// Algorithm:
/// 1. Dump all IPv4 addresses on `iface`.
/// 2. If the desired `new_ip/new_prefix` is already there, done.
/// 3. Otherwise, delete every other IPv4 address on the iface (we
///    assume the supervisor owns the addressing — there's no expected
///    "extra" IP an operator would have added out of band, since the
///    appliance has no shell).
/// 4. Add the new address.
///
/// Tolerates ENOENT / File exists on individual operations — the
/// kernel state may have shifted slightly between our get and our
/// del/add, which is fine as long as the final state is what we
/// wanted.
async fn reconcile_iface_address(
    iface: &str,
    new_ip: std::net::Ipv4Addr,
    new_prefix: u8,
    role: &str, // "lan" or "wan", for log tagging
) -> Result<(), String> {
    use futures_util::stream::TryStreamExt;
    use rtnetlink::packet_route::{AddressFamily, address::AddressAttribute};

    let (connection, handle, _messages) = rtnetlink::new_connection().map_err(|e| e.to_string())?;
    let conn_task = tokio::spawn(connection);

    // Resolve iface → index.
    let idx = {
        let mut stream = handle.link().get().match_name(iface.to_string()).execute();
        let msg = stream
            .try_next()
            .await
            .map_err(|e| format!("link get {iface}: {e}"))?
            .ok_or_else(|| format!("link {iface} not found"))?;
        msg.header.index
    };

    // Dump IPv4 addresses on the iface. Collect (is_desired, msg) so
    // we can act on them after the stream closes (calling another
    // rtnetlink op while a dump stream is open would deadlock the
    // handle).
    let mut desired_present = false;
    let mut to_delete: Vec<rtnetlink::packet_route::address::AddressMessage> = Vec::new();
    let mut addrs = handle.address().get().execute();
    while let Some(msg) = addrs
        .try_next()
        .await
        .map_err(|e| format!("address get: {e}"))?
    {
        if msg.header.index != idx {
            continue;
        }
        if msg.header.family != AddressFamily::Inet {
            continue;
        }
        let mut this_ip: Option<std::net::Ipv4Addr> = None;
        for attr in &msg.attributes {
            if let AddressAttribute::Address(std::net::IpAddr::V4(a)) = attr {
                this_ip = Some(*a);
                break;
            }
        }
        let Some(ip) = this_ip else {
            continue;
        };
        if ip == new_ip && msg.header.prefix_len == new_prefix {
            desired_present = true;
        } else {
            to_delete.push(msg);
        }
    }

    for msg in to_delete {
        let ip_str = format_v4_from_attrs(&msg.attributes);
        let prefix = msg.header.prefix_len;
        if let Err(e) = handle.address().del(msg).execute().await {
            conn_task.abort();
            return Err(format!("del {ip_str}/{prefix}: {e}"));
        }
        tracing::info!(
            role,
            iface,
            deleted = %ip_str,
            prefix,
            "reconcile: removed stale address"
        );
    }

    if !desired_present {
        match handle
            .address()
            .add(idx, std::net::IpAddr::V4(new_ip), new_prefix)
            .execute()
            .await
        {
            Ok(()) => {
                tracing::info!(role, iface, %new_ip, new_prefix, "reconcile: added address");
            }
            Err(e) => {
                let msg = e.to_string();
                if !msg.contains("File exists") {
                    conn_task.abort();
                    return Err(format!("add {new_ip}/{new_prefix}: {e}"));
                }
                // Race: something added it between our dump and our add.
                // Treat as success.
            }
        }
    }

    conn_task.abort();
    Ok(())
}

fn format_v4_from_attrs(attrs: &[rtnetlink::packet_route::address::AddressAttribute]) -> String {
    use rtnetlink::packet_route::address::AddressAttribute;
    for attr in attrs {
        if let AddressAttribute::Address(std::net::IpAddr::V4(a)) = attr {
            return a.to_string();
        }
    }
    "?".to_string()
}
