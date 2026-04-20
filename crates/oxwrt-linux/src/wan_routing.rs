//! Per-zone WAN selection via policy routing.
//!
//! When a `[[firewall.zones]]` entry declares `wan = "<name>"`,
//! forwarded traffic from that zone's ifaces routes through the
//! named WAN's per-WAN table instead of the main-table default.
//! Independent of the failover coordinator — a zone's WAN is
//! static at config time, doesn't change on coordinator picks.
//!
//! Layout:
//!   - Main table (254) keeps the coordinator-picked WAN's default
//!     for router-originated traffic and zones without `wan`.
//!   - Per-WAN tables at 100 + priority-slot (100, 101, …) hold
//!     the default via that specific WAN, installed by this module
//!     whenever the WAN has a lease.
//!   - `ip rule iif <zone_iface> lookup <table>` at priority 800
//!     (between bypass=500 and vpn=1000) diverts forwarded traffic.
//!     If both `wan=X` AND `via_vpn=true` are set on a zone, the
//!     VPN iif rule at 1000 is evaluated AFTER the WAN-routing
//!     rule at 800; the first match wins — so per-zone WAN would
//!     route packets to that WAN's table first. Operator caveat:
//!     declaring both means you want the WAN, not the VPN. Keep
//!     `via_vpn` for VPN, don't mix.

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::sync::Mutex;

use futures_util::stream::TryStreamExt;
use oxwrt_api::config::Config;
use rtnetlink::packet_route::rule::RuleAction;
use rtnetlink::{Error as RtError, Handle, RouteMessageBuilder};

use crate::net::Error;

/// Priority the per-zone WAN-routing iif rules sit at. Below
/// VPN_RULE_PRIORITY (1000) so a zone with both `wan` and
/// `via_vpn` set hits the WAN rule first. Above
/// VPN_BYPASS_PRIORITY (500) so a bypass CIDR still wins for
/// dest matches.
pub const WAN_RULE_PRIORITY: u32 = 800;

/// Base routing table ID. Each WAN gets `WAN_TABLE_BASE + i`
/// where i is its index in cfg.networks (WAN-filtered). 100
/// avoids the reserved main (254), local (255), default (253)
/// and oxwrt's VPN_TABLE (51). Keep below 252.
pub const WAN_TABLE_BASE: u32 = 100;

/// Set of ifaces we've installed iif rules for, keyed by
/// (iface, table_id). Tracked for diff-on-reload.
static INSTALLED_ZONE_RULES: Mutex<Option<HashSet<(String, u32)>>> = Mutex::new(None);

/// Deterministic table-id for a WAN by name: index in
/// cfg.networks' WAN-only subset, + WAN_TABLE_BASE. Returns None
/// if the name doesn't match any declared WAN.
pub fn wan_table_id(wan_name: &str, cfg: &Config) -> Option<u32> {
    let idx = cfg
        .networks
        .iter()
        .filter(|n| matches!(n, oxwrt_api::config::Network::Wan { .. }))
        .position(|n| n.name() == wan_name)?;
    Some(WAN_TABLE_BASE + idx as u32)
}

/// Install (or replace) the default route in a per-WAN table.
/// Called by the WAN-lease apply path whenever a lease lands —
/// makes the per-WAN table usable for forwarded zone traffic the
/// moment that WAN comes up.
pub async fn set_wan_table_default(
    handle: &Handle,
    table_id: u32,
    wan_iface: &str,
    wan_gw: Ipv4Addr,
) -> Result<(), Error> {
    let ifindex = ifindex(handle, wan_iface).await?;
    let route = RouteMessageBuilder::<Ipv4Addr>::new()
        .destination_prefix(Ipv4Addr::UNSPECIFIED, 0)
        .gateway(wan_gw)
        .output_interface(ifindex)
        .table_id(table_id)
        .priority(0)
        .build();
    match handle.route().add(route).replace().execute().await {
        Ok(()) => {
            tracing::info!(table_id, wan_iface, %wan_gw, "wan_routing: per-WAN default set");
            Ok(())
        }
        Err(e) => Err(Error::Rtnetlink(e)),
    }
}

/// Install `ip rule iif <zone_iface> lookup <wan_table>` for
/// every (zone_iface, table) pair derived from zones with
/// `wan = "<name>"`. Idempotent + diffed-against-previous —
/// stale rules from a previous reload are reaped.
pub async fn install_zone_wan_rules(handle: &Handle, cfg: &Config) -> Result<(), Error> {
    use oxwrt_api::config::Network;
    let mut new_set: HashSet<(String, u32)> = HashSet::new();
    for zone in &cfg.firewall.zones {
        let Some(wan_name) = &zone.wan else {
            continue;
        };
        let Some(table_id) = wan_table_id(wan_name, cfg) else {
            tracing::warn!(
                zone = %zone.name, wan = %wan_name,
                "wan_routing: zone references unknown WAN name; skipping"
            );
            continue;
        };
        for net_name in &zone.networks {
            // Resolve zone.networks → iface names. Mirrors
            // net::zone_ifaces but avoids a dependency loop.
            for net in &cfg.networks {
                if net.name() != net_name {
                    continue;
                }
                let iface = match net {
                    Network::Lan { bridge, .. } => bridge.clone(),
                    Network::Simple { iface, .. } => iface.clone(),
                    Network::Wan { iface, .. } => iface.clone(),
                };
                new_set.insert((iface, table_id));
            }
        }
    }
    let old_set = {
        let guard = INSTALLED_ZONE_RULES.lock().unwrap();
        guard.clone().unwrap_or_default()
    };
    // Delete stale.
    for (iface, table) in old_set.difference(&new_set) {
        let mut add_builder = handle
            .rule()
            .add()
            .v4()
            .input_interface(iface.clone())
            .table_id(*table)
            .priority(WAN_RULE_PRIORITY)
            .action(RuleAction::ToTable);
        let msg = add_builder.message_mut().clone();
        match handle.rule().del(msg).execute().await {
            Ok(()) => tracing::info!(%iface, table, "wan_routing: stale zone rule removed"),
            Err(e) if is_noent(&e) => {}
            Err(e) => {
                tracing::warn!(%iface, table, error = %e, "wan_routing: zone rule del failed")
            }
        }
    }
    // Install new.
    for (iface, table) in &new_set {
        let res = handle
            .rule()
            .add()
            .v4()
            .input_interface(iface.clone())
            .table_id(*table)
            .priority(WAN_RULE_PRIORITY)
            .action(RuleAction::ToTable)
            .execute()
            .await;
        match res {
            Ok(()) => tracing::info!(
                %iface, table,
                "wan_routing: zone iif rule installed"
            ),
            Err(e) if is_exists(&e) => {}
            Err(e) => return Err(Error::Rtnetlink(e)),
        }
    }
    *INSTALLED_ZONE_RULES.lock().unwrap() = Some(new_set);
    Ok(())
}

async fn ifindex(handle: &Handle, name: &str) -> Result<u32, Error> {
    let mut stream = handle.link().get().match_name(name.to_string()).execute();
    let msg = stream
        .try_next()
        .await
        .map_err(Error::Rtnetlink)?
        .ok_or_else(|| Error::LinkNotFound(name.to_string()))?;
    Ok(msg.header.index)
}

fn is_exists(e: &RtError) -> bool {
    let s = format!("{e}");
    s.contains("File exists") || s.contains("os error 17")
}

fn is_noent(e: &RtError) -> bool {
    let s = format!("{e}");
    s.contains("No such file or directory")
        || s.contains("os error 2")
        || s.contains("No such process")
        || s.contains("os error 3")
}
