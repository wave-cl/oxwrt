//! Policy routing for the client-side VPN feature.
//!
//! For each firewall zone flagged `via_vpn = true`, we install
//! `ip rule iif <zone_iface> lookup 51` — any forwarded packet
//! arriving on that iface uses routing table 51 for its next-hop
//! decision. Table 51's default points at the currently-active
//! vpn_client iface (set by the coordinator), with a blackhole
//! fallback at a worse metric so kill-switch stays in effect
//! when no profile is healthy.
//!
//! iif-based rules over fwmark-based:
//!   - Simpler. No nftables marking required; the routing
//!     decision happens at the kernel's routing layer where the
//!     iif is already known.
//!   - Correctness: fwmark stamped in a forward chain runs AFTER
//!     the routing decision is made, so the mark wouldn't affect
//!     routing at all. Would need a mangle/prerouting chain to
//!     work, which adds another chain + another hook.
//!   - LAN zones without via_vpn keep using the WAN default
//!     regardless of tunnel state — no split-tunnel config.
//!   - Router-originated traffic (output path) has no iif so
//!     these rules don't match. oxctl callbacks, sQUIC, NTP all
//!     stay on WAN.
//!
//! Ordering inside this module:
//!   - `install_policy_rules` + `install_table_51_blackhole` run
//!     on every reload and at boot. Each per-iface rule is
//!     idempotent (EEXIST tolerated). Stale rules from a
//!     previous via_vpn=true that's now false are currently NOT
//!     cleaned — operators changing that flag live should reboot
//!     for the cleanest result. Follow-up: track installed rules
//!     on ControlState and diff.
//!   - `set_table_51_default` + `clear_table_51_default` are called
//!     by the coordinator on active-profile change.
//!   - `install_endpoint_exemption` is called by the coordinator
//!     per-profile whenever the peer endpoint or the active WAN
//!     gateway changes. It prevents the handshake-traffic-through-
//!     the-tunnel recursion — the wg peer itself needs to be
//!     reached via WAN, not via the thing we're trying to bring up.

use std::net::Ipv4Addr;

use futures_util::stream::TryStreamExt;
use rtnetlink::packet_route::{
    route::{RouteAttribute, RouteType},
    rule::RuleAction,
};
use rtnetlink::{Error as RtError, Handle, RouteMessageBuilder};

use crate::net::Error;

/// Routing table that holds the VPN default route. Any table ID
/// 1..=2^31 not already in use works; 51 is far enough from the
/// reserved main (254) / local (255) / default (253) tables to
/// avoid confusion in `ip route show table all`.
pub const VPN_TABLE: u32 = 51;

/// Priority the iif rules sit at in the lookup order. Lower =
/// earlier. The default `main` lookup is at 32766; sitting at
/// 1000 means our iif rule runs first but still leaves headroom
/// for an operator to squeeze rules in front.
pub const VPN_RULE_PRIORITY: u32 = 1000;

/// Install one `ip rule iif <zone_iface> lookup 51` per iface of
/// a via_vpn firewall zone. Idempotent — duplicate adds are
/// tolerated (EEXIST). Safe to call on every reload because
/// adding a rule that already exists is a no-op.
///
/// Caveat: this function doesn't CLEAN UP rules for ifaces that
/// were via_vpn in the previous config and aren't anymore. Live-
/// toggling the flag off requires a reboot (the stale rule stays
/// until then, which is harmless because table 51 still has the
/// kill-switch blackhole so the worst case is "zone uses VPN
/// when it shouldn't"). Follow-up: track installed rules on
/// ControlState and diff on reload.
pub async fn install_policy_rules(
    handle: &Handle,
    via_vpn_ifaces: &[String],
) -> Result<(), Error> {
    for iface in via_vpn_ifaces {
        let res = handle
            .rule()
            .add()
            .v4()
            .input_interface(iface.clone())
            .table_id(VPN_TABLE)
            .priority(VPN_RULE_PRIORITY)
            .action(RuleAction::ToTable)
            .execute()
            .await;
        match res {
            Ok(()) => {
                tracing::info!(
                    iif = %iface,
                    table = VPN_TABLE,
                    priority = VPN_RULE_PRIORITY,
                    "vpn_routing: iif policy rule installed"
                );
            }
            Err(e) if is_exists(&e) => {
                tracing::debug!(iif = %iface, "vpn_routing: iif rule already present");
            }
            Err(e) => return Err(Error::Rtnetlink(e)),
        }
    }
    Ok(())
}

/// Plant the kill-switch fallback: a blackhole default in table
/// 51 at a high metric. When the coordinator installs a real
/// default (metric 0), the real route wins. When it clears the
/// real default, this one is still there and marked traffic gets
/// dropped instead of falling through to main (which would be
/// a WAN leak).
pub async fn install_table_51_blackhole(handle: &Handle) -> Result<(), Error> {
    let route = RouteMessageBuilder::<Ipv4Addr>::new()
        .destination_prefix(Ipv4Addr::UNSPECIFIED, 0)
        .table_id(VPN_TABLE)
        .priority(9999)
        .kind(RouteType::BlackHole)
        .build();
    match handle.route().add(route).execute().await {
        Ok(()) => {
            tracing::info!(table = VPN_TABLE, "vpn_routing: blackhole fallback installed");
            Ok(())
        }
        Err(e) if is_exists(&e) => Ok(()),
        Err(e) => Err(Error::Rtnetlink(e)),
    }
}

/// Set (or replace) table 51's primary default route to point at
/// the given VPN iface. Called by the coordinator on active-
/// profile change. Uses `.replace()` so the call is idempotent
/// across coordinator restarts — we don't have to track whether
/// a prior route exists.
pub async fn set_table_51_default(handle: &Handle, iface: &str) -> Result<(), Error> {
    let ifindex = ifindex(handle, iface).await?;
    let route = RouteMessageBuilder::<Ipv4Addr>::new()
        .destination_prefix(Ipv4Addr::UNSPECIFIED, 0)
        .output_interface(ifindex)
        .table_id(VPN_TABLE)
        .priority(0)
        .build();
    match handle.route().add(route).replace().execute().await {
        Ok(()) => {
            tracing::info!(iface, table = VPN_TABLE, "vpn_routing: default set");
            Ok(())
        }
        Err(e) => Err(Error::Rtnetlink(e)),
    }
}

/// Remove the non-blackhole default from table 51. Called by the
/// coordinator when no profile is healthy — the blackhole then
/// becomes the only default, and marked traffic is killswitched.
/// ENOENT is tolerated (we may not have installed one yet).
pub async fn clear_table_51_default(handle: &Handle) -> Result<(), Error> {
    // We don't have ifindex to match on when deleting; use the
    // destination + table + non-blackhole-kind combo. The kernel
    // matches by the header fields, not attributes, so a
    // build-with-default matches both "dev X" and "via Y" routes
    // at 0.0.0.0/0 in the table.
    let route = RouteMessageBuilder::<Ipv4Addr>::new()
        .destination_prefix(Ipv4Addr::UNSPECIFIED, 0)
        .table_id(VPN_TABLE)
        .priority(0)
        .build();
    match handle.route().del(route).execute().await {
        Ok(()) => {
            tracing::info!(table = VPN_TABLE, "vpn_routing: default cleared");
            Ok(())
        }
        Err(e) if is_noent(&e) => {
            tracing::debug!("vpn_routing: default already absent");
            Ok(())
        }
        Err(e) => Err(Error::Rtnetlink(e)),
    }
}

/// Install a /32 exemption for the VPN peer endpoint in the main
/// routing table. The handshake — which happens OVER WAN to
/// establish the tunnel — must not itself route through the
/// tunnel, or we'd loop infinitely the moment the wg iface comes
/// up. Without this, the first packet that tries to hit the
/// provider endpoint gets fwmarked (well, it wouldn't, since
/// router-originated traffic isn't marked; but `allowed_ips =
/// 0.0.0.0/0` on the wg iface would capture it anyway via the
/// kernel's WG source-routing). Explicit /32 via WAN is the
/// standard pattern from wg-quick(8).
///
/// Uses `.replace()` — if the endpoint or WAN gateway changes
/// (e.g. WAN failover), calling this again overwrites cleanly.
pub async fn install_endpoint_exemption(
    handle: &Handle,
    endpoint_ip: Ipv4Addr,
    wan_gw: Ipv4Addr,
    wan_iface: &str,
) -> Result<(), Error> {
    let ifindex = ifindex(handle, wan_iface).await?;
    let route = RouteMessageBuilder::<Ipv4Addr>::new()
        .destination_prefix(endpoint_ip, 32)
        .gateway(wan_gw)
        .output_interface(ifindex)
        .build();
    match handle.route().add(route).replace().execute().await {
        Ok(()) => {
            tracing::info!(
                %endpoint_ip, %wan_gw, wan_iface,
                "vpn_routing: endpoint exemption installed"
            );
            Ok(())
        }
        Err(e) => Err(Error::Rtnetlink(e)),
    }
}

/// Remove a previously-installed endpoint exemption. Used when a
/// profile is removed via reload — without cleanup, stale /32s
/// accumulate in the main table across CRUD cycles.
pub async fn remove_endpoint_exemption(
    handle: &Handle,
    endpoint_ip: Ipv4Addr,
) -> Result<(), Error> {
    let route = RouteMessageBuilder::<Ipv4Addr>::new()
        .destination_prefix(endpoint_ip, 32)
        .build();
    match handle.route().del(route).execute().await {
        Ok(()) => Ok(()),
        Err(e) if is_noent(&e) => Ok(()),
        Err(e) => Err(Error::Rtnetlink(e)),
    }
}

// ── internals ───────────────────────────────────────────────────

async fn ifindex(handle: &Handle, name: &str) -> Result<u32, Error> {
    let mut stream = handle
        .link()
        .get()
        .match_name(name.to_string())
        .execute();
    let msg = stream
        .try_next()
        .await
        .map_err(Error::Rtnetlink)?
        .ok_or_else(|| Error::LinkNotFound(name.to_string()))?;
    Ok(msg.header.index)
}

/// Best-effort check for NLE_EEXIST on the rtnetlink Error. The
/// error shape varies (sometimes Io, sometimes NetlinkError); we
/// match on any occurrence of the "File exists" / errno 17
/// substring so we don't have to chase every shape.
fn is_exists(e: &RtError) -> bool {
    let s = format!("{e}");
    s.contains("File exists") || s.contains("os error 17")
}

/// Same shape as is_exists but for ENOENT on delete.
fn is_noent(e: &RtError) -> bool {
    let s = format!("{e}");
    s.contains("No such file or directory")
        || s.contains("os error 2")
        || s.contains("No such process")
        || s.contains("os error 3")
}

// Silence unused-import warning on platforms where RouteAttribute
// isn't touched directly — kept in case future helpers need it.
#[allow(dead_code)]
fn _unused_route_attr_link() -> Option<RouteAttribute> {
    None
}
