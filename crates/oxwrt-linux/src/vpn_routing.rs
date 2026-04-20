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
//!     idempotent (EEXIST tolerated). Stale rules (from zones
//!     whose via_vpn just flipped false) are cleaned via the
//!     `INSTALLED_IIF_RULES` static: we diff the new iface set
//!     against the last-installed set and `del` the leftovers
//!     before adding new ones.
//!   - `set_table_51_default` + `clear_table_51_default` are called
//!     by the coordinator on active-profile change.
//!   - `install_endpoint_exemption` is called by the coordinator
//!     per-profile whenever the peer endpoint or the active WAN
//!     gateway changes. It prevents the handshake-traffic-through-
//!     the-tunnel recursion — the wg peer itself needs to be
//!     reached via WAN, not via the thing we're trying to bring up.

use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;

use futures_util::stream::TryStreamExt;
use rtnetlink::packet_route::{
    route::{RouteAttribute, RouteProtocol, RouteType},
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

/// Priority for `bypass_destinations` rules. Must be LOWER than
/// VPN_RULE_PRIORITY so dest-matched bypass rules evaluate first
/// (kernel rule order is ascending priority). A packet from a
/// via_vpn zone whose dest falls in the bypass list hits
/// `lookup main` here, finds the WAN default, egresses direct —
/// never reaches the iif rule.
pub const VPN_BYPASS_PRIORITY: u32 = 500;

/// Custom `rtm_protocol` value stamped on every endpoint /32
/// exemption this module installs. Picked from the unassigned
/// range (> named protocols in rtnetlink's RouteProtocol enum,
/// < 252 reserved range). Lets us identify our own stale routes
/// across reboots — `cleanup_stale_endpoint_exemptions` walks
/// the main table looking for this proto, deletes matches. See
/// `iana.org/assignments/rtnetlink-routing-protocols` for why
/// 155: nobody else claims it, and it's far enough from RTPROT_
/// named ones that a future kernel addition won't collide.
pub const VPN_ENDPOINT_PROTO: u8 = 155;

/// Set of ifaces we've installed `ip rule iif <iface> lookup 51`
/// for. Lets reload remove rules for zones that just toggled
/// via_vpn off. Static because `Net` is reconstructed on every
/// reload but the kernel's rtnetlink state persists; tracking on
/// ControlState would forget across the reload that spawns a
/// fresh coordinator.
static INSTALLED_IIF_RULES: Mutex<Option<HashSet<String>>> = Mutex::new(None);

/// Set of (dest_ip, prefix_len) bypass rules we've installed.
/// Same diff-on-reload pattern as INSTALLED_IIF_RULES.
static INSTALLED_BYPASS_RULES: Mutex<Option<HashSet<(Ipv4Addr, u8)>>> = Mutex::new(None);

/// v6 counterpart to INSTALLED_IIF_RULES. Populated only when
/// any vpn_client profile declares `address_v6` — no-op otherwise.
static INSTALLED_IIF_RULES_V6: Mutex<Option<HashSet<String>>> = Mutex::new(None);

/// v6 counterpart to INSTALLED_BYPASS_RULES. Tracked separately
/// because Ipv4Addr and Ipv6Addr aren't the same key type.
static INSTALLED_BYPASS_RULES_V6: Mutex<Option<HashSet<(Ipv6Addr, u8)>>> = Mutex::new(None);

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
pub async fn install_policy_rules(handle: &Handle, via_vpn_ifaces: &[String]) -> Result<(), Error> {
    // Diff against what we installed last time. Rules for ifaces
    // that were in the previous set but aren't in this one are
    // removed; rules for new ifaces are added. Rules that stay
    // are already in the kernel — EEXIST is the tell.
    let new_set: HashSet<String> = via_vpn_ifaces.iter().cloned().collect();
    let old_set = {
        let guard = INSTALLED_IIF_RULES.lock().unwrap();
        guard.clone().unwrap_or_default()
    };
    for iface in old_set.difference(&new_set) {
        // rtnetlink 0.20's RuleHandle::del takes a RuleMessage
        // directly (no builder). Easiest way to build a matching
        // one is to reuse RuleAddRequest as a construction helper
        // and pull its message_mut clone — same fields we'd have
        // emitted on add, so the kernel's match-by-attributes
        // finds the right rule.
        let mut add_builder = handle
            .rule()
            .add()
            .v4()
            .input_interface(iface.clone())
            .table_id(VPN_TABLE)
            .priority(VPN_RULE_PRIORITY)
            .action(RuleAction::ToTable);
        let msg = add_builder.message_mut().clone();
        let res = handle.rule().del(msg).execute().await;
        match res {
            Ok(()) => tracing::info!(iif = %iface, "vpn_routing: stale iif rule removed"),
            Err(e) if is_noent(&e) => {
                tracing::debug!(iif = %iface, "vpn_routing: iif rule already gone");
            }
            Err(e) => tracing::warn!(iif = %iface, error = %e, "vpn_routing: iif rule del failed"),
        }
    }
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
    // Track what's live now so the NEXT reload knows what to
    // diff against.
    *INSTALLED_IIF_RULES.lock().unwrap() = Some(new_set);
    Ok(())
}

/// Install `ip rule to <cidr> lookup main priority 500` for
/// every bypass-destination CIDR across the active vpn_client
/// set. At priority 500 (< VPN_RULE_PRIORITY 1000), these rules
/// match BEFORE the iif-based VPN rules, so a dest-matched
/// packet from a via_vpn zone routes direct via WAN.
///
/// Parses CIDR strings like "192.0.2.0/24" into (Ipv4Addr, u8).
/// Malformed entries log a warn and skip — an operator typo
/// shouldn't block the rest of the bypass list.
///
/// Diff-and-delete on reload: rules present in the previous set
/// but not the current one are removed first; new ones are then
/// added. Duplicate adds EEXIST-tolerated.
pub async fn install_bypass_rules(handle: &Handle, bypass_cidrs: &[String]) -> Result<(), Error> {
    let mut new_set: HashSet<(Ipv4Addr, u8)> = HashSet::new();
    for s in bypass_cidrs {
        match parse_cidr_v4(s) {
            Some(parsed) => {
                new_set.insert(parsed);
            }
            None => {
                tracing::warn!(cidr = %s, "vpn_routing: invalid bypass CIDR; skipped");
            }
        }
    }
    let old_set = {
        let guard = INSTALLED_BYPASS_RULES.lock().unwrap();
        guard.clone().unwrap_or_default()
    };
    // Delete stale.
    for (addr, prefix) in old_set.difference(&new_set) {
        let mut add_builder = handle
            .rule()
            .add()
            .v4()
            .destination_prefix(*addr, *prefix)
            .table_id(254) // RT_TABLE_MAIN — well-known, not in rtnetlink's pub consts
            .priority(VPN_BYPASS_PRIORITY)
            .action(RuleAction::ToTable);
        let msg = add_builder.message_mut().clone();
        match handle.rule().del(msg).execute().await {
            Ok(()) => tracing::info!(%addr, prefix, "vpn_routing: stale bypass rule removed"),
            Err(e) if is_noent(&e) => {}
            Err(e) => tracing::warn!(%addr, prefix, error = %e, "vpn_routing: bypass del failed"),
        }
    }
    // Install new.
    for (addr, prefix) in &new_set {
        let res = handle
            .rule()
            .add()
            .v4()
            .destination_prefix(*addr, *prefix)
            .table_id(254) // RT_TABLE_MAIN — well-known, not in rtnetlink's pub consts
            .priority(VPN_BYPASS_PRIORITY)
            .action(RuleAction::ToTable)
            .execute()
            .await;
        match res {
            Ok(()) => tracing::info!(
                %addr, prefix,
                "vpn_routing: bypass rule installed"
            ),
            Err(e) if is_exists(&e) => {
                tracing::debug!(%addr, prefix, "vpn_routing: bypass rule already present");
            }
            Err(e) => return Err(Error::Rtnetlink(e)),
        }
    }
    *INSTALLED_BYPASS_RULES.lock().unwrap() = Some(new_set);
    Ok(())
}

fn parse_cidr_v4(s: &str) -> Option<(Ipv4Addr, u8)> {
    let (ip_str, prefix_str) = s.split_once('/')?;
    let ip: Ipv4Addr = ip_str.parse().ok()?;
    let prefix: u8 = prefix_str.parse().ok()?;
    if prefix > 32 {
        return None;
    }
    Some((ip, prefix))
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
            tracing::info!(
                table = VPN_TABLE,
                "vpn_routing: blackhole fallback installed"
            );
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
    // Stamp with VPN_ENDPOINT_PROTO so cleanup_stale_endpoint_exemptions
    // can find + del these across reboots (coordinator state is
    // per-process; without the marker, a crashed oxwrtd would
    // leave /32s in the main table that the new oxwrtd has no
    // record of).
    let route = RouteMessageBuilder::<Ipv4Addr>::new()
        .destination_prefix(endpoint_ip, 32)
        .gateway(wan_gw)
        .output_interface(ifindex)
        .protocol(RouteProtocol::Other(VPN_ENDPOINT_PROTO))
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

/// Walk the main table, delete any route whose rtm_protocol
/// matches VPN_ENDPOINT_PROTO. Called once at boot before the
/// coordinator spawns — on a clean boot it's a no-op, on a post-
/// reboot boot it reaps /32s left by the previous oxwrtd process.
///
/// The walk uses handle.route().get() with an empty message,
/// which rtnetlink 0.20 turns into NLM_F_DUMP (all routes).
/// Errors on individual dels are logged + skipped — the whole
/// cleanup is best-effort; a single stuck route shouldn't block
/// the rest.
pub async fn cleanup_stale_endpoint_exemptions(handle: &Handle) -> Result<(), Error> {
    let msg = RouteMessageBuilder::<Ipv4Addr>::new().build();
    let mut stream = handle.route().get(msg).execute();
    let mut stale: Vec<rtnetlink::packet_route::route::RouteMessage> = Vec::new();
    while let Some(r) = stream.try_next().await.map_err(Error::Rtnetlink)? {
        // RouteProtocol::Other(v) → v; named variants → kernel
        // numeric value. We match the raw u8 to dodge the enum
        // conversion asymmetry (Other(155) vs some future named
        // variant claiming 155).
        let proto_raw: u8 = r.header.protocol.into();
        if proto_raw == VPN_ENDPOINT_PROTO {
            stale.push(r);
        }
    }
    let n = stale.len();
    for r in stale {
        // Extract the destination + prefix for the log; the
        // RouteMessage itself is what we hand to del.
        let dst: Option<String> = r.attributes.iter().find_map(|a| match a {
            RouteAttribute::Destination(ra) => Some(format!("{ra:?}")),
            _ => None,
        });
        match handle.route().del(r).execute().await {
            Ok(()) => {
                tracing::info!(
                    dst = dst.as_deref().unwrap_or("?"),
                    "vpn_routing: stale endpoint exemption removed"
                );
            }
            Err(e) => {
                tracing::warn!(
                    dst = dst.as_deref().unwrap_or("?"),
                    error = %e,
                    "vpn_routing: stale exemption del failed"
                );
            }
        }
    }
    if n > 0 {
        tracing::info!(count = n, "vpn_routing: endpoint-exemption cleanup done");
    }
    Ok(())
}

/// Install TCP MSS clamp on the WAN forward path so wg-over-UDP
/// packets don't exceed the WAN MTU and get fragmented. OpenWrt's
/// firewall4 does this by default; we need it explicitly because
/// our rustables-managed `oxwrt` table doesn't have exthdr
/// expression support for setting maxseg.
///
/// Shelled out to `nft -f -` against a dedicated `oxwrt-mss`
/// table so the rustables batch in `install_firewall` doesn't
/// clobber it. Idempotent via `delete table; add table`.
///
/// Clamps to `rt mtu` (PMTU) rather than a hardcoded 1380 — the
/// kernel derives the right value per-flow from the outgoing
/// iface's MTU. If an operator sets `mtu = 1380` on a VPN
/// profile because their ISP uses PPPoE + some extra overhead,
/// this clamp adjusts automatically.
pub fn install_mss_clamp(wan_iface: &str) -> Result<(), Error> {
    use std::io::Write as _;
    use std::process::{Command, Stdio};

    let script = format!(
        "table inet oxwrt-mss {{\n\
             chain forward {{\n\
                 type filter hook forward priority mangle; policy accept;\n\
                 oifname \"{w}\" tcp flags syn tcp option maxseg size set rt mtu\n\
                 iifname \"{w}\" tcp flags syn tcp option maxseg size set rt mtu\n\
             }}\n\
         }}\n",
        w = wan_iface
    );
    // delete then add ensures idempotency; the delete swallows
    // "No such file or directory" if the table doesn't exist yet.
    let _ = Command::new("nft")
        .args(["delete", "table", "inet", "oxwrt-mss"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| Error::Firewall(format!("nft spawn: {e}")))?;
    if let Some(stdin) = child.stdin.as_mut() {
        stdin
            .write_all(script.as_bytes())
            .map_err(|e| Error::Firewall(format!("nft stdin: {e}")))?;
    }
    let out = child
        .wait_with_output()
        .map_err(|e| Error::Firewall(format!("nft wait: {e}")))?;
    if !out.status.success() {
        return Err(Error::Firewall(format!(
            "nft add oxwrt-mss: exit {:?}: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    tracing::info!(wan_iface, "vpn_routing: MSS clamp installed");
    Ok(())
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
    let mut stream = handle.link().get().match_name(name.to_string()).execute();
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

// ── IPv6 variants ────────────────────────────────────────────────
//
// Mirror the v4 functions for v6 — same semantics, different
// address family. Kept in this module (not a separate file)
// because the kernel objects they manipulate are twins; splitting
// would force two parallel `use` trees and make cross-referencing
// noisier.

/// v6 counterpart to install_policy_rules. Rule shape is
/// identical except `.v6()` and no fwmark (we still bind by iif).
pub async fn install_policy_rules_v6(
    handle: &Handle,
    via_vpn_ifaces: &[String],
) -> Result<(), Error> {
    let new_set: HashSet<String> = via_vpn_ifaces.iter().cloned().collect();
    let old_set = {
        let guard = INSTALLED_IIF_RULES_V6.lock().unwrap();
        guard.clone().unwrap_or_default()
    };
    for iface in old_set.difference(&new_set) {
        let mut add_builder = handle
            .rule()
            .add()
            .v6()
            .input_interface(iface.clone())
            .table_id(VPN_TABLE)
            .priority(VPN_RULE_PRIORITY)
            .action(RuleAction::ToTable);
        let msg = add_builder.message_mut().clone();
        match handle.rule().del(msg).execute().await {
            Ok(()) => tracing::info!(iif = %iface, "vpn_routing: stale v6 iif rule removed"),
            Err(e) if is_noent(&e) => {}
            Err(e) => {
                tracing::warn!(iif = %iface, error = %e, "vpn_routing: v6 iif rule del failed")
            }
        }
    }
    for iface in via_vpn_ifaces {
        let res = handle
            .rule()
            .add()
            .v6()
            .input_interface(iface.clone())
            .table_id(VPN_TABLE)
            .priority(VPN_RULE_PRIORITY)
            .action(RuleAction::ToTable)
            .execute()
            .await;
        match res {
            Ok(()) => tracing::info!(iif = %iface, "vpn_routing: v6 iif policy rule installed"),
            Err(e) if is_exists(&e) => {}
            Err(e) => return Err(Error::Rtnetlink(e)),
        }
    }
    *INSTALLED_IIF_RULES_V6.lock().unwrap() = Some(new_set);
    Ok(())
}

/// v6 blackhole in table 51. Metric 9999 so the coordinator's
/// real v6 default beats it when installed.
pub async fn install_table_51_blackhole_v6(handle: &Handle) -> Result<(), Error> {
    let route = RouteMessageBuilder::<Ipv6Addr>::new()
        .destination_prefix(Ipv6Addr::UNSPECIFIED, 0)
        .table_id(VPN_TABLE)
        .priority(9999)
        .kind(RouteType::BlackHole)
        .build();
    match handle.route().add(route).execute().await {
        Ok(()) => {
            tracing::info!(table = VPN_TABLE, "vpn_routing: v6 blackhole installed");
            Ok(())
        }
        Err(e) if is_exists(&e) => Ok(()),
        Err(e) => Err(Error::Rtnetlink(e)),
    }
}

/// Set (or replace) table 51's v6 default to point at `iface`.
/// Called by the coordinator when the active profile has a
/// v6 tunnel address.
pub async fn set_table_51_default_v6(handle: &Handle, iface: &str) -> Result<(), Error> {
    let ifindex = ifindex(handle, iface).await?;
    let route = RouteMessageBuilder::<Ipv6Addr>::new()
        .destination_prefix(Ipv6Addr::UNSPECIFIED, 0)
        .output_interface(ifindex)
        .table_id(VPN_TABLE)
        .priority(0)
        .build();
    match handle.route().add(route).replace().execute().await {
        Ok(()) => {
            tracing::info!(iface, table = VPN_TABLE, "vpn_routing: v6 default set");
            Ok(())
        }
        Err(e) => Err(Error::Rtnetlink(e)),
    }
}

/// Remove the non-blackhole v6 default from table 51. Killswitch
/// transition: coordinator clears both v4 and v6 defaults so
/// marked traffic is kill-switched for both families.
pub async fn clear_table_51_default_v6(handle: &Handle) -> Result<(), Error> {
    let route = RouteMessageBuilder::<Ipv6Addr>::new()
        .destination_prefix(Ipv6Addr::UNSPECIFIED, 0)
        .table_id(VPN_TABLE)
        .priority(0)
        .build();
    match handle.route().del(route).execute().await {
        Ok(()) => Ok(()),
        Err(e) if is_noent(&e) => Ok(()),
        Err(e) => Err(Error::Rtnetlink(e)),
    }
}

/// v6 counterpart to install_bypass_rules. Same diff + apply
/// pattern; rules install as `ip -6 rule to <cidr> lookup main
/// priority 500`. Malformed CIDRs log + skip.
pub async fn install_bypass_rules_v6(
    handle: &Handle,
    bypass_cidrs: &[String],
) -> Result<(), Error> {
    let mut new_set: HashSet<(Ipv6Addr, u8)> = HashSet::new();
    for s in bypass_cidrs {
        match parse_cidr_v6(s) {
            Some(parsed) => {
                new_set.insert(parsed);
            }
            None => {
                tracing::warn!(cidr = %s, "vpn_routing: invalid v6 bypass CIDR; skipped");
            }
        }
    }
    let old_set = {
        let guard = INSTALLED_BYPASS_RULES_V6.lock().unwrap();
        guard.clone().unwrap_or_default()
    };
    for (addr, prefix) in old_set.difference(&new_set) {
        let mut add_builder = handle
            .rule()
            .add()
            .v6()
            .destination_prefix(*addr, *prefix)
            .table_id(254) // RT_TABLE_MAIN
            .priority(VPN_BYPASS_PRIORITY)
            .action(RuleAction::ToTable);
        let msg = add_builder.message_mut().clone();
        match handle.rule().del(msg).execute().await {
            Ok(()) => tracing::info!(%addr, prefix, "vpn_routing: stale v6 bypass rule removed"),
            Err(e) if is_noent(&e) => {}
            Err(e) => {
                tracing::warn!(%addr, prefix, error = %e, "vpn_routing: v6 bypass del failed");
            }
        }
    }
    for (addr, prefix) in &new_set {
        let res = handle
            .rule()
            .add()
            .v6()
            .destination_prefix(*addr, *prefix)
            .table_id(254)
            .priority(VPN_BYPASS_PRIORITY)
            .action(RuleAction::ToTable)
            .execute()
            .await;
        match res {
            Ok(()) => tracing::info!(%addr, prefix, "vpn_routing: v6 bypass rule installed"),
            Err(e) if is_exists(&e) => {}
            Err(e) => return Err(Error::Rtnetlink(e)),
        }
    }
    *INSTALLED_BYPASS_RULES_V6.lock().unwrap() = Some(new_set);
    Ok(())
}

fn parse_cidr_v6(s: &str) -> Option<(Ipv6Addr, u8)> {
    let (ip_str, prefix_str) = s.split_once('/')?;
    let ip: Ipv6Addr = ip_str.parse().ok()?;
    let prefix: u8 = prefix_str.parse().ok()?;
    if prefix > 128 {
        return None;
    }
    Some((ip, prefix))
}
