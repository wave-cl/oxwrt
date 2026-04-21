//! Pure validation helpers used by the CRUD handlers.
//!
//! Split out of `server` because `server` is gated to
//! `target_os = "linux"` (it calls netlink, mount, seccomp, etc.) and
//! these helpers are platform-agnostic — pure functions of
//! `config::Config` and the candidate item. Keeping them here lets
//! `cargo test` exercise them on the developer's workstation without
//! cross-compiling the rest of the control plane.
//!
//! Two families:
//!
//! - `check_*_refs(item, cfg) -> Result<(), String>`: run on Add/Update
//!   to refuse mutations that would introduce a dangling reference
//!   (zone → unknown network, wifi → unknown radio, etc.). Error messages
//!   name both the item and the bad ref so the operator can fix the
//!   input without re-reading the config.
//!
//! - `dependents_on_*(name, cfg) -> Vec<String>`: run on Remove to
//!   enumerate the things that would be left with a dangling reference
//!   if the target were dropped. Empty list → the remove is safe.
//!   Non-empty list → the caller builds an "X is referenced by: A, B, C"
//!   error so the operator knows what to unwire first.
//!
//! The checks are intentionally shallow — they catch typos and obvious
//! ordering mistakes. Deeper semantic validation (DAG-free zone graph,
//! coherent firewall intent) is left to `reload` when it actually
//! tries to install the new state.

use crate::config::{Config, NetMode, Network, Rule, Service, Wifi, Zone};

/// Validate VLAN consistency across all networks. A Simple network
/// with `vlan` set must also set `vlan_parent` — we refuse to infer
/// the parent from the iface name (too magical, and the dot
/// convention isn't universal). A `vlan_parent` without `vlan` is
/// also rejected so a typo doesn't silently degrade to "untagged
/// iface named x.10".
pub fn check_vlan_consistency(cfg: &Config) -> Result<(), String> {
    for net in &cfg.networks {
        if let Network::Simple {
            name,
            vlan,
            vlan_parent,
            ..
        } = net
        {
            match (vlan, vlan_parent) {
                (Some(id), _) if *id == 0 || *id > 4094 => {
                    return Err(format!(
                        "network {name}: vlan id {id} out of range (must be 1..=4094)"
                    ));
                }
                (Some(_), None) => {
                    return Err(format!(
                        "network {name}: `vlan` set without `vlan_parent`; \
                         specify the parent iface explicitly"
                    ));
                }
                (None, Some(_)) => {
                    return Err(format!(
                        "network {name}: `vlan_parent` set without `vlan`; \
                         remove the parent or add a vlan id"
                    ));
                }
                _ => {}
            }
        }
    }
    Ok(())
}

/// Validate every `[[ipsets]]` entry. Catches:
/// - duplicate names (nft would fail the whole batch on the second
///   `add set` with a "File exists" error)
/// - `family = "any"` (nft sets are single-family; no `any` option)
/// - malformed entries (wrong family, unparseable CIDR/address)
/// - CIDR prefix > address width
///
/// Called once per reload, not per CRUD op on sets (we don't have
/// per-entry CRUD for ipsets yet — they're edited via `Set` RPC on
/// the full config). The list is expected to be short (dozens at
/// most), so O(n²) dup-check is fine.
pub fn check_ipsets(cfg: &Config) -> Result<(), String> {
    use oxwrt_api::config::Family;
    let mut seen = std::collections::HashSet::new();
    for set in &cfg.ipsets {
        if set.name.trim().is_empty() {
            return Err("ipset: name must not be empty".to_string());
        }
        if !seen.insert(&set.name) {
            return Err(format!("ipset {}: duplicate name", set.name));
        }
        if set.family == Family::Any {
            return Err(format!(
                "ipset {}: family must be ipv4 or ipv6 (got any)",
                set.name
            ));
        }
        for entry in &set.entries {
            let (addr_str, prefix_str) = match entry.split_once('/') {
                Some((a, p)) => (a, Some(p)),
                None => (entry.as_str(), None),
            };
            match set.family {
                Family::Ipv4 => {
                    let _: std::net::Ipv4Addr = addr_str.parse().map_err(|_| {
                        format!("ipset {}: invalid ipv4 entry {:?}", set.name, entry)
                    })?;
                    if let Some(p) = prefix_str {
                        let p: u8 = p.parse().map_err(|_| {
                            format!("ipset {}: invalid prefix in {:?}", set.name, entry)
                        })?;
                        if p > 32 {
                            return Err(format!(
                                "ipset {}: prefix {p} out of range for ipv4 in {:?}",
                                set.name, entry
                            ));
                        }
                    }
                }
                Family::Ipv6 => {
                    let _: std::net::Ipv6Addr = addr_str.parse().map_err(|_| {
                        format!("ipset {}: invalid ipv6 entry {:?}", set.name, entry)
                    })?;
                    if let Some(p) = prefix_str {
                        let p: u8 = p.parse().map_err(|_| {
                            format!("ipset {}: invalid prefix in {:?}", set.name, entry)
                        })?;
                        if p > 128 {
                            return Err(format!(
                                "ipset {}: prefix {p} out of range for ipv6 in {:?}",
                                set.name, entry
                            ));
                        }
                    }
                }
                Family::Any => unreachable!(),
            }
        }
    }
    Ok(())
}

pub fn check_zone_network_refs(zone: &Zone, cfg: &Config) -> Result<(), String> {
    for net in &zone.networks {
        if !cfg.networks.iter().any(|n| n.name() == net) {
            return Err(format!(
                "zone {} references unknown network: {net}",
                zone.name
            ));
        }
    }
    Ok(())
}

pub fn check_rule_zone_refs(rule: &Rule, cfg: &Config) -> Result<(), String> {
    // Name: operators will scroll through the CRUD list by name,
    // and it shows up verbatim in error messages. An empty name
    // makes every follow-up message ambiguous.
    if rule.name.trim().is_empty() {
        return Err("rule: name must not be empty".to_string());
    }

    // Zone refs: src and dest must exist in firewall.zones when set.
    if let Some(src) = &rule.src {
        if !cfg.firewall.zones.iter().any(|z| z.name == *src) {
            return Err(format!(
                "rule {} references unknown src zone: {src}",
                rule.name
            ));
        }
    }
    if let Some(dest) = &rule.dest {
        if !cfg.firewall.zones.iter().any(|z| z.name == *dest) {
            return Err(format!(
                "rule {} references unknown dest zone: {dest}",
                rule.name
            ));
        }
    }

    // Action + dnat_target consistency: DNAT requires a target;
    // any other action with a target set is almost certainly a
    // confused operator who means to use action=dnat. Reject with
    // a specific message pointing at the fix.
    use crate::config::{Action, Proto};
    match rule.action {
        Action::Dnat => {
            let target = rule.dnat_target.as_deref().ok_or_else(|| {
                format!(
                    "rule {}: action=dnat requires dnat_target (e.g. \"10.0.0.5:8080\")",
                    rule.name
                )
            })?;
            let (ip, port) = target.rsplit_once(':').ok_or_else(|| {
                format!(
                    "rule {}: dnat_target {:?} is not ip:port",
                    rule.name, target
                )
            })?;
            let _: std::net::Ipv4Addr = ip
                .parse()
                .map_err(|_| format!("rule {}: dnat_target IP {:?} invalid", rule.name, ip))?;
            let _: u16 = port
                .parse()
                .map_err(|_| format!("rule {}: dnat_target port {:?} invalid", rule.name, port))?;
        }
        _ => {
            if rule.dnat_target.is_some() {
                return Err(format!(
                    "rule {}: dnat_target is only valid with action=dnat (got action={:?})",
                    rule.name, rule.action
                ));
            }
        }
    }

    // proto=icmp + dest_port is nonsensical (ICMP has no ports).
    // Catches operators copying a TCP rule and flipping proto.
    if rule.proto == Some(Proto::Icmp) && rule.dest_port.is_some() {
        return Err(format!(
            "rule {}: proto=icmp cannot have dest_port (ICMP has no port field)",
            rule.name
        ));
    }

    // Port-range strings: validate at reload time so a typo like
    // "22--80" or "22-abc" fails here rather than as an nft parse
    // error deep in the install phase (where the whole ruleset
    // rejects and the operator loses context). Applies to both
    // src_port and dest_port.
    use oxwrt_api::config::PortSpec;
    for (which, spec) in [("dest_port", &rule.dest_port), ("src_port", &rule.src_port)] {
        if let Some(PortSpec::Range(s)) = spec {
            PortSpec::parse_range(s).map_err(|e| format!("rule {}: {which}: {e}", rule.name))?;
        }
    }

    // Schedule must parse if set. Catches typos before reload
    // puts the rule in front of the kernel.
    if let Some(sched) = rule.schedule.as_deref() {
        oxwrt_api::firewall_schedule::parse_schedule(sched)
            .map_err(|e| format!("rule {}: schedule: {e}", rule.name))?;
    }

    // reject_with only makes sense with action=reject. On any
    // other action it's either a paste bug or a confused
    // operator; reject cleanly instead of silently ignoring.
    if rule.reject_with.is_some() && rule.action != Action::Reject {
        return Err(format!(
            "rule {}: reject_with is only valid with action=reject (got action={:?})",
            rule.name, rule.action
        ));
    }
    // limit_burst without limit is nft-syntactically valid (it
    // would default the rate, which isn't what the operator
    // meant to say). Treat as operator error.
    if rule.limit_burst.is_some() && rule.limit.is_none() {
        return Err(format!(
            "rule {}: limit_burst requires `limit` to also be set",
            rule.name
        ));
    }
    // device must be non-empty when present. Empty renders as
    // `iifname ""` which nft rejects.
    if let Some(dev) = rule.device.as_deref() {
        if dev.trim().is_empty() {
            return Err(format!("rule {}: device must not be empty", rule.name));
        }
    }

    // match_set must name an existing [[ipsets]] entry. Family
    // mismatches would surface as an nft parse error at install
    // time ("type ipv4_addr can't match ip6 saddr") — catching them
    // here keeps the reload transaction honest.
    if let Some(ms) = rule.match_set.as_ref() {
        use oxwrt_api::config::Family;
        let Some(set) = cfg.ipsets.iter().find(|s| s.name == ms.name) else {
            return Err(format!(
                "rule {}: match_set references unknown ipset: {}",
                rule.name, ms.name
            ));
        };
        if set.family == Family::Any {
            return Err(format!(
                "rule {}: match_set target ipset {} has family=any (must be ipv4 or ipv6)",
                rule.name, ms.name
            ));
        }
        // If the rule pins a family, it must match the set's family.
        if rule.family != Family::Any && rule.family != set.family {
            return Err(format!(
                "rule {}: family={:?} conflicts with ipset {} (family={:?})",
                rule.name, rule.family, ms.name, set.family
            ));
        }
    }

    Ok(())
}

/// Validate a `[[firewall.forwardings]]` entry: both zones must
/// exist, they must differ (self-forward is a no-op and usually
/// a typo — reject so the operator notices), and the src/dest
/// zones must have at least one resolvable iface each (otherwise
/// the install-time loop silently drops the forwarding with a
/// warn and the operator doesn't understand why LAN→WAN stopped
/// working).
pub fn check_forwarding(fwd: &oxwrt_api::config::Forwarding, cfg: &Config) -> Result<(), String> {
    if !cfg.firewall.zones.iter().any(|z| z.name == fwd.src) {
        return Err(format!(
            "forwarding {}→{}: unknown src zone",
            fwd.src, fwd.dest
        ));
    }
    if !cfg.firewall.zones.iter().any(|z| z.name == fwd.dest) {
        return Err(format!(
            "forwarding {}→{}: unknown dest zone",
            fwd.src, fwd.dest
        ));
    }
    if fwd.src == fwd.dest {
        return Err(format!(
            "forwarding {}→{}: src and dest are the same (self-forward is a no-op)",
            fwd.src, fwd.dest
        ));
    }
    Ok(())
}

pub fn check_port_forward(pf: &crate::config::PortForward, cfg: &Config) -> Result<(), String> {
    // Source zone must exist. We don't default to "wan" silently
    // here — the config field defaulted when parsed; by the time
    // validation runs `src` is populated.
    if !cfg.firewall.zones.iter().any(|z| z.name == pf.src) {
        return Err(format!(
            "port-forward {} references unknown src zone: {}",
            pf.name, pf.src
        ));
    }
    // Dest zone, if explicit, must exist.
    if let Some(dest) = &pf.dest {
        if !cfg.firewall.zones.iter().any(|z| z.name == *dest) {
            return Err(format!(
                "port-forward {} references unknown dest zone: {dest}",
                pf.name
            ));
        }
    }
    // Internal target must parse as `ip:port` or `[v6]:port`.
    // We defer to `SocketAddr::from_str` which accepts both shapes
    // — same parser the installer uses, so validation can't drift
    // from install.
    let sa: std::net::SocketAddr = pf.internal.parse().map_err(|_| {
        format!(
            "port-forward {}: internal must be 'ip:port' or '[ipv6]:port' (got {:?})",
            pf.name, pf.internal
        )
    })?;
    // If dest zone is auto-detected (not provided), a LAN/Simple
    // network must contain the internal IP — otherwise install
    // can't emit the companion FORWARD rule. Same rule applies to
    // both families; we branch only on which subnet predicate to
    // use (v4 prefix vs v6 prefix).
    if pf.dest.is_none() {
        let hit = match sa.ip() {
            std::net::IpAddr::V4(v4) => cfg.networks.iter().any(|n| {
                use crate::config::Network;
                match n {
                    Network::Lan {
                        address, prefix, ..
                    }
                    | Network::Simple {
                        address, prefix, ..
                    } => ipv4_in_subnet(v4, *address, *prefix),
                    Network::Wan { .. } => false,
                }
            }),
            std::net::IpAddr::V6(v6) => cfg.networks.iter().any(|n| {
                use crate::config::Network;
                match n {
                    Network::Lan {
                        ipv6_address,
                        ipv6_prefix,
                        ..
                    }
                    | Network::Simple {
                        ipv6_address,
                        ipv6_prefix,
                        ..
                    } => match ipv6_address {
                        Some(addr) => ipv6_in_subnet(v6, *addr, ipv6_prefix.unwrap_or(64)),
                        None => false,
                    },
                    Network::Wan { .. } => false,
                }
            }),
        };
        if !hit {
            return Err(format!(
                "port-forward {}: internal IP {} is not in any LAN/Simple subnet; set `dest` explicitly",
                pf.name,
                sa.ip(),
            ));
        }
    }
    Ok(())
}

fn ipv6_in_subnet(ip: std::net::Ipv6Addr, subnet: std::net::Ipv6Addr, prefix: u8) -> bool {
    if prefix > 128 {
        return false;
    }
    if prefix == 0 {
        return true;
    }
    let ip_bits = u128::from(ip);
    let sn_bits = u128::from(subnet);
    let mask: u128 = u128::MAX.checked_shl(128 - prefix as u32).unwrap_or(0);
    (ip_bits & mask) == (sn_bits & mask)
}

fn ipv4_in_subnet(ip: std::net::Ipv4Addr, subnet: std::net::Ipv4Addr, prefix: u8) -> bool {
    if prefix > 32 {
        return false;
    }
    if prefix == 0 {
        return true;
    }
    let mask: u32 = u32::MAX.checked_shl(32 - prefix as u32).unwrap_or(0);
    (u32::from(ip) & mask) == (u32::from(subnet) & mask)
}

/// Cross-field consistency on a [[services]] entry. Checks:
///
/// 1. `net_mode = "isolated"` without a `veth` block → the service
///    spawns in a fresh netns with no network path at all. Almost
///    never what the operator wants; refuse at validate time.
/// 2. `net_mode = "host"` with a `veth` block → the veth is
///    allocated but unused (the service sits on the host netns).
///    Harmless but wasteful; refuse so the operator notices.
/// 3. `depends_on` entries must name a real service. A typo here
///    silently skips the auto-forward rule at firewall-install time.
/// 4. A service that lists a `depends_on` peer but the peer has no
///    `veth` configured — the implicit forward rule can't route
///    anywhere. Refuse so the failure surfaces at reload, not at
///    first RPC that tries to hit the peer.
///
/// Called from CRUD Add/Update on services and (future) from a
/// reload preflight that iterates every service.
pub fn check_service(svc: &Service, cfg: &Config) -> Result<(), String> {
    match svc.net_mode {
        NetMode::Isolated if svc.veth.is_none() => {
            return Err(format!(
                "service {}: net_mode = \"isolated\" requires a [services.veth] block \
                 (host_ip / peer_ip / prefix); otherwise the service has no network path",
                svc.name
            ));
        }
        NetMode::Host if svc.veth.is_some() => {
            return Err(format!(
                "service {}: [services.veth] is set but net_mode = \"host\" — the veth \
                 would be allocated and unused. Set net_mode = \"isolated\" or drop the \
                 veth block",
                svc.name
            ));
        }
        _ => {}
    }
    for dep in &svc.depends_on {
        let Some(peer) = cfg.services.iter().find(|s| &s.name == dep) else {
            return Err(format!(
                "service {}: depends_on references unknown service: {}",
                svc.name, dep
            ));
        };
        if peer.veth.is_none() {
            return Err(format!(
                "service {}: depends_on peer {} has no veth, so the auto-forward rule \
                 {} → {} can't be installed",
                svc.name, peer.name, svc.name, peer.name
            ));
        }
    }
    Ok(())
}

pub fn check_wifi_refs(wifi: &Wifi, cfg: &Config) -> Result<(), String> {
    if !cfg.radios.iter().any(|r| r.phy == wifi.radio) {
        return Err(format!(
            "wifi {} references unknown radio phy: {}",
            wifi.ssid, wifi.radio
        ));
    }
    if !cfg.networks.iter().any(|n| n.name() == wifi.network) {
        return Err(format!(
            "wifi {} references unknown network: {}",
            wifi.ssid, wifi.network
        ));
    }
    Ok(())
}

pub fn dependents_on_network(name: &str, cfg: &Config) -> Vec<String> {
    let mut out = Vec::new();
    for z in &cfg.firewall.zones {
        if z.networks.iter().any(|n| n == name) {
            out.push(format!("zone {}", z.name));
        }
    }
    for w in &cfg.wifi {
        if w.network == name {
            out.push(format!("wifi {}", w.ssid));
        }
    }
    out
}

pub fn dependents_on_zone(name: &str, cfg: &Config) -> Vec<String> {
    cfg.firewall
        .rules
        .iter()
        .filter(|r| r.src.as_deref() == Some(name) || r.dest.as_deref() == Some(name))
        .map(|r| format!("rule {}", r.name))
        .collect()
}

pub fn dependents_on_radio(phy: &str, cfg: &Config) -> Vec<String> {
    cfg.wifi
        .iter()
        .filter(|w| w.radio == phy)
        .map(|w| format!("wifi {}", w.ssid))
        .collect()
}

/// Shallow merge of top-level object fields. Used by the CRUD `Update`
/// action to apply a partial JSON patch on top of an existing item:
/// the operator sends only the fields they want changed, the handler
/// serializes the existing item to a `Value`, calls this, and
/// deserializes back to the typed struct.
///
/// Intentionally shallow: a nested object in the patch replaces the
/// nested object in the base wholesale. Callers that want to preserve
/// sub-fields must send the full nested object. This matches the
/// RFC 7396 merge-patch semantics for the cases we use it for, and
/// keeps behavior predictable (no "did my nested field get deep-merged
/// or replaced?" ambiguity).
///
/// No-op if either side isn't an object. Our callers always pass
/// struct-serialized values which produce objects, but defending
/// against surprises is cheap.
pub fn json_merge(base: &mut serde_json::Value, patch: &serde_json::Value) {
    if let (Some(base_obj), Some(patch_obj)) = (base.as_object_mut(), patch.as_object()) {
        for (k, v) in patch_obj {
            base_obj.insert(k.clone(), v.clone());
        }
    }
}

/// Service-update variant of [`json_merge`] with special-cased
/// deep-merging of the `security` subfield.
///
/// Why: caught a real footgun during the 2026-04-20 pid-namespace
/// rollout. Operators sending `{"security":{"pid_namespace":true}}`
/// as a "just flip this one bit" update had the whole security
/// block replaced with that single field. Since `SecurityProfile`
/// uses `#[serde(default)]` on every field, the missing ones got
/// silently reset to defaults — wiping `caps: [SYS_TIME]` etc.
/// Services then crashed with cryptic EPERMs on syscalls that
/// looked like the new sandboxing was broken.
///
/// Fix: if both sides carry a `security` object, pre-merge the
/// partial onto the existing security subtree so the top-level
/// merge sees a complete security block. Every other field keeps
/// the documented shallow-replace semantics — only `security`
/// gets this two-level treatment, because it's the only field
/// that's commonly partially-updated and whose default values
/// are subtly destructive.
pub fn json_merge_service_update(
    existing: &mut serde_json::Value,
    partial: &mut serde_json::Value,
) {
    if let (Some(existing_sec), Some(partial_sec)) = (
        existing.get("security").cloned(),
        partial.get_mut("security"),
    ) {
        let mut merged_sec = existing_sec;
        json_merge(&mut merged_sec, partial_sec);
        *partial_sec = merged_sec;
    }
    json_merge(existing, partial);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        Action, ChainPolicy, Config, Control, Firewall, Network, Radio, Rule, Service, Wifi,
        WifiSecurity, Zone,
    };
    use serde_json::json;
    use std::collections::BTreeMap;
    use std::net::Ipv4Addr;
    use std::path::PathBuf;

    /// Build a minimal but realistic config: WAN (dhcp) + LAN + a guest
    /// network, two zones, one rule, one radio, one wifi SSID, two
    /// services. Exactly enough to exercise the cross-ref helpers without
    /// being a full fixture dump.
    fn make_test_config() -> Config {
        Config {
            hostname: "test".to_string(),
            timezone: None,
            networks: vec![
                Network::Wan {
                    name: "wan".to_string(),
                    iface: "eth1".to_string(),
                    wan: crate::config::WanConfig::Dhcp {
                        send_hostname: false,
                        hostname_override: None,
                        vendor_class_id: None,
                    },
                    ipv6_pd: false,
                    sqm: None,
                    priority: 100,
                    probe_target: None,
                    mac_address: None,
                },
                Network::Lan {
                    name: "lan".to_string(),
                    bridge: "br-lan".to_string(),
                    members: vec!["lan1".to_string()],
                    vlan_filtering: false,
                    vlan_ports: vec![],
                    address: Ipv4Addr::new(192, 168, 1, 1),
                    prefix: 24,
                    ipv6_address: None,
                    ipv6_prefix: None,
                    ipv6_subnet_id: None,
                    router_advertisements: None,
                },
                Network::Simple {
                    name: "guest".to_string(),
                    iface: "br-guest".to_string(),
                    address: Ipv4Addr::new(10, 99, 0, 1),
                    prefix: 24,
                    ipv6_address: None,
                    ipv6_prefix: None,
                    ipv6_subnet_id: None,
                    vlan: None,
                    vlan_parent: None,
                    router_advertisements: None,
                },
            ],
            firewall: Firewall {
                zones: vec![
                    Zone {
                        name: "lan".to_string(),
                        networks: vec!["lan".to_string()],
                        default_input: ChainPolicy::Accept,
                        default_forward: ChainPolicy::Drop,
                        default_output: ChainPolicy::Accept,
                        masquerade: false,
                        via_vpn: false,
                        wan: None,
                        mtu_fix: false,
                    },
                    Zone {
                        name: "wan".to_string(),
                        networks: vec!["wan".to_string()],
                        default_input: ChainPolicy::Drop,
                        default_forward: ChainPolicy::Drop,
                        default_output: ChainPolicy::Accept,
                        masquerade: true,
                        via_vpn: false,
                        wan: None,
                        mtu_fix: false,
                    },
                ],
                rules: vec![Rule {
                    name: "lan-to-wan".to_string(),
                    enabled: true,
                    family: oxwrt_api::config::Family::Any,
                    src_ip: vec![],
                    dest_ip: vec![],
                    src_mac: vec![],
                    src_port: None,
                    icmp_type: None,
                    limit: None,
                    log: None,
                    src: Some("lan".to_string()),
                    dest: Some("wan".to_string()),
                    proto: None,
                    dest_port: None,
                    ct_state: vec![],
                    action: Action::Accept,
                    dnat_target: None,
                    schedule: None,
                    match_set: None,
                    counter: false,
                    limit_burst: None,
                    reject_with: None,
                    device: None,
                }],
                raw_nft: vec![],
                defaults: Default::default(),
                forwardings: vec![],
            },
            radios: vec![Radio {
                phy: "phy0".to_string(),
                band: "2g".to_string(),
                channel: 1,
                ..Default::default()
            }],
            wifi: vec![Wifi {
                radio: "phy0".to_string(),
                ssid: "MyNet".to_string(),
                security: WifiSecurity::Wpa3Sae,
                passphrase: "pw".to_string(),
                network: "lan".to_string(),
                ..Default::default()
            }],
            services: vec![
                Service {
                    name: "dns".to_string(),
                    rootfs: PathBuf::from("/x/dns"),
                    entrypoint: vec!["/bin".to_string()],
                    env: BTreeMap::new(),
                    net_mode: Default::default(),
                    veth: None,
                    memory_max: None,
                    cpu_max: None,
                    pids_max: None,
                    binds: vec![],
                    depends_on: vec![],
                    security: Default::default(),
                },
                Service {
                    name: "dhcp".to_string(),
                    rootfs: PathBuf::from("/x/dhcp"),
                    entrypoint: vec!["/bin".to_string()],
                    env: BTreeMap::new(),
                    net_mode: Default::default(),
                    veth: None,
                    memory_max: None,
                    cpu_max: None,
                    pids_max: None,
                    binds: vec![],
                    depends_on: vec!["dns".to_string()],
                    security: Default::default(),
                },
            ],
            port_forwards: vec![],
            wireguard: vec![],
            ddns: vec![],
            metrics: None,
            routes: vec![],
            routes6: vec![],
            blocklists: vec![],
            ipsets: vec![],
            upnp: None,
            vpn_client: vec![],
            backup_sftp: None,
            dns: None,
            dhcp: None,
            ntp: None,
            control: Control {
                listen: vec!["[::1]:51820".to_string()],
                authorized_keys: PathBuf::from("/etc/oxwrt/authorized_keys"),
                clients: vec![],
                max_connections: 32,
                max_rpcs_per_sec: 20,
            },
        }
    }

    // ── check_zone_network_refs ────────────────────────────────────

    #[test]
    fn zone_with_known_network_ok() {
        let cfg = make_test_config();
        let zone = Zone {
            name: "dmz".to_string(),
            networks: vec!["guest".to_string()],
            default_input: ChainPolicy::Drop,
            default_forward: ChainPolicy::Drop,
            default_output: ChainPolicy::Accept,
            masquerade: false,
            via_vpn: false,
            wan: None,
            mtu_fix: false,
        };
        assert!(check_zone_network_refs(&zone, &cfg).is_ok());
    }

    #[test]
    fn zone_with_unknown_network_rejected_with_name() {
        let cfg = make_test_config();
        let zone = Zone {
            name: "dmz".to_string(),
            networks: vec!["ghost".to_string()],
            default_input: ChainPolicy::Drop,
            default_forward: ChainPolicy::Drop,
            default_output: ChainPolicy::Accept,
            masquerade: false,
            via_vpn: false,
            wan: None,
            mtu_fix: false,
        };
        let err = check_zone_network_refs(&zone, &cfg).unwrap_err();
        assert!(err.contains("dmz"), "error should name the zone: {err}");
        assert!(
            err.contains("ghost"),
            "error should name the bad ref: {err}"
        );
    }

    #[test]
    fn zone_with_multiple_networks_all_checked() {
        let cfg = make_test_config();
        // first ref is good, second is bad — should still reject
        let zone = Zone {
            name: "dmz".to_string(),
            networks: vec!["lan".to_string(), "ghost".to_string()],
            default_input: ChainPolicy::Drop,
            default_forward: ChainPolicy::Drop,
            default_output: ChainPolicy::Accept,
            masquerade: false,
            via_vpn: false,
            wan: None,
            mtu_fix: false,
        };
        assert!(check_zone_network_refs(&zone, &cfg).is_err());
    }

    // ── check_rule_zone_refs ───────────────────────────────────────

    #[test]
    fn rule_with_no_zone_refs_ok() {
        let cfg = make_test_config();
        let rule = Rule {
            name: "ct-est".to_string(),
            enabled: true,
            family: oxwrt_api::config::Family::Any,
            src_ip: vec![],
            dest_ip: vec![],
            src_mac: vec![],
            src_port: None,
            icmp_type: None,
            limit: None,
            log: None,
            src: None,
            dest: None,
            proto: None,
            dest_port: None,
            ct_state: vec!["established".to_string()],
            action: Action::Accept,
            dnat_target: None,
            schedule: None,
            match_set: None,
            counter: false,
            limit_burst: None,
            reject_with: None,
            device: None,
        };
        assert!(check_rule_zone_refs(&rule, &cfg).is_ok());
    }

    #[test]
    fn rule_with_known_src_and_dest_ok() {
        let cfg = make_test_config();
        let rule = Rule {
            name: "r".to_string(),
            enabled: true,
            family: oxwrt_api::config::Family::Any,
            src_ip: vec![],
            dest_ip: vec![],
            src_mac: vec![],
            src_port: None,
            icmp_type: None,
            limit: None,
            log: None,
            src: Some("lan".to_string()),
            dest: Some("wan".to_string()),
            proto: None,
            dest_port: None,
            ct_state: vec![],
            action: Action::Accept,
            dnat_target: None,
            schedule: None,
            match_set: None,
            counter: false,
            limit_burst: None,
            reject_with: None,
            device: None,
        };
        assert!(check_rule_zone_refs(&rule, &cfg).is_ok());
    }

    #[test]
    fn rule_with_unknown_src_rejected() {
        let cfg = make_test_config();
        let rule = Rule {
            name: "r".to_string(),
            enabled: true,
            family: oxwrt_api::config::Family::Any,
            src_ip: vec![],
            dest_ip: vec![],
            src_mac: vec![],
            src_port: None,
            icmp_type: None,
            limit: None,
            log: None,
            src: Some("nowhere".to_string()),
            dest: None,
            proto: None,
            dest_port: None,
            ct_state: vec![],
            action: Action::Accept,
            dnat_target: None,
            schedule: None,
            match_set: None,
            counter: false,
            limit_burst: None,
            reject_with: None,
            device: None,
        };
        let err = check_rule_zone_refs(&rule, &cfg).unwrap_err();
        assert!(err.contains("src"), "error should flag src: {err}");
        assert!(err.contains("nowhere"), "error should name bad ref: {err}");
    }

    #[test]
    fn rule_with_unknown_dest_rejected() {
        let cfg = make_test_config();
        let rule = Rule {
            name: "r".to_string(),
            enabled: true,
            family: oxwrt_api::config::Family::Any,
            src_ip: vec![],
            dest_ip: vec![],
            src_mac: vec![],
            src_port: None,
            icmp_type: None,
            limit: None,
            log: None,
            src: None,
            dest: Some("nowhere".to_string()),
            proto: None,
            dest_port: None,
            ct_state: vec![],
            action: Action::Accept,
            dnat_target: None,
            schedule: None,
            match_set: None,
            counter: false,
            limit_burst: None,
            reject_with: None,
            device: None,
        };
        let err = check_rule_zone_refs(&rule, &cfg).unwrap_err();
        assert!(err.contains("dest"), "error should flag dest: {err}");
    }

    #[test]
    fn rule_with_empty_name_rejected() {
        let cfg = make_test_config();
        let rule = Rule {
            name: "   ".to_string(),
            enabled: true,
            family: oxwrt_api::config::Family::Any,
            src_ip: vec![],
            dest_ip: vec![],
            src_mac: vec![],
            src_port: None,
            icmp_type: None,
            limit: None,
            log: None,
            src: None,
            dest: None,
            proto: None,
            dest_port: None,
            ct_state: vec![],
            action: Action::Accept,
            dnat_target: None,
            schedule: None,
            match_set: None,
            counter: false,
            limit_burst: None,
            reject_with: None,
            device: None,
        };
        let err = check_rule_zone_refs(&rule, &cfg).unwrap_err();
        assert!(err.contains("name"), "empty-name error: {err}");
    }

    #[test]
    fn rule_dnat_without_target_rejected() {
        let cfg = make_test_config();
        let rule = Rule {
            name: "r".to_string(),
            enabled: true,
            family: oxwrt_api::config::Family::Any,
            src_ip: vec![],
            dest_ip: vec![],
            src_mac: vec![],
            src_port: None,
            icmp_type: None,
            limit: None,
            log: None,
            src: None,
            dest: None,
            proto: Some(crate::config::Proto::Tcp),
            dest_port: Some(crate::config::PortSpec::Single(80)),
            ct_state: vec![],
            action: Action::Dnat,
            dnat_target: None,
            schedule: None,
            match_set: None,
            counter: false,
            limit_burst: None,
            reject_with: None,
            device: None,
        };
        let err = check_rule_zone_refs(&rule, &cfg).unwrap_err();
        assert!(err.contains("dnat_target"), "got: {err}");
    }

    #[test]
    fn rule_dnat_with_malformed_target_rejected() {
        let cfg = make_test_config();
        let rule = Rule {
            name: "r".to_string(),
            enabled: true,
            family: oxwrt_api::config::Family::Any,
            src_ip: vec![],
            dest_ip: vec![],
            src_mac: vec![],
            src_port: None,
            icmp_type: None,
            limit: None,
            log: None,
            src: None,
            dest: None,
            proto: Some(crate::config::Proto::Tcp),
            dest_port: Some(crate::config::PortSpec::Single(80)),
            ct_state: vec![],
            action: Action::Dnat,
            dnat_target: Some("not-an-ip-port".to_string()),
            schedule: None,
            match_set: None,
            counter: false,
            limit_burst: None,
            reject_with: None,
            device: None,
        };
        assert!(check_rule_zone_refs(&rule, &cfg).is_err());
    }

    #[test]
    fn rule_non_dnat_with_target_rejected() {
        let cfg = make_test_config();
        let rule = Rule {
            name: "r".to_string(),
            enabled: true,
            family: oxwrt_api::config::Family::Any,
            src_ip: vec![],
            dest_ip: vec![],
            src_mac: vec![],
            src_port: None,
            icmp_type: None,
            limit: None,
            log: None,
            src: None,
            dest: None,
            proto: None,
            dest_port: None,
            ct_state: vec![],
            action: Action::Accept,
            dnat_target: Some("10.0.0.1:80".to_string()),
            schedule: None,
            match_set: None,
            counter: false,
            limit_burst: None,
            reject_with: None,
            device: None,
        };
        let err = check_rule_zone_refs(&rule, &cfg).unwrap_err();
        assert!(
            err.contains("dnat_target") && err.contains("action=dnat"),
            "got: {err}"
        );
    }

    #[test]
    fn rule_icmp_with_dest_port_rejected() {
        let cfg = make_test_config();
        let rule = Rule {
            name: "r".to_string(),
            enabled: true,
            family: oxwrt_api::config::Family::Any,
            src_ip: vec![],
            dest_ip: vec![],
            src_mac: vec![],
            src_port: None,
            icmp_type: None,
            limit: None,
            log: None,
            src: None,
            dest: None,
            proto: Some(crate::config::Proto::Icmp),
            dest_port: Some(crate::config::PortSpec::Single(53)),
            ct_state: vec![],
            action: Action::Accept,
            dnat_target: None,
            schedule: None,
            match_set: None,
            counter: false,
            limit_burst: None,
            reject_with: None,
            device: None,
        };
        let err = check_rule_zone_refs(&rule, &cfg).unwrap_err();
        assert!(
            err.contains("icmp") && err.contains("dest_port"),
            "got: {err}"
        );
    }

    // ── fw4-parity: new primitive coupling checks ──────────────────

    fn build_basic_rule_for_test(name: &str) -> Rule {
        Rule {
            name: name.to_string(),
            enabled: true,
            family: oxwrt_api::config::Family::Any,
            src_ip: vec![],
            dest_ip: vec![],
            src_mac: vec![],
            src_port: None,
            icmp_type: None,
            limit: None,
            log: None,
            src: None,
            dest: None,
            proto: None,
            dest_port: None,
            ct_state: vec![],
            action: Action::Accept,
            dnat_target: None,
            schedule: None,
            match_set: None,
            counter: false,
            limit_burst: None,
            reject_with: None,
            device: None,
        }
    }

    #[test]
    fn rule_reject_with_on_non_reject_action_rejected() {
        let cfg = make_test_config();
        let mut r = build_basic_rule_for_test("bad-reject");
        r.action = Action::Accept;
        r.reject_with = Some("tcp reset".to_string());
        let err = check_rule_zone_refs(&r, &cfg).unwrap_err();
        assert!(err.contains("reject_with"), "got: {err}");
        assert!(err.contains("action=reject"), "got: {err}");
    }

    #[test]
    fn rule_reject_with_on_reject_action_ok() {
        let cfg = make_test_config();
        let mut r = build_basic_rule_for_test("ok-reject");
        r.action = Action::Reject;
        r.reject_with = Some("icmpx type admin-prohibited".to_string());
        assert!(check_rule_zone_refs(&r, &cfg).is_ok());
    }

    #[test]
    fn rule_limit_burst_without_limit_rejected() {
        let cfg = make_test_config();
        let mut r = build_basic_rule_for_test("no-base-rate");
        r.limit_burst = Some(50);
        // limit left None
        let err = check_rule_zone_refs(&r, &cfg).unwrap_err();
        assert!(err.contains("limit_burst"), "got: {err}");
    }

    #[test]
    fn rule_limit_burst_with_limit_ok() {
        let cfg = make_test_config();
        let mut r = build_basic_rule_for_test("rate-burst");
        r.limit = Some("10/second".to_string());
        r.limit_burst = Some(50);
        assert!(check_rule_zone_refs(&r, &cfg).is_ok());
    }

    #[test]
    fn rule_empty_device_rejected() {
        let cfg = make_test_config();
        let mut r = build_basic_rule_for_test("empty-dev");
        r.device = Some("   ".to_string());
        let err = check_rule_zone_refs(&r, &cfg).unwrap_err();
        assert!(err.contains("device"), "got: {err}");
    }

    // ── check_forwarding ───────────────────────────────────────────

    #[test]
    fn forwarding_known_zones_ok() {
        let cfg = make_test_config();
        let fwd = oxwrt_api::config::Forwarding {
            src: "lan".to_string(),
            dest: "wan".to_string(),
            family: oxwrt_api::config::Family::Any,
        };
        assert!(check_forwarding(&fwd, &cfg).is_ok());
    }

    #[test]
    fn forwarding_unknown_src_rejected() {
        let cfg = make_test_config();
        let fwd = oxwrt_api::config::Forwarding {
            src: "nowhere".to_string(),
            dest: "wan".to_string(),
            family: oxwrt_api::config::Family::Any,
        };
        let err = check_forwarding(&fwd, &cfg).unwrap_err();
        assert!(err.contains("src zone"), "got: {err}");
    }

    #[test]
    fn forwarding_self_rejected() {
        let cfg = make_test_config();
        let fwd = oxwrt_api::config::Forwarding {
            src: "lan".to_string(),
            dest: "lan".to_string(),
            family: oxwrt_api::config::Family::Any,
        };
        let err = check_forwarding(&fwd, &cfg).unwrap_err();
        assert!(err.contains("same"), "got: {err}");
    }

    // ── check_wifi_refs ────────────────────────────────────────────

    #[test]
    fn wifi_with_known_refs_ok() {
        let cfg = make_test_config();
        let wifi = Wifi {
            radio: "phy0".to_string(),
            ssid: "Guest".to_string(),
            security: WifiSecurity::Wpa3Sae,
            passphrase: "pw".to_string(),
            network: "guest".to_string(),
            hidden: false,
            bridge: None,
            wpa_key_mgmt: None,
            rsn_pairwise: None,
            ieee80211w: None,
            sae_require_mfp: None,
            macaddr_acl: None,
            auth_algs: None,
            ap_isolate: None,
            max_num_sta: None,
            wmm_enabled: None,
            ft_over_ds: None,
            sae_pwe: None,
            extra: Vec::new(),
            rotate_hours: None,
        };
        assert!(check_wifi_refs(&wifi, &cfg).is_ok());
    }

    #[test]
    fn wifi_unknown_radio_rejected() {
        let cfg = make_test_config();
        let wifi = Wifi {
            radio: "phy99".to_string(),
            ssid: "X".to_string(),
            security: WifiSecurity::Wpa3Sae,
            passphrase: "pw".to_string(),
            network: "lan".to_string(),
            ..Default::default()
        };
        let err = check_wifi_refs(&wifi, &cfg).unwrap_err();
        assert!(err.contains("phy99"));
    }

    #[test]
    fn wifi_unknown_network_rejected() {
        let cfg = make_test_config();
        let wifi = Wifi {
            radio: "phy0".to_string(),
            ssid: "X".to_string(),
            security: WifiSecurity::Wpa3Sae,
            passphrase: "pw".to_string(),
            network: "nowhere".to_string(),
            ..Default::default()
        };
        let err = check_wifi_refs(&wifi, &cfg).unwrap_err();
        assert!(err.contains("nowhere"));
    }

    // ── dependents_on_* ────────────────────────────────────────────

    #[test]
    fn dependents_on_network_lists_zone_and_wifi() {
        let cfg = make_test_config();
        // "lan" is referenced by zone "lan" AND wifi "MyNet"
        let deps = dependents_on_network("lan", &cfg);
        assert_eq!(deps.len(), 2, "expected 2 deps, got {deps:?}");
        assert!(deps.iter().any(|d| d.contains("zone lan")));
        assert!(deps.iter().any(|d| d.contains("wifi MyNet")));
    }

    #[test]
    fn dependents_on_network_unreferenced_is_empty() {
        let cfg = make_test_config();
        assert!(dependents_on_network("guest", &cfg).is_empty());
    }

    #[test]
    fn dependents_on_zone_lists_rule() {
        let cfg = make_test_config();
        let deps = dependents_on_zone("lan", &cfg);
        assert_eq!(deps.len(), 1);
        assert!(deps[0].contains("lan-to-wan"));
        let deps = dependents_on_zone("wan", &cfg);
        assert_eq!(deps.len(), 1);
    }

    #[test]
    fn dependents_on_zone_unreferenced_is_empty() {
        let cfg = make_test_config();
        assert!(dependents_on_zone("nonexistent", &cfg).is_empty());
    }

    #[test]
    fn dependents_on_radio_lists_wifi() {
        let cfg = make_test_config();
        let deps = dependents_on_radio("phy0", &cfg);
        assert_eq!(deps.len(), 1);
        assert!(deps[0].contains("wifi MyNet"));
    }

    // ── json_merge ─────────────────────────────────────────────────

    #[test]
    fn json_merge_overwrites_top_level_field() {
        let mut base = json!({"a": 1, "b": 2});
        json_merge(&mut base, &json!({"b": 99}));
        assert_eq!(base, json!({"a": 1, "b": 99}));
    }

    #[test]
    fn json_merge_adds_new_field() {
        let mut base = json!({"a": 1});
        json_merge(&mut base, &json!({"c": 3}));
        assert_eq!(base, json!({"a": 1, "c": 3}));
    }

    #[test]
    fn json_merge_is_shallow_replaces_nested_object_wholesale() {
        // Confirms the documented semantics: partial-merge Update is a
        // *shallow* merge. Nested objects are replaced, not deep-merged.
        let mut base = json!({"sec": {"caps": ["A"], "seccomp": true}});
        json_merge(&mut base, &json!({"sec": {"caps": ["B"]}}));
        assert_eq!(base, json!({"sec": {"caps": ["B"]}}));
    }

    #[test]
    fn json_merge_noop_on_non_object_base() {
        let mut base = json!([1, 2, 3]);
        json_merge(&mut base, &json!({"x": 1}));
        assert_eq!(base, json!([1, 2, 3]));
    }

    // ── json_merge_service_update ──────────────────────────────────

    /// The footgun fix: a partial `security` patch preserves
    /// unspecified fields instead of resetting them to defaults.
    /// This is exactly the case that wiped SYS_TIME off ntp and
    /// NET_RAW off corerad during the 2026-04-20 pid-ns rollout.
    #[test]
    fn service_update_security_deep_merges() {
        let mut existing = json!({
            "name": "ntp",
            "net_mode": "isolated",
            "security": {
                "caps": ["SETUID", "SETGID", "SETPCAP", "SYS_TIME"],
                "no_new_privs": true,
                "seccomp": true,
                "seccomp_allow": [],
                "user_namespace": false,
                "pid_namespace": false,
                "landlock": true
            }
        });
        // Operator sends "just flip pid_namespace on":
        let mut partial = json!({"security": {"pid_namespace": true}});
        json_merge_service_update(&mut existing, &mut partial);
        // caps must still be there (previously got reset to [] via
        // Default::default on the replaced SecurityProfile).
        assert_eq!(
            existing["security"]["caps"],
            json!(["SETUID", "SETGID", "SETPCAP", "SYS_TIME"])
        );
        assert_eq!(existing["security"]["pid_namespace"], json!(true));
        assert_eq!(existing["security"]["landlock"], json!(true));
    }

    /// Top-level fields (net_mode, entrypoint, binds, ...) keep the
    /// shallow-replace contract. Only `security` is special-cased.
    #[test]
    fn service_update_top_level_still_shallow() {
        let mut existing = json!({
            "name": "dns",
            "net_mode": "isolated",
            "binds": [{"source": "/old", "target": "/old", "readonly": true}],
        });
        let mut partial = json!({
            "binds": [{"source": "/new", "target": "/new", "readonly": true}]
        });
        json_merge_service_update(&mut existing, &mut partial);
        // `binds` is an array — shallow replace wins.
        assert_eq!(
            existing["binds"],
            json!([{"source": "/new", "target": "/new", "readonly": true}])
        );
    }

    /// If the partial doesn't touch security, nothing magical happens
    /// — existing security is preserved as usual by the shallow merge
    /// on the top level (it simply isn't in the patch).
    #[test]
    fn service_update_no_security_patch_is_noop_on_security() {
        let mut existing = json!({
            "name": "ntp",
            "security": {"caps": ["SYS_TIME"], "pid_namespace": false},
        });
        let mut partial = json!({"memory_max": 1000});
        json_merge_service_update(&mut existing, &mut partial);
        assert_eq!(
            existing["security"],
            json!({"caps": ["SYS_TIME"], "pid_namespace": false})
        );
        assert_eq!(existing["memory_max"], json!(1000));
    }

    // ── check_vlan_consistency ─────────────────────────────────────

    fn simple_vlan(name: &str, iface: &str, vlan: Option<u16>, parent: Option<&str>) -> Network {
        Network::Simple {
            name: name.to_string(),
            iface: iface.to_string(),
            address: Ipv4Addr::new(10, 99, 0, 1),
            prefix: 24,
            ipv6_address: None,
            ipv6_prefix: None,
            ipv6_subnet_id: None,
            vlan,
            vlan_parent: parent.map(str::to_string),
            router_advertisements: None,
        }
    }

    fn cfg_with_networks(networks: Vec<Network>) -> Config {
        let mut cfg = make_test_config();
        cfg.networks = networks;
        cfg
    }

    #[test]
    fn vlan_with_parent_ok() {
        let cfg = cfg_with_networks(vec![simple_vlan("v10", "eth0.10", Some(10), Some("eth0"))]);
        assert!(check_vlan_consistency(&cfg).is_ok());
    }

    #[test]
    fn vlan_without_parent_rejected() {
        let cfg = cfg_with_networks(vec![simple_vlan("v10", "eth0.10", Some(10), None)]);
        let err = check_vlan_consistency(&cfg).unwrap_err();
        assert!(
            err.contains("vlan_parent"),
            "expected parent-required err: {err}"
        );
    }

    #[test]
    fn parent_without_vlan_rejected() {
        let cfg = cfg_with_networks(vec![simple_vlan("x", "eth0.99", None, Some("eth0"))]);
        let err = check_vlan_consistency(&cfg).unwrap_err();
        assert!(err.contains("vlan_parent` set without"), "{err}");
    }

    #[test]
    fn vlan_id_out_of_range_rejected() {
        let cfg = cfg_with_networks(vec![simple_vlan("bad", "x", Some(4095), Some("eth0"))]);
        assert!(
            check_vlan_consistency(&cfg)
                .unwrap_err()
                .contains("out of range")
        );
        let cfg0 = cfg_with_networks(vec![simple_vlan("bad", "x", Some(0), Some("eth0"))]);
        assert!(
            check_vlan_consistency(&cfg0)
                .unwrap_err()
                .contains("out of range")
        );
    }

    #[test]
    fn vlan_none_on_non_vlan_simple_ok() {
        // The existing make_test_config's guest Simple has no vlan
        // fields set — this should pass unchanged.
        let cfg = make_test_config();
        assert!(check_vlan_consistency(&cfg).is_ok());
    }

    // ── check_service ─────────────────────────────────────────────

    fn svc(name: &str, net_mode: NetMode, with_veth: bool) -> Service {
        use crate::config::VethConfig;
        Service {
            name: name.to_string(),
            rootfs: PathBuf::from(format!("/x/{name}")),
            entrypoint: vec!["/bin".to_string()],
            env: BTreeMap::new(),
            net_mode,
            veth: with_veth.then(|| VethConfig {
                host_ip: "10.0.0.1".parse().unwrap(),
                peer_ip: "10.0.0.2".parse().unwrap(),
                prefix: 30,
            }),
            memory_max: None,
            cpu_max: None,
            pids_max: None,
            binds: vec![],
            depends_on: vec![],
            security: Default::default(),
        }
    }

    fn cfg_with_services(services: Vec<Service>) -> Config {
        let mut c = make_test_config();
        c.services = services;
        c
    }

    #[test]
    fn service_isolated_without_veth_rejected() {
        let cfg = cfg_with_services(vec![svc("dns", NetMode::Isolated, false)]);
        let err = check_service(&cfg.services[0], &cfg).unwrap_err();
        assert!(err.contains("requires a [services.veth] block"), "{err}");
    }

    #[test]
    fn service_isolated_with_veth_ok() {
        let cfg = cfg_with_services(vec![svc("dns", NetMode::Isolated, true)]);
        assert!(check_service(&cfg.services[0], &cfg).is_ok());
    }

    #[test]
    fn service_host_with_veth_rejected() {
        let cfg = cfg_with_services(vec![svc("dhcp", NetMode::Host, true)]);
        let err = check_service(&cfg.services[0], &cfg).unwrap_err();
        assert!(err.contains("allocated and unused"), "{err}");
    }

    #[test]
    fn service_host_without_veth_ok() {
        let cfg = cfg_with_services(vec![svc("dhcp", NetMode::Host, false)]);
        assert!(check_service(&cfg.services[0], &cfg).is_ok());
    }

    #[test]
    fn service_depends_on_unknown_rejected() {
        let mut s = svc("dns", NetMode::Isolated, true);
        s.depends_on = vec!["ntp".to_string()];
        let cfg = cfg_with_services(vec![s]);
        let err = check_service(&cfg.services[0], &cfg).unwrap_err();
        assert!(err.contains("unknown service: ntp"), "{err}");
    }

    #[test]
    fn service_depends_on_vethless_peer_rejected() {
        // Two services, B depends on A, but A has no veth.
        let a = svc("a", NetMode::Host, false);
        let mut b = svc("b", NetMode::Isolated, true);
        b.depends_on = vec!["a".to_string()];
        let cfg = cfg_with_services(vec![a, b]);
        let err = check_service(&cfg.services[1], &cfg).unwrap_err();
        assert!(err.contains("has no veth"), "{err}");
    }

    #[test]
    fn service_depends_on_veth_peer_ok() {
        let a = svc("dns", NetMode::Isolated, true);
        let mut b = svc("ntp", NetMode::Isolated, true);
        b.depends_on = vec!["dns".to_string()];
        let cfg = cfg_with_services(vec![a, b]);
        assert!(check_service(&cfg.services[1], &cfg).is_ok());
    }
}
