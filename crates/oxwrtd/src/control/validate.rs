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

use crate::config::{Config, Rule, Wifi, Zone};

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
    // Internal target must parse as IP:port.
    let (ip_part, port_part) = pf.internal.split_once(':').ok_or_else(|| {
        format!(
            "port-forward {}: internal must be 'ip:port' (got {:?})",
            pf.name, pf.internal
        )
    })?;
    let ip: std::net::Ipv4Addr = ip_part.parse().map_err(|_| {
        format!(
            "port-forward {}: invalid internal IP {:?}",
            pf.name, ip_part
        )
    })?;
    let _port: u16 = port_part.parse().map_err(|_| {
        format!(
            "port-forward {}: invalid internal port {:?}",
            pf.name, port_part
        )
    })?;
    // If dest zone is auto-detected (not provided), a LAN/Simple
    // network must contain the internal IP — otherwise install
    // can't emit the companion FORWARD rule.
    if pf.dest.is_none() {
        let hit = cfg.networks.iter().any(|n| {
            use crate::config::Network;
            match n {
                Network::Lan {
                    address, prefix, ..
                }
                | Network::Simple {
                    address, prefix, ..
                } => ipv4_in_subnet(ip, *address, *prefix),
                Network::Wan { .. } => false,
            }
        });
        if !hit {
            return Err(format!(
                "port-forward {}: internal IP {ip} is not in any LAN/Simple subnet; set `dest` explicitly",
                pf.name
            ));
        }
    }
    Ok(())
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
                    wan: crate::config::WanConfig::Dhcp,
                    ipv6_pd: false,
                    sqm: None,
                },
                Network::Lan {
                    name: "lan".to_string(),
                    bridge: "br-lan".to_string(),
                    members: vec!["lan1".to_string()],
                    address: Ipv4Addr::new(192, 168, 1, 1),
                    prefix: 24,
                    ipv6_address: None,
                    ipv6_prefix: None,
                    ipv6_subnet_id: None,
                },
                Network::Simple {
                    name: "guest".to_string(),
                    iface: "br-guest".to_string(),
                    address: Ipv4Addr::new(10, 99, 0, 1),
                    prefix: 24,
                    ipv6_address: None,
                    ipv6_prefix: None,
                    ipv6_subnet_id: None,
                },
            ],
            firewall: Firewall {
                zones: vec![
                    Zone {
                        name: "lan".to_string(),
                        networks: vec!["lan".to_string()],
                        default_input: ChainPolicy::Accept,
                        default_forward: ChainPolicy::Drop,
                        masquerade: false,
                    },
                    Zone {
                        name: "wan".to_string(),
                        networks: vec!["wan".to_string()],
                        default_input: ChainPolicy::Drop,
                        default_forward: ChainPolicy::Drop,
                        masquerade: true,
                    },
                ],
                rules: vec![Rule {
                    name: "lan-to-wan".to_string(),
                    src: Some("lan".to_string()),
                    dest: Some("wan".to_string()),
                    proto: None,
                    dest_port: None,
                    ct_state: vec![],
                    action: Action::Accept,
                    dnat_target: None,
                }],
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
            control: Control {
                listen: vec!["[::1]:51820".to_string()],
                authorized_keys: PathBuf::from("/etc/oxwrt/authorized_keys"),
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
            masquerade: false,
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
            masquerade: false,
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
            masquerade: false,
        };
        assert!(check_zone_network_refs(&zone, &cfg).is_err());
    }

    // ── check_rule_zone_refs ───────────────────────────────────────

    #[test]
    fn rule_with_no_zone_refs_ok() {
        let cfg = make_test_config();
        let rule = Rule {
            name: "ct-est".to_string(),
            src: None,
            dest: None,
            proto: None,
            dest_port: None,
            ct_state: vec!["established".to_string()],
            action: Action::Accept,
            dnat_target: None,
        };
        assert!(check_rule_zone_refs(&rule, &cfg).is_ok());
    }

    #[test]
    fn rule_with_known_src_and_dest_ok() {
        let cfg = make_test_config();
        let rule = Rule {
            name: "r".to_string(),
            src: Some("lan".to_string()),
            dest: Some("wan".to_string()),
            proto: None,
            dest_port: None,
            ct_state: vec![],
            action: Action::Accept,
            dnat_target: None,
        };
        assert!(check_rule_zone_refs(&rule, &cfg).is_ok());
    }

    #[test]
    fn rule_with_unknown_src_rejected() {
        let cfg = make_test_config();
        let rule = Rule {
            name: "r".to_string(),
            src: Some("nowhere".to_string()),
            dest: None,
            proto: None,
            dest_port: None,
            ct_state: vec![],
            action: Action::Accept,
            dnat_target: None,
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
            src: None,
            dest: Some("nowhere".to_string()),
            proto: None,
            dest_port: None,
            ct_state: vec![],
            action: Action::Accept,
            dnat_target: None,
        };
        let err = check_rule_zone_refs(&rule, &cfg).unwrap_err();
        assert!(err.contains("dest"), "error should flag dest: {err}");
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
}
