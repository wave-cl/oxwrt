//! handle_set + TOML mutation helpers. Split out in step 7.

use super::*;

pub(super) fn handle_set(state: &ControlState, key: &str, value: &str) -> Response {
    use crate::config::{self, Network, WanConfig};
    use std::net::Ipv4Addr;
    use std::path::Path;

    // Phase 1: validate the value parses into the right type and clone
    // the in-memory Config with the mutation applied. Any parse error
    // here rejects the request before we touch the disk.
    let cfg_arc = state.config_snapshot();
    let mut new_cfg = (*cfg_arc).clone();

    match key {
        "hostname" => {
            if value.is_empty() {
                return Response::Err {
                    message: "hostname must not be empty".to_string(),
                };
            }
            new_cfg.hostname = value.to_string();
            // Apply to the live kernel immediately — otherwise `set
            // hostname` only updates the in-memory config + /etc/
            // oxwrt.toml, and the kernel hostname doesn't change
            // until the next `reload` (or the next boot). In
            // --control-only mode `reload` short-circuits the
            // reconcile phases, so the apply would never happen at
            // all. sethostname(2) is cheap + idempotent; just do it
            // here for instant operator feedback.
            if let Err(e) = rustix::system::sethostname(value.as_bytes()) {
                tracing::warn!(error = %e, hostname = %value, "sethostname failed");
            }
        }
        "timezone" => {
            new_cfg.timezone = if value.is_empty() {
                None
            } else {
                Some(value.to_string())
            };
        }
        "lan.address" => {
            let addr = match value.parse::<Ipv4Addr>() {
                Ok(a) => a,
                Err(e) => {
                    return Response::Err {
                        message: format!("invalid ipv4 address: {e}"),
                    };
                }
            };
            let Some(lan) = new_cfg
                .networks
                .iter_mut()
                .find(|n| matches!(n, Network::Lan { .. }))
            else {
                return Response::Err {
                    message: "no lan network configured".to_string(),
                };
            };
            if let Network::Lan { address, .. } = lan {
                *address = addr;
            }
        }
        "lan.prefix" => {
            let p = match value.parse::<u8>() {
                Ok(p) if p <= 32 => p,
                _ => {
                    return Response::Err {
                        message: "lan.prefix must be 0..=32".to_string(),
                    };
                }
            };
            let Some(lan) = new_cfg
                .networks
                .iter_mut()
                .find(|n| matches!(n, Network::Lan { .. }))
            else {
                return Response::Err {
                    message: "no lan network configured".to_string(),
                };
            };
            if let Network::Lan { prefix, .. } = lan {
                *prefix = p;
            }
        }
        "lan.bridge" => {
            if value.is_empty() || value.len() >= 16 {
                return Response::Err {
                    message: "lan.bridge must be 1..15 chars".to_string(),
                };
            }
            let Some(lan) = new_cfg
                .networks
                .iter_mut()
                .find(|n| matches!(n, Network::Lan { .. }))
            else {
                return Response::Err {
                    message: "no lan network configured".to_string(),
                };
            };
            if let Network::Lan { bridge, .. } = lan {
                *bridge = value.to_string();
            }
        }
        "wan.mode" => {
            // Switching WAN mode replaces the WanConfig inside the Wan variant.
            // The iface is carried over from the current config.
            let Some(wan_net) = new_cfg
                .networks
                .iter_mut()
                .find(|n| matches!(n, Network::Wan { .. }))
            else {
                return Response::Err {
                    message: "no wan network configured".to_string(),
                };
            };
            let Network::Wan { wan, .. } = wan_net else {
                unreachable!()
            };
            match value {
                "dhcp" => {
                    *wan = WanConfig::Dhcp {
                        send_hostname: false,
                        hostname_override: None,
                        vendor_class_id: None,
                    };
                }
                "static" => {
                    *wan = WanConfig::Static {
                        address: Ipv4Addr::new(0, 0, 0, 0),
                        prefix: 24,
                        gateway: Ipv4Addr::new(0, 0, 0, 0),
                        dns: vec![],
                    };
                }
                "pppoe" => {
                    *wan = WanConfig::Pppoe {
                        username: String::new(),
                        password: String::new(),
                    };
                }
                _ => {
                    return Response::Err {
                        message: format!("unknown wan.mode: {value:?}. Valid: dhcp, static, pppoe"),
                    };
                }
            }
        }
        "wan.iface" => {
            let Some(wan_net) = new_cfg
                .networks
                .iter_mut()
                .find(|n| matches!(n, Network::Wan { .. }))
            else {
                return Response::Err {
                    message: "no wan network configured".to_string(),
                };
            };
            if let Network::Wan { iface, .. } = wan_net {
                *iface = value.to_string();
            }
        }
        "wan.address" => {
            let addr = match value.parse::<Ipv4Addr>() {
                Ok(a) => a,
                Err(e) => {
                    return Response::Err {
                        message: format!("invalid ipv4 address: {e}"),
                    };
                }
            };
            let Some(wan_net) = new_cfg
                .networks
                .iter_mut()
                .find(|n| matches!(n, Network::Wan { .. }))
            else {
                return Response::Err {
                    message: "no wan network configured".to_string(),
                };
            };
            match wan_net {
                Network::Wan {
                    wan: WanConfig::Static { address, .. },
                    ..
                } => *address = addr,
                _ => {
                    return Response::Err {
                        message: "wan.address only valid when wan.mode = \"static\"".to_string(),
                    };
                }
            }
        }
        "wan.prefix" => {
            let p = match value.parse::<u8>() {
                Ok(p) if p <= 32 => p,
                Ok(_) => {
                    return Response::Err {
                        message: "wan.prefix must be 0..=32".to_string(),
                    };
                }
                Err(_) => {
                    return Response::Err {
                        message: "wan.prefix must be 0..=32".to_string(),
                    };
                }
            };
            let Some(wan_net) = new_cfg
                .networks
                .iter_mut()
                .find(|n| matches!(n, Network::Wan { .. }))
            else {
                return Response::Err {
                    message: "no wan network configured".to_string(),
                };
            };
            match wan_net {
                Network::Wan {
                    wan: WanConfig::Static { prefix, .. },
                    ..
                } => *prefix = p,
                _ => {
                    return Response::Err {
                        message: "wan.prefix only valid when wan.mode = \"static\"".to_string(),
                    };
                }
            }
        }
        "wan.gateway" => {
            let addr = match value.parse::<Ipv4Addr>() {
                Ok(a) => a,
                Err(e) => {
                    return Response::Err {
                        message: format!("invalid ipv4 address: {e}"),
                    };
                }
            };
            let Some(wan_net) = new_cfg
                .networks
                .iter_mut()
                .find(|n| matches!(n, Network::Wan { .. }))
            else {
                return Response::Err {
                    message: "no wan network configured".to_string(),
                };
            };
            match wan_net {
                Network::Wan {
                    wan: WanConfig::Static { gateway, .. },
                    ..
                } => *gateway = addr,
                _ => {
                    return Response::Err {
                        message: "wan.gateway only valid when wan.mode = \"static\"".to_string(),
                    };
                }
            }
        }
        "wan.username" => {
            let Some(wan_net) = new_cfg
                .networks
                .iter_mut()
                .find(|n| matches!(n, Network::Wan { .. }))
            else {
                return Response::Err {
                    message: "no wan network configured".to_string(),
                };
            };
            match wan_net {
                Network::Wan {
                    wan: WanConfig::Pppoe { username, .. },
                    ..
                } => *username = value.to_string(),
                _ => {
                    return Response::Err {
                        message: "wan.username only valid when wan.mode = \"pppoe\"".to_string(),
                    };
                }
            }
        }
        "wan.password" => {
            let Some(wan_net) = new_cfg
                .networks
                .iter_mut()
                .find(|n| matches!(n, Network::Wan { .. }))
            else {
                return Response::Err {
                    message: "no wan network configured".to_string(),
                };
            };
            match wan_net {
                Network::Wan {
                    wan: WanConfig::Pppoe { password, .. },
                    ..
                } => *password = value.to_string(),
                _ => {
                    return Response::Err {
                        message: "wan.password only valid when wan.mode = \"pppoe\"".to_string(),
                    };
                }
            }
        }
        "wan.dns" => {
            // Comma-separated list of IP addresses, e.g. "1.1.1.1,9.9.9.9".
            // Only valid in static mode (DHCP mode gets DNS from the lease).
            let Some(wan_net) = new_cfg
                .networks
                .iter_mut()
                .find(|n| matches!(n, Network::Wan { .. }))
            else {
                return Response::Err {
                    message: "no wan network configured".to_string(),
                };
            };
            let Network::Wan {
                wan: WanConfig::Static { dns, .. },
                ..
            } = wan_net
            else {
                return Response::Err {
                    message: "wan.dns only valid when wan.mode = \"static\"".to_string(),
                };
            };
            let mut addrs = Vec::new();
            for part in value.split(',') {
                let trimmed = part.trim();
                if trimmed.is_empty() {
                    continue;
                }
                match trimmed.parse::<std::net::IpAddr>() {
                    Ok(a) => addrs.push(a),
                    Err(e) => {
                        return Response::Err {
                            message: format!("invalid IP address {trimmed:?}: {e}"),
                        };
                    }
                }
            }
            *dns = addrs;
        }
        _ => {
            return Response::Err {
                message: format!(
                    "key '{key}' is not writable. Writable keys: \
                     hostname, timezone, lan.bridge, lan.address, \
                     lan.prefix, wan.mode, wan.iface, \
                     wan.address, wan.prefix, wan.gateway, wan.dns"
                ),
            };
        }
    }

    // Phase 2: surgically patch the on-disk TOML via `toml_edit` so we
    // preserve the operator's comments and formatting. This is more
    // work than `toml::to_string(&new_cfg)` but it's the right thing
    // for a file that humans edit by hand.
    let path = Path::new(config::DEFAULT_PATH);
    let original = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            return Response::Err {
                message: format!("read {path:?}: {e}"),
            };
        }
    };
    let mut doc = match original.parse::<toml_edit::DocumentMut>() {
        Ok(d) => d,
        Err(e) => {
            return Response::Err {
                message: format!("parse {path:?}: {e}"),
            };
        }
    };
    if let Err(msg) = apply_set_to_toml(&mut doc, key, value) {
        return Response::Err { message: msg };
    }

    // Phase 3: write to disk.
    if let Err(e) = atomic_write_config(&doc.to_string()) {
        return Response::Err { message: e };
    }

    // Phase 4: publish the new in-memory config so subsequent Get/Status
    // see the update. Services are NOT restarted — operator follows up
    // with Reload to apply.
    {
        let Ok(mut cfg_lock) = state.config.write() else {
            return Response::Err {
                message: "config lock poisoned".to_string(),
            };
        };
        *cfg_lock = std::sync::Arc::new(new_cfg);
    }

    tracing::info!(key, value, "config key updated (pending reload)");
    Response::Value {
        value: format!("{key} = {value} (persisted; run `reload` to apply)"),
    }
}

/// Navigate the `toml_edit` document to the right field and replace its
/// value, preserving comments and formatting. Returns a human-readable
/// error message on unknown keys or unexpected document shapes.
///
/// With the unified `[[networks]]` format, `lan.*` and `wan.*` keys must
/// find the right entry in the `[[networks]]` array-of-tables by matching
/// the `name` field.
fn apply_set_to_toml(
    doc: &mut toml_edit::DocumentMut,
    key: &str,
    value: &str,
) -> Result<(), String> {
    use toml_edit::{Item, value as tv};

    match key {
        "hostname" => {
            doc["hostname"] = tv(value);
        }
        "timezone" => {
            if value.is_empty() {
                if let Some(tbl) = doc.as_table_mut().get_mut("timezone") {
                    *tbl = Item::None;
                }
            } else {
                doc["timezone"] = tv(value);
            }
        }
        "lan.bridge" => {
            let lan = find_network_table(doc, "lan")?;
            lan["bridge"] = tv(value);
        }
        "lan.address" => {
            let lan = find_network_table(doc, "lan")?;
            lan["address"] = tv(value);
        }
        "lan.prefix" => {
            let n: i64 = value.parse::<u8>().unwrap() as i64;
            let lan = find_network_table(doc, "lan")?;
            lan["prefix"] = tv(n);
        }
        "wan.mode" => {
            let wan = find_network_table(doc, "wan")?;
            // Preserve name, type, iface; rewrite mode-specific fields.
            let iface = wan
                .get("iface")
                .and_then(|v| v.as_str())
                .unwrap_or("eth0")
                .to_string();
            let name = wan
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("wan")
                .to_string();
            wan.clear();
            wan.insert("name", tv(&name));
            wan.insert("type", tv("wan"));
            wan.insert("iface", tv(&iface));
            wan.insert("mode", tv(value));
            match value {
                "static" => {
                    wan.insert("address", tv("0.0.0.0"));
                    wan.insert("prefix", tv(24i64));
                    wan.insert("gateway", tv("0.0.0.0"));
                    let arr = toml_edit::Array::new();
                    wan.insert("dns", Item::Value(toml_edit::Value::Array(arr)));
                }
                "pppoe" => {
                    wan.insert("username", tv(""));
                    wan.insert("password", tv(""));
                }
                _ => {} // dhcp — mode + iface is sufficient
            }
        }
        "wan.iface" => {
            let wan = find_network_table(doc, "wan")?;
            wan["iface"] = tv(value);
        }
        "wan.address" | "wan.gateway" => {
            let wan = find_network_table(doc, "wan")?;
            let field = key.strip_prefix("wan.").unwrap();
            wan[field] = tv(value);
        }
        "wan.prefix" => {
            let n: i64 = value.parse::<u8>().unwrap() as i64;
            let wan = find_network_table(doc, "wan")?;
            wan["prefix"] = tv(n);
        }
        "wan.username" | "wan.password" => {
            let wan = find_network_table(doc, "wan")?;
            let field = key.strip_prefix("wan.").unwrap();
            wan[field] = tv(value);
        }
        "wan.dns" => {
            let wan = find_network_table(doc, "wan")?;
            let mut arr = toml_edit::Array::new();
            for part in value.split(',') {
                let trimmed = part.trim();
                if !trimmed.is_empty() {
                    arr.push(trimmed);
                }
            }
            wan["dns"] = Item::Value(toml_edit::Value::Array(arr));
        }
        _ => return Err(format!("BUG: unexpected key in apply_set_to_toml: {key}")),
    }
    Ok(())
}

/// Find the `[[networks]]` entry with the given `name` and return a
/// mutable reference to its table. Used by `apply_set_to_toml` to
/// surgically edit WAN/LAN fields in the TOML array-of-tables.
fn find_network_table<'a>(
    doc: &'a mut toml_edit::DocumentMut,
    name: &str,
) -> Result<&'a mut toml_edit::Table, String> {
    let networks = doc
        .get_mut("networks")
        .and_then(|i| i.as_array_of_tables_mut())
        .ok_or_else(|| "on-disk config has no [[networks]] array".to_string())?;
    // Find the index of the entry with the matching name first, then
    // return a mutable reference via iter_mut().
    let idx = networks
        .iter()
        .position(|tbl| tbl.get("name").and_then(|v| v.as_str()) == Some(name))
        .ok_or_else(|| format!("no [[networks]] entry with name = {:?}", name))?;
    Ok(networks.iter_mut().nth(idx).unwrap())
}
