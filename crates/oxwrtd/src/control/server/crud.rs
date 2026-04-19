//! CRUD handlers for network/zone/rule/wifi/radio/service.
//! Split out in step 7.

use super::*;

pub(super) fn handle_crud_network(state: &ControlState, action: &CrudAction) -> Response {
    use crate::config::Network;
    let cfg = state.config_snapshot();
    match action {
        CrudAction::List => match serde_json::to_string_pretty(&cfg.networks) {
            Ok(json) => Response::Value { value: json },
            Err(e) => Response::Err {
                message: format!("serialize: {e}"),
            },
        },
        CrudAction::Get { name } => match cfg.networks.iter().find(|n| n.name() == name) {
            Some(net) => match serde_json::to_string_pretty(net) {
                Ok(json) => Response::Value { value: json },
                Err(e) => Response::Err {
                    message: format!("serialize: {e}"),
                },
            },
            None => Response::Err {
                message: format!("network not found: {name}"),
            },
        },
        CrudAction::Add { json } => {
            let item: Network = match serde_json::from_str(json) {
                Ok(v) => v,
                Err(e) => {
                    return Response::Err {
                        message: format!("invalid JSON: {e}"),
                    };
                }
            };
            let item_name = item.name().to_string();
            if cfg.networks.iter().any(|n| n.name() == item_name) {
                return Response::Err {
                    message: format!("network already exists: {item_name}"),
                };
            }
            let mut new_cfg = (*cfg).clone();
            new_cfg.networks.push(item);
            if let Err(e) = crate::control::validate::check_vlan_consistency(&new_cfg) {
                return Response::Err { message: e };
            }
            persist_and_swap(state, new_cfg, &format!("added network {item_name}"))
        }
        CrudAction::Update { name, json } => {
            let idx = match cfg.networks.iter().position(|n| n.name() == name) {
                Some(i) => i,
                None => {
                    return Response::Err {
                        message: format!("network not found: {name}"),
                    };
                }
            };
            let mut existing = match serde_json::to_value(&cfg.networks[idx]) {
                Ok(v) => v,
                Err(e) => {
                    return Response::Err {
                        message: format!("serialize existing: {e}"),
                    };
                }
            };
            let partial: serde_json::Value = match serde_json::from_str(json) {
                Ok(v) => v,
                Err(e) => {
                    return Response::Err {
                        message: format!("invalid JSON: {e}"),
                    };
                }
            };
            json_merge(&mut existing, &partial);
            let updated: Network = match serde_json::from_value(existing) {
                Ok(v) => v,
                Err(e) => {
                    return Response::Err {
                        message: format!("merged value invalid: {e}"),
                    };
                }
            };
            let mut new_cfg = (*cfg).clone();
            new_cfg.networks[idx] = updated;
            if let Err(e) = crate::control::validate::check_vlan_consistency(&new_cfg) {
                return Response::Err { message: e };
            }
            persist_and_swap(state, new_cfg, &format!("updated network {name}"))
        }
        CrudAction::Remove { name } => {
            if !cfg.networks.iter().any(|n| n.name() == name) {
                return Response::Err {
                    message: format!("network not found: {name}"),
                };
            }
            let dependents = dependents_on_network(name, &cfg);
            if !dependents.is_empty() {
                return Response::Err {
                    message: format!(
                        "network {name} is referenced by: {}; update or remove those first",
                        dependents.join(", ")
                    ),
                };
            }
            let mut new_cfg = (*cfg).clone();
            new_cfg.networks.retain(|n| n.name() != name);
            persist_and_swap(state, new_cfg, &format!("removed network {name}"))
        }
    }
}

pub(super) fn handle_crud_zone(state: &ControlState, action: &CrudAction) -> Response {
    use crate::config::Zone;
    let cfg = state.config_snapshot();
    match action {
        CrudAction::List => match serde_json::to_string_pretty(&cfg.firewall.zones) {
            Ok(json) => Response::Value { value: json },
            Err(e) => Response::Err {
                message: format!("serialize: {e}"),
            },
        },
        CrudAction::Get { name } => match cfg.firewall.zones.iter().find(|z| z.name == *name) {
            Some(zone) => match serde_json::to_string_pretty(zone) {
                Ok(json) => Response::Value { value: json },
                Err(e) => Response::Err {
                    message: format!("serialize: {e}"),
                },
            },
            None => Response::Err {
                message: format!("zone not found: {name}"),
            },
        },
        CrudAction::Add { json } => {
            let item: Zone = match serde_json::from_str(json) {
                Ok(v) => v,
                Err(e) => {
                    return Response::Err {
                        message: format!("invalid JSON: {e}"),
                    };
                }
            };
            if cfg.firewall.zones.iter().any(|z| z.name == item.name) {
                return Response::Err {
                    message: format!("zone already exists: {}", item.name),
                };
            }
            if let Err(e) = check_zone_network_refs(&item, &cfg) {
                return Response::Err { message: e };
            }
            let mut new_cfg = (*cfg).clone();
            let item_name = item.name.clone();
            new_cfg.firewall.zones.push(item);
            persist_and_swap(state, new_cfg, &format!("added zone {item_name}"))
        }
        CrudAction::Update { name, json } => {
            let idx = match cfg.firewall.zones.iter().position(|z| z.name == *name) {
                Some(i) => i,
                None => {
                    return Response::Err {
                        message: format!("zone not found: {name}"),
                    };
                }
            };
            let mut existing = match serde_json::to_value(&cfg.firewall.zones[idx]) {
                Ok(v) => v,
                Err(e) => {
                    return Response::Err {
                        message: format!("serialize existing: {e}"),
                    };
                }
            };
            let partial: serde_json::Value = match serde_json::from_str(json) {
                Ok(v) => v,
                Err(e) => {
                    return Response::Err {
                        message: format!("invalid JSON: {e}"),
                    };
                }
            };
            json_merge(&mut existing, &partial);
            let updated: Zone = match serde_json::from_value(existing) {
                Ok(v) => v,
                Err(e) => {
                    return Response::Err {
                        message: format!("merged value invalid: {e}"),
                    };
                }
            };
            if let Err(e) = check_zone_network_refs(&updated, &cfg) {
                return Response::Err { message: e };
            }
            let mut new_cfg = (*cfg).clone();
            new_cfg.firewall.zones[idx] = updated;
            persist_and_swap(state, new_cfg, &format!("updated zone {name}"))
        }
        CrudAction::Remove { name } => {
            if !cfg.firewall.zones.iter().any(|z| z.name == *name) {
                return Response::Err {
                    message: format!("zone not found: {name}"),
                };
            }
            let dependents = dependents_on_zone(name, &cfg);
            if !dependents.is_empty() {
                return Response::Err {
                    message: format!(
                        "zone {name} is referenced by: {}; update or remove those first",
                        dependents.join(", ")
                    ),
                };
            }
            let mut new_cfg = (*cfg).clone();
            new_cfg.firewall.zones.retain(|z| z.name != *name);
            persist_and_swap(state, new_cfg, &format!("removed zone {name}"))
        }
    }
}

pub(super) fn handle_crud_rule(state: &ControlState, action: &CrudAction) -> Response {
    use crate::config::Rule;
    let cfg = state.config_snapshot();
    match action {
        CrudAction::List => match serde_json::to_string_pretty(&cfg.firewall.rules) {
            Ok(json) => Response::Value { value: json },
            Err(e) => Response::Err {
                message: format!("serialize: {e}"),
            },
        },
        CrudAction::Get { name } => match cfg.firewall.rules.iter().find(|r| r.name == *name) {
            Some(rule) => match serde_json::to_string_pretty(rule) {
                Ok(json) => Response::Value { value: json },
                Err(e) => Response::Err {
                    message: format!("serialize: {e}"),
                },
            },
            None => Response::Err {
                message: format!("rule not found: {name}"),
            },
        },
        CrudAction::Add { json } => {
            let item: Rule = match serde_json::from_str(json) {
                Ok(v) => v,
                Err(e) => {
                    return Response::Err {
                        message: format!("invalid JSON: {e}"),
                    };
                }
            };
            if cfg.firewall.rules.iter().any(|r| r.name == item.name) {
                return Response::Err {
                    message: format!("rule already exists: {}", item.name),
                };
            }
            if let Err(e) = check_rule_zone_refs(&item, &cfg) {
                return Response::Err { message: e };
            }
            let mut new_cfg = (*cfg).clone();
            let item_name = item.name.clone();
            new_cfg.firewall.rules.push(item);
            persist_and_swap(state, new_cfg, &format!("added rule {item_name}"))
        }
        CrudAction::Update { name, json } => {
            let idx = match cfg.firewall.rules.iter().position(|r| r.name == *name) {
                Some(i) => i,
                None => {
                    return Response::Err {
                        message: format!("rule not found: {name}"),
                    };
                }
            };
            let mut existing = match serde_json::to_value(&cfg.firewall.rules[idx]) {
                Ok(v) => v,
                Err(e) => {
                    return Response::Err {
                        message: format!("serialize existing: {e}"),
                    };
                }
            };
            let partial: serde_json::Value = match serde_json::from_str(json) {
                Ok(v) => v,
                Err(e) => {
                    return Response::Err {
                        message: format!("invalid JSON: {e}"),
                    };
                }
            };
            json_merge(&mut existing, &partial);
            let updated: Rule = match serde_json::from_value(existing) {
                Ok(v) => v,
                Err(e) => {
                    return Response::Err {
                        message: format!("merged value invalid: {e}"),
                    };
                }
            };
            if let Err(e) = check_rule_zone_refs(&updated, &cfg) {
                return Response::Err { message: e };
            }
            let mut new_cfg = (*cfg).clone();
            new_cfg.firewall.rules[idx] = updated;
            persist_and_swap(state, new_cfg, &format!("updated rule {name}"))
        }
        CrudAction::Remove { name } => {
            if !cfg.firewall.rules.iter().any(|r| r.name == *name) {
                return Response::Err {
                    message: format!("rule not found: {name}"),
                };
            }
            let mut new_cfg = (*cfg).clone();
            new_cfg.firewall.rules.retain(|r| r.name != *name);
            persist_and_swap(state, new_cfg, &format!("removed rule {name}"))
        }
    }
}

pub(super) fn handle_crud_wifi(state: &ControlState, action: &CrudAction) -> Response {
    use crate::config::Wifi;
    let cfg = state.config_snapshot();
    match action {
        CrudAction::List => match serde_json::to_string_pretty(&cfg.wifi) {
            Ok(json) => Response::Value { value: json },
            Err(e) => Response::Err {
                message: format!("serialize: {e}"),
            },
        },
        CrudAction::Get { name } => match cfg.wifi.iter().find(|w| w.ssid == *name) {
            Some(wifi) => match serde_json::to_string_pretty(wifi) {
                Ok(json) => Response::Value { value: json },
                Err(e) => Response::Err {
                    message: format!("serialize: {e}"),
                },
            },
            None => Response::Err {
                message: format!("wifi not found: {name}"),
            },
        },
        CrudAction::Add { json } => {
            let item: Wifi = match serde_json::from_str(json) {
                Ok(v) => v,
                Err(e) => {
                    return Response::Err {
                        message: format!("invalid JSON: {e}"),
                    };
                }
            };
            if cfg.wifi.iter().any(|w| w.ssid == item.ssid) {
                return Response::Err {
                    message: format!("wifi already exists: {}", item.ssid),
                };
            }
            if let Err(e) = check_wifi_refs(&item, &cfg) {
                return Response::Err { message: e };
            }
            let mut new_cfg = (*cfg).clone();
            let item_ssid = item.ssid.clone();
            new_cfg.wifi.push(item);
            persist_and_swap(state, new_cfg, &format!("added wifi {item_ssid}"))
        }
        CrudAction::Update { name, json } => {
            let idx = match cfg.wifi.iter().position(|w| w.ssid == *name) {
                Some(i) => i,
                None => {
                    return Response::Err {
                        message: format!("wifi not found: {name}"),
                    };
                }
            };
            let mut existing = match serde_json::to_value(&cfg.wifi[idx]) {
                Ok(v) => v,
                Err(e) => {
                    return Response::Err {
                        message: format!("serialize existing: {e}"),
                    };
                }
            };
            let partial: serde_json::Value = match serde_json::from_str(json) {
                Ok(v) => v,
                Err(e) => {
                    return Response::Err {
                        message: format!("invalid JSON: {e}"),
                    };
                }
            };
            json_merge(&mut existing, &partial);
            let updated: Wifi = match serde_json::from_value(existing) {
                Ok(v) => v,
                Err(e) => {
                    return Response::Err {
                        message: format!("merged value invalid: {e}"),
                    };
                }
            };
            if let Err(e) = check_wifi_refs(&updated, &cfg) {
                return Response::Err { message: e };
            }
            let mut new_cfg = (*cfg).clone();
            new_cfg.wifi[idx] = updated;
            persist_and_swap(state, new_cfg, &format!("updated wifi {name}"))
        }
        CrudAction::Remove { name } => {
            if !cfg.wifi.iter().any(|w| w.ssid == *name) {
                return Response::Err {
                    message: format!("wifi not found: {name}"),
                };
            }
            let mut new_cfg = (*cfg).clone();
            new_cfg.wifi.retain(|w| w.ssid != *name);
            persist_and_swap(state, new_cfg, &format!("removed wifi {name}"))
        }
    }
}

pub(super) fn handle_crud_radio(state: &ControlState, action: &CrudAction) -> Response {
    use crate::config::Radio;
    let cfg = state.config_snapshot();
    match action {
        CrudAction::List => match serde_json::to_string_pretty(&cfg.radios) {
            Ok(json) => Response::Value { value: json },
            Err(e) => Response::Err {
                message: format!("serialize: {e}"),
            },
        },
        CrudAction::Get { name } => match cfg.radios.iter().find(|r| r.phy == *name) {
            Some(radio) => match serde_json::to_string_pretty(radio) {
                Ok(json) => Response::Value { value: json },
                Err(e) => Response::Err {
                    message: format!("serialize: {e}"),
                },
            },
            None => Response::Err {
                message: format!("radio not found: {name}"),
            },
        },
        CrudAction::Add { json } => {
            let item: Radio = match serde_json::from_str(json) {
                Ok(v) => v,
                Err(e) => {
                    return Response::Err {
                        message: format!("invalid JSON: {e}"),
                    };
                }
            };
            if cfg.radios.iter().any(|r| r.phy == item.phy) {
                return Response::Err {
                    message: format!("radio already exists: {}", item.phy),
                };
            }
            let mut new_cfg = (*cfg).clone();
            let item_phy = item.phy.clone();
            new_cfg.radios.push(item);
            persist_and_swap(state, new_cfg, &format!("added radio {item_phy}"))
        }
        CrudAction::Update { name, json } => {
            let idx = match cfg.radios.iter().position(|r| r.phy == *name) {
                Some(i) => i,
                None => {
                    return Response::Err {
                        message: format!("radio not found: {name}"),
                    };
                }
            };
            let mut existing = match serde_json::to_value(&cfg.radios[idx]) {
                Ok(v) => v,
                Err(e) => {
                    return Response::Err {
                        message: format!("serialize existing: {e}"),
                    };
                }
            };
            let partial: serde_json::Value = match serde_json::from_str(json) {
                Ok(v) => v,
                Err(e) => {
                    return Response::Err {
                        message: format!("invalid JSON: {e}"),
                    };
                }
            };
            json_merge(&mut existing, &partial);
            let updated: Radio = match serde_json::from_value(existing) {
                Ok(v) => v,
                Err(e) => {
                    return Response::Err {
                        message: format!("merged value invalid: {e}"),
                    };
                }
            };
            let mut new_cfg = (*cfg).clone();
            new_cfg.radios[idx] = updated;
            persist_and_swap(state, new_cfg, &format!("updated radio {name}"))
        }
        CrudAction::Remove { name } => {
            if !cfg.radios.iter().any(|r| r.phy == *name) {
                return Response::Err {
                    message: format!("radio not found: {name}"),
                };
            }
            let dependents = dependents_on_radio(name, &cfg);
            if !dependents.is_empty() {
                return Response::Err {
                    message: format!(
                        "radio {name} is referenced by: {}; update or remove those first",
                        dependents.join(", ")
                    ),
                };
            }
            let mut new_cfg = (*cfg).clone();
            new_cfg.radios.retain(|r| r.phy != *name);
            persist_and_swap(state, new_cfg, &format!("removed radio {name}"))
        }
    }
}

/// Service CRUD. Services are configured (name, rootfs, entrypoint,
/// caps, …) but their runtime state (pid, state, restart count) lives
/// in the `Supervisor`. This handler only mutates the *declaration* —
/// a subsequent `reload` or process restart picks up the change. Adding
/// a new service does not spawn it until reload; removing a service
/// does not kill a running instance until reload. This matches the
/// pattern for every other collection: declarations persist, reload
/// applies.
pub(super) fn handle_crud_service(state: &ControlState, action: &CrudAction) -> Response {
    use crate::config::Service;
    let cfg = state.config_snapshot();
    match action {
        CrudAction::List => match serde_json::to_string_pretty(&cfg.services) {
            Ok(json) => Response::Value { value: json },
            Err(e) => Response::Err {
                message: format!("serialize: {e}"),
            },
        },
        CrudAction::Get { name } => match cfg.services.iter().find(|s| s.name == *name) {
            Some(svc) => match serde_json::to_string_pretty(svc) {
                Ok(json) => Response::Value { value: json },
                Err(e) => Response::Err {
                    message: format!("serialize: {e}"),
                },
            },
            None => Response::Err {
                message: format!("service not found: {name}"),
            },
        },
        CrudAction::Add { json } => {
            let item: Service = match serde_json::from_str(json) {
                Ok(v) => v,
                Err(e) => {
                    return Response::Err {
                        message: format!("invalid JSON: {e}"),
                    };
                }
            };
            let item_name = item.name.clone();
            if cfg.services.iter().any(|s| s.name == item_name) {
                return Response::Err {
                    message: format!("service already exists: {item_name}"),
                };
            }
            // depends_on cross-check: every listed dep must exist in
            // the (soon-to-be) service list. Catches typos before reload.
            for dep in &item.depends_on {
                if *dep == item_name {
                    return Response::Err {
                        message: format!("service {item_name} depends on itself"),
                    };
                }
                if !cfg.services.iter().any(|s| s.name == *dep) {
                    return Response::Err {
                        message: format!("service {item_name} depends on unknown {dep}"),
                    };
                }
            }
            let mut new_cfg = (*cfg).clone();
            new_cfg.services.push(item);
            persist_and_swap(state, new_cfg, &format!("added service {item_name}"))
        }
        CrudAction::Update { name, json } => {
            let idx = match cfg.services.iter().position(|s| s.name == *name) {
                Some(i) => i,
                None => {
                    return Response::Err {
                        message: format!("service not found: {name}"),
                    };
                }
            };
            let mut existing = match serde_json::to_value(&cfg.services[idx]) {
                Ok(v) => v,
                Err(e) => {
                    return Response::Err {
                        message: format!("serialize existing: {e}"),
                    };
                }
            };
            let partial: serde_json::Value = match serde_json::from_str(json) {
                Ok(v) => v,
                Err(e) => {
                    return Response::Err {
                        message: format!("invalid JSON: {e}"),
                    };
                }
            };
            json_merge(&mut existing, &partial);
            let updated: Service = match serde_json::from_value(existing) {
                Ok(v) => v,
                Err(e) => {
                    return Response::Err {
                        message: format!("merged value invalid: {e}"),
                    };
                }
            };
            let mut new_cfg = (*cfg).clone();
            new_cfg.services[idx] = updated;
            persist_and_swap(state, new_cfg, &format!("updated service {name}"))
        }
        CrudAction::Remove { name } => {
            if !cfg.services.iter().any(|s| s.name == *name) {
                return Response::Err {
                    message: format!("service not found: {name}"),
                };
            }
            // Refuse to leave dangling depends_on references. If any
            // other service depends on the one being removed, force
            // the operator to update the dependent first.
            let dependents: Vec<&str> = cfg
                .services
                .iter()
                .filter(|s| s.depends_on.iter().any(|d| d == name))
                .map(|s| s.name.as_str())
                .collect();
            if !dependents.is_empty() {
                return Response::Err {
                    message: format!(
                        "service {name} is depended on by: {}; update or remove those first",
                        dependents.join(", ")
                    ),
                };
            }
            let mut new_cfg = (*cfg).clone();
            new_cfg.services.retain(|s| s.name != *name);
            persist_and_swap(state, new_cfg, &format!("removed service {name}"))
        }
    }
}

pub(super) fn handle_crud_port_forward(state: &ControlState, action: &CrudAction) -> Response {
    use crate::config::PortForward;
    use crate::control::validate::check_port_forward;
    let cfg = state.config_snapshot();
    match action {
        CrudAction::List => match serde_json::to_string_pretty(&cfg.port_forwards) {
            Ok(json) => Response::Value { value: json },
            Err(e) => Response::Err {
                message: format!("serialize: {e}"),
            },
        },
        CrudAction::Get { name } => match cfg.port_forwards.iter().find(|p| p.name == *name) {
            Some(pf) => match serde_json::to_string_pretty(pf) {
                Ok(json) => Response::Value { value: json },
                Err(e) => Response::Err {
                    message: format!("serialize: {e}"),
                },
            },
            None => Response::Err {
                message: format!("port-forward not found: {name}"),
            },
        },
        CrudAction::Add { json } => {
            let item: PortForward = match serde_json::from_str(json) {
                Ok(v) => v,
                Err(e) => {
                    return Response::Err {
                        message: format!("invalid JSON: {e}"),
                    };
                }
            };
            if cfg.port_forwards.iter().any(|p| p.name == item.name) {
                return Response::Err {
                    message: format!("port-forward already exists: {}", item.name),
                };
            }
            if let Err(e) = check_port_forward(&item, &cfg) {
                return Response::Err { message: e };
            }
            let mut new_cfg = (*cfg).clone();
            let item_name = item.name.clone();
            new_cfg.port_forwards.push(item);
            persist_and_swap(state, new_cfg, &format!("added port-forward {item_name}"))
        }
        CrudAction::Update { name, json } => {
            let idx = match cfg.port_forwards.iter().position(|p| p.name == *name) {
                Some(i) => i,
                None => {
                    return Response::Err {
                        message: format!("port-forward not found: {name}"),
                    };
                }
            };
            let mut existing = match serde_json::to_value(&cfg.port_forwards[idx]) {
                Ok(v) => v,
                Err(e) => {
                    return Response::Err {
                        message: format!("serialize existing: {e}"),
                    };
                }
            };
            let partial: serde_json::Value = match serde_json::from_str(json) {
                Ok(v) => v,
                Err(e) => {
                    return Response::Err {
                        message: format!("invalid JSON: {e}"),
                    };
                }
            };
            json_merge(&mut existing, &partial);
            let updated: PortForward = match serde_json::from_value(existing) {
                Ok(v) => v,
                Err(e) => {
                    return Response::Err {
                        message: format!("merged value invalid: {e}"),
                    };
                }
            };
            if let Err(e) = check_port_forward(&updated, &cfg) {
                return Response::Err { message: e };
            }
            let mut new_cfg = (*cfg).clone();
            new_cfg.port_forwards[idx] = updated;
            persist_and_swap(state, new_cfg, &format!("updated port-forward {name}"))
        }
        CrudAction::Remove { name } => {
            if !cfg.port_forwards.iter().any(|p| p.name == *name) {
                return Response::Err {
                    message: format!("port-forward not found: {name}"),
                };
            }
            let mut new_cfg = (*cfg).clone();
            new_cfg.port_forwards.retain(|p| p.name != *name);
            persist_and_swap(state, new_cfg, &format!("removed port-forward {name}"))
        }
    }
}

pub(super) fn handle_crud_wg_peer(state: &ControlState, action: &CrudAction) -> Response {
    use crate::config::WireguardPeer;
    let cfg = state.config_snapshot();
    // MVP: one wg iface supported. The index 0 convention keeps the
    // JSON payloads flat — peer CRUD without a `parent_iface` field —
    // while leaving room for a future multi-iface `wg-peer@wg1` syntax
    // if/when a second tunnel becomes a real requirement.
    if cfg.wireguard.is_empty() {
        return Response::Err {
            message: "wg-peer: no [[wireguard]] iface declared in config \
                      (add one before managing peers)"
                .to_string(),
        };
    }
    match action {
        CrudAction::List => match serde_json::to_string_pretty(&cfg.wireguard[0].peers) {
            Ok(json) => Response::Value { value: json },
            Err(e) => Response::Err {
                message: format!("serialize: {e}"),
            },
        },
        CrudAction::Get { name } => match cfg.wireguard[0].peers.iter().find(|p| p.name == *name) {
            Some(peer) => match serde_json::to_string_pretty(peer) {
                Ok(json) => Response::Value { value: json },
                Err(e) => Response::Err {
                    message: format!("serialize: {e}"),
                },
            },
            None => Response::Err {
                message: format!("wg-peer not found: {name}"),
            },
        },
        CrudAction::Add { json } => {
            let item: WireguardPeer = match serde_json::from_str(json) {
                Ok(v) => v,
                Err(e) => {
                    return Response::Err {
                        message: format!("invalid JSON: {e}"),
                    };
                }
            };
            if cfg.wireguard[0].peers.iter().any(|p| p.name == item.name) {
                return Response::Err {
                    message: format!("wg-peer already exists: {}", item.name),
                };
            }
            if let Err(e) = validate_wg_peer(&item) {
                return Response::Err { message: e };
            }
            let mut new_cfg = (*cfg).clone();
            let item_name = item.name.clone();
            new_cfg.wireguard[0].peers.push(item);
            persist_and_swap(state, new_cfg, &format!("added wg-peer {item_name}"))
        }
        CrudAction::Update { name, json } => {
            let idx = match cfg.wireguard[0].peers.iter().position(|p| p.name == *name) {
                Some(i) => i,
                None => {
                    return Response::Err {
                        message: format!("wg-peer not found: {name}"),
                    };
                }
            };
            let mut existing = match serde_json::to_value(&cfg.wireguard[0].peers[idx]) {
                Ok(v) => v,
                Err(e) => {
                    return Response::Err {
                        message: format!("serialize existing: {e}"),
                    };
                }
            };
            let partial: serde_json::Value = match serde_json::from_str(json) {
                Ok(v) => v,
                Err(e) => {
                    return Response::Err {
                        message: format!("invalid JSON: {e}"),
                    };
                }
            };
            json_merge(&mut existing, &partial);
            let updated: WireguardPeer = match serde_json::from_value(existing) {
                Ok(v) => v,
                Err(e) => {
                    return Response::Err {
                        message: format!("merged value invalid: {e}"),
                    };
                }
            };
            if let Err(e) = validate_wg_peer(&updated) {
                return Response::Err { message: e };
            }
            let mut new_cfg = (*cfg).clone();
            new_cfg.wireguard[0].peers[idx] = updated;
            persist_and_swap(state, new_cfg, &format!("updated wg-peer {name}"))
        }
        CrudAction::Remove { name } => {
            if !cfg.wireguard[0].peers.iter().any(|p| p.name == *name) {
                return Response::Err {
                    message: format!("wg-peer not found: {name}"),
                };
            }
            let mut new_cfg = (*cfg).clone();
            new_cfg.wireguard[0].peers.retain(|p| p.name != *name);
            persist_and_swap(state, new_cfg, &format!("removed wg-peer {name}"))
        }
    }
}

/// Validate the shape of a WireGuard peer before persisting. Cheap
/// structural checks only — we don't round-trip through `wg` here
/// (no system deps in this crate), we just ensure the pubkey looks
/// like a 32-byte base64 value and allowed_ips parses as a CIDR
/// list. Malformed-at-install is still caught at apply time, but
/// rejecting early gives operators an immediate "your typo is
/// here" instead of a silent dead peer.
fn validate_wg_peer(p: &crate::config::WireguardPeer) -> Result<(), String> {
    if p.name.is_empty() {
        return Err("wg-peer: name must not be empty".into());
    }
    // Base64 of 32 bytes → 44 chars with one '=' padding.
    if p.pubkey.len() != 44 || !p.pubkey.ends_with('=') {
        return Err(format!(
            "wg-peer {}: pubkey must be 44-char base64 ending in '='",
            p.name
        ));
    }
    if let Some(psk) = &p.preshared_key {
        if psk.len() != 44 || !psk.ends_with('=') {
            return Err(format!(
                "wg-peer {}: preshared_key must be 44-char base64",
                p.name
            ));
        }
    }
    // allowed_ips: comma-separated CIDRs, each parseable.
    if p.allowed_ips.trim().is_empty() {
        return Err(format!("wg-peer {}: allowed_ips must not be empty", p.name));
    }
    for cidr in p.allowed_ips.split(',').map(str::trim) {
        let Some((addr, prefix)) = cidr.split_once('/') else {
            return Err(format!(
                "wg-peer {}: allowed_ips entry {:?} missing /prefix",
                p.name, cidr
            ));
        };
        // Accept both v4 and v6 numerically; we don't enforce which.
        let ip_ok = addr.parse::<std::net::Ipv4Addr>().is_ok()
            || addr.parse::<std::net::Ipv6Addr>().is_ok();
        if !ip_ok {
            return Err(format!(
                "wg-peer {}: allowed_ips entry {:?} has invalid address",
                p.name, cidr
            ));
        }
        let prefix: u8 = prefix.parse().map_err(|_| {
            format!(
                "wg-peer {}: allowed_ips entry {:?} has invalid prefix",
                p.name, cidr
            )
        })?;
        if prefix > 128 {
            return Err(format!(
                "wg-peer {}: allowed_ips prefix {} out of range",
                p.name, prefix
            ));
        }
    }
    Ok(())
}

/// Server-generated peer enrollment: runs `wg genkey` + `wg pubkey`
/// to produce a fresh client keypair, adds the public half to
/// `cfg.wireguard[0].peers`, persists, and returns a complete client
/// `.conf` (with the generated PRIVATE key embedded) as a Value
/// response. The private key leaves the router exactly once in this
/// reply and is never persisted — if the operator loses it, re-enroll
/// is the fix (that's also why there's no separate "give me alice's
/// private key again" RPC).
///
/// Requires the `wg` binary from wireguard-tools — call fails early
/// with a friendly error if the binary is missing (e.g. test harness
/// VM without the package).
pub(super) fn handle_wg_enroll(
    state: &ControlState,
    name: &str,
    allowed_ips: &str,
    endpoint_host: &str,
    dns: Option<&str>,
) -> Response {
    use std::process::Command;

    let cfg = state.config_snapshot();
    if cfg.wireguard.is_empty() {
        return Response::Err {
            message: "wg-enroll: no [[wireguard]] iface declared in config".to_string(),
        };
    }
    let wg = &cfg.wireguard[0];
    if wg.peers.iter().any(|p| p.name == name) {
        return Response::Err {
            message: format!("wg-enroll: peer already exists: {name}"),
        };
    }

    // 1. Generate client private key.
    let genkey_out = match Command::new("wg").arg("genkey").output() {
        Ok(o) if o.status.success() => o,
        Ok(o) => {
            return Response::Err {
                message: format!(
                    "wg-enroll: wg genkey failed: {}",
                    String::from_utf8_lossy(&o.stderr)
                ),
            };
        }
        Err(e) => {
            return Response::Err {
                message: format!("wg-enroll: wg genkey: {e} (is wireguard-tools installed?)"),
            };
        }
    };
    let client_priv = String::from_utf8_lossy(&genkey_out.stdout)
        .trim()
        .to_string();

    // 2. Derive client pubkey (pipe private key into `wg pubkey`).
    let client_pub = match run_wg_pubkey(&client_priv) {
        Ok(s) => s,
        Err(e) => {
            return Response::Err {
                message: format!("wg-enroll: wg pubkey: {e}"),
            };
        }
    };

    // 3. Derive SERVER pubkey from the on-disk private key. Must
    //    match what install-time will push to the iface. If the file
    //    doesn't exist yet (first enroll before first reload), we
    //    can fall back to generating + persisting it now so the
    //    rendered client .conf's PublicKey line matches reality.
    let server_priv = match std::fs::read_to_string(&wg.key_path) {
        Ok(s) => s.trim().to_string(),
        Err(_) => {
            // Generate + persist so both halves line up.
            let g = match Command::new("wg").arg("genkey").output() {
                Ok(o) if o.status.success() => o,
                Ok(o) => {
                    return Response::Err {
                        message: format!(
                            "wg-enroll: server key auto-gen failed: {}",
                            String::from_utf8_lossy(&o.stderr)
                        ),
                    };
                }
                Err(e) => {
                    return Response::Err {
                        message: format!("wg-enroll: server key auto-gen: {e}"),
                    };
                }
            };
            let k = String::from_utf8_lossy(&g.stdout).trim().to_string();
            if let Some(parent) = std::path::Path::new(&wg.key_path).parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if let Err(e) = std::fs::write(&wg.key_path, format!("{k}\n")) {
                return Response::Err {
                    message: format!("wg-enroll: write {}: {e}", wg.key_path),
                };
            }
            #[cfg(target_os = "linux")]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ =
                    std::fs::set_permissions(&wg.key_path, std::fs::Permissions::from_mode(0o600));
            }
            k
        }
    };
    let server_pub = match run_wg_pubkey(&server_priv) {
        Ok(s) => s,
        Err(e) => {
            return Response::Err {
                message: format!("wg-enroll: server pubkey: {e}"),
            };
        }
    };

    // 4. Persist the new peer (using CLIENT pubkey, not private).
    let peer = crate::config::WireguardPeer {
        name: name.to_string(),
        pubkey: client_pub.clone(),
        allowed_ips: allowed_ips.to_string(),
        preshared_key: None,
        endpoint: None,
        persistent_keepalive: None,
    };
    let mut new_cfg = (*cfg).clone();
    new_cfg.wireguard[0].peers.push(peer);
    let persist_resp = persist_and_swap(state, new_cfg, &format!("wg-enroll {name}"));
    // Persist returns Response::Ok on success, Err on failure.
    if matches!(persist_resp, Response::Err { .. }) {
        return persist_resp;
    }

    // 5. Render the client-side .conf. Note: AllowedIPs = 0.0.0.0/0
    //    is the "route-all" default — full-tunnel VPN. A split-
    //    tunnel variant (e.g. only LAN subnets) can be operator-
    //    edited on the client side; we don't over-spec here.
    let mut conf = String::new();
    let _ = write_client_conf(
        &mut conf,
        &client_priv,
        allowed_ips,
        &server_pub,
        wg.listen_port,
        endpoint_host,
        dns,
    );

    Response::Value { value: conf }
}

fn run_wg_pubkey(priv_key: &str) -> Result<String, String> {
    use std::io::Write as _;
    use std::process::{Command, Stdio};
    let mut child = Command::new("wg")
        .arg("pubkey")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn: {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(priv_key.as_bytes());
        let _ = stdin.write_all(b"\n");
    }
    let out = child.wait_with_output().map_err(|e| format!("wait: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "wg pubkey: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn write_client_conf(
    out: &mut String,
    client_priv: &str,
    client_address: &str,
    server_pub: &str,
    server_port: u16,
    endpoint_host: &str,
    dns: Option<&str>,
) -> std::fmt::Result {
    use std::fmt::Write as _;
    writeln!(out, "[Interface]")?;
    writeln!(out, "PrivateKey = {client_priv}")?;
    writeln!(out, "Address = {client_address}")?;
    if let Some(d) = dns {
        writeln!(out, "DNS = {d}")?;
    }
    writeln!(out)?;
    writeln!(out, "[Peer]")?;
    writeln!(out, "PublicKey = {server_pub}")?;
    writeln!(out, "AllowedIPs = 0.0.0.0/0")?;
    writeln!(out, "Endpoint = {endpoint_host}:{server_port}")?;
    writeln!(out, "PersistentKeepalive = 25")?;
    Ok(())
}

pub(super) fn handle_crud_ddns(state: &ControlState, action: &CrudAction) -> Response {
    use crate::config::Ddns;
    let cfg = state.config_snapshot();
    match action {
        CrudAction::List => match serde_json::to_string_pretty(&cfg.ddns) {
            Ok(json) => Response::Value { value: json },
            Err(e) => Response::Err {
                message: format!("serialize: {e}"),
            },
        },
        CrudAction::Get { name } => match cfg.ddns.iter().find(|d| d.name() == name) {
            Some(d) => match serde_json::to_string_pretty(d) {
                Ok(json) => Response::Value { value: json },
                Err(e) => Response::Err {
                    message: format!("serialize: {e}"),
                },
            },
            None => Response::Err {
                message: format!("ddns not found: {name}"),
            },
        },
        CrudAction::Add { json } => {
            let item: Ddns = match serde_json::from_str(json) {
                Ok(v) => v,
                Err(e) => {
                    return Response::Err {
                        message: format!("invalid JSON: {e}"),
                    };
                }
            };
            let item_name = item.name().to_string();
            if cfg.ddns.iter().any(|d| d.name() == item_name) {
                return Response::Err {
                    message: format!("ddns already exists: {item_name}"),
                };
            }
            let mut new_cfg = (*cfg).clone();
            new_cfg.ddns.push(item);
            persist_and_swap(state, new_cfg, &format!("added ddns {item_name}"))
        }
        CrudAction::Update { name, json } => {
            let idx = match cfg.ddns.iter().position(|d| d.name() == name) {
                Some(i) => i,
                None => {
                    return Response::Err {
                        message: format!("ddns not found: {name}"),
                    };
                }
            };
            let mut existing = match serde_json::to_value(&cfg.ddns[idx]) {
                Ok(v) => v,
                Err(e) => {
                    return Response::Err {
                        message: format!("serialize existing: {e}"),
                    };
                }
            };
            let partial: serde_json::Value = match serde_json::from_str(json) {
                Ok(v) => v,
                Err(e) => {
                    return Response::Err {
                        message: format!("invalid JSON: {e}"),
                    };
                }
            };
            json_merge(&mut existing, &partial);
            // Ddns is a tagged enum — the `provider` field must be
            // present in the merged value for serde to dispatch to
            // the right variant. json_merge preserves the existing
            // tag by default unless the partial overrode it.
            let updated: Ddns = match serde_json::from_value(existing) {
                Ok(v) => v,
                Err(e) => {
                    return Response::Err {
                        message: format!("merged value invalid: {e}"),
                    };
                }
            };
            let mut new_cfg = (*cfg).clone();
            new_cfg.ddns[idx] = updated;
            persist_and_swap(state, new_cfg, &format!("updated ddns {name}"))
        }
        CrudAction::Remove { name } => {
            if !cfg.ddns.iter().any(|d| d.name() == name) {
                return Response::Err {
                    message: format!("ddns not found: {name}"),
                };
            }
            let mut new_cfg = (*cfg).clone();
            new_cfg.ddns.retain(|d| d.name() != name);
            persist_and_swap(state, new_cfg, &format!("removed ddns {name}"))
        }
    }
}
