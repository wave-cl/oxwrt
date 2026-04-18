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
        CrudAction::Get { name } => {
            match cfg.networks.iter().find(|n| n.name() == name) {
                Some(net) => match serde_json::to_string_pretty(net) {
                    Ok(json) => Response::Value { value: json },
                    Err(e) => Response::Err {
                        message: format!("serialize: {e}"),
                    },
                },
                None => Response::Err {
                    message: format!("network not found: {name}"),
                },
            }
        }
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
        CrudAction::Get { name } => {
            match cfg.firewall.zones.iter().find(|z| z.name == *name) {
                Some(zone) => match serde_json::to_string_pretty(zone) {
                    Ok(json) => Response::Value { value: json },
                    Err(e) => Response::Err {
                        message: format!("serialize: {e}"),
                    },
                },
                None => Response::Err {
                    message: format!("zone not found: {name}"),
                },
            }
        }
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
        CrudAction::Get { name } => {
            match cfg.firewall.rules.iter().find(|r| r.name == *name) {
                Some(rule) => match serde_json::to_string_pretty(rule) {
                    Ok(json) => Response::Value { value: json },
                    Err(e) => Response::Err {
                        message: format!("serialize: {e}"),
                    },
                },
                None => Response::Err {
                    message: format!("rule not found: {name}"),
                },
            }
        }
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
        CrudAction::Get { name } => {
            match cfg.wifi.iter().find(|w| w.ssid == *name) {
                Some(wifi) => match serde_json::to_string_pretty(wifi) {
                    Ok(json) => Response::Value { value: json },
                    Err(e) => Response::Err {
                        message: format!("serialize: {e}"),
                    },
                },
                None => Response::Err {
                    message: format!("wifi not found: {name}"),
                },
            }
        }
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
        CrudAction::Get { name } => {
            match cfg.radios.iter().find(|r| r.phy == *name) {
                Some(radio) => match serde_json::to_string_pretty(radio) {
                    Ok(json) => Response::Value { value: json },
                    Err(e) => Response::Err {
                        message: format!("serialize: {e}"),
                    },
                },
                None => Response::Err {
                    message: format!("radio not found: {name}"),
                },
            }
        }
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

pub(super) fn handle_crud_port_forward(
    state: &ControlState,
    action: &CrudAction,
) -> Response {
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
            persist_and_swap(
                state,
                new_cfg,
                &format!("added port-forward {item_name}"),
            )
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
