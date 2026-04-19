//! Multi-WAN failover coordinator.
//!
//! With one WAN, this module is a no-op — the single DHCP client
//! writes its lease into the shared slot and the kernel default
//! route is set on acquire. With two or more WANs declared, each
//! gets its own DHCP client running in parallel; this coordinator
//! picks the "active" one based on priority + health and keeps
//! the kernel's default route pointing at that WAN's gateway.
//!
//! # Health model (v1)
//!
//! A WAN is healthy if its DHCP lease slot is `Some` — i.e. the
//! client acquired + renewed successfully. Lease loss (expiry,
//! rebind failure, iface down) flips the slot to `None`; the
//! coordinator notices on its next 2 s poll and fails over to
//! the next highest-priority healthy WAN.
//!
//! ICMP probes for "lease valid but upstream is dead" belong to
//! v2 — the lease-state signal catches carrier drops and the
//! common residential-ISP outage shape (DHCP renew fails when
//! the upstream is gone).
//!
//! # Failover semantics
//!
//! - Every 2 s the coordinator scans `WanLeases`.
//! - `active = wans.filter(healthy).min_by_key(priority).first()`
//! - When `active` changes:
//!     1. `ip route del default`  (old default, if any)
//!     2. `ip route add default via <new-gw> dev <new-iface>`
//!     3. Copy `WanLeases[new]` into the legacy `SharedLease` so
//!        downstream code (DDNS updater, Status RPC, metrics)
//!        automatically picks up the new externally-visible IP.
//!
//! - When all WANs go unhealthy, the default route is removed
//!   but the SharedLease is NOT cleared (so DDNS doesn't push a
//!   spurious "no IP" update). It'll be overwritten on the next
//!   successful acquire.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use oxwrt_api::config::{Config, Network};
use rtnetlink::{Handle, RouteMessageBuilder};

use crate::wan_dhcp::{DhcpLease, SharedLease};

/// Per-WAN lease slots. Each DHCP client writes into its own entry
/// keyed by Wan.name. The failover coordinator reads all slots,
/// picks the best healthy one, and mirrors its lease into the
/// legacy `SharedLease`.
pub type WanLeases = Arc<RwLock<HashMap<String, Option<DhcpLease>>>>;

pub fn new_wan_leases() -> WanLeases {
    Arc::new(RwLock::new(HashMap::new()))
}

/// The currently-active WAN (by name). `None` = no healthy WAN.
/// Updated by the failover coordinator; read by Status RPC.
pub type ActiveWan = Arc<Mutex<Option<String>>>;

pub fn new_active_wan() -> ActiveWan {
    Arc::new(Mutex::new(None))
}

/// Spawn the failover coordinator. `cfg_snapshot` captures the
/// WAN-set ordering at spawn time; for v1 we don't re-read cfg
/// mid-run (a `reload` that changes WANs re-spawns the whole
/// subsystem anyway via supervisor rebuild).
pub fn spawn(
    cfg: Arc<Config>,
    wan_leases: WanLeases,
    active_wan: ActiveWan,
    shared_lease: SharedLease,
    handle: Handle,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut prev_active: Option<(String, Ipv4Addr)> = None;
        let mut tick = tokio::time::interval(Duration::from_secs(2));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            let desired = pick_active(&cfg, &wan_leases);
            // Only swap when the (name, gateway) tuple changes —
            // same WAN re-acquiring the same gateway is a no-op
            // for routing; re-installing the route in that case
            // would needlessly flap conntrack on ongoing flows.
            let now_key = desired
                .as_ref()
                .and_then(|(n, l)| l.gateway.map(|gw| (n.clone(), gw)));
            if now_key == prev_active {
                // Still mirror the lease — it might have changed
                // fields other than name+gateway (lease time on
                // renew, new DNS servers).
                if let Some((name, lease)) = &desired {
                    *active_wan.lock().unwrap() = Some(name.clone());
                    *shared_lease.write().unwrap() = Some(lease.clone());
                }
                continue;
            }

            // Transition. Log it loudly — failover events are
            // exactly the thing operators will grep dmesg for
            // after a mystery outage.
            match (&prev_active, &now_key) {
                (None, Some((n, gw))) => tracing::warn!(active = %n, gateway = %gw, "wan failover: activating"),
                (Some((old, _)), Some((new, gw))) if old == new => {
                    tracing::info!(wan = %new, gateway = %gw, "wan failover: gateway changed on same WAN")
                }
                (Some((old, _)), Some((new, gw))) => {
                    tracing::warn!(from = %old, to = %new, gateway = %gw, "wan failover: switching")
                }
                (Some((old, _)), None) => {
                    tracing::error!(was = %old, "wan failover: no healthy WAN left, removing default route")
                }
                (None, None) => {}
            }

            // Remove old default route (if any) BEFORE installing
            // new — avoids transient two-defaults scenarios where
            // the kernel load-balances between the old-dead and
            // new-alive gateways.
            if prev_active.is_some() {
                del_default_route(&handle).await;
            }
            if let Some((name, lease)) = &desired {
                if let Some(gw) = lease.gateway {
                    // Find the iface for this WAN from cfg.
                    let iface = cfg.networks.iter().find_map(|n| match n {
                        Network::Wan { name: n2, iface, .. } if n2 == name => Some(iface.clone()),
                        _ => None,
                    });
                    if let Some(iface) = iface {
                        add_default_route(&handle, &iface, gw).await;
                    }
                }
                *active_wan.lock().unwrap() = Some(name.clone());
                *shared_lease.write().unwrap() = Some(lease.clone());
            } else {
                *active_wan.lock().unwrap() = None;
            }

            prev_active = now_key;
        }
    })
}

/// Pure selection: given a config + per-WAN lease map, return the
/// (name, lease) of the best healthy WAN, or None. Highest
/// priority (lowest number) among WANs with a Some lease wins.
/// Extracted for unit testing.
pub fn pick_active(cfg: &Config, wan_leases: &WanLeases) -> Option<(String, DhcpLease)> {
    let leases = wan_leases.read().ok()?;
    let mut best: Option<(u32, String, DhcpLease)> = None;
    for net in &cfg.networks {
        if let Network::Wan { name, priority, .. } = net {
            if let Some(Some(lease)) = leases.get(name) {
                let take = match &best {
                    None => true,
                    Some((p, _, _)) => *priority < *p,
                };
                if take {
                    best = Some((*priority, name.clone(), lease.clone()));
                }
            }
        }
    }
    best.map(|(_, name, lease)| (name, lease))
}

async fn add_default_route(handle: &Handle, iface: &str, gw: Ipv4Addr) {
    // Find the iface index via rtnetlink. Short-circuit errors
    // to a warn rather than a hard failure — the coordinator
    // loops every 2 s and will retry on the next tick.
    use futures_util::stream::TryStreamExt;
    let mut stream = handle.link().get().match_name(iface.to_string()).execute();
    let idx = match stream.try_next().await {
        Ok(Some(msg)) => msg.header.index,
        _ => {
            tracing::warn!(iface = %iface, "wan failover: iface not found, can't install default route");
            return;
        }
    };
    let route = RouteMessageBuilder::<Ipv4Addr>::new()
        .destination_prefix(Ipv4Addr::UNSPECIFIED, 0)
        .gateway(gw)
        .output_interface(idx)
        .build();
    match handle.route().add(route).execute().await {
        Ok(()) => tracing::info!(iface = %iface, %gw, "wan failover: default route installed"),
        Err(e) => {
            // EEXIST: a default is still there. Try del-and-re-add.
            tracing::warn!(iface = %iface, %gw, error = %e, "wan failover: add default failed; trying del+add");
            del_default_route(handle).await;
            let route = RouteMessageBuilder::<Ipv4Addr>::new()
                .destination_prefix(Ipv4Addr::UNSPECIFIED, 0)
                .gateway(gw)
                .output_interface(idx)
                .build();
            if let Err(e) = handle.route().add(route).execute().await {
                tracing::error!(iface = %iface, %gw, error = %e, "wan failover: add after del also failed");
            }
        }
    }
}

async fn del_default_route(handle: &Handle) {
    // Delete the UNSPECIFIED/0 entry. Build the minimal message
    // the kernel accepts for delete — destination prefix is the
    // key, the rest is ignored on DEL.
    let route = RouteMessageBuilder::<Ipv4Addr>::new()
        .destination_prefix(Ipv4Addr::UNSPECIFIED, 0)
        .build();
    match handle.route().del(route).execute().await {
        Ok(()) => tracing::info!("wan failover: old default route removed"),
        Err(e) => {
            // ESRCH is fine — the route was already gone.
            tracing::debug!(error = %e, "wan failover: del default returned (may be absent)");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn mk_lease(addr: [u8; 4], gw: [u8; 4]) -> DhcpLease {
        DhcpLease {
            address: Ipv4Addr::from(addr),
            prefix: 24,
            gateway: Some(Ipv4Addr::from(gw)),
            dns: vec![],
            lease_seconds: 3600,
            server: Ipv4Addr::from(gw),
        }
    }

    fn wan(name: &str, iface: &str, priority: u32) -> Network {
        Network::Wan {
            name: name.into(),
            iface: iface.into(),
            wan: oxwrt_api::config::WanConfig::Dhcp,
            ipv6_pd: false,
            sqm: None,
            priority,
            probe_target: None,
        }
    }

    fn mk_cfg(wans: Vec<Network>) -> Config {
        use oxwrt_api::config::{ChainPolicy, Control, Firewall};
        use std::path::PathBuf;
        Config {
            hostname: "t".into(),
            timezone: None,
            networks: wans,
            firewall: Firewall {
                zones: vec![],
                rules: vec![],
            },
            radios: vec![],
            wifi: vec![],
            services: vec![],
            port_forwards: vec![],
            wireguard: vec![],
            ddns: vec![],
            metrics: None,
            routes: vec![],
            routes6: vec![],
            blocklists: vec![],
            upnp: None,
            control: Control {
                listen: vec!["[::1]:51820".into()],
                authorized_keys: PathBuf::from("/x"),
            },
        }
    }

    #[test]
    fn picks_lowest_priority_healthy() {
        let cfg = mk_cfg(vec![
            wan("primary", "eth1", 100),
            wan("backup", "eth2", 200),
        ]);
        let leases = new_wan_leases();
        leases
            .write()
            .unwrap()
            .insert("primary".into(), Some(mk_lease([1, 2, 3, 4], [1, 2, 3, 1])));
        leases
            .write()
            .unwrap()
            .insert("backup".into(), Some(mk_lease([5, 6, 7, 8], [5, 6, 7, 1])));

        let (active, lease) = pick_active(&cfg, &leases).unwrap();
        assert_eq!(active, "primary");
        assert_eq!(lease.address, Ipv4Addr::new(1, 2, 3, 4));
    }

    #[test]
    fn fails_over_when_primary_unhealthy() {
        let cfg = mk_cfg(vec![
            wan("primary", "eth1", 100),
            wan("backup", "eth2", 200),
        ]);
        let leases = new_wan_leases();
        leases.write().unwrap().insert("primary".into(), None);
        leases
            .write()
            .unwrap()
            .insert("backup".into(), Some(mk_lease([5, 6, 7, 8], [5, 6, 7, 1])));

        let (active, _) = pick_active(&cfg, &leases).unwrap();
        assert_eq!(active, "backup", "primary unhealthy → backup takes over");
    }

    #[test]
    fn returns_none_when_all_unhealthy() {
        let cfg = mk_cfg(vec![wan("primary", "eth1", 100)]);
        let leases = new_wan_leases();
        leases.write().unwrap().insert("primary".into(), None);
        assert!(pick_active(&cfg, &leases).is_none());
    }

    #[test]
    fn single_wan_works_unchanged() {
        let cfg = mk_cfg(vec![wan("wan", "eth1", 100)]);
        let leases = new_wan_leases();
        leases
            .write()
            .unwrap()
            .insert("wan".into(), Some(mk_lease([1, 2, 3, 4], [1, 2, 3, 1])));
        let (name, _) = pick_active(&cfg, &leases).unwrap();
        assert_eq!(name, "wan");
    }

    #[test]
    fn priority_ties_break_on_first_declared() {
        let cfg = mk_cfg(vec![
            wan("a", "eth1", 100),
            wan("b", "eth2", 100), // tied
        ]);
        let leases = new_wan_leases();
        leases
            .write()
            .unwrap()
            .insert("a".into(), Some(mk_lease([1, 1, 1, 1], [1, 1, 1, 254])));
        leases
            .write()
            .unwrap()
            .insert("b".into(), Some(mk_lease([2, 2, 2, 2], [2, 2, 2, 254])));
        let (name, _) = pick_active(&cfg, &leases).unwrap();
        assert_eq!(name, "a", "first-declared breaks priority ties");
    }
}
