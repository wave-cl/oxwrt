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

/// Per-WAN probe health. Keyed by WAN name; value = "last probe
/// result" where `true` = the most recent ICMP ping succeeded
/// within the probe window. WANs without a `probe_target`
/// declared are absent from this map — the coordinator treats
/// absence as "no probe override, trust the lease."
///
/// Using `bool` (not a success-count streak) keeps the coordinator
/// simple: probes internally track hysteresis (N fails → unhealthy,
/// M successes → healthy) and only flip the map entry on state
/// change. That way a single missed ping on an otherwise-fine
/// link doesn't cause spurious failover.
pub type WanHealth = Arc<RwLock<HashMap<String, bool>>>;

pub fn new_wan_health() -> WanHealth {
    Arc::new(RwLock::new(HashMap::new()))
}

/// Per-WAN live summary for Status RPC. One entry per declared
/// Network::Wan, regardless of whether it's the active one.
#[derive(Debug, Clone)]
pub struct WanSnapshot {
    pub name: String,
    pub iface: String,
    pub priority: u32,
    /// Resolved health = lease-is-Some AND (no probe declared
    /// OR probe is passing).
    pub healthy: bool,
    /// Current IPv4 address on the lease, if any.
    pub address: Option<Ipv4Addr>,
    /// Current default gateway on the lease, if any.
    pub gateway: Option<Ipv4Addr>,
    /// Is this WAN the one currently serving traffic?
    pub active: bool,
}

/// Build a snapshot of all WANs' live state. Called by the
/// Status RPC; takes cheap locks then releases them before the
/// formatter runs.
pub fn snapshot_all(
    cfg: &Config,
    wan_leases: &WanLeases,
    wan_health: &WanHealth,
    active_wan: &ActiveWan,
) -> Vec<WanSnapshot> {
    let leases = wan_leases
        .read()
        .map(|g| g.clone())
        .unwrap_or_default();
    let health = wan_health
        .read()
        .map(|g| g.clone())
        .unwrap_or_default();
    let active_name: Option<String> = active_wan.lock().ok().and_then(|g| (*g).clone());
    cfg.networks
        .iter()
        .filter_map(|n| match n {
            Network::Wan {
                name,
                iface,
                priority,
                ..
            } => {
                let lease = leases.get(name).cloned().unwrap_or(None);
                let probe_healthy = health.get(name).copied();
                let lease_healthy = lease.is_some();
                // Healthy = lease is Some AND (probe is passing
                // OR no probe declared). Probe absence = "trust
                // the lease."
                let healthy = lease_healthy && probe_healthy.unwrap_or(true);
                Some(WanSnapshot {
                    name: name.clone(),
                    iface: iface.clone(),
                    priority: *priority,
                    healthy,
                    address: lease.as_ref().map(|l| l.address),
                    gateway: lease.as_ref().and_then(|l| l.gateway),
                    active: active_name.as_deref() == Some(name.as_str()),
                })
            }
            _ => None,
        })
        .collect()
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
    wan_health: WanHealth,
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
            let desired = pick_active(&cfg, &wan_leases, &wan_health);
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
pub fn pick_active(
    cfg: &Config,
    wan_leases: &WanLeases,
    wan_health: &WanHealth,
) -> Option<(String, DhcpLease)> {
    let leases = wan_leases.read().ok()?;
    let health = wan_health.read().ok()?;
    let mut best: Option<(u32, String, DhcpLease)> = None;
    for net in &cfg.networks {
        if let Network::Wan { name, priority, .. } = net {
            // Health rule:
            //   lease = Some AND (no probe declared OR probe passing).
            // Probe absence (no entry in wan_health) = "trust the
            // lease alone." Probe entry of `false` vetoes even a
            // valid lease — that's the whole point of active
            // probing: catch upstream-dead-with-valid-renew.
            if let Some(Some(lease)) = leases.get(name) {
                let probe_ok = health.get(name).copied().unwrap_or(true);
                if !probe_ok {
                    continue;
                }
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

/// Spawn one ICMP probe task per WAN that declared a
/// `probe_target`. Each task:
///   - pings the target through the WAN's iface every 5s
///   - maintains a hysteresis state: 3 consecutive fails →
///     unhealthy; 2 consecutive successes → healthy
///   - writes the state to `wan_health[name]` ONLY on transition
///     (writes are rare, not once-per-probe, so the coordinator
///     doesn't race)
///
/// Uses busybox `ping -I <iface> -c 1 -W 2 <target>` — a common
/// binary in any OpenWrt image. Running as a subprocess is fine
/// at 5s cadence; the fork overhead is a few ms.
pub fn spawn_probes(cfg: &Config, wan_health: WanHealth) -> Vec<tokio::task::JoinHandle<()>> {
    const PROBE_INTERVAL: Duration = Duration::from_secs(5);
    const FAIL_THRESHOLD: u32 = 3;
    const OK_THRESHOLD: u32 = 2;
    const PING_TIMEOUT_S: &str = "2";

    let mut handles = Vec::new();
    for net in &cfg.networks {
        let Network::Wan {
            name,
            iface,
            probe_target: Some(target),
            ..
        } = net
        else {
            continue;
        };
        let name = name.clone();
        let iface = iface.clone();
        let target = target.to_string();
        let wan_health = wan_health.clone();
        // Seed as healthy so a fresh boot doesn't fail over before
        // the first probe has run.
        wan_health.write().unwrap().insert(name.clone(), true);

        handles.push(tokio::spawn(async move {
            let mut consec_ok: u32 = 0;
            let mut consec_fail: u32 = 0;
            let mut last_published: bool = true;
            let mut tick = tokio::time::interval(PROBE_INTERVAL);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tick.tick().await;
                let ok = probe_once(&iface, &target, PING_TIMEOUT_S).await;
                if ok {
                    consec_ok += 1;
                    consec_fail = 0;
                } else {
                    consec_fail += 1;
                    consec_ok = 0;
                }

                let desired_state = if consec_fail >= FAIL_THRESHOLD {
                    Some(false)
                } else if consec_ok >= OK_THRESHOLD {
                    Some(true)
                } else {
                    None // hysteresis middle — don't publish
                };
                if let Some(s) = desired_state {
                    if s != last_published {
                        if s {
                            tracing::info!(wan = %name, target = %target, "probe: WAN healthy");
                        } else {
                            tracing::warn!(wan = %name, target = %target, consec_fail, "probe: WAN unhealthy");
                        }
                        wan_health.write().unwrap().insert(name.clone(), s);
                        last_published = s;
                    }
                }
            }
        }));
    }
    handles
}

async fn probe_once(iface: &str, target: &str, timeout_s: &str) -> bool {
    // Single ICMP echo, 2s timeout, bound to the WAN iface so
    // the probe goes out via the right gateway even without a
    // default route pointing through this WAN. busybox ping
    // accepts -I <iface> but some variants also want numeric
    // -c / -W; pass both.
    let res = tokio::process::Command::new("ping")
        .args([
            "-I", iface,
            "-c", "1",
            "-W", timeout_s,
            "-q", // quiet, only emit summary
            target,
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await;
    matches!(res, Ok(s) if s.success())
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

        let health = new_wan_health();
        let (active, lease) = pick_active(&cfg, &leases, &health).unwrap();
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

        let health = new_wan_health();
        let (active, _) = pick_active(&cfg, &leases, &health).unwrap();
        assert_eq!(active, "backup", "primary unhealthy → backup takes over");
    }

    #[test]
    fn returns_none_when_all_unhealthy() {
        let cfg = mk_cfg(vec![wan("primary", "eth1", 100)]);
        let leases = new_wan_leases();
        leases.write().unwrap().insert("primary".into(), None);
        let health = new_wan_health();
        assert!(pick_active(&cfg, &leases, &health).is_none());
    }

    #[test]
    fn single_wan_works_unchanged() {
        let cfg = mk_cfg(vec![wan("wan", "eth1", 100)]);
        let leases = new_wan_leases();
        leases
            .write()
            .unwrap()
            .insert("wan".into(), Some(mk_lease([1, 2, 3, 4], [1, 2, 3, 1])));
        let health = new_wan_health();
        let (name, _) = pick_active(&cfg, &leases, &health).unwrap();
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
        let health = new_wan_health();
        let (name, _) = pick_active(&cfg, &leases, &health).unwrap();
        assert_eq!(name, "a", "first-declared breaks priority ties");
    }

    /// Probe-veto: a lease-healthy WAN with an unhealthy probe
    /// is skipped in favour of a lower-priority healthy one.
    #[test]
    fn unhealthy_probe_vetoes_lease() {
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
        let health = new_wan_health();
        // Primary's lease is fine but probe says upstream is dead.
        health.write().unwrap().insert("primary".into(), false);
        // Backup has no probe entry → trust its lease.
        let (active, _) = pick_active(&cfg, &leases, &health).unwrap();
        assert_eq!(active, "backup", "probe veto must demote primary");
    }

    /// Probe-ok doesn't promote a leaseless WAN. Probes override
    /// downward, not upward.
    #[test]
    fn probe_ok_without_lease_stays_unhealthy() {
        let cfg = mk_cfg(vec![wan("wan", "eth1", 100)]);
        let leases = new_wan_leases();
        leases.write().unwrap().insert("wan".into(), None);
        let health = new_wan_health();
        health.write().unwrap().insert("wan".into(), true);
        assert!(pick_active(&cfg, &leases, &health).is_none());
    }

    #[test]
    fn snapshot_reports_all_wans() {
        let cfg = mk_cfg(vec![
            wan("primary", "eth1", 100),
            wan("backup", "eth2", 200),
        ]);
        let leases = new_wan_leases();
        leases
            .write()
            .unwrap()
            .insert("primary".into(), Some(mk_lease([1, 2, 3, 4], [1, 2, 3, 1])));
        leases.write().unwrap().insert("backup".into(), None);
        let health = new_wan_health();
        let active = new_active_wan();
        *active.lock().unwrap() = Some("primary".into());
        let snap = snapshot_all(&cfg, &leases, &health, &active);
        assert_eq!(snap.len(), 2);
        let p = snap.iter().find(|w| w.name == "primary").unwrap();
        assert!(p.active);
        assert!(p.healthy);
        assert_eq!(p.address, Some(Ipv4Addr::new(1, 2, 3, 4)));
        let b = snap.iter().find(|w| w.name == "backup").unwrap();
        assert!(!b.active);
        assert!(!b.healthy, "no lease → not healthy");
        assert_eq!(b.address, None);
    }
}
