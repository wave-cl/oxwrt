//! Client-side VPN failover coordinator.
//!
//! Mirrors the wan_failover pattern: for each `[[vpn_client]]`
//! profile, a probe task pings `probe_target` through the wg
//! iface with 3-fail/2-ok hysteresis. Every 2 s the coordinator
//! looks at the (lease, probe) map, picks the lowest-priority
//! healthy profile, and — if that's different from the current
//! active — updates:
//!   - routing table 51's default (to new iface)
//!   - endpoint exemption in main table (pinned to current
//!     ActiveWan so the handshake traffic itself leaves WAN-ward)
//!   - ActiveVpn (read by Status RPC + metrics)
//!
//! Reload support: handles are stored on ControlState so the
//! reload path can abort + respawn with the new config. Same
//! pattern as the recent wan_failover probe respawn (commit
//! 82ad076).
//!
//! Endpoint exemption depends on ActiveWan. When WAN fails over,
//! the exemption must be reinstalled with the new WAN gateway
//! or handshake packets would be routed to the old gateway (wg
//! already reaching via WAN but WAN having changed). Solved by
//! checking the current active WAN every tick and re-calling
//! install_endpoint_exemption whenever wan_gateway or active_vpn
//! changes. Cheap — install_endpoint_exemption uses `.replace()`.

use std::collections::HashMap;
use std::net::{Ipv4Addr, ToSocketAddrs};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use oxwrt_api::config::{Config, Network};
use rtnetlink::Handle;

use crate::vpn_routing;
use crate::wan_failover::{ActiveWan, WanLeases};

/// Per-profile "bring-up succeeded" flag. True = iface exists +
/// `wg setconf` landed + link is up. False = setup failed or
/// iface is admin-down. The coordinator treats this as one half
/// of "healthy" (the other half is probe state).
pub type VpnBringup = Arc<RwLock<HashMap<String, bool>>>;

pub fn new_vpn_bringup() -> VpnBringup {
    Arc::new(RwLock::new(HashMap::new()))
}

/// Per-profile probe health. Keyed by profile name; value = most
/// recent hysteresis-settled state. Missing = "no probe declared,
/// trust the bring-up." Mirrors wan_failover::WanHealth semantics.
pub type VpnHealth = Arc<RwLock<HashMap<String, bool>>>;

pub fn new_vpn_health() -> VpnHealth {
    Arc::new(RwLock::new(HashMap::new()))
}

/// Currently-active VPN profile name, or None if no profile is
/// healthy (→ kill-switch engaged). Updated by the coordinator;
/// read by the Status RPC.
pub type ActiveVpn = Arc<Mutex<Option<String>>>;

pub fn new_active_vpn() -> ActiveVpn {
    Arc::new(Mutex::new(None))
}

/// Snapshot for the Status RPC. One entry per declared profile.
#[derive(Debug, Clone)]
pub struct VpnSnapshot {
    pub name: String,
    pub iface: String,
    pub priority: u32,
    pub healthy: bool,
    pub active: bool,
    pub endpoint: String,
    pub probe_target: Ipv4Addr,
}

pub fn snapshot_all(
    cfg: &Config,
    bringup: &VpnBringup,
    health: &VpnHealth,
    active: &ActiveVpn,
) -> Vec<VpnSnapshot> {
    let bringup = bringup.read().map(|g| g.clone()).unwrap_or_default();
    let health = health.read().map(|g| g.clone()).unwrap_or_default();
    let active_name: Option<String> = active.lock().ok().and_then(|g| (*g).clone());
    cfg.vpn_client
        .iter()
        .map(|v| {
            let up = bringup.get(&v.name).copied().unwrap_or(false);
            let probe_ok = health.get(&v.name).copied().unwrap_or(true);
            let healthy = up && probe_ok;
            VpnSnapshot {
                name: v.name.clone(),
                iface: v.iface.clone(),
                priority: v.priority,
                healthy,
                active: active_name.as_deref() == Some(v.name.as_str()),
                endpoint: v.endpoint.clone(),
                probe_target: v.probe_target,
            }
        })
        .collect()
}

/// Pure selection: given cfg + bring-up map + health map, return
/// the best healthy profile name or None. Extracted so the
/// coordinator task stays thin and tests have something to hit.
///
/// Health rule:
///   lease (bring-up) present AND (probe absent OR probe ok)
pub fn pick_active_vpn(
    cfg: &Config,
    bringup: &VpnBringup,
    health: &VpnHealth,
) -> Option<String> {
    let bringup = bringup.read().ok()?;
    let health = health.read().ok()?;
    let mut best: Option<(u32, String)> = None;
    for v in &cfg.vpn_client {
        let up = bringup.get(&v.name).copied().unwrap_or(false);
        if !up {
            continue;
        }
        let probe_ok = health.get(&v.name).copied().unwrap_or(true);
        if !probe_ok {
            continue;
        }
        let take = match &best {
            None => true,
            Some((p, _)) => v.priority < *p,
        };
        if take {
            best = Some((v.priority, v.name.clone()));
        }
    }
    best.map(|(_, n)| n)
}

/// Spawn the coordinator task. Loops every 2s, reconciles table
/// 51's default + endpoint exemption to the active profile.
pub fn spawn(
    cfg: Arc<Config>,
    bringup: VpnBringup,
    health: VpnHealth,
    active: ActiveVpn,
    wan_leases: WanLeases,
    active_wan: ActiveWan,
    handle: Handle,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // Track last-installed state so we only issue netlink
        // calls on actual transitions.
        let mut prev_active: Option<String> = None;
        let mut prev_endpoint_key: Option<(String, Ipv4Addr, Ipv4Addr, String)> = None; // (profile, endpoint_ip, wan_gw, wan_iface)

        let mut tick = tokio::time::interval(Duration::from_secs(2));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            let desired = pick_active_vpn(&cfg, &bringup, &health);

            // 1. Maintain endpoint exemptions for the currently-
            //    active profile (and only that one — stale /32s
            //    for ex-profiles are removed on transition).
            if let Some(profile_name) = &desired {
                let Some(profile) = cfg.vpn_client.iter().find(|v| &v.name == profile_name)
                else {
                    continue;
                };
                // Resolve endpoint host:port → IP. Endpoint may be
                // a hostname; we only install a /32 exemption
                // if we successfully got a v4 IP. DNS hangs are
                // tolerated because the resolver inside the
                // coordinator is sync + uses tokio's blocking
                // wrapper below.
                let endpoint = profile.endpoint.clone();
                let endpoint_ip = tokio::task::spawn_blocking(move || resolve_v4(&endpoint))
                    .await
                    .ok()
                    .flatten();

                // Find the current active WAN's iface + gateway.
                // If there's no active WAN, skip endpoint-exemption
                // reinstall (handshake can't reach anywhere until
                // WAN comes back anyway). If active WAN changes
                // mid-loop, the prev_endpoint_key comparison
                // triggers a reinstall.
                let wan_info = {
                    let active_name: Option<String> =
                        active_wan.lock().ok().and_then(|g| (*g).clone());
                    let leases = wan_leases.read().ok();
                    active_name
                        .zip(leases)
                        .and_then(|(name, l)| l.get(&name).cloned().flatten().map(|lease| (name, lease)))
                };

                if let (Some(endpoint_ip), Some((wan_name, wan_lease))) =
                    (endpoint_ip, wan_info.clone())
                {
                    if let Some(wan_gw) = wan_lease.gateway {
                        let wan_iface = cfg.networks.iter().find_map(|n| match n {
                            Network::Wan { name, iface, .. } if name == &wan_name => {
                                Some(iface.clone())
                            }
                            _ => None,
                        });
                        if let Some(wan_iface) = wan_iface {
                            let key = (
                                profile.name.clone(),
                                endpoint_ip,
                                wan_gw,
                                wan_iface.clone(),
                            );
                            if prev_endpoint_key.as_ref() != Some(&key) {
                                // Remove the prior exemption BEFORE
                                // installing the new one. Otherwise
                                // a profile swap leaves the old
                                // /32 permanently in the main table —
                                // harmless routing-wise (it just
                                // points at WAN for an IP we're no
                                // longer using), but accumulates
                                // across CRUD cycles + clutters
                                // `ip route`. Only skip the remove
                                // when the endpoint IP is exactly
                                // the same (e.g. profile stayed,
                                // only wan_gw changed) — otherwise
                                // we'd yank the live exemption.
                                if let Some((_, prev_ip, _, _)) = &prev_endpoint_key {
                                    if *prev_ip != endpoint_ip {
                                        if let Err(e) =
                                            vpn_routing::remove_endpoint_exemption(
                                                &handle,
                                                *prev_ip,
                                            )
                                            .await
                                        {
                                            tracing::debug!(
                                                prev_ip = %prev_ip,
                                                error = %e,
                                                "vpn failover: stale exemption cleanup failed"
                                            );
                                        }
                                    }
                                }
                                if let Err(e) = vpn_routing::install_endpoint_exemption(
                                    &handle,
                                    endpoint_ip,
                                    wan_gw,
                                    &wan_iface,
                                )
                                .await
                                {
                                    tracing::warn!(
                                        profile = %profile.name, %endpoint_ip, %wan_gw,
                                        error = %e,
                                        "vpn failover: endpoint exemption install failed"
                                    );
                                }
                                prev_endpoint_key = Some(key);
                            }
                        }
                    }
                }
            }

            // 2. Routing-table transition.
            if desired == prev_active {
                continue;
            }

            // Log the transition prominently — operators grep
            // dmesg for these strings when troubleshooting.
            match (&prev_active, &desired) {
                (None, Some(n)) => {
                    tracing::warn!(active = %n, "vpn failover: activating")
                }
                (Some(old), Some(new)) if old == new => {} // impossible, we just compared
                (Some(old), Some(new)) => {
                    tracing::warn!(from = %old, to = %new, "vpn failover: switching profile")
                }
                (Some(old), None) => {
                    tracing::error!(was = %old, "vpn failover: no healthy profile, killswitch engaged")
                }
                (None, None) => {}
            }

            if let Some(profile_name) = &desired {
                let Some(profile) = cfg.vpn_client.iter().find(|v| &v.name == profile_name)
                else {
                    continue;
                };
                if let Err(e) = vpn_routing::set_table_51_default(&handle, &profile.iface).await {
                    tracing::error!(
                        profile = %profile.name, iface = %profile.iface,
                        error = %e,
                        "vpn failover: set_table_51_default failed"
                    );
                }
                // v6 default only when the profile has a v6
                // address — no point setting table 51 v6 default
                // to an iface that won't accept v6 traffic (wg
                // kernel module would drop it because AllowedIPs
                // wouldn't include ::/0).
                if profile.address_v6.is_some() {
                    if let Err(e) =
                        vpn_routing::set_table_51_default_v6(&handle, &profile.iface).await
                    {
                        tracing::warn!(
                            profile = %profile.name, iface = %profile.iface,
                            error = %e,
                            "vpn failover: v6 set_table_51_default failed"
                        );
                    }
                }
                *active.lock().unwrap() = Some(profile_name.clone());
            } else {
                if let Err(e) = vpn_routing::clear_table_51_default(&handle).await {
                    tracing::warn!(error = %e, "vpn failover: clear_table_51_default failed");
                }
                if let Err(e) = vpn_routing::clear_table_51_default_v6(&handle).await {
                    tracing::debug!(error = %e, "vpn failover: clear v6 failed (maybe absent)");
                }
                // Kill-switch transition: no active profile means
                // no endpoint is reachable-through-tunnel. Remove
                // the /32 exemption so it doesn't linger forever
                // across a profile delete-and-re-add cycle.
                if let Some((_, prev_ip, _, _)) = &prev_endpoint_key {
                    if let Err(e) =
                        vpn_routing::remove_endpoint_exemption(&handle, *prev_ip).await
                    {
                        tracing::debug!(
                            prev_ip = %prev_ip, error = %e,
                            "vpn failover: exemption cleanup on killswitch failed"
                        );
                    }
                }
                *active.lock().unwrap() = None;
                prev_endpoint_key = None;
            }

            prev_active = desired;
        }
    })
}

/// Spawn one probe task per profile with a `probe_target`. Mirrors
/// `wan_failover::spawn_probes` verbatim; returns the handles so
/// reload can abort + respawn. Seeded as healthy so the first ~15s
/// after boot doesn't reject a freshly-up profile before the
/// 2-ok hysteresis settles.
pub fn spawn_probes(cfg: &Config, health: VpnHealth) -> Vec<tokio::task::JoinHandle<()>> {
    const PROBE_INTERVAL: Duration = Duration::from_secs(5);
    const FAIL_THRESHOLD: u32 = 3;
    const OK_THRESHOLD: u32 = 2;
    const PING_TIMEOUT_S: &str = "2";

    let mut handles = Vec::new();
    for v in &cfg.vpn_client {
        let name = v.name.clone();
        let iface = v.iface.clone();
        let target = v.probe_target.to_string();
        let health = health.clone();
        // Seed healthy.
        health.write().unwrap().insert(name.clone(), true);

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
                let desired = if consec_fail >= FAIL_THRESHOLD {
                    Some(false)
                } else if consec_ok >= OK_THRESHOLD {
                    Some(true)
                } else {
                    None
                };
                if let Some(s) = desired {
                    if s != last_published {
                        if s {
                            tracing::info!(profile = %name, target = %target, "vpn probe: healthy");
                        } else {
                            tracing::warn!(profile = %name, target = %target, consec_fail, "vpn probe: unhealthy");
                        }
                        health.write().unwrap().insert(name.clone(), s);
                        last_published = s;
                    }
                }
            }
        }));
    }
    handles
}

async fn probe_once(iface: &str, target: &str, timeout_s: &str) -> bool {
    let res = tokio::process::Command::new("ping")
        .args([
            "-I",
            iface,
            "-c",
            "1",
            "-W",
            timeout_s,
            "-q",
            target,
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await;
    matches!(res, Ok(s) if s.success())
}

fn resolve_v4(host_port: &str) -> Option<Ipv4Addr> {
    // Accept both "host:port" (standard WG endpoint) and bare
    // "host" inputs. If no colon, append dummy port for the
    // resolver.
    let with_port = if host_port.contains(':') {
        host_port.to_string()
    } else {
        format!("{host_port}:0")
    };
    with_port
        .to_socket_addrs()
        .ok()?
        .find_map(|sa| match sa.ip() {
            std::net::IpAddr::V4(v) => Some(v),
            _ => None,
        })
}

/// Seed the bringup map to true/false per profile based on
/// whether `vpn_client::setup_all` succeeded. Called from the
/// boot path + reload path. Keeps the coordinator's source of
/// truth centralized (no re-checking `ip link show` mid-loop).
pub fn mark_bringup(bringup: &VpnBringup, cfg: &Config, success: bool) {
    let Ok(mut b) = bringup.write() else {
        return;
    };
    for v in &cfg.vpn_client {
        b.insert(v.name.clone(), success);
    }
}

