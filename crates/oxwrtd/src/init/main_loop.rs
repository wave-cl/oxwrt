//! The three async entry points that `init::run::run*` hand off to.
//!
//! Split out of init/run.rs in late 2025 because run.rs had grown
//! past 1400 lines — the entrypoints + helpers were drowning under
//! the 900-line `async_main` body.
//!
//! Callers reach these via `super::main_loop::X`; all three are
//! `pub(super)` because the only callers are `run`, `run_control_
//! only`, and `run_services_only` one dir up.
//!
//! No behavior change from the split.

// Sibling-module items referenced by the three `*_main` bodies
// below. `use super::*;` picks up everything `init/mod.rs`
// re-exports (Arc, Path, Config, Supervisor, the crate-level
// types) so we only name the specific helpers that live in peer
// submodules.
use super::SIGNING_KEY_PATH;
use super::clock::{bootstrap_clock_floor, sntp_bootstrap_clock};
use super::preinit::run_uci_defaults;
use super::run::parse_listen_addrs;
use super::watchdog::{spawn_heartbeat, spawn_watchdog_pet};
use super::*;

pub(super) async fn services_only_main(cfg: Config) -> Result<(), Error> {
    tracing::info!(
        hostname = %cfg.hostname,
        services = cfg.services.len(),
        "oxwrtd: services-only mode"
    );

    // cgroup controller enable is idempotent and cheap — even if procd
    // already did it, re-enabling the subset we need (memory/cpu/pids)
    // costs a few writes to /sys/fs/cgroup/cgroup.subtree_control. If
    // the write fails (e.g. kernel doesn't support v2) we continue
    // degraded; per-service memory_max etc. just won't be enforced.
    if let Err(e) = crate::container::enable_cgroup_controllers() {
        tracing::warn!(error = %e, "enable_cgroup_controllers failed");
    }

    // No WAN DHCP, no host veths, no firewall install. The supervisor
    // runs against the services verbatim — this mode is specifically
    // for services that use `net_mode = "host"` and don't require
    // isolated netns setup. An isolated service here would start
    // without its veth, which the container pre_exec will flag.
    let wan_lease: control::SharedLease = Arc::new(std::sync::RwLock::new(None));
    let supervisor = Supervisor::from_config(&cfg.services);
    let logd = Logd::new();
    let firewall_dump: Vec<String> = Vec::new();
    // Note: services-only still uses the control-only flag on
    // ControlState — reload should not reinstall the firewall or
    // reconcile netlink here either. What's different from
    // --control-only is just that the supervisor is populated.
    let state = ControlState::new_control_only(
        cfg.clone(),
        supervisor,
        logd.clone(),
        firewall_dump,
        wan_lease,
    );

    let listen_addrs = parse_listen_addrs(&cfg.control.listen);
    if listen_addrs.is_empty() {
        return Err(Error::Runtime(
            "no valid control listen addresses in config".to_string(),
        ));
    }
    tracing::info!(?listen_addrs, "starting sQUIC control plane");

    let server = Arc::new(Server::load(
        Path::new(SIGNING_KEY_PATH),
        &cfg.control,
        state.clone(),
    )?);
    let server_task = {
        let server = server.clone();
        tokio::spawn(async move {
            if let Err(e) = server.listen(&listen_addrs).await {
                tracing::error!(error = %e, "control server exited");
            }
        })
    };

    // Supervisor tick loop — same cadence as --init. Services start on
    // the first tick after spawn; crashed services respawn per their
    // backoff schedule.
    let mut tick = tokio::time::interval(Duration::from_millis(100));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|e| Error::Runtime(e.to_string()))?;

    loop {
        tokio::select! {
            _ = tick.tick() => {
                if let Ok(mut sup) = state.supervisor.lock() {
                    sup.tick(&logd);
                }
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("oxwrtd: SIGINT → shutdown");
                break;
            }
            _ = term.recv() => {
                tracing::info!("oxwrtd: SIGTERM → shutdown");
                break;
            }
        }
    }

    if let Ok(mut sup) = state.supervisor.lock() {
        sup.shutdown();
    }
    server_task.abort();
    Ok(())
}

pub(super) async fn control_only_main(cfg: Config) -> Result<(), Error> {
    tracing::info!(
        hostname = %cfg.hostname,
        services = cfg.services.len(),
        "oxwrtd: control-plane-only mode"
    );

    // Empty state: no firewall dump, no WAN lease, empty supervisor.
    let wan_lease: control::SharedLease = Arc::new(std::sync::RwLock::new(None));
    let supervisor = Supervisor::from_config(&[]);
    let logd = Logd::new();
    let firewall_dump: Vec<String> = Vec::new();
    let state = ControlState::new_control_only(
        cfg.clone(),
        supervisor,
        logd.clone(),
        firewall_dump,
        wan_lease,
    );

    let listen_addrs = parse_listen_addrs(&cfg.control.listen);
    if listen_addrs.is_empty() {
        return Err(Error::Runtime(
            "no valid control listen addresses in config".to_string(),
        ));
    }
    tracing::info!(?listen_addrs, "starting sQUIC control plane");

    let server = Arc::new(Server::load(
        Path::new(SIGNING_KEY_PATH),
        &cfg.control,
        state.clone(),
    )?);
    let server_task = {
        let server = server.clone();
        tokio::spawn(async move {
            if let Err(e) = server.listen(&listen_addrs).await {
                tracing::error!(error = %e, "control server exited");
            }
        })
    };

    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|e| Error::Runtime(e.to_string()))?;

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("oxwrtd: SIGINT → shutdown");
        }
        _ = term.recv() => {
            tracing::info!("oxwrtd: SIGTERM → shutdown");
        }
    }

    server_task.abort();
    Ok(())
}

pub(super) async fn async_main(cfg: Config) -> Result<(), Error> {
    // Boot flow (plan §3): network bring-up → start containers → start sQUIC
    // control → main select loop {sigchld, control_cmd, reload, shutdown}.
    //
    // v0: supervisor tick loop + ctrl_c shutdown. Network bring-up and sQUIC
    // control plane are still to be wired.
    tracing::info!(
        hostname = %cfg.hostname,
        services = cfg.services.len(),
        "oxwrtd: supervisor starting"
    );

    // Apply the hostname to the kernel so `gethostname(2)` returns what
    // the operator configured. Without this, services that call
    // `gethostname` see whatever the kernel was booted with (usually
    // "localhost" on a fresh boot or the stale hostname from the
    // previous shutdown on a reboot). Best-effort: failure just logs.
    if let Err(e) = rustix::system::sethostname(cfg.hostname.as_bytes()) {
        tracing::warn!(error = %e, hostname = %cfg.hostname, "sethostname failed");
    }

    // Bootstrap the system clock to at least the binary's build time.
    //
    // The GL-MT6000 has no battery-backed RTC. Every cold boot starts
    // at Jan 1 1970, which breaks the sQUIC replay-window check (clients
    // with real timestamps are >56 years ahead, way outside ±120s).
    // Operators can't push a new config or talk to the control plane
    // until the clock is sane — and NTP can't help, because ntpd runs
    // as a supervised service that needs DNS which needs WAN.
    //
    // BUILD_EPOCH_SECS is baked in at compile time by build.rs. Bumping
    // the clock up to that value gives us a floor that's "recent enough"
    // for an operator who just flashed the image: if they connect within
    // ~2 minutes of binary build time, their timestamp will be within
    // the replay window. Stale images (more than ~2 min old) still need
    // a real NTP sync — see TODO in the `wan_dhcp` flow.
    //
    // Only moves the clock FORWARD — never steps backwards, which would
    // make other processes unhappy. Best-effort: failure just logs.
    bootstrap_clock_floor();

    // Pet the hardware watchdog. The Flint 2 (and most OpenWrt boards)
    // enable a hardware watchdog at boot — on mediatek/filogic the
    // timeout is 31s by default. procd normally writes to /dev/watchdog
    // every few seconds to keep the timer from firing. When we replace
    // procd, the watchdog is still on but nobody's petting it, so the
    // device reboots ~30s into every boot. That reboot loop is
    // indistinguishable from an oxwrtd crash unless you squint at
    // UART logs for "mtk-wdt ... Watchdog enabled".
    //
    // Best-effort: opens /dev/watchdog, writes a byte, sleeps 5s, loops
    // forever. If the device doesn't exist or we can't open it, log
    // and give up — the system will reboot in 30s, at which point the
    // operator will notice something's wrong.
    spawn_watchdog_pet();
    // Heartbeat ticks the counter the pet thread gates on. Must
    // be spawned on the same runtime as the rest of oxwrtd so a
    // stall there stops the tick → pet thread stops feeding →
    // kernel reboots the board.
    spawn_heartbeat();

    // Enable cgroup v2 controllers once so per-service memory/cpu/pids
    // limits from config take effect when `container::setup_cgroup` writes
    // to memory.max etc.
    if let Err(e) = crate::container::enable_cgroup_controllers() {
        tracing::warn!(error = %e, "enable_cgroup_controllers failed");
    }

    // Run once-per-boot first-boot scripts under /etc/uci-defaults/.
    // Normally procd executes these as part of its boot sequence; since
    // we replace procd, we have to do it ourselves — otherwise
    // /etc/init.d/oxwrtd never gets enabled (irrelevant under our own
    // supervision) and more importantly the per-service rootfs
    // provisioners (97-oxwrt-debug-ssh-rootfs, 98-oxwrt-diag-rootfs)
    // never run, leaving those services with empty rootfs dirs and
    // permanent "spawn failed: No such file" errors.
    //
    // Semantics: execute each script, and on successful exit (status 0)
    // delete it — matching procd's convention. Failed scripts stay
    // around for the next boot to retry. Run in alphabetical order so
    // 97 < 98 < 99 sequencing is preserved.
    run_uci_defaults();

    // Network bring-up is non-fatal. A missing kernel module (e.g. bridge,
    // veth) or a misconfigured interface shouldn't prevent the control plane
    // from starting — the operator can fix it over sQUIC and `reload`.
    let net = match Net::new() {
        Ok(n) => Some(n),
        Err(e) => {
            tracing::error!(error = %e, "rtnetlink init failed; network unavailable");
            None
        }
    };
    if let Some(ref net) = net {
        if let Err(e) = net.bring_up(&cfg).await {
            tracing::error!(error = %e, "network bring-up failed; continuing in degraded mode");
        }
    }

    // WireGuard bring-up (if any [[wireguard]] entries): creates
    // wg0, writes /etc/oxwrt/wg0.key if missing, applies the peer
    // list via `wg setconf`, brings the link up. Runs after
    // `net.bring_up` so addresses from matching `[[networks]]
    // type="simple"` entries are already assigned before wg starts
    // routing. Kmod-wireguard + wireguard-tools packages must be
    // in the image — without them the `ip link add type wireguard`
    // or `wg` invocations fail at runtime and the error is logged
    // (non-fatal: the rest of the router stays up).
    // Run the independent setup steps in parallel. Each is
    // blocking I/O (subprocess exec for wg / tc, file writes for
    // corerad / miniupnpd configs), and none of them depend on
    // each other — sequentially they cost ~150-300 ms on first
    // boot (wireguard genkey + tc qdisc add dominate), which all
    // runs before the first service spawn. tokio::join! on
    // spawn_blocking wrappers lets them overlap, clawing back
    // that window for services to come up sooner.
    let cfg_wg = cfg.clone();
    let cfg_corerad = cfg.clone();
    let cfg_upnp = cfg.clone();
    let cfg_sqm = cfg.clone();
    let cfg_vpn = cfg.clone();
    let (wg_res, corerad_res, upnp_res, sqm_res, vpn_res) = tokio::join!(
        tokio::task::spawn_blocking(move || crate::wireguard::setup_wireguard(&cfg_wg)),
        tokio::task::spawn_blocking(move || crate::corerad::write_config(&cfg_corerad)),
        tokio::task::spawn_blocking(move || crate::miniupnpd::write_config(&cfg_upnp)),
        tokio::task::spawn_blocking(move || crate::sqm::setup_sqm(&cfg_sqm)),
        tokio::task::spawn_blocking(move || crate::vpn_client::setup_all(&cfg_vpn)),
    );
    if let Ok(Err(e)) = wg_res {
        tracing::error!(error = %e, "wireguard setup failed; tunnels disabled");
    }
    if let Ok(Err(e)) = corerad_res {
        tracing::error!(error = %e, "corerad config generation failed");
    }
    // Render hickory-dns / coredhcp / ntpd-rs service configs from
    // their [dns] / [dhcp] / [ntp] sections. Serially — each write
    // is a few hundred bytes of synchronous I/O, parallelism isn't
    // worth the pattern complexity. Absent sections → no-op so
    // existing installs keep their image-shipped binds.
    if let Err(e) = crate::hickory::write_config(&cfg) {
        tracing::error!(error = %e, "hickory config generation failed");
    }
    if let Err(e) = crate::coredhcp::write_config(&cfg) {
        tracing::error!(error = %e, "coredhcp config generation failed");
    }
    if let Err(e) = crate::ntpd::write_config(&cfg) {
        tracing::error!(error = %e, "ntpd config generation failed");
    }
    if let Err(e) = crate::svc_resolv::write_all(&cfg) {
        tracing::error!(error = %e, "svc_resolv generation failed");
    }
    if let Ok(Err(e)) = upnp_res {
        tracing::error!(error = %e, "miniupnpd config generation failed");
    }
    if let Ok(Err(e)) = sqm_res {
        tracing::error!(error = %e, "sqm setup failed");
    }
    if let Ok(Err(e)) = vpn_res {
        tracing::error!(error = %e, "vpn_client setup failed; tunnels disabled");
    }

    // Policy-routing scaffolding for the via_vpn feature. Per
    // via_vpn zone, install `ip rule iif <iface> lookup 51`; plant
    // a blackhole default in table 51 so when no profile is
    // active marked traffic is kill-switched instead of falling
    // through to main. Both calls are idempotent across reload +
    // reboot. Scoped to `if let Some(net)` so we don't invoke
    // without rtnetlink.
    if let Some(net_handle) = &net {
        if !cfg.vpn_client.is_empty() || cfg.firewall.zones.iter().any(|z| z.via_vpn) {
            let handle = net_handle.handle().clone();
            let via_vpn_ifaces: Vec<String> = cfg
                .firewall
                .zones
                .iter()
                .filter(|z| z.via_vpn)
                .flat_map(|z| crate::net::zone_ifaces(&cfg, &z.name))
                .collect();
            if let Err(e) = crate::vpn_routing::install_policy_rules(&handle, &via_vpn_ifaces).await
            {
                tracing::error!(error = %e, "vpn_routing: policy rules install failed");
            }
            if let Err(e) = crate::vpn_routing::install_table_51_blackhole(&handle).await {
                tracing::error!(error = %e, "vpn_routing: blackhole fallback install failed");
            }
            // Reap stale /32 endpoint exemptions left by a
            // previous oxwrtd process (crash, power loss, reboot
            // without a clean shutdown). Coordinator reinstalls
            // fresh ones for the currently-active profile on its
            // first tick. Runs BEFORE the coordinator spawns so
            // there's no race where the coordinator's first
            // install is immediately wiped by this cleanup.
            if let Err(e) = crate::vpn_routing::cleanup_stale_endpoint_exemptions(&handle).await {
                tracing::warn!(error = %e, "vpn_routing: exemption cleanup failed");
            }
            // IPv6 parallel. Only installed when at least one
            // vpn_client profile declares `address_v6` — otherwise
            // we'd install v6 rules against an uninhabited table
            // 51, killing v6 forwarding from via_vpn zones as a
            // side effect.
            if cfg.vpn_client.iter().any(|v| v.address_v6.is_some()) {
                if let Err(e) =
                    crate::vpn_routing::install_policy_rules_v6(&handle, &via_vpn_ifaces).await
                {
                    tracing::error!(error = %e, "vpn_routing: v6 policy rules install failed");
                }
                if let Err(e) = crate::vpn_routing::install_table_51_blackhole_v6(&handle).await {
                    tracing::error!(error = %e, "vpn_routing: v6 blackhole install failed");
                }
            }
            // Bypass-destination rules: union CIDRs across all
            // declared vpn_client profiles. Active-profile-
            // agnostic by design (one stable set for operators
            // to reason about).
            let bypass: Vec<String> = cfg
                .vpn_client
                .iter()
                .flat_map(|v| v.bypass_destinations.iter().cloned())
                .collect();
            if let Err(e) = crate::vpn_routing::install_bypass_rules(&handle, &bypass).await {
                tracing::error!(error = %e, "vpn_routing: bypass rule install failed");
            }
            let bypass_v6: Vec<String> = cfg
                .vpn_client
                .iter()
                .flat_map(|v| v.bypass_destinations_v6.iter().cloned())
                .collect();
            if !bypass_v6.is_empty() {
                if let Err(e) =
                    crate::vpn_routing::install_bypass_rules_v6(&handle, &bypass_v6).await
                {
                    tracing::error!(error = %e, "vpn_routing: v6 bypass rule install failed");
                }
            }
        }
    }
    // Per-zone WAN routing: install ip rule iif <zone_iface> →
    // per-WAN table 100+ for any zone with `wan=<name>` set.
    // Per-WAN table defaults are populated by the DHCP lease-
    // apply code above on acquire; this call just installs the
    // rules that divert zone traffic into those tables.
    if let Some(net_handle) = &net {
        if cfg.firewall.zones.iter().any(|z| z.wan.is_some()) {
            let handle = net_handle.handle().clone();
            if let Err(e) = crate::wan_routing::install_zone_wan_rules(&handle, &cfg).await {
                tracing::error!(error = %e, "wan_routing: zone rules install failed");
            }
        }
    }

    // MSS clamp on the WAN iface — separate nft table so rustables
    // batch rebuilds don't wipe it. Gated on "there's at least one
    // vpn_client declared" because the clamp is only useful for
    // wg-over-WAN encapsulation headroom.
    if !cfg.vpn_client.is_empty() {
        if let Some(wan) = cfg.primary_wan() {
            if let Err(e) = crate::vpn_routing::install_mss_clamp(wan.iface()) {
                tracing::warn!(error = %e, "vpn_routing: MSS clamp install failed");
            }
        }
    }

    let wan_lease: control::SharedLease = std::sync::Arc::new(std::sync::RwLock::new(None));

    // Per-WAN lease slots: one entry per Network::Wan declared in
    // cfg, keyed by name. Each DHCP client writes into its own
    // slot; the failover coordinator picks the best-priority
    // healthy slot and mirrors it into `wan_lease` above (which
    // downstream code — DDNS, Status, metrics — reads).
    let wan_leases = crate::wan_failover::new_wan_leases();
    let wan_health = crate::wan_failover::new_wan_health();
    let active_wan = crate::wan_failover::new_active_wan();

    // ICMP probes: one task per WAN that declared a probe_target.
    // Hysteresis inside the task debounces transient loss; the
    // coordinator only sees stable state changes. Handles are
    // stored on ControlState so `reload` can abort + respawn
    // them when probe_target changes live.
    let initial_probe_handles = crate::wan_failover::spawn_probes(&cfg, wan_health.clone());

    if let Some(net_handle) = &net {
        // Pre-populate the slots so the coordinator sees entries
        // from t=0 (even with no lease yet). Without this, a WAN
        // that hasn't ACQUIRED yet would be absent from the map,
        // which works but is noisier in the coordinator logs.
        {
            let mut leases = wan_leases.write().unwrap();
            for w in cfg.wans_by_priority() {
                leases.insert(w.name().to_string(), None);
            }
        }

        // Spawn DHCP acquire + renewal per WAN. Same retry/backoff
        // pattern as before; only change is each task writes its
        // own named slot in wan_leases instead of the shared one.
        // SNTP bootstrap still fires once any WAN reaches Acquired
        // — first-to-acquire wins the "set the clock" race, which
        // is fine because all WANs talk to the same anycast NTP.
        let sntp_fired = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        for w in cfg.wans_by_priority() {
            if let Network::Wan {
                name,
                iface,
                wan:
                    WanConfig::Dhcp {
                        send_hostname,
                        hostname_override,
                        vendor_class_id,
                    },
                ..
            } = w
            {
                let handle = net_handle.handle().clone();
                let iface = iface.clone();
                let name = name.clone();
                let wan_leases = wan_leases.clone();
                let sntp_fired = sntp_fired.clone();
                let cfg_for_wanrt = cfg.clone();
                // Build the DHCP client identity bits from the WAN
                // config's Dhcp variant fields. Hostname resolves
                // to the override if set, otherwise the router's
                // own hostname; suppressed entirely when
                // send_hostname=false. Empty strings also treated
                // as suppression (`insert_client_opts` skips them).
                let client_opts = crate::wan_dhcp::DhcpClientOpts {
                    hostname: if *send_hostname {
                        Some(
                            hostname_override
                                .clone()
                                .unwrap_or_else(|| cfg.hostname.clone()),
                        )
                    } else {
                        None
                    },
                    vendor_class_id: vendor_class_id.clone(),
                };
                tokio::spawn(async move {
                    let mut backoff = Duration::from_secs(10);
                    let lease = loop {
                        match wan_dhcp::acquire(
                            &handle,
                            &iface,
                            Duration::from_secs(15),
                            &client_opts,
                        )
                        .await
                        {
                            Ok(l) => break l,
                            Err(e) => {
                                tracing::warn!(
                                    wan = %name, iface = %iface, error = %e, backoff_s = backoff.as_secs(),
                                    "wan dhcp: initial acquire failed; retrying"
                                );
                                tokio::time::sleep(backoff).await;
                                backoff = (backoff * 2).min(Duration::from_secs(300));
                            }
                        }
                    };
                    if let Err(e) = wan_dhcp::apply_lease(&handle, &iface, &lease).await {
                        tracing::error!(wan = %name, iface = %iface, error = %e, "wan dhcp: apply_lease failed");
                    }
                    // Install the WAN's default into its per-WAN
                    // routing table so any zone that declared
                    // `wan = "<name>"` routes through it via the
                    // iif rule at priority 800. No-op when no
                    // zone references this WAN — the table sits
                    // populated-but-unused, which costs nothing
                    // except a few bytes.
                    if let (Some(table_id), Some(gw)) = (
                        crate::wan_routing::wan_table_id(&name, &cfg_for_wanrt),
                        lease.gateway,
                    ) {
                        if let Err(e) =
                            crate::wan_routing::set_wan_table_default(&handle, table_id, &iface, gw)
                                .await
                        {
                            tracing::warn!(wan = %name, table_id, error = %e, "wan_routing: per-WAN default install failed");
                        }
                    }
                    wan_leases
                        .write()
                        .unwrap()
                        .insert(name.clone(), Some(lease.clone()));

                    // Per-WAN renewal loop. The lease-slot
                    // parameter is THIS wan's slot — a renewal
                    // failure clears our slot, the failover
                    // coordinator notices and switches to the
                    // next priority.
                    //
                    // spawn_renewal_loop takes a SharedLease
                    // (single-slot). To fit the per-WAN map, we
                    // thread a dedicated SharedLease through and
                    // copy changes back into wan_leases via a
                    // mirror task. Cheap.
                    let per_wan_shared: control::SharedLease =
                        std::sync::Arc::new(std::sync::RwLock::new(Some(lease.clone())));
                    drop(wan_dhcp::spawn_renewal_loop(
                        handle,
                        iface.clone(),
                        lease,
                        per_wan_shared.clone(),
                        client_opts,
                    ));
                    // Mirror per_wan_shared → wan_leases[name]
                    // every 2 s so failover sees renewals.
                    {
                        let wan_leases = wan_leases.clone();
                        let name = name.clone();
                        tokio::spawn(async move {
                            loop {
                                tokio::time::sleep(Duration::from_secs(2)).await;
                                let snap: Option<Option<crate::wan_dhcp::DhcpLease>> =
                                    per_wan_shared.read().ok().map(|g| g.clone());
                                if let Some(s) = snap {
                                    wan_leases.write().unwrap().insert(name.clone(), s);
                                }
                            }
                        });
                    }

                    // Fire SNTP bootstrap once across all WANs —
                    // the first to reach Acquired wins. Uses the
                    // anycast time.cloudflare.com so there's no
                    // per-WAN dependency.
                    if !sntp_fired.swap(true, std::sync::atomic::Ordering::SeqCst) {
                        if let Err(e) = sntp_bootstrap_clock("162.159.200.1:123").await {
                            tracing::warn!(error = %e, "sntp bootstrap failed");
                        }
                    }
                });
            }
        }

        // Publish static WANs as synthesized leases. The coordinator
        // treats wan_leases opaquely — a lease is a lease is a
        // lease — so handing it a static entry makes failover work
        // for mixed DHCP+static deployments. lease_seconds is set
        // to u32::MAX (static never expires); server is 0.0.0.0
        // (no DHCP server involved); DNS is filtered to v4 entries
        // only since DhcpLease stores Vec<Ipv4Addr>.
        {
            let mut leases = wan_leases.write().unwrap();
            for w in cfg.wans_by_priority() {
                if let Network::Wan {
                    name,
                    wan:
                        WanConfig::Static {
                            address,
                            prefix,
                            gateway,
                            dns,
                        },
                    ..
                } = w
                {
                    let v4_dns: Vec<std::net::Ipv4Addr> = dns
                        .iter()
                        .filter_map(|ip| match ip {
                            std::net::IpAddr::V4(v) => Some(*v),
                            _ => None,
                        })
                        .collect();
                    let synth = crate::wan_dhcp::DhcpLease {
                        address: *address,
                        prefix: *prefix,
                        gateway: Some(*gateway),
                        dns: v4_dns,
                        lease_seconds: u32::MAX,
                        server: std::net::Ipv4Addr::UNSPECIFIED,
                    };
                    leases.insert(name.clone(), Some(synth));
                }
            }
        }

        // Failover coordinator: picks highest-priority WAN with
        // a Some lease, mirrors into `wan_lease`, installs default
        // route. Single-WAN deployments still run this; it's a
        // no-op on the trivial case (pick_active always returns
        // the sole WAN's lease).
        let cfg_for_failover = std::sync::Arc::new(cfg.clone());
        drop(crate::wan_failover::spawn(
            cfg_for_failover,
            wan_leases.clone(),
            wan_health.clone(),
            active_wan.clone(),
            wan_lease.clone(),
            net_handle.handle().clone(),
        ));
    }

    // DHCPv6-PD on WAN. Gated on `ipv6_pd = true`. Acquire → apply
    // → corerad regen → kick off a renewal loop that handles T1
    // Renew / T2 Rebind / expiry-restart per RFC 8415 § 18.2.10.
    let v6_lease: wan_dhcp6::SharedV6Lease = std::sync::Arc::new(std::sync::RwLock::new(None));
    if let (
        Some(net_handle),
        Some(Network::Wan {
            iface,
            ipv6_pd: true,
            ..
        }),
    ) = (&net, cfg.primary_wan())
    {
        let handle = net_handle.handle().clone();
        let iface = iface.clone();
        let cfg_clone = cfg.clone();
        let v6_lease_clone = v6_lease.clone();
        tokio::spawn(async move {
            let mut backoff = Duration::from_secs(10);
            let lease = loop {
                match wan_dhcp6::acquire(&iface, Duration::from_secs(15)).await {
                    Ok(l) => break l,
                    Err(e) => {
                        tracing::warn!(
                            iface = %iface, error = %e, backoff_s = backoff.as_secs(),
                            "wan dhcpv6-pd: initial acquire failed; retrying"
                        );
                        tokio::time::sleep(backoff).await;
                        backoff = (backoff * 2).min(Duration::from_secs(300));
                    }
                }
            };
            tracing::info!(
                prefix = %lease.prefix,
                prefix_len = lease.prefix_len,
                valid = lease.valid_lifetime,
                t1 = lease.t1,
                t2 = lease.t2,
                "wan dhcpv6-pd: lease acquired"
            );
            if let Err(e) = wan_dhcp6::apply_delegation(&handle, &cfg_clone, &lease).await {
                tracing::error!(error = %e, "v6 apply_delegation failed");
            }
            let new_cfg = wan_dhcp6::cfg_with_delegated_prefix(&cfg_clone, &lease);
            if let Err(e) = crate::corerad::write_config(&new_cfg) {
                tracing::error!(error = %e, "corerad regen after PD failed");
            }
            // Drive renew/rebind/re-Solicit for the lifetime of this
            // boot. Detached — JoinHandle intentionally dropped like
            // the v4 renewal loop.
            drop(wan_dhcp6::spawn_renewal_loop(
                iface,
                lease,
                v6_lease_clone,
                cfg_clone,
                handle,
            ));
        });
    }
    let _ = v6_lease; // reserved for future diag exposure

    let firewall_dump = if net.is_some() {
        if let Err(e) = net::install_firewall(&cfg) {
            tracing::error!(error = %e, "install_firewall failed");
        }
        net::format_firewall_dump(&cfg)
    } else {
        Vec::new()
    };

    // Blocklists: fetch each configured list and install the
    // oxwrt-blocklist nftables table with one set + one drop rule
    // per list. Best-effort — fetch failures install an empty set
    // and log warn, so a CDN outage at boot doesn't drop all
    // traffic. Runs after install_firewall so the main table's
    // INPUT is already in place (our table is priority -10 and
    // short-circuits before it).
    if let Err(e) = crate::blocklists::install(&cfg).await {
        tracing::error!(error = %e, "blocklists install failed");
    }
    // Per-list refreshers — each sleeps its configured
    // refresh_seconds and updates just its own set on wake. Pass
    // an owned Arc<Config> snapshot; a later reload spawns fresh
    // refreshers off the new cfg and the old tasks are abandoned
    // (no explicit cancel — they live forever but do no meaningful
    // work once the sets they wrote are flushed by the reload).
    let _blocklist_tasks = crate::blocklists::spawn_refreshers(std::sync::Arc::new(cfg.clone()));

    // Static routes: install after WAN bring-up + firewall. If a route
    // targets a gateway reachable only via WAN, and WAN DHCP is still
    // in progress at this point, the add returns ENETUNREACH — we log
    // warn and the reconcile on the next `reload` picks it up once WAN
    // is live. This is fine because real deployments that need routes
    // synchronized with WAN acquisition use the DHCP client's own
    // classless-static-routes handling instead.
    if let Some(ref net) = net {
        if let Err(e) = crate::static_routes::install(&cfg, net.handle()).await {
            tracing::error!(error = %e, "static_routes install failed");
        }
    }

    // Pre-create host-side veth for every Isolated service + enable
    // forwarding + install NAT MASQUERADE. These are one-shot boot steps;
    // the per-spawn peer move/config happens inside `container::spawn`.
    let mut isolated_services = 0usize;
    if let Some(ref net) = net {
        for svc in &cfg.services {
            if svc.net_mode != NetMode::Isolated {
                continue;
            }
            let Some(veth) = &svc.veth else {
                tracing::warn!(
                    service = %svc.name,
                    "Isolated service missing veth config; skipping host veth setup"
                );
                continue;
            };
            match net
                .setup_host_veth(&svc.name, veth.host_ip, veth.prefix)
                .await
            {
                Ok((host, peer)) => {
                    tracing::info!(
                        service = %svc.name,
                        host_iface = %host,
                        peer_iface = %peer,
                        host_ip = %veth.host_ip,
                        "host veth ready"
                    );
                    isolated_services += 1;
                }
                Err(e) => {
                    tracing::error!(
                        service = %svc.name,
                        error = %e,
                        "host veth setup failed; service will start without network"
                    );
                }
            }
        }
    }
    // Forwarding is needed whenever the router forwards between subnets —
    // any deployment with either an isolated service or an isolated subnet.
    // Enable unconditionally; idempotent and no-op on a pure-LAN deployment.
    if isolated_services > 0 || !cfg.networks.is_empty() {
        if let Err(e) = net::enable_ipv4_forwarding() {
            tracing::error!(error = %e, "enable_ipv4_forwarding failed");
        }
    }
    // IPv6 forwarding — harmless without v6 connectivity, required for
    // corerad's RAs on a routing LAN. Idempotent.
    if let Err(e) = net::enable_ipv6_forwarding() {
        tracing::error!(error = %e, "enable_ipv6_forwarding failed");
    }

    let supervisor = Supervisor::from_config(&cfg.services);
    let logd = Logd::new();
    let state = ControlState::new(
        cfg.clone(),
        supervisor,
        logd.clone(),
        firewall_dump,
        wan_lease.clone(),
        active_wan.clone(),
        wan_leases.clone(),
        wan_health.clone(),
    );
    // Move the initial probe handles into ControlState so reload
    // can abort + respawn.
    if let Ok(mut h) = state.probe_handles.lock() {
        h.extend(initial_probe_handles);
    }

    // ── VPN coordinator + probes ───────────────────────────────────
    //
    // Seed bring-up state from the earlier `vpn_client::setup_all`
    // result — in v1 that's all-or-nothing per profile (the function
    // returns Ok() unconditionally and logs per-profile errors), so
    // mark all declared profiles as brought-up. A future refinement
    // would plumb per-profile results through and seed accordingly.
    // Mark everything as `true` so the coordinator lets probes alone
    // veto; effectively "if `wg setconf` didn't throw, trust the
    // kernel."
    crate::vpn_failover::mark_bringup(&state.vpn_bringup, &cfg, true);

    // Guest-WiFi rotation: one tokio task per [[wifi]] entry with
    // `rotate_hours` set. Each rotates the passphrase on its
    // schedule, writes sidecars at /etc/oxwrt/wifi-*-passphrase.txt
    // and -qr.txt, logs a "run `oxctl reload`" hint. v1
    // operator-triggered reload; auto-reload is a follow-up.
    //
    // async_main doesn't receive the config path by parameter;
    // re-derive from env + the DEFAULT_PATH fallback the outer
    // run() used (same logic, since env doesn't change between
    // them).
    let rotate_cfg_path = std::env::var("OXWRT_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(config::DEFAULT_PATH));
    crate::wifi_rotate::spawn_all(&cfg, rotate_cfg_path);

    // Scheduled off-router config backup. Runs every
    // cfg.backup_sftp.interval_hours (default 24), shells out to
    // ssh(1) to push /etc/oxwrt/* tarball to a remote host. No-op
    // when cfg.backup_sftp is None.
    let include_secrets = cfg
        .backup_sftp
        .as_ref()
        .map(|s| s.include_secrets)
        .unwrap_or(true);
    crate::backup_sftp::spawn(&cfg, move || {
        crate::control::server::backup::build_tarball(include_secrets)
    });

    if !cfg.vpn_client.is_empty() {
        if let Some(net_handle) = &net {
            let probes = crate::vpn_failover::spawn_probes(&cfg, state.vpn_health.clone());
            if let Ok(mut h) = state.vpn_probe_handles.lock() {
                h.extend(probes);
            }
            let coord = crate::vpn_failover::spawn(
                std::sync::Arc::new(cfg.clone()),
                state.vpn_bringup.clone(),
                state.vpn_health.clone(),
                state.active_vpn.clone(),
                wan_leases.clone(),
                active_wan.clone(),
                net_handle.handle().clone(),
            );
            if let Ok(mut h) = state.vpn_coordinator_handle.lock() {
                *h = Some(coord);
            }
            tracing::info!(
                profiles = cfg.vpn_client.len(),
                "vpn_failover: coordinator + probes spawned"
            );
        }
    }

    let listen_addrs = parse_listen_addrs(&cfg.control.listen);
    let server = Arc::new(Server::load(
        Path::new(SIGNING_KEY_PATH),
        &cfg.control,
        state.clone(),
    )?);
    let server_task = {
        let server = server.clone();
        tokio::spawn(async move {
            if let Err(e) = server.listen(&listen_addrs).await {
                tracing::error!(error = %e, "control server exited");
            }
        })
    };

    // DDNS updater. Polls the shared WAN lease and pushes the
    // current IP to every configured [[ddns]] provider when it
    // changes. No-op if the list is empty. Safe to start this
    // before the first DHCP lease lands — the task internally
    // skips ticks where the lease is still None.
    crate::ddns::spawn(state.clone(), wan_lease.clone());

    // Prometheus /metrics endpoint. No-op when cfg.metrics is None.
    // Same Arc<ControlState> the RPC server uses, so `oxctl status`
    // and `curl http://router:9100/metrics` return consistent data.
    crate::metrics::apply(&state);

    // Persistent urandom seed. Periodic writes to
    // /etc/urandom.seed so the next boot's preinit finds a warm
    // CRNG seed to feed into /dev/urandom — closes the "Seed
    // file not found" gap on every first-after-flash boot. Also
    // means unexpected power-cycles preserve up to 30 min of
    // entropy freshness. Fire-and-forget: task lives for the
    // process lifetime, no explicit abort on shutdown.
    // JoinHandle intentionally dropped — the task lives for the
    // process lifetime; no shutdown cleanup to hook.
    drop(crate::urandom_seed::spawn_saver());

    // AP-state watcher. Fires a warn-log if any expected AP iface
    // (one per [[wifi]] entry, named `{phy}-ap0`) is still `down` 90s
    // past boot. Caught today's MT7986 DFS-CAC-stuck bug cold; without
    // this, a silently-down AP produces no log output anywhere — the
    // only way operators notice is a client failing to associate.
    //
    // Fire-and-forget: runs for ~180s, logs once per still-down AP at
    // each check, then exits. Short-circuit exit the moment all
    // expected APs are up — no point burning cpu once everything's
    // healthy.
    {
        let state = state.clone();
        tokio::spawn(async move {
            use std::time::Instant;
            let start = Instant::now();
            let warn_threshold = Duration::from_secs(90);
            let watcher_deadline = Duration::from_secs(180);
            let mut already_warned: std::collections::HashSet<String> =
                std::collections::HashSet::new();
            loop {
                tokio::time::sleep(Duration::from_secs(10)).await;
                let elapsed = start.elapsed();
                if elapsed >= watcher_deadline {
                    return;
                }
                let cfg = state.config_snapshot();
                let aps = control::server::collect_ap_status(&cfg);
                let still_down: Vec<&crate::rpc::ApStatus> =
                    aps.iter().filter(|ap| ap.operstate != "up").collect();
                if still_down.is_empty() {
                    return; // all healthy — exit early
                }
                if elapsed >= warn_threshold {
                    for ap in &still_down {
                        if !already_warned.contains(&ap.iface) {
                            tracing::warn!(
                                ssid = %ap.ssid,
                                iface = %ap.iface,
                                operstate = %ap.operstate,
                                radio = %ap.radio_phy,
                                band = %ap.band,
                                channel = ap.channel,
                                elapsed_s = elapsed.as_secs(),
                                "AP iface not up {}s after boot — check hostapd logs, DFS status, regulatory domain",
                                elapsed.as_secs(),
                            );
                            already_warned.insert(ap.iface.clone());
                        }
                    }
                }
            }
        });
    }

    // Boot reconcile succeeded — everything up to this point
    // (early mounts, netdev rename, firewall install, services up,
    // control server listening) is the known-good state oxwrt
    // should roll back TO if a subsequent reload breaks things.
    // First boot on a fresh flash: this creates the initial
    // snapshot. Subsequent boots: overwrites with whatever just
    // came up, so a post-sysupgrade config that boots is
    // automatically promoted to last-good.
    let snap_path = std::env::var("OXWRT_CONFIG")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from(crate::config::DEFAULT_PATH));
    crate::control::server::rollback::take_snapshot(&snap_path);

    let mut tick = tokio::time::interval(Duration::from_millis(100));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|e| Error::Runtime(e.to_string()))?;
    let mut hup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        .map_err(|e| Error::Runtime(e.to_string()))?;

    loop {
        tokio::select! {
            _ = tick.tick() => {
                if let Ok(mut sup) = state.supervisor.lock() {
                    sup.tick(&logd);
                }
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("oxwrtd: SIGINT → shutdown");
                break;
            }
            _ = term.recv() => {
                tracing::info!("oxwrtd: SIGTERM → shutdown");
                break;
            }
            _ = hup.recv() => {
                // Standard Unix convention: SIGHUP → re-read config.
                // Runs the same five-phase pipeline as the sQUIC Reload
                // RPC: parse → reconcile netlink → reinstall firewall →
                // rebuild supervisor → publish new state. Useful when an
                // operator edits /etc/oxwrt.toml via TFTP/serial
                // recovery and wants to apply without a reboot.
                tracing::info!("oxwrtd: SIGHUP → reload");
                let resp = control::server::handle_reload_async(&state).await;
                match &resp {
                    crate::rpc::Response::Ok => {
                        tracing::info!("SIGHUP reload: ok");
                    }
                    crate::rpc::Response::Err { message } => {
                        tracing::error!(error = %message, "SIGHUP reload failed");
                    }
                    _ => {
                        tracing::warn!("SIGHUP reload: unexpected response: {resp:?}");
                    }
                }
            }
        }
    }

    if let Ok(mut sup) = state.supervisor.lock() {
        sup.shutdown();
    }
    server_task.abort();
    Ok(())
}
