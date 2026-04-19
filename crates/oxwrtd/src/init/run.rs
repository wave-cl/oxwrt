//! Daemon entry points + async orchestration.
//!
//! Split out of init.rs in step 6 of the workspace refactor.

#![allow(clippy::too_many_lines)]

use super::SIGNING_KEY_PATH;
use super::clock::bootstrap_clock_floor;
use super::clock::sntp_bootstrap_clock;
use super::modules::load_modules;
use super::netdev::{create_wifi_ap_interfaces, rename_netdevs_from_dts};
use super::preinit::*;
use super::watchdog::spawn_watchdog_pet;
use super::*;

pub fn run() -> Result<(), Error> {
    early_mounts()?;

    // Temporary diagnostic: log /dev contents and /proc/mounts after
    // early_mounts. Helps pinpoint why /dev/mmcblk0pN isn't available
    // when mount_root tries to open it on the standalone pid1 path.
    {
        let mut dev_entries: Vec<String> = std::fs::read_dir("/dev")
            .ok()
            .into_iter()
            .flatten()
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().into_string().ok())
            .collect();
        dev_entries.sort();
        tracing::info!(count = dev_entries.len(), sample = ?dev_entries.iter().take(20).collect::<Vec<_>>(), "diag: /dev entries after early_mounts");
        if let Ok(mounts) = std::fs::read_to_string("/proc/mounts") {
            for line in mounts.lines().take(15) {
                tracing::info!(line, "diag: /proc/mounts");
            }
        }
    }

    // Stage 1 of the procd-init takeover: kernel module loading.
    // Walk /etc/modules-boot.d/ then /etc/modules.d/ and finit_module
    // each entry. In coexist mode (procd-init still runs preinit
    // upstream), every call returns EEXIST and this is a no-op —
    // that's intentional, the migration path is "land the code, verify
    // it's benign in coexist, then remove procd-init ahead of it."
    load_modules();

    // Stage 2 of the takeover: mount_root. Gate on "is the overlay
    // already mounted?" — in coexist with procd-init the answer is
    // always yes (procd ran /lib/preinit/80_mount_root upstream) and
    // we skip. When Stage 4 removes procd-init, this becomes the hot
    // path.
    // Stage 3 of the takeover: netdev renaming from DTS labels.
    // On OpenWrt the target-specific /lib/preinit/04_set_netdev_label
    // hook walks /sys/class/net/*/of_node/label and renames the
    // interface to match. On the GL-MT6000 this is what makes the
    // kernel's default ethX naming line up with the "lan1..lan5"
    // labels we reference in oxwrt.toml. In coexist this has already
    // happened upstream and our walk is all no-ops.
    rename_netdevs_from_dts();

    // Wifi AP interfaces. Once the mt76 driver has registered phy0/phy1,
    // we need AP-mode netdevs on them before hostapd can start (hostapd
    // with driver=nl80211 does not auto-create from the `phyN-` prefix
    // convention — OpenWrt's netifd did that on top). Idempotent: `iw
    // interface add` returns EEXIST if the iface is already there, which
    // we log and ignore. Skipped silently when iw isn't shipped (image
    // without wifi) or when the phys aren't registered (driver not
    // loaded / no hardware).
    create_wifi_ap_interfaces();

    if let Err(e) = mount_root_if_needed() {
        // Non-fatal: if we fail to set up the overlay here AND
        // procd-init didn't set it up either, /etc is read-only
        // squashfs and config-reload will fail. But oxwrtd can
        // still start the control plane on the in-memory config,
        // so operators have a recovery path.
        tracing::error!(error = %e, "mount_root_if_needed failed");
    }

    let config_path = std::env::var("OXWRT_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(config::DEFAULT_PATH));
    let cfg = Config::load(&config_path)?;

    // Sanity-truncate coredhcp's persisted lease file if any lease falls
    // outside the configured LAN subnet. This protects against the LAN
    // being renumbered (e.g. 192.168.1.0/24 → 192.168.50.0/24 to fix a
    // double-NAT collision): the range plugin fails fatally with
    // "allocator did not re-allocate requested leased ip X" when it
    // reads a pre-existing lease outside its pool. Losing DHCP lease
    // persistence on a subnet change is an acceptable trade — clients
    // re-DISCOVER within seconds.
    truncate_stale_dhcp_leases(&cfg);

    // Generate per-phy hostapd.conf files at /etc/oxwrt/hostapd/ from
    // the [[radios]] + [[wifi]] config. Bind-mount sources for the
    // hostapd-5g / hostapd-2g services point here (writable overlay
    // path), so changes via CRUD → reload → hostapd restart pick up the
    // new SSID / passphrase without a reflash. Non-fatal: if the write
    // fails, hostapd may start with stale or absent config, but the
    // rest of the router still comes up.
    if let Err(e) = crate::wifi::write_all(&cfg) {
        tracing::error!(error = %e, "wifi: write_all failed at boot");
    }

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_io()
        .enable_time()
        .worker_threads(2)
        .build()
        .map_err(|e| Error::Runtime(e.to_string()))?;

    rt.block_on(async_main(cfg))
}

/// Control-plane-only mode: starts the sQUIC listener + supervisor tick
/// loop, but skips early mounts, network bring-up, service spawning, and
/// firewall install. Safe to run as a normal process (procd managed or
/// from SSH) on a live OpenWrt device — won't touch the network config.
///
/// Use this for development: test CRUD / config-dump / diag / status
/// against real hardware before committing to a PID 1 replacement.
pub fn run_control_only() -> Result<(), Error> {
    let config_path = std::env::var("OXWRT_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(config::DEFAULT_PATH));
    let cfg = Config::load(&config_path)?;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_io()
        .enable_time()
        .worker_threads(2)
        .build()
        .map_err(|e| Error::Runtime(e.to_string()))?;

    rt.block_on(control_only_main(cfg))
}

/// Services-only mode: control plane + supervisor (running the real
/// services declared in config), but no early mounts, no netlink
/// network bring-up, no WAN DHCP, no firewall install. Intermediate
/// between `--control-only` (supervisor empty) and full `--init`
/// (supervisor + netlink + firewall + PID 1 duties). Used during
/// bring-up to exercise the supervisor on a stock OpenWrt device:
/// procd/netifd/fw4 stay in charge of the network, oxwrtd only
/// runs the declared services.
///
/// Prerequisite on the host: `/dev/pts` already mounted (procd does
/// this in its initramfs), cgroup v2 controllers usable (likewise).
/// When we later promote this binary to PID 1, early_mounts() sets
/// those up — but as a side binary we rely on the host's.
pub fn run_services_only() -> Result<(), Error> {
    let config_path = std::env::var("OXWRT_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(config::DEFAULT_PATH));
    let cfg = Config::load(&config_path)?;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_io()
        .enable_time()
        .worker_threads(2)
        .build()
        .map_err(|e| Error::Runtime(e.to_string()))?;

    rt.block_on(services_only_main(cfg))
}

async fn services_only_main(cfg: Config) -> Result<(), Error> {
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
        &cfg.control.authorized_keys,
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

async fn control_only_main(cfg: Config) -> Result<(), Error> {
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
        &cfg.control.authorized_keys,
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

async fn async_main(cfg: Config) -> Result<(), Error> {
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
    if let Err(e) = crate::wireguard::setup_wireguard(&cfg) {
        tracing::error!(error = %e, "wireguard setup failed; tunnels disabled");
    }

    // corerad config is derived from cfg.networks' ipv6_* fields;
    // regenerate at boot so changes to [[networks]] take effect
    // without a rebuild-and-flash cycle.
    if let Err(e) = crate::corerad::write_config(&cfg) {
        tracing::error!(error = %e, "corerad config generation failed");
    }

    let wan_lease: control::SharedLease = std::sync::Arc::new(std::sync::RwLock::new(None));

    if let (
        Some(net_handle),
        Some(Network::Wan {
            iface,
            wan: WanConfig::Dhcp,
            ..
        }),
    ) = (&net, cfg.primary_wan())
    {
        let handle = net_handle.handle().clone();
        let iface = iface.clone();
        let wan_lease_clone = wan_lease.clone();
        // Spawn acquire + renewal as a single background task so initial
        // failure (e.g. WAN cable not plugged at boot) doesn't give up
        // forever. The task retries acquire with 10s→5min backoff until
        // the link is usable, then spawns the normal renewal loop and
        // triggers SNTP bootstrap. Keeps oxwrt boot deterministic — we
        // don't block userspace-init waiting for DHCP.
        tokio::spawn(async move {
            let mut backoff = Duration::from_secs(10);
            let lease = loop {
                match wan_dhcp::acquire(&handle, &iface, Duration::from_secs(15)).await {
                    Ok(l) => break l,
                    Err(e) => {
                        tracing::warn!(
                            iface = %iface, error = %e, backoff_s = backoff.as_secs(),
                            "wan dhcp: initial acquire failed; retrying"
                        );
                        tokio::time::sleep(backoff).await;
                        backoff = (backoff * 2).min(Duration::from_secs(300));
                    }
                }
            };
            if let Err(e) = wan_dhcp::apply_lease(&handle, &iface, &lease).await {
                tracing::error!(iface = %iface, error = %e, "wan dhcp: apply_lease failed");
            }
            *wan_lease_clone.write().unwrap() = Some(lease.clone());
            // Renewal loop runs as a detached tokio task — the returned
            // JoinHandle isn't awaited (fire-and-forget). `drop(_)`
            // over `let _ =` so clippy's non-binding-let-on-future
            // lint doesn't fire.
            drop(wan_dhcp::spawn_renewal_loop(
                handle,
                iface.clone(),
                lease,
                wan_lease_clone,
            ));
            // SNTP bootstrap once WAN is up. See historical comment:
            // time.cloudflare.com (162.159.200.1) is anycast, no DNS
            // needed, used only to initialize the clock floor before
            // ntpd-rs takes over.
            if let Err(e) = sntp_bootstrap_clock("162.159.200.1:123").await {
                tracing::warn!(error = %e, "sntp bootstrap failed");
            }
        });
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
    );

    let listen_addrs = parse_listen_addrs(&cfg.control.listen);
    let server = Arc::new(Server::load(
        Path::new(SIGNING_KEY_PATH),
        &cfg.control.authorized_keys,
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

fn parse_listen_addrs(listen: &[String]) -> Vec<SocketAddr> {
    listen
        .iter()
        .filter_map(|s| match s.parse::<SocketAddr>() {
            Ok(a) => Some(a),
            Err(e) => {
                tracing::warn!(addr = %s, error = %e, "skipping malformed control listen address");
                None
            }
        })
        .collect()
}
