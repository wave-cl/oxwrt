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
use super::watchdog::{spawn_heartbeat, spawn_watchdog_pet};
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

    // Mark the overlay as READY so libfstools's next-boot mount_overlay()
    // doesn't fall through to overlay_delete() and wipe everything.
    //
    // OpenWrt's fstools treats /overlay/.fs_state as a three-state marker
    // (symlink target "0"=UNKNOWN, "1"=PENDING, "2"=READY). On boot, if
    // it reads PENDING (or UNKNOWN, which it auto-upgrades to PENDING),
    // mount_overlay() calls overlay_delete(overlay_mp, true) BEFORE the
    // pivot. That deletes every file on the overlay (libfstools/overlay.c
    // line 452-453: "overlay filesystem has not been fully initialized
    // yet" \u2192 overlay_delete).
    //
    // The READY transition is normally done by `mount_root done`,
    // invoked by procd at end-of-init (mount_root.c:132). Since oxwrtd
    // replaced procd as PID 1 and never calls `mount_root done`, the
    // overlay stays at PENDING forever \u2014 which means every boot wipes
    // the overlay, which is why pushed configs + urandom seed kept
    // reverting.
    mark_overlay_ready();

    let config_path = std::env::var("OXWRT_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(config::DEFAULT_PATH));

    // Forensics: log the on-disk config size + the WAN count so
    // we can correlate "pushed config lost on reboot" with what
    // oxwrtd actually read from disk at pid-1 time. Written to
    // /dev/kmsg directly (bypassing the tracing layer) so an
    // early-boot tracing-writer hiccup can't hide it.
    {
        use std::io::Write;
        let live_size = std::fs::metadata(&config_path)
            .map(|m| m.len())
            .unwrap_or(0);
        let rom_path = std::path::PathBuf::from(format!("/rom{}", config_path.display()));
        let rom_size = std::fs::metadata(&rom_path).map(|m| m.len()).unwrap_or(0);
        let live_body = std::fs::read_to_string(&config_path).unwrap_or_default();
        let wan_count = live_body.matches("type = \"wan\"").count();
        let probes = live_body.matches("probe_target").count();
        let backups = live_body.matches("wan-backup").count();
        let upper_new = std::fs::metadata("/overlay/upper/etc/oxwrt/oxwrt.toml")
            .map(|m| m.len())
            .ok();
        let upper_legacy = std::fs::metadata("/overlay/upper/etc/oxwrt.toml")
            .map(|m| m.len())
            .ok();
        let sysupgrade_tgz = std::fs::metadata("/sysupgrade.tgz").is_ok()
            || std::fs::metadata("/overlay/upper/sysupgrade.tgz").is_ok();
        let msg = format!(
            "<4>forensic: path={} live={} rom={} upper_new={:?} upper_legacy={:?} wan_count={} probe_target={} wan_backup={} sysupgrade_tgz={}\n",
            config_path.display(), live_size, rom_size, upper_new, upper_legacy, wan_count, probes, backups, sysupgrade_tgz
        );
        if let Ok(mut kmsg) = std::fs::OpenOptions::new().write(true).open("/dev/kmsg") {
            let _ = kmsg.write_all(msg.as_bytes());
        }
    }

    run_secrets_migration(&config_path);
    tighten_secrets_file_mode(&config_path);
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

    // Point the router's own resolver at the LAN IP. Outbound
    // libc-resolving code (ddns reqwest, sysupgrade fetch, etc.)
    // falls through without this — there's no /etc/resolv.conf on
    // a fresh OpenWrt rootfs and nothing else populates it after
    // we ditched dnsmasq + resolvfs. Queries to <lan>:53 hit the
    // firewall's DNAT rule and land on the hickory container,
    // which forwards via DoH — so the router inherits the same
    // encrypted-upstream property as LAN clients.
    write_self_resolv_conf(&cfg);

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
    run_secrets_migration(&config_path);
    tighten_secrets_file_mode(&config_path);
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
    run_secrets_migration(&config_path);
    tighten_secrets_file_mode(&config_path);
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
            if let Err(e) =
                crate::vpn_routing::cleanup_stale_endpoint_exemptions(&handle).await
            {
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
                wan: WanConfig::Dhcp,
                ..
            } = w
            {
                let handle = net_handle.handle().clone();
                let iface = iface.clone();
                let name = name.clone();
                let wan_leases = wan_leases.clone();
                let sntp_fired = sntp_fired.clone();
                let cfg_for_wanrt = cfg.clone();
                tokio::spawn(async move {
                    let mut backoff = Duration::from_secs(10);
                    let lease = loop {
                        match wan_dhcp::acquire(&handle, &iface, Duration::from_secs(15)).await {
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
                        if let Err(e) = crate::wan_routing::set_wan_table_default(
                            &handle, table_id, &iface, gw,
                        )
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
            let probes =
                crate::vpn_failover::spawn_probes(&cfg, state.vpn_health.clone());
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
    let _ = crate::urandom_seed::spawn_saver();

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

/// Ensure `oxwrt.secrets.toml` is mode 0600 on every boot.
/// Defence-in-depth: an operator hand-edit might copy the file
/// with default umask, exposing the secrets to local non-root
/// processes. Called right after the migration shim, before
/// Config::load, so the permission is tight before anyone reads
/// the file. No-op if the file doesn't exist.
fn tighten_secrets_file_mode(public_path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let secrets = public_path.with_file_name("oxwrt.secrets.toml");
    let Ok(meta) = std::fs::metadata(&secrets) else {
        return;
    };
    let mode = meta.permissions().mode() & 0o777;
    if mode != 0o600 {
        if let Err(e) = std::fs::set_permissions(
            &secrets,
            std::fs::Permissions::from_mode(0o600),
        ) {
            tracing::error!(
                error = %e,
                path = %secrets.display(),
                prev_mode = format!("{mode:o}"),
                "failed to tighten oxwrt.secrets.toml mode to 0600"
            );
        } else {
            tracing::warn!(
                path = %secrets.display(),
                prev_mode = format!("{mode:o}"),
                "tightened oxwrt.secrets.toml mode to 0600 (was looser)"
            );
        }
    }
}

/// One-shot migration from the old single-file `oxwrt.toml` (inline
/// secrets) to the split public + `oxwrt.secrets.toml` layout.
///
/// Called once on boot, before `Config::load`. Idempotent:
/// subsequent boots find the public file already clean and
/// short-circuit. On error we log and continue — the loader's
/// merge path handles any partial state.
fn run_secrets_migration(public_path: &Path) {
    use oxwrt_api::secrets::{MigrationOutcome, migrate_public_to_split};
    match migrate_public_to_split(public_path) {
        Ok(MigrationOutcome::Migrated { count }) => {
            tracing::info!(
                count,
                public = %public_path.display(),
                secrets = %public_path.with_file_name("oxwrt.secrets.toml").display(),
                "migrated secrets out of public config; public file is now publishable"
            );
        }
        Ok(MigrationOutcome::AlreadyClean) => {} // steady state
        Ok(MigrationOutcome::NoPublicFile) => {}
        Ok(MigrationOutcome::BothPresentUnsafe) => {
            tracing::warn!(
                public = %public_path.display(),
                "oxwrt.toml contains inline secrets and oxwrt.secrets.toml \
                 already exists; leaving both alone. Delete oxwrt.secrets.toml \
                 to force re-migration, or remove the inline secrets from the \
                 public file by hand."
            );
        }
        Err(e) => {
            tracing::error!(error = %e, "secrets migration failed; loader will merge whatever is on disk");
        }
    }
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

/// Write `/etc/resolv.conf` so libc-resolver-based code on the
/// router (ddns reqwest, sysupgrade fetches, etc.) uses the
/// on-device hickory-dns via the firewall's DNAT rule — the same
/// DoH upstream path LAN clients take. Idempotent.
///
/// Uses the first LAN bridge's address; falls back to the first
/// Simple network if there's no LAN (unusual) and skips entirely
/// if neither exists (router has no internal net to resolve
/// through; local libc queries will fail, but that's already the
/// reality today so no regression).
fn write_self_resolv_conf(cfg: &Config) {
    use crate::config::Network;
    let ip = cfg.networks.iter().find_map(|n| match n {
        Network::Lan { address, .. } | Network::Simple { address, .. } => Some(*address),
        Network::Wan { .. } => None,
    });
    let Some(ip) = ip else {
        tracing::info!("no LAN/Simple network configured; skipping /etc/resolv.conf generation");
        return;
    };
    let text = format!(
        "# Auto-generated by oxwrtd at boot. Points at the on-device\n\
         # hickory-dns via the firewall's DNAT rule; do not edit\n\
         # manually — the file is rewritten every boot.\n\
         nameserver {ip}\n"
    );
    if let Err(e) = std::fs::write("/etc/resolv.conf", text) {
        tracing::warn!(error = %e, "failed to write /etc/resolv.conf");
    } else {
        tracing::info!(nameserver = %ip, "wrote /etc/resolv.conf");
    }
}
