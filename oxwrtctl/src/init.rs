//! PID 1 entrypoint. Mounts early filesystems, reaps children, supervises
//! containers, hosts the sQUIC control plane.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::config::{self, Config, NetMode, Network, WanConfig};
use crate::container::Supervisor;
use crate::control::{self, ControlState, server::Server};
use crate::logd::Logd;
use crate::net::{self, Net};
use crate::wan_dhcp;

const SIGNING_KEY_PATH: &str = "/etc/oxwrt/key.ed25519";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("config: {0}")]
    Config(#[from] config::Error),
    #[error("mount {target}: {source}")]
    Mount {
        target: String,
        #[source]
        source: rustix::io::Errno,
    },
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("net: {0}")]
    Net(#[from] net::Error),
    #[error("control: {0}")]
    Control(#[from] crate::control::server::Error),
    #[error("runtime: {0}")]
    Runtime(String),
}

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

    if let Err(e) = mount_root_if_needed() {
        // Non-fatal: if we fail to set up the overlay here AND
        // procd-init didn't set it up either, /etc is read-only
        // squashfs and config-reload will fail. But oxwrtctl can
        // still start the control plane on the in-memory config,
        // so operators have a recovery path.
        tracing::error!(error = %e, "mount_root_if_needed failed");
    }

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
/// procd/netifd/fw4 stay in charge of the network, oxwrtctl only
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
        "oxwrtctl: services-only mode"
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
                tracing::info!("oxwrtctl: SIGINT → shutdown");
                break;
            }
            _ = term.recv() => {
                tracing::info!("oxwrtctl: SIGTERM → shutdown");
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
        "oxwrtctl: control-plane-only mode"
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
            tracing::info!("oxwrtctl: SIGINT → shutdown");
        }
        _ = term.recv() => {
            tracing::info!("oxwrtctl: SIGTERM → shutdown");
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
        "oxwrtctl: supervisor starting"
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
    // indistinguishable from an oxwrtctl crash unless you squint at
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
    // /etc/init.d/oxwrtctl never gets enabled (irrelevant under our own
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

    let wan_lease: control::SharedLease =
        std::sync::Arc::new(std::sync::RwLock::new(None));

    if let (Some(net_handle), Some(Network::Wan { iface, wan: WanConfig::Dhcp, .. })) =
        (&net, cfg.primary_wan())
    {
        let handle = net_handle.handle().clone();
        match wan_dhcp::acquire(&handle, iface, Duration::from_secs(15)).await {
            Ok(lease) => {
                if let Err(e) = wan_dhcp::apply_lease(&handle, iface, &lease).await {
                    tracing::error!(iface = %iface, error = %e, "wan dhcp: apply_lease failed");
                }
                *wan_lease.write().unwrap() = Some(lease.clone());
                let _ = wan_dhcp::spawn_renewal_loop(
                    handle,
                    iface.clone(),
                    lease,
                    wan_lease.clone(),
                );

                // Now that we have a WAN lease, fire a one-shot SNTP
                // query against a hard-coded IP to snap the system
                // clock to real-time. We can't use the ntpd-rs service
                // for this: it needs DNS to resolve pool.ntp.org, which
                // needs the dns container up, which needs us past this
                // boot phase. And without NTP the bootstrap-clock-floor
                // is only accurate to build-time ± replay_window — fine
                // for operators who flash and immediately connect, but
                // broken for images that sat for hours before boot.
                //
                // time.cloudflare.com (162.159.200.1) — anycast, very
                // reliable, no DNS needed. Not authenticated (NTS would
                // need time and roots both), but we only use the result
                // to initialize a floor; ntpd-rs takes over for ongoing
                // discipline.
                tokio::spawn(async {
                    if let Err(e) = sntp_bootstrap_clock("162.159.200.1:123").await {
                        tracing::warn!(error = %e, "sntp bootstrap failed");
                    }
                });
            }
            Err(e) => {
                tracing::warn!(iface = %iface, error = %e, "wan dhcp: no lease acquired");
            }
        }
    }

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
            match net.setup_host_veth(&svc.name, veth.host_ip, veth.prefix).await {
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
        wan_lease,
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
                tracing::info!("oxwrtctl: SIGINT → shutdown");
                break;
            }
            _ = term.recv() => {
                tracing::info!("oxwrtctl: SIGTERM → shutdown");
                break;
            }
            _ = hup.recv() => {
                // Standard Unix convention: SIGHUP → re-read config.
                // Runs the same five-phase pipeline as the sQUIC Reload
                // RPC: parse → reconcile netlink → reinstall firewall →
                // rebuild supervisor → publish new state. Useful when an
                // operator edits /etc/oxwrt.toml via TFTP/serial
                // recovery and wants to apply without a reboot.
                tracing::info!("oxwrtctl: SIGHUP → reload");
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

/// One-shot SNTP client: query `addr` (e.g. a hard-coded NTP server
/// IP), read the reply's transmit timestamp, and step the system
/// clock to match.
///
/// Minimal RFC 4330 implementation — no stratum / delay / precision
/// handling. We only use the result to initialize the clock; ntpd-rs
/// (our supervised service) takes over long-term discipline once DNS
/// is working.
///
/// Fails loudly if anything goes wrong (unreachable server, malformed
/// reply, clock_settime EPERM): best-effort, logged, not fatal.
async fn sntp_bootstrap_clock(addr: &str) -> Result<(), String> {
    use tokio::net::UdpSocket;
    use tokio::time::{Duration, timeout};

    // SNTP request: 48 zero bytes except the first, which is the
    // LI/VN/Mode header. 0x1B = LI=0, VN=3, Mode=3 (client).
    let mut req = [0u8; 48];
    req[0] = 0x1B;

    let sock = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| format!("bind: {e}"))?;
    sock.connect(addr).await.map_err(|e| format!("connect {addr}: {e}"))?;

    timeout(Duration::from_secs(5), sock.send(&req))
        .await
        .map_err(|_| "send timeout".to_string())?
        .map_err(|e| format!("send: {e}"))?;

    let mut buf = [0u8; 48];
    timeout(Duration::from_secs(5), sock.recv(&mut buf))
        .await
        .map_err(|_| "recv timeout".to_string())?
        .map_err(|e| format!("recv: {e}"))?;

    // Transmit timestamp: offset 40, 8 bytes (32-bit seconds since
    // NTP epoch 1900, 32-bit fractional seconds).
    let ntp_secs = u32::from_be_bytes([buf[40], buf[41], buf[42], buf[43]]);
    let ntp_frac = u32::from_be_bytes([buf[44], buf[45], buf[46], buf[47]]);
    if ntp_secs == 0 {
        return Err("reply had zero transmit timestamp".to_string());
    }

    // NTP epoch is Jan 1 1900; UNIX epoch is Jan 1 1970 —
    // 2_208_988_800 seconds earlier.
    const NTP_TO_UNIX_EPOCH: u64 = 2_208_988_800;
    let unix_secs = u64::from(ntp_secs).saturating_sub(NTP_TO_UNIX_EPOCH);
    // Fractional seconds → nanoseconds: (frac / 2^32) * 1e9.
    let unix_nsec = ((u64::from(ntp_frac) * 1_000_000_000) >> 32) as u32;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let skew = unix_secs as i64 - now as i64;

    let tv = rustix::time::Timespec {
        tv_sec: unix_secs as i64,
        tv_nsec: unix_nsec as i64,
    };
    rustix::time::clock_settime(rustix::time::ClockId::Realtime, tv)
        .map_err(|e| format!("clock_settime: {e}"))?;

    tracing::info!(
        server = %addr,
        unix_secs,
        skew_secs = skew,
        "sntp bootstrap: clock set from ntp reply"
    );
    Ok(())
}

/// Locate the /dev/watchdog file descriptor inherited from procd-init.
///
/// Walks /proc/self/fd and returns the first entry whose readlink
/// target matches "/dev/watchdog" (optionally with a trailing " (deleted)"
/// tag — unlikely here but cheap to tolerate). Returned File takes
/// ownership of the existing fd via from_raw_fd, so close-on-drop
/// behavior is correct.
fn find_inherited_watchdog_fd() -> Option<std::fs::File> {
    use std::os::fd::FromRawFd;
    let rd = std::fs::read_dir("/proc/self/fd").ok()?;
    for entry in rd.flatten() {
        let Ok(target) = std::fs::read_link(entry.path()) else {
            continue;
        };
        let s = target.to_string_lossy();
        if s == "/dev/watchdog" || s.starts_with("/dev/watchdog ") {
            let fd_name = entry.file_name();
            let Some(fd_str) = fd_name.to_str() else {
                continue;
            };
            let Ok(fd) = fd_str.parse::<i32>() else {
                continue;
            };
            // Don't steal stdio (0/1/2) even if some weirdness has those
            // pointing at /dev/watchdog — that'd deadlock logging.
            if fd < 3 {
                continue;
            }
            tracing::info!(fd = fd, "reusing inherited /dev/watchdog fd");
            // SAFETY: the fd is open in our process (we just verified
            // via /proc/self/fd), and we're taking ownership — nothing
            // else will close it.
            return Some(unsafe { std::fs::File::from_raw_fd(fd) });
        }
    }
    None
}

/// Pet the hardware watchdog in a background task.
///
/// Every OpenWrt board with a hardware watchdog (almost all of them,
/// including mediatek/filogic which this firmware targets) expects
/// userspace to write to /dev/watchdog periodically, or the watchdog
/// fires and the SoC reboots. On the GL-MT6000 the default timeout is
/// 31s. Stock procd runs a watchdog.c thread that writes every 5s.
///
/// We need to do the same. If /dev/watchdog doesn't exist (QEMU,
/// non-watchdog boards, --services-only side-binary), this logs at
/// debug level and returns — the loop only runs when the device is
/// actually there.
fn spawn_watchdog_pet() {
    use std::io::Write;

    // /sbin/init (procd-init) opens /dev/watchdog during preinit and
    // execve's /sbin/procd (us) with the fd still open — file
    // descriptors survive execve unless FD_CLOEXEC is set, which
    // procd-init intentionally doesn't set on the watchdog fd.
    //
    // The kernel only allows one open() on /dev/watchdog at a time
    // (EBUSY on the second), so we CAN'T just open it ourselves — we
    // have to find the inherited fd. Real procd does the same trick
    // (see procd.git watchdog.c). Scan /proc/self/fd, find the entry
    // whose readlink target is "/dev/watchdog", and keep petting it.
    let wd = match find_inherited_watchdog_fd() {
        Some(f) => f,
        None => {
            // No inherited fd — either we're not pid 1 yet (side-binary
            // mode / tests) or /sbin/init didn't open one. Fall back to
            // opening fresh, which works in QEMU / test envs.
            match std::fs::OpenOptions::new().write(true).open("/dev/watchdog") {
                Ok(f) => f,
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::NotFound {
                        tracing::debug!("no /dev/watchdog; skipping");
                    } else {
                        tracing::warn!(error = %e, "open /dev/watchdog failed");
                    }
                    return;
                }
            }
        }
    };
    tracing::info!("watchdog petting loop started (5s interval)");

    std::thread::Builder::new()
        .name("watchdog".to_string())
        .spawn(move || {
            let mut wd = wd;
            loop {
                if let Err(e) = wd.write_all(b"\0") {
                    tracing::warn!(error = %e, "watchdog write failed");
                }
                let _ = wd.flush();
                std::thread::sleep(std::time::Duration::from_secs(5));
            }
        })
        .expect("spawn watchdog thread");
}

/// Move the system clock forward to at least the binary's build time
/// if it's currently behind. Never moves the clock backwards.
///
/// Rationale: see the call site comment in `async_main`. Short version:
/// cold boot with no RTC → clock is 1970 → sQUIC replay window (±120s)
/// rejects every client handshake until something syncs time. NTP is
/// downstream of DNS which is downstream of WAN, so NTP can't bootstrap
/// from a cold start — we have to do it ourselves before the control
/// plane listens.
fn bootstrap_clock_floor() {
    const BUILD_EPOCH_SECS: u64 = match u64::from_str_radix(env!("BUILD_EPOCH_SECS"), 10) {
        Ok(v) => v,
        Err(_) => 0,
    };
    if BUILD_EPOCH_SECS == 0 {
        return;
    }

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    if now_secs >= BUILD_EPOCH_SECS {
        // Clock is already at or past build time — NTP probably synced
        // us earlier (warm reboot preserving /var/lib/oxwrt), or the
        // operator ran `date -s` over UART. Nothing to do.
        return;
    }

    // Pre-check: don't bother calling settimeofday(2) if the delta is
    // less than a second — avoids noise in logs on the normal case
    // where the clock is already set.
    let delta = BUILD_EPOCH_SECS - now_secs;

    let tv = rustix::time::Timespec {
        tv_sec: BUILD_EPOCH_SECS as i64,
        tv_nsec: 0,
    };
    match rustix::time::clock_settime(rustix::time::ClockId::Realtime, tv) {
        Ok(()) => {
            tracing::info!(
                from_secs = now_secs,
                to_secs = BUILD_EPOCH_SECS,
                forward_by_secs = delta,
                "clock bootstrapped to build-time floor"
            );
        }
        Err(e) => {
            // EPERM on a system that doesn't let us clock_settime —
            // shouldn't happen when we're PID 1, but could happen when
            // running as a side binary for development. Not fatal.
            tracing::warn!(
                error = %e,
                from_secs = now_secs,
                to_secs = BUILD_EPOCH_SECS,
                "clock bootstrap failed (clock_settime EPERM?) — sQUIC may reject clients with real timestamps"
            );
        }
    }
}

/// Populate /dev with device nodes discovered via sysfs.
///
/// Equivalent of procd's `early_dev()` (procd/utils/mkdev.c). Walks
/// /sys/dev/block/M:N/uevent and /sys/dev/char/M:N/uevent; each
/// entry lists `MAJOR=`, `MINOR=`, `DEVNAME=`. mknod the node at
/// /dev/<DEVNAME> with the right major:minor.
///
/// We need this only when the kernel lacks CONFIG_DEVTMPFS. On
/// kernels that have devtmpfs, the kernel populates /dev itself as
/// soon as we mount it; this fallback is a no-op because all
/// expected nodes are already present (mknod would EEXIST, which
/// we tolerate).
///
/// No udev-rule processing, no permission tweaking — every node gets
/// mode 0600, owner root. That's enough for oxwrtctl's needs.
fn populate_dev_from_sys() {
    use std::ffi::CString;
    for (kind, mode_bits) in [("block", libc::S_IFBLK), ("char", libc::S_IFCHR)] {
        let dir = format!("/sys/dev/{kind}");
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        for entry in rd.flatten() {
            let name = entry.file_name();
            let Some(_mm) = name.to_str() else { continue };
            // entry.path() here is the symlink (e.g.,
            // /sys/dev/block/179:7 → ../../devices/...), which we
            // can still read uevent from.
            let uevent_path = entry.path().join("uevent");
            let Ok(content) = std::fs::read_to_string(&uevent_path) else { continue };
            let mut major: Option<u32> = None;
            let mut minor: Option<u32> = None;
            let mut devname: Option<&str> = None;
            for line in content.lines() {
                if let Some(v) = line.strip_prefix("MAJOR=") {
                    major = v.parse().ok();
                } else if let Some(v) = line.strip_prefix("MINOR=") {
                    minor = v.parse().ok();
                } else if let Some(v) = line.strip_prefix("DEVNAME=") {
                    devname = Some(v);
                }
            }
            let (Some(major), Some(minor), Some(devname)) = (major, minor, devname) else {
                continue;
            };
            let devpath = format!("/dev/{devname}");
            // Create parent dirs if the DEVNAME contains "/" (e.g.
            // "bus/usb/001/001").
            if let Some(parent) = std::path::Path::new(&devpath).parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let Ok(cpath) = CString::new(devpath.as_bytes()) else { continue };
            let dev = unsafe { libc::makedev(major, minor) };
            let rc = unsafe { libc::mknod(cpath.as_ptr(), mode_bits | 0o600, dev) };
            if rc != 0 {
                let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                if errno != libc::EEXIST {
                    tracing::debug!(path = devpath, errno, "mknod failed");
                }
            }
        }
    }
}

/// Rename network interfaces so their kernel name matches the
/// DTS-declared label (or `openwrt,netdev-name` property). Equivalent
/// of the target's /lib/preinit/04_set_netdev_label shell hook.
///
/// Walks `/sys/class/net/*/of_node/label` — each entry is one name.
/// If the current ifname differs from the label, issue RTM_SETLINK
/// (IFLA_IFNAME) via rtnetlink. Interface must be DOWN for the kernel
/// to accept a rename; during preinit all interfaces ARE down
/// (netifd hasn't brought anything up yet), so this is safe before
/// `net::Net::bring_up`.
///
/// Spins its own tokio current-thread runtime — init::run() is sync
/// and the async main runtime hasn't started yet. Best-effort: a
/// single bad rename doesn't block the others, and a complete failure
/// is logged but not propagated.
///
/// In coexist, procd-init's preinit already ran this and every
/// netdev already has its final name. Every iteration here finds
/// `cur == label` and no-ops — silent.
fn rename_netdevs_from_dts() {
    let rd = match std::fs::read_dir("/sys/class/net") {
        Ok(rd) => rd,
        Err(e) => {
            tracing::warn!(error = %e, "netdev_rename: read /sys/class/net failed");
            return;
        }
    };

    // Gather (current_name, desired_label) pairs by reading sysfs.
    // Two possible label sources match OpenWrt convention: `label`
    // (standard) and `openwrt,netdev-name` (target-overridden).
    let mut pairs: Vec<(String, String)> = Vec::new();
    for entry in rd.flatten() {
        let cur = match entry.file_name().into_string() {
            Ok(s) => s,
            Err(_) => continue,
        };
        // Try target-specific name first, then the standard label.
        let label = std::fs::read_to_string(
            entry.path().join("of_node").join("openwrt,netdev-name"),
        )
        .or_else(|_| {
            std::fs::read_to_string(entry.path().join("of_node").join("label"))
        });
        let Ok(label) = label else {
            continue;
        };
        let label = label.trim().trim_end_matches('\0').to_string();
        if label.is_empty() || label == cur {
            continue;
        }
        pairs.push((cur, label));
    }
    if pairs.is_empty() {
        return;
    }

    // Spin a current-thread runtime just for these netlink ops; drop
    // it once all renames are dispatched.
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            tracing::warn!(error = %e, "netdev_rename: tokio runtime build failed");
            return;
        }
    };
    rt.block_on(async {
        use rtnetlink::{LinkUnspec, new_connection};
        let (connection, handle, _) = match new_connection() {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "netdev_rename: rtnetlink connection failed");
                return;
            }
        };
        let conn_task = tokio::spawn(connection);

        for (cur, desired) in &pairs {
            use futures_util::TryStreamExt;
            let mut stream = handle
                .link()
                .get()
                .match_name(cur.clone())
                .execute();
            let idx = match stream.try_next().await {
                Ok(Some(msg)) => msg.header.index,
                Ok(None) => {
                    tracing::warn!(cur = %cur, "netdev_rename: link disappeared mid-scan");
                    continue;
                }
                Err(e) => {
                    tracing::warn!(cur = %cur, error = %e, "netdev_rename: link_get failed");
                    continue;
                }
            };
            // Rename. In rtnetlink 0.20, LinkUnspec::name() attaches
            // IFLA_IFNAME to the set() message — exact equivalent of
            // `ip link set dev <cur> name <desired>`.
            let req = LinkUnspec::new_with_index(idx)
                .name(desired.clone())
                .build();
            match handle.link().set(req).execute().await {
                Ok(()) => {
                    tracing::info!(cur = %cur, desired = %desired, "netdev renamed");
                }
                Err(e) => {
                    tracing::warn!(cur = %cur, desired = %desired, error = %e, "netdev rename failed");
                }
            }
        }

        drop(handle);
        conn_task.abort();
    });
}

/// If the rootfs overlay isn't already attached (i.e. /overlay has no
/// mount entry in /proc/mounts), do a full libfstools-equivalent setup:
/// find the rootfs partition, locate the overlay region after the
/// squashfs tail, create a loop device at that offset, detect the
/// f2fs filesystem on it (or format if first boot / DEADCODE marker),
/// mount the f2fs, stack overlayfs with `lowerdir=/,upperdir=/overlay/
/// upper,workdir=/overlay/work`, pivot_root into the stacked tree.
/// Finally restore any sysupgrade config-backup tgz into upper.
///
/// In coexist mode (Stage 1-3), procd-init's preinit pipeline has
/// already done all this before our pid-1 entry — /proc/mounts will
/// show an `overlay` mount on `/` and an f2fs mount on /overlay.
/// Detect and return early with a single info log.
///
/// Only the detect path is wired up at this stage. The hot path
/// is stubbed (with a clear error) until Stage 4, where we actually
/// remove procd-init and need to own the mount lifecycle. Landing
/// the function now lets us verify the detection against real boot
/// data without touching anything destructive.
fn mount_root_if_needed() -> Result<(), Error> {
    if overlay_is_attached()? {
        tracing::info!(
            "mount_root: rootfs overlay already attached upstream; skipping"
        );
        return Ok(());
    }

    tracing::warn!("mount_root: no upstream overlay; engaging hot path");
    mount_root_hot_path()
}

/// The actual libfstools-in-Rust path. Assumes we're pid 1 with the
/// rootfs mounted read-only on `/` (kernel's default from `root=` on
/// the cmdline), /proc, /sys, /dev, /tmp already set up by
/// `early_mounts`, and nobody else has touched the overlay region.
///
/// Steps (matches fstools `rootdisk.c` + `mount.c` + `overlay.c`):
///  1. Find rootfs block device from GPT PARTLABEL=rootfs.
///  2. Parse squashfs superblock magic + bytes_used; align to 64 KiB
///     → overlay_off.
///  3. Detect what's at overlay_off:
///      - f2fs superblock magic at +0x400 → existing overlay, just
///        mount it.
///      - DEADCODE or ones/junk → unformatted. Scan forward ≤256 KiB
///        for a gzip-wrapped config backup (from sysupgrade) and
///        stash it in RAM if present.
///  4. Create /dev/loopN (LOOP_CTL_GET_FREE), bind to rootfs fd with
///     lo_offset = overlay_off. **Leak the rootfs fd.**
///  5. mkfs.f2fs the loop device if needed (shell out — writing an
///     f2fs formatter in Rust is a hundred times more code than
///     shelling out).
///  6. Mount f2fs on the loop device at /overlay.
///  7. Build /overlay/upper + /overlay/work, stack overlayfs at /mnt
///     with lowerdir=/.
///  8. pivot_root: /mnt → /, old / → /mnt/rom.
///  9. mount_move /rom/{proc,sys,dev,tmp,overlay} into the new root.
/// 10. If step 3 found a backup, tar-extract it over the new /.
fn mount_root_hot_path() -> Result<(), Error> {
    use rustix::mount::{MountFlags, mount, mount_move};
    use std::io::{Read, Seek, SeekFrom};
    use std::os::fd::AsRawFd;

    // 1. Rootfs partition.
    let rootfs_dev = crate::sysupgrade::resolve_partition("rootfs")
        .map_err(|e| Error::Runtime(format!("mount_root: resolve_partition: {e}")))?;
    tracing::info!(dev = %rootfs_dev.display(), "mount_root: using rootfs device");

    // 2. Parse squashfs superblock for bytes_used. Keep the fd — we
    // later reuse it as the loop backing.
    let mut rootfs_file = std::fs::File::options()
        .read(true)
        .write(true)
        .open(&rootfs_dev)
        .map_err(Error::Io)?;
    let mut sb = [0u8; 96];
    rootfs_file.read_exact(&mut sb).map_err(Error::Io)?;
    if &sb[..4] != b"hsqs" {
        return Err(Error::Runtime(format!(
            "mount_root: {} is not squashfs (magic {:02x?})",
            rootfs_dev.display(),
            &sb[..4]
        )));
    }
    let bytes_used = u64::from_le_bytes(sb[40..48].try_into().unwrap());
    // Align UP to 64 KiB — matches libfstools ROOTDEV_OVERLAY_ALIGN.
    let overlay_off = (bytes_used + 0xFFFF) & !0xFFFF;
    tracing::info!(
        bytes_used,
        overlay_off,
        "mount_root: squashfs header parsed"
    );

    // 3. Check what's at overlay_off.
    let mut probe = [0u8; 0x420];
    rootfs_file
        .seek(SeekFrom::Start(overlay_off))
        .map_err(Error::Io)?;
    rootfs_file.read_exact(&mut probe).map_err(Error::Io)?;
    const F2FS_MAGIC: u32 = 0xF2F5_2010;
    let f2fs_at = u32::from_le_bytes(probe[0x400..0x404].try_into().unwrap());
    let first_le = u32::from_le_bytes(probe[0..4].try_into().unwrap());

    // Gzip magic `1f 8b 08 00` as LE u32 = 0x00088b1f. Our native
    // sysupgrade writes the config-backup tgz directly at overlay_off
    // (no preceding DEADCODE marker, which stock libfstools uses).
    // Accept that case too.
    const GZIP_MAGIC_LE: u32 = 0x00088b1f;

    let (needs_format, backup_tgz): (bool, Option<Vec<u8>>) = if f2fs_at == F2FS_MAGIC {
        tracing::info!("mount_root: existing f2fs overlay detected");
        (false, None)
    } else if first_le == 0xDEADC0DE || first_le == 0xFFFFFFFF {
        // Stock sysupgrade convention: DEADCODE or FFFFFFFF marker,
        // gzip backup ≤256 KiB forward.
        tracing::info!(marker = format!("{first_le:#010x}"), "mount_root: unformatted marker; scanning for config backup");
        let backup = scan_for_backup_tgz(&mut rootfs_file, overlay_off)
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "mount_root: backup scan failed");
                None
            });
        (true, backup)
    } else if first_le == GZIP_MAGIC_LE {
        // Our native sysupgrade's convention: gzip backup starts
        // directly at overlay_off. Read it and treat overlay as
        // unformatted.
        tracing::info!("mount_root: gzip backup at overlay_off; unformatted overlay");
        let backup = scan_for_backup_tgz(&mut rootfs_file, overlay_off)
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "mount_root: backup read failed");
                None
            });
        (true, backup)
    } else if first_le == 0x00000000 && f2fs_at == 0x00000000 {
        // Freshly-flashed region (U-Boot HTTP recovery writes zeros
        // past the rootfs — no marker, no backup, no filesystem).
        // Treat as unformatted, no backup.
        tracing::info!("mount_root: zero region (fresh flash); will format f2fs");
        (true, None)
    } else {
        // Something in the overlay region but not f2fs — bail loudly
        // rather than format and potentially destroy user data.
        return Err(Error::Runtime(format!(
            "mount_root: overlay region has unknown content \
             (first_le={first_le:#010x}, f2fs_probe={f2fs_at:#010x})"
        )));
    };

    // 4. Create loop device.
    let loop_dev = create_loop_device(&rootfs_file, overlay_off)?;
    tracing::info!(loop_dev = %loop_dev.display(), "mount_root: loop device attached");
    // CRUCIAL: leak the rootfs_file so its fd stays alive for the
    // loop device's lifetime. If dropped, LO_FLAGS_AUTOCLEAR fires
    // and the loop detaches the next time we umount — meaning the
    // next sysupgrade will fail with "device busy" at best and
    // silent corruption at worst.
    std::mem::forget(rootfs_file);

    // 5. Format if needed. Shell out to mkfs.f2fs — implementing
    // f2fs formatting in Rust is way too much for one firmware
    // feature.
    if needs_format {
        tracing::info!(dev = %loop_dev.display(), "mount_root: formatting f2fs");
        let status = std::process::Command::new("/usr/sbin/mkfs.f2fs")
            .args(["-q", "-f", "-l", "rootfs_data"])
            .arg(&loop_dev)
            .status()
            .map_err(Error::Io)?;
        if !status.success() {
            return Err(Error::Runtime(format!(
                "mount_root: mkfs.f2fs exited {status}"
            )));
        }
    }

    // 6. Mount f2fs at /overlay.
    std::fs::create_dir_all("/overlay").map_err(Error::Io)?;
    mount(&loop_dev, "/overlay", "f2fs", MountFlags::NOATIME, None::<&std::ffi::CStr>)
        .map_err(|e| Error::Runtime(format!("mount_root: mount f2fs: {e}")))?;

    // 7. Stack overlayfs.
    std::fs::create_dir_all("/overlay/upper").map_err(Error::Io)?;
    std::fs::create_dir_all("/overlay/work").map_err(Error::Io)?;
    std::fs::create_dir_all("/mnt").map_err(Error::Io)?;
    let overlay_opts = std::ffi::CString::new(
        "lowerdir=/,upperdir=/overlay/upper,workdir=/overlay/work",
    )
    .expect("no NUL in overlay opts");
    mount(
        "overlayfs:/overlay",
        "/mnt",
        "overlay",
        MountFlags::NOATIME,
        Some(overlay_opts.as_c_str()),
    )
    .map_err(|e| Error::Runtime(format!("mount_root: mount overlay: {e}")))?;

    // 8. pivot_root. `/mnt/rom` must exist BEFORE the call.
    std::fs::create_dir_all("/mnt/rom").map_err(Error::Io)?;
    // fstools moves /proc BEFORE pivot_root — if /proc isn't in the
    // new root, pivot_root can fail with EINVAL ("shared parent").
    mount_move("/proc", "/mnt/proc")
        .map_err(|e| Error::Runtime(format!("mount_root: move /proc: {e}")))?;
    rustix::process::pivot_root("/mnt", "/mnt/rom")
        .map_err(|e| Error::Runtime(format!("mount_root: pivot_root: {e}")))?;
    std::env::set_current_dir("/").map_err(Error::Io)?;

    // 9. Move the rest. sys/dev/overlay — in that order. /overlay
    // must move last because we depend on the original /overlay bind
    // until we unmount /rom.
    //
    // /tmp is intentionally NOT in this list: early_mounts doesn't
    // mount a tmpfs on /tmp, so /rom/tmp is just a directory on the
    // old rootfs — `mount_move` returns EINVAL on non-mountpoints.
    // Instead, mount a fresh tmpfs on the new /tmp below (step 9b).
    for (src, dst) in [
        ("/rom/sys", "/sys"),
        ("/rom/dev", "/dev"),
        ("/rom/overlay", "/overlay"),
    ] {
        if std::path::Path::new(src).exists() {
            if let Err(e) = mount_move(src, dst) {
                tracing::warn!(src, dst, error = %e, "mount_root: move failed");
            }
        }
    }

    // 9b. Fresh tmpfs on /tmp. Stock OpenWrt does this via preinit's
    // `/lib/preinit/10_indicate_preinit`; we own that responsibility
    // now. Standard size (half of RAM) matches procd's default.
    if let Err(e) = mount(
        "tmpfs",
        "/tmp",
        "tmpfs",
        MountFlags::NOSUID | MountFlags::NODEV,
        Some(std::ffi::CString::new("mode=1777").unwrap().as_c_str()),
    ) {
        tracing::warn!(error = %e, "mount_root: tmpfs /tmp failed");
    }

    // 10. Restore backup.
    if let Some(tgz) = backup_tgz {
        tracing::info!(bytes = tgz.len(), "mount_root: restoring config backup");
        if let Err(e) = extract_tgz_over_root(&tgz) {
            tracing::warn!(error = %e, "mount_root: backup restore failed");
        }
    }

    // Keep a note that we did this, for the logs.
    tracing::info!("mount_root: hot path complete, overlay live");
    Ok(())
}

/// Scan forward from `overlay_off` up to 256 KiB looking for a gzip
/// header (1f 8b 08 00). If found, return the bytes from there to
/// end-of-scan (gzip is self-delimiting so the tail after the gzip
/// trailer is ignored by gunzip).
fn scan_for_backup_tgz(
    f: &mut std::fs::File,
    overlay_off: u64,
) -> Result<Option<Vec<u8>>, Error> {
    use std::io::{Read, Seek, SeekFrom};
    const MAX_SCAN: usize = 256 * 1024;
    f.seek(SeekFrom::Start(overlay_off)).map_err(Error::Io)?;
    let mut buf = vec![0u8; MAX_SCAN];
    let n = f.read(&mut buf).map_err(Error::Io)?;
    buf.truncate(n);
    // Gzip magic with exact FLG=0 byte — matches fstools'
    // cpu_to_le32(0x88b1f) expectation.
    let needle: [u8; 4] = [0x1f, 0x8b, 0x08, 0x00];
    for i in 0..buf.len().saturating_sub(4) {
        if buf[i..i + 4] == needle {
            tracing::info!(offset = i, "mount_root: gzip magic located in overlay region");
            return Ok(Some(buf[i..].to_vec()));
        }
    }
    Ok(None)
}

/// Create a loop device bound to `backing`'s fd at `offset`. Returns
/// the `/dev/loopN` path. Leaves the backing fd OPEN (caller must
/// `std::mem::forget` it or otherwise keep it alive).
fn create_loop_device(backing: &std::fs::File, offset: u64) -> Result<PathBuf, Error> {
    use std::os::fd::AsRawFd;

    // Constants lifted from <linux/loop.h>. Use `_` as the ioctl
    // request type — libc has it as c_int on some arches and c_ulong
    // on others, and letting inference pick avoids a per-arch cfg.
    const LOOP_CTL_GET_FREE: u32 = 0x4C82;
    const LOOP_SET_FD: u32 = 0x4C00;
    const LOOP_SET_STATUS64: u32 = 0x4C04;
    const LO_FLAGS_AUTOCLEAR: u32 = 4;

    // loop_info64 layout — matches <linux/loop.h>. 232 bytes on
    // most arches. We only need lo_offset; the rest stays zero.
    #[repr(C)]
    struct LoopInfo64 {
        lo_device: u64,
        lo_inode: u64,
        lo_rdevice: u64,
        lo_offset: u64,
        lo_sizelimit: u64,
        lo_number: u32,
        lo_encrypt_type: u32,
        lo_encrypt_key_size: u32,
        lo_flags: u32,
        lo_file_name: [u8; 64],
        lo_crypt_name: [u8; 64],
        lo_encrypt_key: [u8; 32],
        lo_init: [u64; 2],
    }

    // Get a free loop number via the control device.
    let ctl = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/loop-control")
        .map_err(Error::Io)?;
    let num = unsafe { libc::ioctl(ctl.as_raw_fd(), LOOP_CTL_GET_FREE as _) };
    if num < 0 {
        return Err(Error::Runtime(format!(
            "LOOP_CTL_GET_FREE: {}",
            std::io::Error::last_os_error()
        )));
    }
    let loop_dev = PathBuf::from(format!("/dev/loop{num}"));
    let lf = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&loop_dev)
        .map_err(Error::Io)?;
    // Associate backing fd.
    if unsafe { libc::ioctl(lf.as_raw_fd(), LOOP_SET_FD as _, backing.as_raw_fd() as libc::c_ulong) } < 0 {
        return Err(Error::Runtime(format!(
            "LOOP_SET_FD: {}",
            std::io::Error::last_os_error()
        )));
    }
    // Set offset + autoclear flag.
    let mut info: LoopInfo64 = unsafe { std::mem::zeroed() };
    info.lo_offset = offset;
    info.lo_flags = LO_FLAGS_AUTOCLEAR;
    if unsafe { libc::ioctl(lf.as_raw_fd(), LOOP_SET_STATUS64 as _, &info as *const _ as libc::c_ulong) } < 0 {
        return Err(Error::Runtime(format!(
            "LOOP_SET_STATUS64: {}",
            std::io::Error::last_os_error()
        )));
    }
    // Intentionally leak the loop fd too — keeping it open guards
    // against another process opening the loop device with a
    // different offset. Matches fstools rootdisk.c lifetime model.
    std::mem::forget(lf);
    Ok(loop_dev)
}

/// Extract a gzipped tar over `/`. Used to restore a sysupgrade
/// config backup that was embedded in the overlay region.
///
/// Does NOT merge passwd/group/shadow (which stock does) — our
/// image has a fixed /etc/passwd and the backup only needs to
/// restore /etc/oxwrt/, /etc/dropbear/authorized_keys etc.
fn extract_tgz_over_root(bytes: &[u8]) -> Result<(), Error> {
    use flate2::read::GzDecoder;
    let gz = GzDecoder::new(bytes);
    let mut ar = tar::Archive::new(gz);
    ar.unpack("/").map_err(Error::Io)
}

/// Parse /proc/mounts looking for an overlayfs mount on `/`. That's

/// Parse /proc/mounts looking for an overlayfs mount on `/`. That's
/// what fstools leaves us with after its pivot_root: root filesystem
/// is of type "overlay" with `lowerdir=/,upperdir=/overlay/upper,...`.
///
/// We could also look at the `/overlay` entry (f2fs on loop0), but
/// the overlay-on-/ signal is the definitive "the whole stack is
/// set up" marker.
fn overlay_is_attached() -> Result<bool, Error> {
    let mounts = std::fs::read_to_string("/proc/mounts")
        .map_err(Error::Io)?;
    for line in mounts.lines() {
        // Each line: "<src> <mountpoint> <fstype> <opts> <dump> <pass>"
        let mut it = line.split_whitespace();
        let _src = it.next();
        let Some(mp) = it.next() else { continue };
        let Some(fstype) = it.next() else { continue };
        if mp == "/" && fstype == "overlay" {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Load kernel modules from /etc/modules-boot.d/ and /etc/modules.d/.
///
/// Equivalent of upstream OpenWrt `ubox/kmodloader.c`, trimmed to
/// what we actually need: boot-time modules (for things procd-init
/// would have loaded before our pid-1 entry) and runtime modules
/// (for drivers needed once the supervisor is up — e.g. `kmod-veth`
/// for container netns peers, `kmod-nft-nat` for the firewall).
///
/// Flow: walk each directory in sorted order, read each file, parse
/// each non-comment non-empty line as `<module_name> [params...]`.
/// For each module, recursively glob /lib/modules/<uname>/ for the
/// `.ko`, call finit_module(2). EEXIST (already loaded) counts as
/// success and is logged at debug, not warn — this is the normal
/// case when running in coexist with procd-init, which already
/// loaded everything during its preinit phase.
///
/// Best-effort: a missing .ko file or a genuine finit_module error
/// is logged at warn level and the loop continues. A missing
/// kernel module is almost never fatal for oxwrtctl's own needs,
/// and a panicked init makes diagnosis much harder than a running
/// init with one missing driver.
///
/// Stage 1 of the procd-init takeover; safe under current (coexist)
/// configuration where procd-init loads modules before us —
/// every finit_module returns EEXIST.
fn load_modules() {
    // Resolve the running kernel release once — matches `uname -r`.
    let kernel_release = match rustix::system::uname()
        .release()
        .to_str()
    {
        Ok(s) => s.to_string(),
        Err(_) => {
            tracing::warn!("load_modules: cannot read kernel release; skipping");
            return;
        }
    };
    let modules_root = PathBuf::from(format!("/lib/modules/{kernel_release}"));
    if !modules_root.exists() {
        tracing::warn!(
            root = %modules_root.display(),
            "load_modules: kernel modules root missing; skipping"
        );
        return;
    }

    // Parse modules.dep once up front. Maps module name → list of
    // dep module names (in bottom-up load order per depmod's
    // convention). Best-effort: if the file is missing or unparseable
    // we continue with an empty map; load_one_module then runs without
    // dep resolution and the /sys/module pre-check keeps it safe.
    let depmap = parse_modules_dep(&modules_root);

    for dir in ["/etc/modules-boot.d", "/etc/modules.d"] {
        let rd = match std::fs::read_dir(dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                tracing::warn!(dir, error = %e, "load_modules: read_dir failed");
                continue;
            }
        };
        let mut files: Vec<_> = rd
            .filter_map(|r| r.ok())
            .map(|e| e.path())
            .filter(|p| p.is_file())
            .collect();
        files.sort();
        for f in files {
            load_modules_file(&f, &modules_root, &depmap);
        }
    }
}

/// Parse /lib/modules/<ver>/modules.dep into a map of
/// `module_name → [dep_names]`. Format:
///
///     kernel/fs/f2fs/f2fs.ko: kernel/crypto/crc32c-generic.ko
///     kernel/net/ipv4/ip_tables.ko:
///     kernel/net/ipv4/nf_reject_ipv4.ko: kernel/net/nf_tables.ko
///
/// Each line: module-path ':' then zero or more dep-paths. We key
/// by the basename-without-.ko.
///
/// Returned deps are in the order they appear, which depmod emits
/// such that loading them left-to-right produces a valid sequence.
/// For our use we do a DFS before loading each top-level module, so
/// order within a single line's deps doesn't matter much — but we
/// preserve it for predictability.
fn parse_modules_dep(
    modules_root: &Path,
) -> std::collections::HashMap<String, Vec<String>> {
    let path = modules_root.join("modules.dep");
    let content = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!(error = %e, path = %path.display(), "modules.dep not read; continuing without dep resolution");
            return std::collections::HashMap::new();
        }
    };
    let mut map = std::collections::HashMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((lhs, rhs)) = line.split_once(':') else {
            continue;
        };
        let name = module_name_from_ko_path(lhs);
        let deps: Vec<String> = rhs
            .split_whitespace()
            .map(module_name_from_ko_path)
            .collect();
        map.insert(name, deps);
    }
    tracing::debug!(modules = map.len(), "parsed modules.dep");
    map
}

/// "kernel/drivers/net/foo.ko" → "foo"
/// "kernel/drivers/net/foo.ko.xz" → "foo"
fn module_name_from_ko_path(p: &str) -> String {
    let base = p.rsplit('/').next().unwrap_or(p);
    let base = base.trim_end_matches(".xz").trim_end_matches(".gz").trim_end_matches(".zst");
    let base = base.trim_end_matches(".ko");
    base.to_string()
}

/// Parse one file under /etc/modules{,-boot}.d/ and load each module
/// listed. Format matches stock ubox/kmodloader:
///   # comment
///   <module-name> [param1=val1 param2=val2 ...]
fn load_modules_file(
    file: &Path,
    modules_root: &Path,
    depmap: &std::collections::HashMap<String, Vec<String>>,
) {
    let content = match std::fs::read_to_string(file) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(file = %file.display(), error = %e, "load_modules: read failed");
            return;
        }
    };
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut it = line.splitn(2, char::is_whitespace);
        let Some(name) = it.next() else { continue };
        let params = it.next().unwrap_or("").trim();
        // Depth-first: load all transitive deps before the requested
        // module. Normalize - → _ for lookup; modules.dep uses the
        // underscore form canonical to the kernel.
        let canon = name.replace('-', "_");
        let mut visited = std::collections::HashSet::new();
        load_with_deps(&canon, depmap, modules_root, &mut visited);
        // Now load the requested module (with its params).
        load_one_module(name, params, modules_root);
    }
}

/// Walk the dep tree of `name` depth-first, loading each dep exactly
/// once (params defaulted to empty for dependency loads — they get
/// the kernel's default settings). `visited` short-circuits cycles
/// and repeat visits.
fn load_with_deps(
    name: &str,
    depmap: &std::collections::HashMap<String, Vec<String>>,
    modules_root: &Path,
    visited: &mut std::collections::HashSet<String>,
) {
    if !visited.insert(name.to_string()) {
        return;
    }
    if let Some(deps) = depmap.get(name) {
        for d in deps {
            load_with_deps(d, depmap, modules_root, visited);
        }
        // Finally load this module (no params — deps don't get the
        // config line's params). Skip if this is the top-level caller,
        // which load_modules_file will load with its own params.
        // Detect "top level" by checking: if the module has no deps
        // at all, is_empty is true — but that doesn't uniquely mark
        // us. Use visited.len() instead: exactly 1 means we're the
        // first node to land in the set and load_modules_file will
        // do the final load with params.
        if visited.len() > 1 {
            load_one_module(name, "", modules_root);
        }
    }
}

/// Locate `<name>.ko`(.xz/.gz/.zst) under `modules_root` and
/// finit_module it. Idempotent — EEXIST is success.
fn load_one_module(name: &str, params: &str, modules_root: &Path) {
    // Quick bail: if /sys/module/<name>/ already exists, the module
    // is loaded (or built into the kernel). This catches both the
    // coexist case (procd-init loaded everything upstream) and the
    // case where an earlier file in the sorted iteration pulled the
    // module in as a dependency. Either way: no work needed. Skipping
    // here is faster than calling finit_module and also avoids the
    // Linux "Unknown symbol" noise when we try to load a module that
    // depends on something not yet loaded — procd-init uses
    // modprobe's dep resolution for this; we don't.
    let sys_name = name.replace('-', "_");
    if Path::new(&format!("/sys/module/{sys_name}")).exists() {
        tracing::debug!(module = name, "already present; skipping");
        return;
    }

    // Normalize module name: kmodloader accepts both "-" and "_" forms.
    // The .ko filename is almost always the underscore form, but some
    // packages install with dashes — try both.
    let candidates = [
        format!("{name}.ko"),
        format!("{}.ko", name.replace('-', "_")),
        format!("{}.ko", name.replace('_', "-")),
    ];
    let ko_path = find_ko_under(modules_root, &candidates);
    let Some(ko_path) = ko_path else {
        // Missing .ko + absent from /sys/module: either the package
        // isn't installed in this image or we have a typo. Log at
        // debug — warning here would be noisy in coexist, where the
        // module might have been compiled out but procd-init also
        // skipped it.
        tracing::debug!(
            module = name,
            "not found under /lib/modules and not in /sys/module; skipping"
        );
        return;
    };

    let ko_file = match std::fs::File::open(&ko_path) {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!(
                module = name,
                path = %ko_path.display(),
                error = %e,
                "load_modules: open .ko failed"
            );
            return;
        }
    };

    // finit_module wants params as a NUL-terminated C string.
    let params_c = match std::ffi::CString::new(params) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(module = name, error = %e, "load_modules: params contain NUL");
            return;
        }
    };

    use std::os::fd::AsFd;
    match rustix::system::finit_module(ko_file.as_fd(), params_c.as_c_str(), 0) {
        Ok(()) => tracing::info!(module = name, "loaded"),
        Err(rustix::io::Errno::EXIST) => {
            tracing::debug!(module = name, "already loaded");
        }
        Err(e) => {
            // ENOENT from finit_module means the module needs a
            // symbol from an unloaded dependency. In coexist mode
            // procd-init resolved this via modprobe ordering; we
            // don't. Treat as debug so the boot log stays clean —
            // when the hot path (Stage 4) runs this function, we'll
            // add modules.dep parsing to drive correct ordering.
            let is_dep_issue = matches!(
                e,
                rustix::io::Errno::NOENT | rustix::io::Errno::NOEXEC
            );
            if is_dep_issue {
                tracing::debug!(module = name, error = %e, "finit_module failed (probable dep issue)");
            } else {
                tracing::warn!(module = name, error = %e, "finit_module failed");
            }
        }
    }
}

/// Recursively walk `root` looking for any of `candidates` as a
/// filename. Returns the first match. O(n) in module tree size but
/// fine on a firmware-sized /lib/modules (a few hundred .ko files).
///
/// Small optimization: cache the tree per-boot? Not worth it for
/// /etc/modules{,-boot}.d/ which has ~5-10 entries total on our
/// image. Defer until profiling shows it matters.
fn find_ko_under(root: &Path, candidates: &[String]) -> Option<PathBuf> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let rd = match std::fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(_) => continue,
        };
        for entry in rd.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let Some(fname) = path.file_name().and_then(|s| s.to_str()) else {
                continue;
            };
            if candidates.iter().any(|c| c == fname) {
                return Some(path);
            }
        }
    }
    None
}

/// Execute once-per-boot scripts under `/etc/uci-defaults/` in
/// alphabetical order. Successful scripts (exit 0) are deleted so they
/// don't re-run on subsequent boots. Failed scripts stay around and
/// are retried next boot. Matches procd's built-in behavior — we only
/// reimplement it here because, as the replacement for `/sbin/procd`,
/// we're the only thing on the system that knows how to drive these.
///
/// Best-effort: any IO error or spawn error is logged, never fatal.
/// A misbehaving uci-default script MUST NOT prevent the supervisor
/// from starting — the operator needs the control plane to debug it.
///
/// Filter: only scripts whose filename contains "oxwrt" are run.
/// OpenWrt's stock uci-defaults (05_fix-compat-version, 10_migrate-
/// shadow, 14_network-generate-duid, 50-dropbear, 15_odhcpd, etc.)
/// all assume a procd + ubus + board.json world. Running them under
/// oxwrtctl-as-pid-1 produces a parade of errors — "local: line 47:
/// not in a function" (dash vs bash), "Failed to parse message data"
/// (no ubus), "/etc/board.json: No such file" (no board-detect init
/// script ran), "uci: Entry not found" (no stock uci configs
/// provisioned). None of these failures do anything useful for oxwrt
/// because we don't use uci or /etc/config at all — our config lives
/// in /etc/oxwrt.toml and is reloaded via the control plane.
///
/// Our own provisioners (97-oxwrt-debug-ssh-rootfs, 98-oxwrt-diag-
/// rootfs, 99-oxwrtctl) all have "oxwrt" in the name. Whitelisting
/// by substring keeps the filter readable and lets operators drop
/// custom scripts that opt in by naming them with "oxwrt" somewhere.
fn run_uci_defaults() {
    const DIR: &str = "/etc/uci-defaults";
    let rd = match std::fs::read_dir(DIR) {
        Ok(rd) => rd,
        Err(e) => {
            // ENOENT is normal on an image with no first-boot scripts
            // (or on the second boot after the first-boot scripts have
            // all been cleared).
            if e.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(error = %e, "uci-defaults: read_dir failed");
            }
            return;
        }
    };

    let mut entries: Vec<_> = rd
        .filter_map(|r| r.ok())
        .map(|e| e.path())
        .filter(|p| {
            if !p.is_file() {
                return false;
            }
            let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
            // Reject hidden files + stock OpenWrt scripts (see
            // doc comment above). "oxwrt" must appear in the name.
            !name.starts_with('.') && name.contains("oxwrt")
        })
        .collect();
    entries.sort();

    for script in entries {
        tracing::info!(script = %script.display(), "uci-defaults: running");
        // Ensure the script is executable — at image-stage time we chmod
        // 755 these, but defensive `chmod +x` via the shell works for
        // hand-dropped operator scripts too. Invoke through /bin/sh so
        // scripts without a shebang still work.
        let status = std::process::Command::new("/bin/sh")
            .arg(&script)
            .status();
        match status {
            Ok(s) if s.success() => {
                if let Err(e) = std::fs::remove_file(&script) {
                    tracing::warn!(
                        script = %script.display(),
                        error = %e,
                        "uci-defaults: remove after success failed"
                    );
                }
            }
            Ok(s) => {
                tracing::warn!(
                    script = %script.display(),
                    status = ?s,
                    "uci-defaults: script failed; will retry next boot"
                );
            }
            Err(e) => {
                tracing::warn!(
                    script = %script.display(),
                    error = %e,
                    "uci-defaults: spawn failed"
                );
            }
        }
    }
}

fn early_mounts() -> Result<(), Error> {
    use rustix::ffi::CStr;
    use rustix::mount::{MountFlags, mount};

    let nsnd = MountFlags::NOSUID | MountFlags::NOEXEC | MountFlags::NODEV;
    // /dev is attempted as devtmpfs first; if the kernel lacks
    // CONFIG_DEVTMPFS (confirmed on the mediatek/filogic image
    // we ship) the mount returns ENODEV and we retry with tmpfs +
    // populate_dev_from_sys(). That fallback does what procd's
    // `early_dev()` does: walks /sys/dev/{block,char}/M:N/uevent for
    // each device, mknod's the corresponding /dev/<name>.
    // devpts needs ptmxmode=666,gid=5 so /dev/pts/ptmx is usable
    // outside root (dropbear drops to logged-in user before calling
    // openpty). Without these options the kernel defaults ptmxmode to
    // 0000 and ptmx opens return EACCES — the exact failure mode seen
    // in the debug-ssh container ("PTY allocation request failed").
    let devpts_opts = std::ffi::CString::new("ptmxmode=666,gid=5").unwrap();
    let mounts: &[(&str, &str, &str, MountFlags, Option<&CStr>)] = &[
        ("proc", "/proc", "proc", nsnd, None),
        ("sysfs", "/sys", "sysfs", nsnd, None),
        ("devtmpfs", "/dev", "devtmpfs", MountFlags::NOSUID, None),
        (
            "devpts", "/dev/pts", "devpts",
            MountFlags::NOSUID | MountFlags::NOEXEC,
            Some(devpts_opts.as_c_str()),
        ),
        ("cgroup2", "/sys/fs/cgroup", "cgroup2", nsnd, None),
    ];

    for (source, target, fstype, flags, data) in mounts {
        // mkdir the target. Two tolerant cases:
        //   AlreadyExists: fine.
        //   EROFS (no such dir on the ro squashfs): log + try mount
        //       anyway. On real hardware the kernel auto-mounts
        //       devtmpfs on /dev (CONFIG_DEVTMPFS_MOUNT=y) before we
        //       run, so /dev exists even if the squashfs didn't
        //       provide it. /proc similarly gets mounted by the
        //       kernel command line on some configs. When it really
        //       doesn't exist, the mount call below fails with a
        //       clearer error than mkdir's EROFS.
        if let Err(e) = std::fs::create_dir_all(target) {
            match e.kind() {
                std::io::ErrorKind::AlreadyExists => {}
                _ if e.raw_os_error() == Some(libc::EROFS) => {
                    tracing::warn!(
                        target = target,
                        "early_mounts: mountpoint missing on ro rootfs; relying on pre-existing mount"
                    );
                }
                _ => return Err(Error::Io(e)),
            }
        }
        match mount(*source, *target, *fstype, *flags, *data) {
            Ok(()) => {
                tracing::info!(target = target, fstype = fstype, "early_mounts: mounted");
            }
            // EBUSY = target already mounted (upstream or prior run).
            Err(rustix::io::Errno::BUSY) => {
                tracing::info!(target = target, "early_mounts: already mounted (EBUSY)");
            }
            // ENODEV = fs type can't be mounted on this target, e.g.,
            // devtmpfs when the kernel lacks CONFIG_DEVTMPFS. This is
            // a real problem for /dev — without devtmpfs we'd need to
            // mknod the device nodes by hand. Log loudly.
            Err(rustix::io::Errno::NODEV) => {
                // Fallback for /dev: mount tmpfs + populate via mknod.
                if *target == "/dev" && *fstype == "devtmpfs" {
                    tracing::warn!("early_mounts: devtmpfs unavailable; falling back to tmpfs + mknod");
                    let tmpfs_opts = std::ffi::CString::new("mode=0755,size=512K").unwrap();
                    match mount(
                        "tmpfs",
                        "/dev",
                        "tmpfs",
                        MountFlags::NOSUID,
                        Some(tmpfs_opts.as_c_str()),
                    ) {
                        Ok(()) => {
                            populate_dev_from_sys();
                            tracing::info!("early_mounts: /dev populated via mknod");
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "early_mounts: tmpfs fallback on /dev failed");
                        }
                    }
                } else {
                    tracing::warn!(target = target, fstype = fstype, "early_mounts: ENODEV (kernel lacks fstype?)");
                }
            }
            // ENOENT = target path doesn't exist AND nothing is
            // mounted there. Can happen for /dev/pts or /sys/fs/cgroup
            // if their parent tmpfs/sysfs doesn't have them yet.
            Err(rustix::io::Errno::NOENT) => {
                tracing::warn!(
                    target = target,
                    "early_mounts: mount target does not exist; skipping"
                );
            }
            Err(source) => {
                return Err(Error::Mount {
                    target: (*target).to_string(),
                    source,
                });
            }
        }
    }
    Ok(())
}

