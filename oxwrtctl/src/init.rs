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

    // Hot path — reached only when procd-init is gone (Stage 4+).
    // Intentionally stubbed: if we hit this during coexist mode
    // development, something's gone wrong and we'd rather fail
    // loudly than silently degrade. Stage 4 replaces the
    // unimplemented!() with real loop0+f2fs+overlayfs+pivot_root
    // logic that mirrors fstools/libfstools/{rootdisk,mount,overlay}.c.
    Err(Error::Runtime(
        "mount_root hot path unimplemented — reaching here means procd-init \
         didn't set up the overlay. Stage 4 fills this in."
            .to_string(),
    ))
}

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
            load_modules_file(&f, &modules_root);
        }
    }
}

/// Parse one file under /etc/modules{,-boot}.d/ and load each module
/// listed. Format matches stock ubox/kmodloader:
///   # comment
///   <module-name> [param1=val1 param2=val2 ...]
fn load_modules_file(file: &Path, modules_root: &Path) {
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
        load_one_module(name, params, modules_root);
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
    let mounts: &[(&str, &str, &str, MountFlags)] = &[
        ("proc", "/proc", "proc", nsnd),
        ("sysfs", "/sys", "sysfs", nsnd),
        ("devtmpfs", "/dev", "devtmpfs", MountFlags::NOSUID),
        ("devpts", "/dev/pts", "devpts", MountFlags::NOSUID | MountFlags::NOEXEC),
        ("cgroup2", "/sys/fs/cgroup", "cgroup2", nsnd),
    ];

    let no_data: Option<&CStr> = None;
    for (source, target, fstype, flags) in mounts {
        if let Err(e) = std::fs::create_dir_all(target) {
            if e.kind() != std::io::ErrorKind::AlreadyExists {
                return Err(Error::Io(e));
            }
        }
        match mount(*source, *target, *fstype, *flags, no_data) {
            Ok(()) => {}
            // EBUSY = target already mounted. ENODEV = fs type can't
            // be mounted on this target (e.g., devtmpfs when /dev is
            // already a different fs). Both mean "someone beat us to
            // it" — fine when not running as true PID 1 (SSH dev test,
            // container that already has /proc etc.).
            Err(rustix::io::Errno::BUSY) | Err(rustix::io::Errno::NODEV) => {
                tracing::debug!(target = target, "mount skipped (already mounted)");
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

