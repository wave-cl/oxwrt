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
            p.is_file()
                && p.file_name()
                    .and_then(|s| s.to_str())
                    .map(|n| !n.starts_with('.'))
                    .unwrap_or(false)
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

