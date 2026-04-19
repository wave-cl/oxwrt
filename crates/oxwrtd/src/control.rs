// client moved to the oxwrtctl-cli crate. The daemon's `--client`
// subcommand in main.rs now calls oxwrtctl_cli::run_client_sync.
#[cfg(target_os = "linux")]
pub mod server;
pub mod validate;

#[cfg(target_os = "linux")]
use std::sync::{Arc, Mutex, RwLock};

#[cfg(target_os = "linux")]
use crate::config::Config;
#[cfg(target_os = "linux")]
use crate::container::Supervisor;
#[cfg(target_os = "linux")]
use crate::logd::Logd;

// SharedLease moved to oxwrt-linux (next to DhcpLease, which is where
// it belongs — the old layout put the alias in the control module
// only as a convenience). Re-exported so every existing
// `crate::control::SharedLease` call site keeps resolving.
#[cfg(target_os = "linux")]
pub use oxwrt_linux::wan_dhcp::SharedLease;

/// State shared between the init main loop and sQUIC control-plane tasks.
///
/// `config` is behind an `RwLock<Arc<Config>>`: readers clone the inner
/// `Arc` (cheap), holders of the write lock can swap it atomically during
/// `Reload`. `supervisor` is behind a `std::sync::Mutex` because all
/// critical sections are purely synchronous. `logd` is `Clone` (it's
/// `Arc` inside) so it needs no outer lock.
///
/// `firewall_dump` is the human-readable rendering of the rules that
/// `net::install_firewall` last installed, captured at boot from
/// `net::format_firewall_dump(&cfg)` and read by the `Diag::firewall`
/// RPC. It's a `RwLock<Vec<String>>` rather than a snapshot field so a
/// future reload that reinstalls the firewall can refresh it.
#[cfg(target_os = "linux")]
pub struct ControlState {
    pub config: RwLock<Arc<Config>>,
    pub supervisor: Mutex<Supervisor>,
    pub logd: Logd,
    pub firewall_dump: RwLock<Vec<String>>,
    pub wan_lease: SharedLease,
    /// `Instant` captured at `ControlState::new`. The `Status` RPC
    /// returns `supervisor_uptime_secs = boot_time.elapsed().as_secs()`
    /// so operators get a "how long has this router been up?" answer
    /// without a separate RPC. Not the PID-1 fork time — there's a
    /// few hundred ms of early mounts / netlink setup before this
    /// fires — but close enough for operational use.
    pub boot_time: std::time::Instant,
    /// True when `oxwrtd` was started with `--control-only`. In this
    /// mode the control plane is the only subsystem running — no early
    /// mounts, no netlink, no firewall, no supervisor. `reload` honors
    /// this flag by re-parsing + swapping the in-memory config but
    /// skipping every reconcile phase (netlink addresses, sethostname,
    /// firewall install, service supervisor). Used for side-binary
    /// testing on stock OpenWrt devices where touching live network
    /// state would kill SSH.
    pub control_only: bool,
    /// Metrics HTTP listener handle + its current bind addr.
    /// `metrics::apply` uses this to make spawn/respawn
    /// idempotent: a reload that toggles [metrics] on/off or
    /// changes listen addr stops the old task and starts a new
    /// one. None = no listener running.
    pub metrics_task: Mutex<Option<MetricsTask>>,
    /// Active WAN name — set by the wan_failover coordinator
    /// each time it picks a WAN to serve the default route. `None`
    /// until the first lease arrives. Read by Status RPC; optional
    /// in single-WAN deployments (the sole WAN's lease appears in
    /// `wan` anyway).
    pub active_wan: Arc<Mutex<Option<String>>>,
}

/// Tracking record for the current metrics HTTP listener.
#[cfg(target_os = "linux")]
pub struct MetricsTask {
    pub handle: tokio::task::JoinHandle<()>,
    pub listen: String,
}

#[cfg(target_os = "linux")]
impl ControlState {
    pub fn new(
        config: Config,
        supervisor: Supervisor,
        logd: Logd,
        firewall_dump: Vec<String>,
        wan_lease: SharedLease,
        active_wan: Arc<Mutex<Option<String>>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            config: RwLock::new(Arc::new(config)),
            supervisor: Mutex::new(supervisor),
            logd,
            firewall_dump: RwLock::new(firewall_dump),
            wan_lease,
            boot_time: std::time::Instant::now(),
            control_only: false,
            metrics_task: Mutex::new(None),
            active_wan,
        })
    }

    /// Construct a ControlState for `--control-only` mode. Same as `new`
    /// but sets the `control_only` flag so `handle_reload_async` skips
    /// its reconcile phases.
    pub fn new_control_only(
        config: Config,
        supervisor: Supervisor,
        logd: Logd,
        firewall_dump: Vec<String>,
        wan_lease: SharedLease,
    ) -> Arc<Self> {
        Arc::new(Self {
            config: RwLock::new(Arc::new(config)),
            supervisor: Mutex::new(supervisor),
            logd,
            firewall_dump: RwLock::new(firewall_dump),
            wan_lease,
            boot_time: std::time::Instant::now(),
            control_only: true,
            metrics_task: Mutex::new(None),
            active_wan: Arc::new(Mutex::new(None)),
        })
    }

    pub fn config_snapshot(&self) -> Arc<Config> {
        self.config.read().unwrap().clone()
    }
}

// Frame codec + RPC parse/format moved to the `oxwrt-proto` crate as
// part of the workspace split. Re-export them here so every existing
// `crate::control::{read_frame, write_frame, parse_request,
// format_response, default_config_text, FrameError}` call site keeps
// resolving. This keeps the diff on the split to the manifest + a
// single use-line, rather than touching every caller.
// Re-exports consumed by the linux-only server module; cfg-gated
// so macOS host builds don't warn about unused imports (the CLI was
// extracted into the oxwrtctl-cli crate, so no caller here uses
// these on macOS anymore).
#[cfg(target_os = "linux")]
pub use oxwrt_proto::{FrameError, default_config_text, read_frame, write_frame};

#[cfg(test)]
#[cfg(target_os = "linux")]
mod tests {
    /// Arg builders for the curated diag binaries validate operator
    /// input and produce a closed argv that can't be injected.
    /// Stays here (not in oxwrt-proto) because it references
    /// `control::server::*` — linux-only daemon internals.
    #[test]
    fn diag_binary_arg_builders() {
        use crate::control::server::{
            build_drill_args, build_ping_args, build_ss_args, build_traceroute_args,
        };

        // ping: valid
        let argv = build_ping_args(&["1.2.3.4".into(), "5".into()]).unwrap();
        assert!(argv.contains(&"5".to_string()));
        assert!(argv.contains(&"1.2.3.4".to_string()));

        // ping: invalid target
        assert!(build_ping_args(&["not-an-ip".into()]).is_err());

        // ping: count out of range
        assert!(build_ping_args(&["1.1.1.1".into(), "99".into()]).is_err());

        // traceroute: valid
        let argv = build_traceroute_args(&["8.8.8.8".into()]).unwrap();
        assert!(argv.contains(&"8.8.8.8".to_string()));

        // traceroute: bad hops
        assert!(build_traceroute_args(&["1.1.1.1".into(), "50".into()]).is_err());

        // drill: valid name
        let argv = build_drill_args(&["example.com".into()]).unwrap();
        assert!(argv.contains(&"example.com".to_string()));

        // drill: name + server + type
        let argv =
            build_drill_args(&["example.com".into(), "@1.1.1.1".into(), "MX".into()]).unwrap();
        assert!(argv.contains(&"@1.1.1.1".to_string()));
        assert!(argv.contains(&"MX".to_string()));

        // drill: rejects flag injection
        assert!(build_drill_args(&["-x".into()]).is_err());

        // ss: defaults
        let argv = build_ss_args(&[]).unwrap();
        assert_eq!(argv, vec!["-tunlp"]);

        // ss: allowed flag
        let argv = build_ss_args(&["-tl".into()]).unwrap();
        assert_eq!(argv, vec!["-tl"]);

        // ss: rejects unknown flag
        assert!(build_ss_args(&["-Z".into()]).is_err());
    }
}
