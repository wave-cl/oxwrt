use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
pub enum Request {
    Get { key: String },
    Set { key: String, value: String },
    Reload,
    Status,
    Logs { service: String, follow: bool },
    Restart { service: String },
    /// Factory reset: overwrite `/etc/oxwrt.toml` with a stock default
    /// config and reload. The `[control]` block (listen addrs +
    /// authorized keys path) is preserved across the reset so the
    /// operator can never lock themselves out — without that
    /// preservation, a reset over the control plane would immediately
    /// drop the only management path. `confirm` MUST be true; the
    /// server rejects any Reset without it so an accidental
    /// `oxwrtctl reset` typo can't wipe the operator's config.
    Reset { confirm: bool },
    /// In-process diagnostic operation. Replaces the "ssh in and run
    /// `ip addr`" recovery loop on traditional routers — every diag
    /// runs inside `oxwrtctl` against the host network namespace
    /// using the existing rtnetlink/rustables deps, so the appliance
    /// model survives (no shell, no extra binaries shipped). The
    /// known ops are a fixed string-keyed enum; unknown ops return an
    /// error response listing the supported set. `args` is reserved
    /// for future ops that need parameters (e.g. `ping <target>`).
    Diag { name: String, args: Vec<String> },
    /// Firmware update phase 1: metadata. The client sends this frame
    /// first, then streams the raw image bytes on the same sQUIC
    /// bi-stream (bypassing write_frame). The server reads `size` bytes,
    /// hashes on the fly, and verifies against `sha256`.
    FwUpdate { size: u64, sha256: String },
    /// Firmware update phase 2: apply the staged image. Triggers
    /// `sysupgrade` and reboots. `confirm` MUST be true (same safety
    /// gate as Reset). The sQUIC connection drops on reboot — the
    /// client interprets this as "update applied, router rebooting."
    ///
    /// `keep_settings`: if true, preserves `/etc/oxwrt.toml` and
    /// `/etc/oxwrt/authorized_keys` across the upgrade (sysupgrade
    /// default). If false, wipes everything (`sysupgrade -n`) — a
    /// clean flash. The client defaults to `true` (keep settings);
    /// pass `--clean` to get `false`.
    FwApply { confirm: bool, keep_settings: bool },
    Collection {
        collection: String,
        action: CrudAction,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "crud", rename_all = "lowercase")]
pub enum CrudAction {
    List,
    Get { name: String },
    Add { json: String },
    Update { name: String, json: String },
    Remove { name: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Response {
    Ok,
    Value { value: String },
    Status {
        services: Vec<ServiceStatus>,
        /// Seconds since `ControlState` was constructed (≈ boot time).
        /// Approximate — we don't track PID-1 fork time separately.
        #[serde(default)]
        supervisor_uptime_secs: u64,
        /// Summary of the current WAN state. `None` for a router
        /// with no WAN lease (static config or failed acquire).
        #[serde(default)]
        wan: Option<WanSummary>,
        /// Number of rules in the installed firewall ruleset (from
        /// the cached dump). Useful for a smoke-test "did the firewall
        /// install?" check without pulling the full dump.
        #[serde(default)]
        firewall_rules: usize,
    },
    LogLine { line: String },
    /// Non-terminal: firmware upload progress. Sent periodically during
    /// `FwUpdate` so the client can display a progress bar.
    FwProgress { bytes_received: u64 },
    Err { message: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceStatus {
    pub name: String,
    pub pid: Option<i32>,
    pub state: ServiceState,
    pub restarts: u32,
    pub uptime_secs: u64,
}

/// Slim WAN summary for the Status RPC. Only the operator-facing
/// fields — full lease detail is available via `diag dhcp`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WanSummary {
    pub address: String,
    pub prefix: u8,
    pub gateway: Option<String>,
    pub lease_seconds: u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ServiceState {
    Starting,
    Running,
    Crashed,
    Stopped,
}
