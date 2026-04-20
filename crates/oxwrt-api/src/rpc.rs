use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
pub enum Request {
    Get {
        key: String,
    },
    Set {
        key: String,
        value: String,
    },
    Reload,
    /// Validate the on-disk `/etc/oxwrt/oxwrt.toml` (+ secrets
    /// overlay + env) and run every pre-flight validator WITHOUT
    /// any reconcile side effects. Returns Ok if the config
    /// parses and passes all cross-section checks; returns Err
    /// with the first violation otherwise.
    ///
    /// Operator workflow: edit TOML → `oxctl reload-dry-run` →
    /// only if it passes, `oxctl reload`. Cheaper than watching a
    /// failed reload auto-restore, and catches typos (bad zone
    /// refs, duplicate names) that the rollback machinery would
    /// surface only after flapping the firewall.
    ReloadDryRun,
    Status,
    Logs {
        service: String,
        follow: bool,
    },
    Restart {
        service: String,
    },
    /// Factory reset: overwrite `/etc/oxwrt.toml` with a stock default
    /// config and reload. The `[control]` block (listen addrs +
    /// authorized keys path) is preserved across the reset so the
    /// operator can never lock themselves out — without that
    /// preservation, a reset over the control plane would immediately
    /// drop the only management path. `confirm` MUST be true; the
    /// server rejects any Reset without it so an accidental
    /// `oxwrtd reset` typo can't wipe the operator's config.
    Reset {
        confirm: bool,
    },
    /// In-process diagnostic operation. Replaces the "ssh in and run
    /// `ip addr`" recovery loop on traditional routers — every diag
    /// runs inside `oxwrtd` against the host network namespace
    /// using the existing rtnetlink/rustables deps, so the appliance
    /// model survives (no shell, no extra binaries shipped). The
    /// known ops are a fixed string-keyed enum; unknown ops return an
    /// error response listing the supported set. `args` is reserved
    /// for future ops that need parameters (e.g. `ping <target>`).
    Diag {
        name: String,
        args: Vec<String>,
    },
    /// Firmware update phase 1: metadata. The client sends this frame
    /// first, then streams the raw image bytes on the same sQUIC
    /// bi-stream (bypassing write_frame). The server reads `size` bytes,
    /// hashes on the fly, and verifies against `sha256`.
    FwUpdate {
        size: u64,
        sha256: String,
    },
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
    FwApply {
        confirm: bool,
        keep_settings: bool,
    },
    Collection {
        collection: String,
        action: CrudAction,
    },
    /// Dump the entire running config as TOML.
    ConfigDump,
    /// Replace the entire config with the provided TOML. Persists
    /// atomically and swaps the in-memory config. Operator must
    /// `reload` to apply. Use with care — no partial validation
    /// beyond "does it parse as a valid Config?"
    ConfigPush {
        toml: String,
    },
    /// Upload a `[[vpn_client]]` private key to the router at
    /// /etc/oxwrt/vpn/<name>.key. `name` must match the profile's
    /// `name` field in oxwrt.toml; path-traversal defense rejects
    /// anything that isn't \[a-zA-Z0-9_-\]+.
    ///
    /// Private keys never go through the regular config flow —
    /// they'd be visible in backups and config dumps. This RPC
    /// writes atomically at 0600 into the existing /etc/oxwrt/
    /// overlay path so they survive sysupgrade via the existing
    /// keeplist. Operators who lose the key must re-upload; the
    /// router neither generates the key from upstream nor echoes
    /// it back. Pair with `oxctl reload` to pick up.
    VpnKeyUpload {
        name: String,
        /// Raw base64 WireGuard private key (44 chars, same shape
        /// `wg genkey` emits). Not re-encoded on the wire — it
        /// travels inside the already-encrypted sQUIC channel.
        private_key_b64: String,
    },
    /// Enroll a new WireGuard roadwarrior peer: the server generates
    /// a fresh client keypair, adds the public half to its peer list
    /// (persisted to oxwrt.toml), and returns a complete client
    /// `.conf` — ready for the operator to hand to the user who
    /// pastes it into wg-quick / the GUI / QR scanner. Closes the
    /// onboarding loop: previously the operator had to generate the
    /// client keypair manually, call `wg-peer add` with the pubkey,
    /// compose a .conf by hand, and remember the server pubkey +
    /// endpoint. Now one RPC does it.
    ///
    /// The client's private key is returned in the response and NOT
    /// persisted on the router — if the operator loses it the only
    /// fix is re-enroll (which regenerates).
    /// Bundle `/etc/oxwrt.toml` + everything under `/etc/oxwrt/`
    /// into a gzipped tar and return it in the response. Lets an
    /// operator grab a point-in-time snapshot before risky changes
    /// (new firmware, config experiments) and restore it later. The
    /// payload includes the sQUIC signing seed, WG private key,
    /// authorized_keys, and debug-ssh host keys — restoring it on
    /// the same device recovers full identity; restoring to a fresh
    /// device impersonates the original.
    Backup,
    /// Replace `/etc/oxwrt.toml` + `/etc/oxwrt/` with the contents
    /// of a backup tarball. Extracts to a staging dir first, then
    /// atomically replaces the live tree. Triggers a reload so the
    /// new config takes effect without a reboot. `confirm` MUST be
    /// true — accidental restore with a stale backup would roll
    /// back everything including the sQUIC key (locking the client
    /// out until UART recovery).
    Restore {
        data_b64: String,
        confirm: bool,
    },
    /// Revert `/etc/oxwrt/oxwrt.toml` (+ secrets overlay) to the
    /// last-known-good snapshot oxwrtd captured after the most
    /// recent successful reload, then reload so the reverted
    /// config takes effect.
    ///
    /// `confirm` MUST be true — rollback discards the current
    /// config (it's not saved anywhere else) and may change the
    /// firewall + services visibly.
    ///
    /// Fails with a clear error if no last-good snapshot exists
    /// (fresh flash that never successfully reloaded, or the
    /// operator deleted `.last-good.toml` by hand).
    Rollback {
        confirm: bool,
    },
    /// Graceful system reboot. Saves urandom seed, shuts down the
    /// supervisor (stops services in reverse-dep order, reaps
    /// children, removes cgroup leaves), syncs filesystems, then
    /// calls `reboot(2)` with LINUX_REBOOT_CMD_RESTART.
    ///
    /// `confirm` MUST be true — same safety gate as Reset / FwApply.
    /// The sQUIC connection drops on reboot; the client interprets
    /// that as "reboot initiated" rather than an error.
    ///
    /// Distinct from FwApply which ALSO reboots but first swaps the
    /// image. Use Reboot when you just want to restart — e.g. to
    /// clear a stuck service, drain a memory leak, or re-read
    /// hardware state after a hotplug.
    Reboot {
        confirm: bool,
    },
    WgEnroll {
        /// Peer name (unique under `[[wireguard.peers]]`).
        name: String,
        /// Allowed IPs on the server side — CIDR(s) the peer is
        /// permitted to source from. Typically a single /32 per
        /// roadwarrior.
        allowed_ips: String,
        /// Endpoint host (IP or DDNS name) the client dials into.
        /// Port is taken from the iface's `listen_port`.
        endpoint_host: String,
        /// DNS server to push to the client's [Interface] block.
        /// Typically the router's LAN IP. None → client uses its
        /// upstream default.
        #[serde(default)]
        dns: Option<String>,
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
    Value {
        value: String,
    },
    Status {
        services: Vec<ServiceStatus>,
        /// Seconds since `ControlState` was constructed (≈ boot time).
        /// Approximate — we don't track PID-1 fork time separately.
        #[serde(default)]
        supervisor_uptime_secs: u64,
        /// Summary of the current WAN state. `None` for a router
        /// with no WAN lease (static config or failed acquire).
        /// On multi-WAN deployments this is the ACTIVE WAN's
        /// lease — the failover coordinator picks the lowest-
        /// priority healthy one and mirrors it here.
        #[serde(default)]
        wan: Option<WanSummary>,
        /// Name of the active WAN on a multi-WAN deployment.
        /// `None` = no healthy WAN right now, or single-WAN
        /// setup where the field is redundant with `wan`. Lets
        /// operators see which upstream is serving traffic
        /// without parsing the route table.
        #[serde(default)]
        active_wan: Option<String>,
        /// Per-WAN breakdown: one entry per declared
        /// `[[networks]] type = "wan"` with its current health,
        /// address, and active-or-standby role. Populated on
        /// every Status call; empty on a no-WAN router.
        #[serde(default)]
        wans: Vec<WanEntry>,
        /// Number of rules in the installed firewall ruleset (from
        /// the cached dump). Useful for a smoke-test "did the firewall
        /// install?" check without pulling the full dump.
        #[serde(default)]
        firewall_rules: usize,
        /// Per-AP-iface status for every `[[wifi]]` entry. Each item
        /// is an expected AP (ssid + backing phy-ap0 iface name) plus
        /// whether its iface is currently Up. Caught the MT7986 DFS-
        /// CAC-stuck bug on day one of this field existing — without
        /// it, operators have no way to notice a silently-down AP
        /// short of associating a client and seeing it fail.
        #[serde(default)]
        aps: Vec<ApStatus>,
        /// Per-WireGuard-iface live peer state. One entry per
        /// declared `[[wireguard]]` iface; each contains zero or more
        /// peers as surfaced by `wg show <iface> dump`. "last
        /// handshake = never" tells you at a glance which clients
        /// have never come up; a stale rx_bytes suggests an asymmetric
        /// MTU issue; a "huge tx_bytes, tiny rx_bytes" pattern
        /// typically means the peer's routing is pointing the wrong
        /// direction.
        #[serde(default)]
        wg: Vec<WgIfaceStatus>,
        /// Currently-active outbound VPN profile name, or None if
        /// no profile is healthy (→ killswitch engaged). Only
        /// meaningful when `[[vpn_client]]` is declared; absent
        /// otherwise. Read from ControlState.active_vpn.
        #[serde(default)]
        active_vpn: Option<String>,
        /// Per-vpn_client breakdown. One entry per declared
        /// profile; fields mirror WanEntry. Empty on a non-VPN
        /// router.
        #[serde(default)]
        vpns: Vec<VpnEntry>,
    },
    LogLine {
        line: String,
    },
    /// Non-terminal: firmware upload progress. Sent periodically during
    /// `FwUpdate` so the client can display a progress bar.
    FwProgress {
        bytes_received: u64,
    },
    Err {
        message: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceStatus {
    pub name: String,
    pub pid: Option<i32>,
    pub state: ServiceState,
    pub restarts: u32,
    pub uptime_secs: u64,
    /// Most recent log line captured from the service's stderr, if
    /// any. Populated from the per-service ring in `logd` — so an
    /// operator looking at `oxwrtd --client <addr> status` gets a
    /// one-line hint about *why* a Crashed service crashed, without
    /// needing to shell into the device or call `logs <name>`.
    ///
    /// `None` for services that have produced zero log output yet
    /// (typically a freshly-declared service that hasn't spawned).
    /// Clipped to 240 chars server-side to keep `status` readable
    /// even when the crash message is a multi-kilobyte backtrace.
    #[serde(default)]
    pub last_log: Option<String>,
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

/// Per-WAN entry in the Status RPC's `wans` field. Emitted for
/// every `[[networks]] type = "wan"` regardless of whether it's
/// active right now — lets operators see at a glance that their
/// backup WAN is healthy and ready to take over, not silently
/// broken waiting for a real failover.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WanEntry {
    pub name: String,
    pub iface: String,
    pub priority: u32,
    pub healthy: bool,
    /// True for the one WAN currently serving the default route.
    pub active: bool,
    /// Current IPv4 address on this WAN's lease, if any.
    #[serde(default)]
    pub address: Option<String>,
    /// Gateway on this WAN's lease, if any.
    #[serde(default)]
    pub gateway: Option<String>,
}

/// Per-VpnClient-profile entry in the Status RPC's `vpns` field.
/// Surfaced for every declared `[[vpn_client]]` so operators see
/// at a glance which profile is active, which are ready-to-
/// failover, and which are down.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnEntry {
    pub name: String,
    pub iface: String,
    pub priority: u32,
    /// bring-up succeeded AND (probe passing OR no probe).
    pub healthy: bool,
    /// True for the one profile currently routing for via_vpn
    /// zones.
    pub active: bool,
    /// Upstream peer endpoint (host:port), for operator
    /// diagnostics. Not resolved to an IP here — that happens
    /// inside the coordinator.
    pub endpoint: String,
    /// Health-probe target pinged through the wg iface.
    pub probe_target: String,
}

/// One AP (BSS) declared in `[[wifi]]`, with its backing kernel iface
/// and live iface state. `iface` is derived at status-collect time from
/// the convention `{phy}-ap0` used by netdev::create_wifi_ap_interfaces.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApStatus {
    pub ssid: String,
    pub iface: String,
    /// Phy the AP is hosted on (e.g. "phy0"). Useful to cross-ref
    /// with `[[radios]]` for band/channel.
    pub radio_phy: String,
    /// "2g" | "5g" — pulled from the matching `[[radios]]` entry.
    /// Empty string if no radio entry exists (misconfigured wifi).
    pub band: String,
    /// Primary channel from the matching `[[radios]]` entry. 0 if
    /// none matched.
    #[serde(default)]
    pub channel: u16,
    /// Raw /sys/class/net/<iface>/operstate string. "up" for a
    /// beaconing AP, "down" pre-bring-up or post-CAC-fail,
    /// "unknown" when kernel hasn't classified it yet.
    pub operstate: String,
}

/// One WireGuard iface's live state. `iface` is the kernel iface
/// name (e.g. "wg0"), `listen_port` is the bound UDP port. `peers`
/// mirrors the `[[wireguard.peers]]` declared in config, with live
/// fields filled in from `wg show dump` output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WgIfaceStatus {
    pub iface: String,
    #[serde(default)]
    pub listen_port: u16,
    #[serde(default)]
    pub peers: Vec<WgPeerStatus>,
}

/// One peer on a WireGuard iface. `name` is the operator-supplied
/// label from the CRUD config; `pubkey` is the cryptographic
/// identity. `endpoint` is the last-seen remote address; empty when
/// the peer has never connected. `last_handshake_secs_ago` is None
/// for a peer that's never handshaked (cold peer, config-only).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WgPeerStatus {
    pub name: String,
    pub pubkey: String,
    #[serde(default)]
    pub endpoint: String,
    /// Seconds since the last successful handshake with this peer.
    /// None = never. `Some(very_large)` means the tunnel is idle.
    #[serde(default)]
    pub last_handshake_secs_ago: Option<u64>,
    #[serde(default)]
    pub rx_bytes: u64,
    #[serde(default)]
    pub tx_bytes: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ServiceState {
    Starting,
    Running,
    Crashed,
    Stopped,
}
