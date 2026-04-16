use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const DEFAULT_PATH: &str = "/etc/oxwrt.toml";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("read {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("parse {path}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub hostname: String,
    #[serde(default)]
    pub timezone: Option<String>,
    pub wan: Wan,
    pub lan: Lan,
    /// Additional untrusted subnets (guest WiFi, IoT VLANs, DMZ, etc.).
    /// Default firewall stance for every isolated subnet is "drop
    /// everything into the router" — per-subnet flags (`allow_dhcp`,
    /// `allow_dns`) explicitly punch holes, and `client_isolation`
    /// adds an L3 defense-in-depth drop for `iif == oif` forwards.
    /// Cross-subnet forwards to the trusted LAN are always blocked.
    #[serde(default)]
    pub isolated_subnets: Vec<IsolatedSubnet>,
    #[serde(default)]
    pub radios: Vec<Radio>,
    #[serde(default)]
    pub services: Vec<Service>,
    pub control: Control,
}

/// A single isolated network: its own L2 domain + subnet, firewalled
/// off from the trusted LAN by default, explicit allows for the router
/// services (DHCP, DNS) the clients need.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsolatedSubnet {
    /// Short name used for logging and rule tagging.
    pub name: String,
    /// Interface (physical, bridge, or veth) that this subnet lives on.
    pub iface: String,
    /// Router's IPv4 address on this subnet.
    pub address: Ipv4Addr,
    /// Prefix length (e.g. 24).
    pub prefix: u8,
    /// Punch a hole in `INPUT` for DHCP server traffic (UDP 67/68)
    /// arriving on this subnet's interface.
    #[serde(default)]
    pub allow_dhcp: bool,
    /// Punch a hole in `INPUT` for DNS traffic (UDP/TCP 53) arriving
    /// on this subnet's interface. Note that the actual DNS service
    /// lives in an isolated netns; `install_dnat_rules` plumbs the
    /// DNAT from this subnet's router IP to the service peer.
    #[serde(default)]
    pub allow_dns: bool,
    /// Whether the sQUIC control plane is reachable from this subnet.
    /// Default false — operators must explicitly opt in to expose the
    /// management plane on an untrusted network. The trusted LAN
    /// always allows the control plane (see `Lan.allow_control_plane`).
    #[serde(default)]
    pub allow_control_plane: bool,
    /// Whether clients on this subnet can forward to the WAN
    /// interface (i.e., reach the internet). Default `false` —
    /// untrusted subnets get no internet unless explicitly opted in.
    /// This is the toggle for "guest WiFi reaches the internet, IoT
    /// VLAN does not."
    #[serde(default)]
    pub allow_wan: bool,
    /// Arbitrary additional INPUT punches for this subnet. Each entry
    /// is a `(proto, port)` rule that gets emitted as one (UDP-only,
    /// TCP-only) or two (Both) accept rules with `iif` matching this
    /// subnet's interface. Useful for mDNS, captive portal, NTP
    /// server, etc. Default empty.
    #[serde(default)]
    pub input_allow: Vec<PortRule>,
    /// Add an L3 defense-in-depth `iif == oif` drop in `FORWARD`.
    /// This is one half of "client isolation"; the radio-level half
    /// (`hostapd.conf: ap_isolate=1`) and L2 bridge-port
    /// (`ip link set ... type bridge_slave isolated on`) halves must
    /// be set up separately when wireless lands.
    #[serde(default = "default_true")]
    pub client_isolation: bool,
    /// Other isolated subnets (by `name`) that this subnet is allowed
    /// to forward to. Each entry produces a one-way `iif=this oif=peer`
    /// accept; the reverse direction must be declared explicitly on
    /// the peer side, so a peer relationship is asymmetric by default.
    /// Use this for things like "guest WiFi can talk to the printer
    /// VLAN but not vice versa." Default empty.
    #[serde(default)]
    pub peers: Vec<String>,
    /// Per-subnet whitelist of service names this subnet may reach
    /// via the supervisor's veth network. `None` (the default) means
    /// "use the implicit port-matching logic" — i.e. `allow_dns` lets
    /// the subnet hit any service exposing port 53, `allow_dhcp` lets
    /// it hit 67/68. `Some(list)` switches to an explicit whitelist:
    /// only the named services are reachable, irrespective of which
    /// ports they expose. `Some(vec![])` means "no services."
    #[serde(default)]
    pub allow_services: Option<Vec<String>>,
}

fn default_true() -> bool {
    true
}

/// A single (protocol, port) firewall rule used in `IsolatedSubnet.input_allow`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortRule {
    pub proto: PortProto,
    pub port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PortProto {
    Udp,
    Tcp,
    /// Emit two rules — one TCP, one UDP. Convenient for protocols like
    /// DNS that natively use both transports.
    Both,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "lowercase")]
pub enum Wan {
    Dhcp { iface: String },
    Static {
        iface: String,
        address: Ipv4Addr,
        prefix: u8,
        gateway: Ipv4Addr,
        dns: Vec<IpAddr>,
    },
    Pppoe {
        iface: String,
        username: String,
        password: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lan {
    pub bridge: String,
    pub members: Vec<String>,
    pub address: Ipv4Addr,
    pub prefix: u8,
    /// Whether the sQUIC control plane is reachable from the trusted
    /// LAN. Default `true` — the operator's primary management path.
    /// Set to `false` only if you've explicitly enabled the control
    /// plane on a different subnet via
    /// `IsolatedSubnet.allow_control_plane`, otherwise you'll lock
    /// yourself out of the router.
    #[serde(default = "default_true")]
    pub allow_control_plane: bool,
    /// Whether the trusted LAN can forward to the WAN interface.
    /// Default `true` — the standard "router routes the LAN to the
    /// internet" behavior. Set to `false` for an air-gapped LAN.
    #[serde(default = "default_true")]
    pub allow_wan: bool,
    /// Whitelist of service names the trusted LAN may reach via the
    /// supervisor's veth network. `None` (the default) means "all
    /// services" — preserves the historical "trusted LAN reaches
    /// everything" behavior. `Some(list)` restricts the LAN to the
    /// named services. `Some(vec![])` means "no services" (the LAN
    /// can still reach the WAN if `allow_wan = true`, just not any
    /// container).
    #[serde(default)]
    pub allow_services: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Radio {
    pub phy: String,
    pub ssid: String,
    pub key: String,
    pub channel: u16,
    #[serde(default)]
    pub disabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Service {
    pub name: String,
    pub rootfs: PathBuf,
    pub entrypoint: Vec<String>,
    /// Environment variables passed to the service at spawn time. Applied
    /// **after** the fixed `HOME`/`PATH`/`HOSTNAME` so a service can override
    /// those too. Preferred over config files for everything that supports
    /// it — see the "Service configuration convention" in the plan file.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub net_mode: NetMode,
    #[serde(default)]
    pub veth: Option<VethConfig>,
    #[serde(default)]
    pub expose: Vec<ExposePort>,
    #[serde(default)]
    pub memory_max: Option<u64>,
    #[serde(default)]
    pub cpu_max: Option<String>,
    #[serde(default)]
    pub pids_max: Option<u64>,
    #[serde(default)]
    pub binds: Vec<BindMount>,
    #[serde(default)]
    pub depends_on: Vec<String>,
    #[serde(default)]
    pub security: SecurityProfile,
}

/// Per-service hardening profile. Applied in `pre_exec` *after* the
/// mount/pivot/etc. setup but *before* the service binary is execve'd.
/// All three layers default to "the safest setting that still allows
/// the common service patterns."
///
/// `Default` is implemented manually so that `SecurityProfile::default()`
/// matches what `#[serde(default)]` produces during config parsing — i.e.
/// the four-cap retain list, `no_new_privs = true`, `seccomp = true`. A
/// derived `Default` would silently produce an empty caps list (drop
/// everything) which is a footgun.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityProfile {
    /// Linux capabilities to **retain**. Anything not in this list is
    /// dropped from the bounding, effective, permitted, and inheritable
    /// sets, so neither this process nor any child it execs (with
    /// `no_new_privs = true`) can ever acquire them.
    ///
    /// Default — see `default_retained_caps()` — is the small set
    /// needed by services that drop privs to `nobody` and bind low
    /// ports: `SETUID`, `SETGID`, `SETPCAP`, `NET_BIND_SERVICE`.
    /// Services that need more (e.g. coredhcp wants `NET_RAW` +
    /// `NET_ADMIN`, a future ntpd-rs that actually steps the clock
    /// wants `SYS_TIME`) override this list explicitly.
    ///
    /// Capability names are the libcap canonical names without the
    /// `CAP_` prefix: `"NET_ADMIN"`, `"SYS_TIME"`, etc.
    #[serde(default = "default_retained_caps")]
    pub caps: Vec<String>,

    /// `prctl(PR_SET_NO_NEW_PRIVS, 1)`. Default `true`. Prevents the
    /// service from acquiring new privileges via `execve` — setuid
    /// binaries, file capabilities, LSM upgrades all become no-ops.
    /// Required precondition for safe seccomp-bpf without
    /// `CAP_SYS_ADMIN`.
    #[serde(default = "default_true")]
    pub no_new_privs: bool,

    /// Apply the seccomp-bpf deny list (a small set of obviously
    /// dangerous syscalls — `ptrace`, `mount`, `init_module`, `bpf`,
    /// `keyctl`, `kexec_*`, etc.) Default `true`. Set `false` if a
    /// service legitimately needs one of the denied syscalls AND it
    /// isn't covered by `seccomp_allow` below.
    #[serde(default = "default_true")]
    pub seccomp: bool,

    /// Syscalls to **remove** from the default deny list for this
    /// service. Use this in preference to `seccomp = false` whenever
    /// a service needs exactly one or two of the denied syscalls —
    /// the rest of the deny list still applies. Names are the bare
    /// syscall names (no `SYS_` prefix), e.g. `"unshare"`, `"bpf"`.
    /// Unknown names produce a `prepare()` error so a typo in the
    /// config can't silently leave the deny list intact.
    #[serde(default)]
    pub seccomp_allow: Vec<String>,

    /// Run the service in a dedicated Linux user namespace, mapping
    /// container uid 0 to host uid 65534 (nobody). Default `false`
    /// (opt-in for v0 — flip to `true` once proven stable). Even if
    /// a service escapes all other sandboxing layers and achieves
    /// arbitrary code execution, it's running as `nobody` on the
    /// host — no root access, no filesystem writes outside the
    /// container, no ability to manipulate other namespaces.
    ///
    /// Implementation uses a helper thread + pipe synchronization:
    /// the child unshares NEWUSER and pauses via a pipe; the helper
    /// thread writes `/proc/<pid>/uid_map` + `/proc/<pid>/gid_map`,
    /// then signals the child to proceed with the rest of the
    /// namespace setup (mounts, pivot_root, etc.).
    #[serde(default)]
    pub user_namespace: bool,

    /// Apply a Landlock LSM sandbox that restricts **writes only**
    /// (reads are unrestricted). Default `true`. With no writable
    /// bind mounts, a service cannot open any new file for writing
    /// — its only writable fds are those inherited from the
    /// supervisor (stdout, stderr, stdin, any passed sockets).
    /// Writable bind mount sources are added as explicit allow
    /// rules so services like coredhcp can persist their lease DB.
    ///
    /// Why writes-only: `/proc`, `/sys`, `/dev` are remounted in
    /// the container child after pivot_root, producing fresh
    /// superblock inodes that parent-side `PathFd`s don't cover.
    /// Restricting reads would break Rust stdlib (`/proc/self/*`)
    /// and most services. Restricting writes is the 80/20 win —
    /// even a compromised service can't write to /etc, /var, /tmp,
    /// or anywhere else except its declared writable mounts.
    #[serde(default = "default_true")]
    pub landlock: bool,
}

pub fn default_retained_caps() -> Vec<String> {
    vec![
        "SETUID".to_string(),
        "SETGID".to_string(),
        // SETPCAP is required to drop other capabilities from the
        // bounding set; the implementation drops it last.
        "SETPCAP".to_string(),
        "NET_BIND_SERVICE".to_string(),
    ]
}

impl Default for SecurityProfile {
    fn default() -> Self {
        Self {
            caps: default_retained_caps(),
            no_new_privs: true,
            seccomp: true,
            seccomp_allow: Vec::new(),
            user_namespace: false, // opt-in for v0
            landlock: true,
        }
    }
}

/// Per-service DNAT entry. Installs `lan_port` → `<veth.peer_ip>:service_port`
/// as a prerouting DNAT rule (for both TCP and UDP) on the LAN bridge, so
/// clients on the LAN can reach the service on its conventional port even
/// though the container listens on an alternate one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExposePort {
    pub lan_port: u16,
    pub service_port: u16,
}

/// Veth pair configuration for an `Isolated`-mode service. The supervisor
/// creates `veth-<svc>` in the host netns with `host_ip/prefix`, creates the
/// peer `veth-<svc>-p` in the child's netns with `peer_ip/prefix`, and
/// expects the service to bind on `peer_ip` (or `0.0.0.0` / `::`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VethConfig {
    pub host_ip: Ipv4Addr,
    pub peer_ip: Ipv4Addr,
    /// Default: `30` (two usable addresses in a /30).
    #[serde(default = "default_veth_prefix")]
    pub prefix: u8,
}

fn default_veth_prefix() -> u8 {
    30
}

/// Network namespace strategy for a service container.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum NetMode {
    /// Unshare `CLONE_NEWNET` — container gets its own empty netns.
    /// The supervisor is expected to attach a veth peer post-fork (not yet
    /// implemented) to provide connectivity. This is the default for real
    /// services so nothing accidentally binds on the host netns.
    #[default]
    Isolated,
    /// Do not unshare the network namespace — container shares the host
    /// (or outer container's) netns. Used by debug / smoke-test paths
    /// where the service needs to be reachable without a veth pair.
    Host,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BindMount {
    pub source: PathBuf,
    pub target: PathBuf,
    /// Defaults to `true`. Immutable-by-default enforces the "config lives
    /// on the host, the container cannot mutate it" half of the service
    /// configuration convention. Writable bind mounts must opt in
    /// explicitly (e.g. coredhcp's lease DB).
    #[serde(default = "default_bind_readonly")]
    pub readonly: bool,
}

fn default_bind_readonly() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Control {
    pub listen: Vec<String>,
    pub authorized_keys: PathBuf,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, Error> {
        let bytes = std::fs::read(path).map_err(|source| Error::Read {
            path: path.to_path_buf(),
            source,
        })?;
        let text = String::from_utf8(bytes).map_err(|e| Error::Read {
            path: path.to_path_buf(),
            source: std::io::Error::new(std::io::ErrorKind::InvalidData, e),
        })?;
        toml::from_str(&text).map_err(|source| Error::Parse {
            path: path.to_path_buf(),
            source,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The example config at `config/oxwrt.toml` must parse against
    /// the current `Config` schema. Catches any schema change that
    /// would break the cookbook example at build time (and forces the
    /// two to stay in sync — a new field without an example is OK,
    /// but a new REQUIRED field without an example entry fails here).
    ///
    /// Path is relative to `CARGO_MANIFEST_DIR` (= `oxwrtctl/`) so
    /// this works regardless of where `cargo test` is invoked from.
    #[test]
    fn example_config_parses() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../config/oxwrt.toml");
        let text = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("read {path}: {e}"));
        let cfg: Config = toml::from_str(&text)
            .unwrap_or_else(|e| panic!("parse {path}: {e}"));

        // A handful of spot checks that double as documentation:
        // future field additions can extend the example TOML AND the
        // assertions here without worrying about redundant coverage.
        assert_eq!(cfg.hostname, "slate7");
        assert_eq!(cfg.timezone.as_deref(), Some("Europe/Berlin"));
        assert_eq!(cfg.lan.bridge, "br-lan");
        assert_eq!(cfg.isolated_subnets.len(), 2);
        assert_eq!(cfg.isolated_subnets[0].name, "guest");
        assert_eq!(cfg.isolated_subnets[0].peers, vec!["iot".to_string()]);
        assert_eq!(cfg.services.len(), 3);

        // The coredhcp service must declare NET_RAW + NET_ADMIN on top
        // of the default retain list — this is the canonical "override
        // the default caps" example.
        let dhcp = cfg
            .services
            .iter()
            .find(|s| s.name == "dhcp")
            .expect("example must include a 'dhcp' service");
        assert!(dhcp.security.caps.contains(&"NET_RAW".to_string()));
        assert!(dhcp.security.caps.contains(&"NET_ADMIN".to_string()));
        // And coredhcp must have at least one writable bind mount for
        // its lease DB — the canonical landlock-compatible writable
        // state example.
        assert!(dhcp.binds.iter().any(|b| !b.readonly));
    }

    /// Both `peers` and `allow_services` survive a TOML round trip and
    /// distinguish "unset" from "empty list" the way the firewall code
    /// expects: `allow_services = None` ⇒ implicit port-match logic,
    /// `Some(vec![])` ⇒ explicit "no services."
    #[test]
    fn isolated_subnet_peers_and_allow_services() {
        let toml_text = r#"
hostname = "rtr"
[wan]
mode = "dhcp"
iface = "eth0"
[lan]
bridge = "br-lan"
members = ["eth1"]
address = "192.168.1.1"
prefix = 24
allow_services = ["dns"]
[control]
listen = ["[::1]:51820"]
authorized_keys = "/etc/oxwrt/keys"

[[isolated_subnets]]
name = "guest"
iface = "br-guest"
address = "192.168.10.1"
prefix = 24
allow_dns = true
peers = ["iot"]
allow_services = []

[[isolated_subnets]]
name = "iot"
iface = "br-iot"
address = "192.168.20.1"
prefix = 24
"#;
        let cfg: Config = toml::from_str(toml_text).expect("parse");
        assert_eq!(cfg.lan.allow_services.as_deref(), Some(&["dns".to_string()][..]));
        let guest = &cfg.isolated_subnets[0];
        assert_eq!(guest.peers, vec!["iot".to_string()]);
        assert_eq!(guest.allow_services.as_deref(), Some(&[][..]));
        let iot = &cfg.isolated_subnets[1];
        assert!(iot.peers.is_empty());
        assert!(iot.allow_services.is_none());
    }
}
