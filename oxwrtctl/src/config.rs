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
    /// Additional networks (guest WiFi, IoT VLANs, DMZ, etc.).
    /// Topology only — firewall policy lives in `firewall.zones`.
    #[serde(default)]
    pub networks: Vec<Network>,
    /// All firewall policy in one place: LAN zone + per-network zones.
    #[serde(default)]
    pub firewall: Firewall,
    #[serde(default)]
    pub radios: Vec<Radio>,
    /// WiFi SSIDs, each referencing a radio (by `phy`) and a network zone.
    #[serde(default)]
    pub wifi: Vec<Wifi>,
    #[serde(default)]
    pub services: Vec<Service>,
    pub control: Control,
}

/// A single network: its own L2 domain + subnet. Topology only —
/// firewall policy lives in `Firewall.zones`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Network {
    pub name: String,
    pub iface: String,
    pub address: Ipv4Addr,
    pub prefix: u8,
}

/// All firewall policy in one place: zones define default policies per
/// network, rules define explicit allows/drops/DNATs.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Firewall {
    #[serde(default)]
    pub zones: Vec<Zone>,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

/// A firewall zone: names a set of networks and declares default chain
/// policies. The LAN is a zone like any other — no special struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Zone {
    pub name: String,
    #[serde(default)]
    pub networks: Vec<String>,
    #[serde(default)]
    pub default_input: ChainPolicy,
    #[serde(default)]
    pub default_forward: ChainPolicy,
    #[serde(default)]
    pub masquerade: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ChainPolicy {
    Accept,
    #[default]
    Drop,
}

/// A single firewall rule. Every firewall behavior is explicit — no
/// `allow_dns = true` magic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub name: String,
    #[serde(default)]
    pub src: Option<String>,
    #[serde(default)]
    pub dest: Option<String>,
    #[serde(default)]
    pub proto: Option<Proto>,
    #[serde(default)]
    pub dest_port: Option<PortSpec>,
    #[serde(default)]
    pub ct_state: Vec<String>,
    pub action: Action,
    #[serde(default)]
    pub dnat_target: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Tcp,
    Udp,
    Both,
    Icmp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PortSpec {
    Single(u16),
    List(Vec<u16>),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Accept,
    Drop,
    Reject,
    Dnat,
}

fn default_true() -> bool {
    true
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Radio {
    pub phy: String,
    #[serde(default)]
    pub band: String,
    pub channel: u16,
    #[serde(default)]
    pub disabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Wifi {
    pub radio: String,
    pub ssid: String,
    #[serde(default = "default_wifi_security")]
    pub security: WifiSecurity,
    #[serde(default)]
    pub passphrase: String,
    pub network: String,
    #[serde(default)]
    pub hidden: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum WifiSecurity {
    Open,
    Wpa2,
    #[default]
    Wpa3Sae,
    Wpa2Wpa3,
}

fn default_wifi_security() -> WifiSecurity {
    WifiSecurity::Wpa3Sae
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
        assert_eq!(cfg.networks.len(), 2);
        assert_eq!(cfg.networks[0].name, "guest");
        assert_eq!(cfg.firewall.zones.len(), 3);
        assert_eq!(cfg.firewall.zones[0].name, "lan");
        assert_eq!(cfg.firewall.zones[2].name, "wan");
        assert!(cfg.firewall.zones[2].masquerade);
        assert!(!cfg.firewall.rules.is_empty());
        assert_eq!(cfg.wifi.len(), 2);
        assert_eq!(cfg.wifi[0].ssid, "MyNetwork");
        assert_eq!(cfg.wifi[0].network, "lan");
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

    /// Zone + rule model round-trips through TOML correctly: zones
    /// declare defaults, rules declare explicit policy, DNAT rules
    /// carry `dnat_target`, and `PortSpec::List` deserializes from
    /// a TOML array.
    #[test]
    fn zone_and_rule_model_roundtrip() {
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
[control]
listen = ["[::1]:51820"]
authorized_keys = "/etc/oxwrt/keys"

[[firewall.zones]]
name = "lan"
networks = ["lan"]
default_input = "accept"
default_forward = "drop"

[[firewall.zones]]
name = "wan"
networks = ["wan"]
default_input = "drop"
default_forward = "drop"
masquerade = true

[[firewall.rules]]
name = "ct-established"
action = "accept"
ct_state = ["established", "related"]

[[firewall.rules]]
name = "guest-dhcp"
src = "guest"
proto = "udp"
dest_port = [67, 68]
action = "accept"

[[firewall.rules]]
name = "dns-dnat"
proto = "both"
dest_port = 53
action = "dnat"
dnat_target = "10.53.0.2:15353"
"#;
        let cfg: Config = toml::from_str(toml_text).expect("parse");
        assert_eq!(cfg.firewall.zones.len(), 2);
        let lan = &cfg.firewall.zones[0];
        assert_eq!(lan.name, "lan");
        assert_eq!(lan.default_input, crate::config::ChainPolicy::Accept);
        assert!(!lan.masquerade);
        let wan = &cfg.firewall.zones[1];
        assert_eq!(wan.name, "wan");
        assert!(wan.masquerade);

        assert_eq!(cfg.firewall.rules.len(), 3);
        let ct = &cfg.firewall.rules[0];
        assert_eq!(ct.ct_state, vec!["established", "related"]);
        assert_eq!(ct.action, crate::config::Action::Accept);
        let dhcp = &cfg.firewall.rules[1];
        assert_eq!(dhcp.src.as_deref(), Some("guest"));
        assert!(matches!(dhcp.dest_port, Some(crate::config::PortSpec::List(ref v)) if v == &[67, 68]));
        let dnat = &cfg.firewall.rules[2];
        assert_eq!(dnat.action, crate::config::Action::Dnat);
        assert_eq!(dnat.dnat_target.as_deref(), Some("10.53.0.2:15353"));
    }
}
