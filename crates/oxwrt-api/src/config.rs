use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
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
    /// All networks: WAN, LAN, and simple (guest/IoT) in a unified array.
    /// Topology only — firewall policy lives in `firewall.zones`.
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
    /// Port forwards (WAN-side external port → LAN-side host:port).
    /// Stored as a first-class collection rather than loose DNAT rules
    /// under `firewall.rules` so operators never forget the companion
    /// FORWARD accept: install emits both from a single entry. Empty
    /// by default (no ports exposed).
    #[serde(default, rename = "port_forwards")]
    pub port_forwards: Vec<PortForward>,
    /// WireGuard roadwarrior server(s). Each entry is one wg iface
    /// (e.g. wg0) with a list of allowed client peers. Peers are
    /// CRUD-managed at runtime via `oxctl wg-peer …`, so this is
    /// often a small stub in the on-disk config that grows as
    /// clients are provisioned. Server keypair is auto-generated
    /// on first boot and persisted at the path named by `key_path`.
    #[serde(default)]
    pub wireguard: Vec<Wireguard>,
    /// Dynamic-DNS updaters. Each entry watches the current WAN IP
    /// (from the DHCP lease) and pushes to a third-party provider's
    /// update API when the address changes — closes the loop on
    /// port-forwards + wg-enroll endpoints that reference a stable
    /// hostname pointing to a dynamic WAN address. Zero entries =
    /// feature off.
    #[serde(default)]
    pub ddns: Vec<Ddns>,
    /// Optional Prometheus-format /metrics endpoint. When set, a
    /// tokio TCP listener binds to `listen` and exports counters
    /// for service state, WG peer handshakes, WAN lease time
    /// remaining, firewall rule count, etc. None = disabled.
    /// No auth — rely on firewall zone rules to restrict access
    /// (typically bind to the LAN IP + allow only LAN queries).
    #[serde(default)]
    pub metrics: Option<Metrics>,
    /// Static IPv4 routes installed at boot and reconciled on reload.
    /// Covers the common OpenWrt use cases of "route 10.20.0.0/16 via
    /// my VPN gateway" and "policy route subnet X out iface Y". IPv6
    /// gets its own `[[routes6]]` whenever someone needs it — same
    /// shape, different address type. Empty = no extra routes beyond
    /// the kernel's on-link + DHCP-installed default.
    #[serde(default)]
    pub routes: Vec<Route>,
    /// Static IPv6 routes. Same shape as [[routes]] but with
    /// Ipv6Addr dest + gateway; reconciled on every reload
    /// alongside the v4 table. Empty = kernel's on-link v6
    /// routes + any RA-installed default are the only ones
    /// present.
    #[serde(default)]
    pub routes6: Vec<Route6>,
    /// IP blocklists: periodically-fetched CIDR lists that drop
    /// matching source addresses at the INPUT chain. One line per
    /// CIDR in the URL body, `#` comments ok. Equivalent to
    /// OpenWrt's `banip` package for the common case. Each list
    /// becomes a named nftables set in the `oxwrt-blocklist`
    /// table, refreshed at `refresh_seconds` cadence.
    #[serde(default)]
    pub blocklists: Vec<Blocklist>,
    /// Optional UPnP / NAT-PMP / PCP port-mapping daemon. When set,
    /// a miniupnpd service is configured (config file generated
    /// from this block) and — assuming the binary is present in
    /// the image — supervised like any other service. LAN clients
    /// can then request transient DNATs for gaming/p2p without the
    /// operator pre-declaring [[port_forwards]]. None = disabled.
    ///
    /// The miniupnpd binary itself is not bundled in oxwrt today;
    /// the schema + config rendering land first so operators can
    /// wire an external package manager build, and a follow-up
    /// task adds the services-upnpd cross-build to the Makefile.
    #[serde(default)]
    pub upnp: Option<UpnpConfig>,
    pub control: Control,
}

/// UPnP / NAT-PMP / PCP (miniupnpd) configuration. Renders to a
/// /etc/oxwrt/miniupnpd.conf that the miniupnpd binary consumes at
/// service start. The daemon installs its own DNAT rules into a
/// dedicated `oxwrt-upnpd` nftables table so its transient
/// mappings never collide with config-driven `[[port_forwards]]`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpnpConfig {
    /// WAN iface miniupnpd advertises (outside). Matches the
    /// `iface` of the primary `[[networks]] type="wan"` entry in
    /// typical setups; breaking this out lets PPPoE deployments
    /// name the ppp0-style iface without wiring a second WAN
    /// declaration.
    pub wan: String,
    /// LAN iface miniupnpd listens on (inside). One iface only —
    /// multi-LAN is a miniupnpd limitation, not ours.
    pub lan: String,
    /// Minimum external port miniupnpd is allowed to map. Lower
    /// bound prevents clients from grabbing well-known ports.
    #[serde(default = "default_upnp_port_min")]
    pub min_port: u16,
    /// Maximum external port miniupnpd is allowed to map.
    #[serde(default = "default_upnp_port_max")]
    pub max_port: u16,
    /// Enable NAT-PMP (RFC 6886, Apple's legacy pre-PCP protocol)
    /// alongside UPnP. Both protocols work over the same daemon;
    /// some older clients only speak NAT-PMP.
    #[serde(default = "default_upnp_natpmp")]
    pub enable_natpmp: bool,
}

fn default_upnp_port_min() -> u16 {
    1024
}
fn default_upnp_port_max() -> u16 {
    65535
}
fn default_upnp_natpmp() -> bool {
    true
}

fn default_wan_priority() -> u32 {
    100
}

/// A single IP blocklist entry. `name` doubles as the nftables set
/// name — keep it `[A-Za-z0-9_-]` to match the kernel's allowed
/// character set. Typical lists: firehol_level1 (~900 prefixes of
/// known bad actors), spamhaus_drop (~1000), abuseipdb feeds.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Blocklist {
    pub name: String,
    pub url: String,
    #[serde(default = "default_blocklist_refresh")]
    pub refresh_seconds: u64,
    /// Zones whose INPUT chain should drop matches. Empty = every
    /// zone (router-wide drop). Naming a zone that doesn't exist is
    /// a validate-time error on reload.
    #[serde(default)]
    pub zones: Vec<String>,
}

fn default_blocklist_refresh() -> u64 {
    86400 // 24h — typical public-list update cadence
}

/// Static IPv4 route declaration. Output iface is required (kernel
/// needs it for an onlink route, and for a via-gateway route it
/// disambiguates which link to use when the gateway is reachable
/// through multiple ifaces — common with multi-WAN / VPN overlays).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Route {
    /// Network address (e.g. 10.20.0.0). Must align with `prefix` —
    /// validated at install time, not parse time.
    pub dest: Ipv4Addr,
    /// Prefix length, 0..=32. `0` = default route (unusual; WAN DHCP
    /// already installs one). `32` = host route.
    pub prefix: u8,
    /// Next-hop gateway. `None` = on-link route (dest is directly
    /// reachable on `iface`, no router in between).
    #[serde(default)]
    pub gateway: Option<Ipv4Addr>,
    /// Output interface. Required — see struct-level doc.
    pub iface: String,
    /// Route metric. Lower wins when multiple routes match. Default
    /// 1024 matches iproute2's convention for operator-installed
    /// static routes (kernel default routes are metric 0, DHCP
    /// installs at metric 100-ish).
    #[serde(default = "default_route_metric")]
    pub metric: u32,
}

fn default_route_metric() -> u32 {
    1024
}

/// Static IPv6 route. Same shape as `Route` with Ipv6Addr fields.
/// Kept as a separate struct rather than generic-over-address so
/// TOML sections remain unambiguous (`[[routes]]` = v4,
/// `[[routes6]]` = v6), which matches how operators think about
/// the two tables.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Route6 {
    /// Network address. Must align with `prefix`.
    pub dest: Ipv6Addr,
    /// Prefix length, 0..=128. `0` = default route (unusual;
    /// RA normally installs one). `128` = host route.
    pub prefix: u8,
    /// Next-hop gateway. `None` = on-link route.
    #[serde(default)]
    pub gateway: Option<Ipv6Addr>,
    /// Output interface. Required — same rationale as the v4
    /// path.
    pub iface: String,
    /// Route metric; lower wins when multiple routes match.
    /// Default 1024 (same convention as v4).
    #[serde(default = "default_route_metric")]
    pub metric: u32,
}

/// Prometheus `/metrics` endpoint configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metrics {
    /// Bind address:port. Typical values:
    ///   "192.168.50.1:9100" — LAN-only, no exposure on WAN
    ///   "127.0.0.1:9100"    — localhost only (ssh tunnel from LAN)
    ///   "0.0.0.0:9100"      — all ifaces; pair with a firewall
    ///                         rule that restricts src zone.
    pub listen: String,
}

/// A single network entry in the unified `[[networks]]` array. The `type`
/// tag selects the variant: `"wan"`, `"lan"`, or `"simple"`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Network {
    Wan {
        name: String,
        iface: String,
        #[serde(flatten)]
        wan: WanConfig,
        /// Enable DHCPv6-PD on this WAN iface. When true, oxwrtd
        /// solicits a delegated prefix (typically a /56 or /60
        /// from the ISP), then slices it into /64s addressed to
        /// each LAN/Simple network that declares `ipv6_subnet_id`.
        /// Default false — operators on ISPs without PD (or with
        /// static v6 routed to them) leave this off and declare
        /// `ipv6_address` per-LAN instead.
        #[serde(default)]
        ipv6_pd: bool,
        /// Smart Queue Management (CAKE) for bufferbloat mitigation
        /// on the WAN pipe. When set, oxwrtd installs tc qdiscs that
        /// shape traffic to the declared bandwidths — egress
        /// directly on this iface, ingress via an IFB redirect.
        /// None = no SQM (default FIFO, may bufferbloat under load).
        #[serde(default)]
        sqm: Option<SqmConfig>,
        /// Failover priority. Lower = higher preference, iproute2
        /// convention. On a multi-WAN deployment, oxwrtd picks the
        /// lowest-numbered WAN whose DHCP lease is healthy as the
        /// active egress, installs its gateway as the default
        /// route, and mirrors its lease into DDNS / SharedLease.
        /// On failure (lease lost, carrier down) the next
        /// priority takes over. Single-WAN deployments don't need
        /// to set this — default 100 covers every one-WAN case.
        #[serde(default = "default_wan_priority")]
        priority: u32,
        /// Optional ICMP probe target for active health checks.
        /// When set, oxwrtd pings this address through the WAN's
        /// iface every `probe_interval_s` seconds (default 5);
        /// a lost probe marks the WAN unhealthy regardless of the
        /// lease state. Covers the "lease valid but upstream router
        /// is dead" case that pure-lease health misses. None =
        /// lease-state alone decides health.
        #[serde(default)]
        probe_target: Option<std::net::IpAddr>,
    },
    Lan {
        name: String,
        bridge: String,
        #[serde(default)]
        members: Vec<String>,
        address: Ipv4Addr,
        prefix: u8,
        /// Static IPv6 address to assign to the bridge. Typically a
        /// ULA (fd00::/8) for isolated setups, or a static v6 from
        /// the ISP. Ignored when DHCPv6-PD is active AND
        /// `ipv6_subnet_id` is set — the delegated prefix's
        /// per-subnet /64 takes precedence. Paired with
        /// `ipv6_prefix`.
        #[serde(default)]
        ipv6_address: Option<Ipv6Addr>,
        /// IPv6 prefix length for `ipv6_address`. Defaults to 64.
        #[serde(default)]
        ipv6_prefix: Option<u8>,
        /// Subnet identifier for DHCPv6-PD slicing. When the WAN
        /// has `ipv6_pd=true` and acquires a delegated prefix, each
        /// LAN/Simple with a subnet_id gets `<prefix>:{subnet_id:x}::1/64`.
        /// Operator picks the ids (0, 1, 2, ...); for a /56
        /// delegation that's up to 256 networks (8 bits of room).
        #[serde(default)]
        ipv6_subnet_id: Option<u16>,
    },
    Simple {
        name: String,
        iface: String,
        address: Ipv4Addr,
        prefix: u8,
        #[serde(default)]
        ipv6_address: Option<Ipv6Addr>,
        #[serde(default)]
        ipv6_prefix: Option<u8>,
        #[serde(default)]
        ipv6_subnet_id: Option<u16>,
        /// 802.1Q VLAN id (1..=4094). When set together with
        /// `vlan_parent`, oxwrtd creates `<vlan_parent>.<vlan>` as a
        /// VLAN sub-iface at boot and assigns `address`/`prefix` on
        /// the resulting iface (instead of on `iface` directly). The
        /// `iface` field in this case should name the VLAN sub-iface
        /// (e.g. "eth0.10") — validate.rs enforces the convention.
        /// None = untagged (classic behavior).
        #[serde(default)]
        vlan: Option<u16>,
        /// Parent iface for the VLAN. Required when `vlan` is set;
        /// rejected at validate-time when `vlan` is None. Splitting
        /// this field from `iface` (rather than inferring the parent
        /// from the dot notation) lets operators name VLAN sub-ifaces
        /// anything they want.
        #[serde(default)]
        vlan_parent: Option<String>,
    },
}

impl Network {
    /// The user-visible name of this network (e.g. "wan", "lan", "guest").
    pub fn name(&self) -> &str {
        match self {
            Network::Wan { name, .. }
            | Network::Lan { name, .. }
            | Network::Simple { name, .. } => name,
        }
    }

    /// The kernel interface name: `iface` for WAN/Simple, `bridge` for LAN.
    pub fn iface(&self) -> &str {
        match self {
            Network::Wan { iface, .. } | Network::Simple { iface, .. } => iface,
            Network::Lan { bridge, .. } => bridge,
        }
    }

    /// IPv6 (address, prefix) if declared. Defaults the prefix to 64
    /// when the operator omits it but supplies an address — the
    /// SLAAC convention, and the only length the kernel accepts for
    /// the RA-advertised prefix on a LAN.
    pub fn ipv6(&self) -> Option<(Ipv6Addr, u8)> {
        let (addr, prefix) = match self {
            Network::Lan {
                ipv6_address,
                ipv6_prefix,
                ..
            }
            | Network::Simple {
                ipv6_address,
                ipv6_prefix,
                ..
            } => (ipv6_address.as_ref()?, *ipv6_prefix),
            Network::Wan { .. } => return None,
        };
        Some((*addr, prefix.unwrap_or(64)))
    }

    /// DHCPv6-PD subnet id if declared. Combined with a delegated
    /// prefix, yields the per-network /64.
    pub fn ipv6_subnet_id(&self) -> Option<u16> {
        match self {
            Network::Lan { ipv6_subnet_id, .. } | Network::Simple { ipv6_subnet_id, .. } => {
                *ipv6_subnet_id
            }
            Network::Wan { .. } => None,
        }
    }
}

impl Config {
    /// Find the first WAN network (for DHCP client, default route, etc.).
    /// On multi-WAN deployments this returns the lowest-priority
    /// entry, which matches the failover convention: lowest number
    /// wins by default. Callers that want the actual runtime-active
    /// WAN should use the failover coordinator's `active_wan`
    /// signal instead — this is just "what the config asks to be
    /// primary before any probes run."
    pub fn primary_wan(&self) -> Option<&Network> {
        self.wans_by_priority().into_iter().next()
    }

    /// All WAN entries, sorted by `priority` ascending (lowest =
    /// highest preference, iproute2 convention). Ties break on
    /// insertion order. On a single-WAN config this is just
    /// `vec![primary_wan()]`; on multi-WAN it's the failover order
    /// the coordinator will walk.
    pub fn wans_by_priority(&self) -> Vec<&Network> {
        let mut wans: Vec<&Network> = self
            .networks
            .iter()
            .filter(|n| matches!(n, Network::Wan { .. }))
            .collect();
        wans.sort_by_key(|n| match n {
            Network::Wan { priority, .. } => *priority,
            _ => u32::MAX,
        });
        wans
    }

    /// Read the priority from a Network::Wan; useful for sorting
    /// per-WAN lease maps or Status RPC entries.
    pub fn wan_priority(net: &Network) -> u32 {
        match net {
            Network::Wan { priority, .. } => *priority,
            _ => u32::MAX,
        }
    }

    /// Find the first LAN network.
    pub fn lan(&self) -> Option<&Network> {
        self.networks
            .iter()
            .find(|n| matches!(n, Network::Lan { .. }))
    }

    /// Find a network by name.
    pub fn network(&self, name: &str) -> Option<&Network> {
        self.networks.iter().find(|n| n.name() == name)
    }
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

/// A single WAN-side port forward. Expanded at install time into
/// (a) a prerouting DNAT rule keyed on the source zone's iface and
/// the external port, plus (b) a FORWARD accept that lets the
/// post-DNAT packet cross into the dest network. Owning both halves
/// in one entry means a port-forward can't be half-configured.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortForward {
    pub name: String,
    pub proto: Proto,
    /// External port on the source zone (usually WAN).
    pub external_port: u16,
    /// Internal destination as "ip:port" — same shape as
    /// `Rule::dnat_target`. The internal port may differ from the
    /// external port (e.g. expose :80 → internal :8080).
    pub internal: String,
    /// Source zone the forward is exposed on. Defaults to "wan".
    #[serde(default = "default_wan_src")]
    pub src: String,
    /// Destination zone (the zone containing the internal IP). If
    /// omitted, the installer auto-detects by matching the internal
    /// IP against LAN/Simple network subnets. Explicit wins when
    /// a host sits on multiple overlapping subnets.
    #[serde(default)]
    pub dest: Option<String>,
}

fn default_wan_src() -> String {
    "wan".to_string()
}

/// A WireGuard server interface declaration. One entry → one wg iface
/// (typically "wg0") hosting multiple peers. The iface is brought up
/// by the netdev init step using the `wg` userspace tool; firewall
/// policy lives in `[[firewall.zones]]` keyed on the iface name
/// (declare a matching `[[networks]] type=simple iface=wg0` to expose
/// the wg0 address to routes + zone enumeration).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Wireguard {
    /// Unique name for CRUD + config references; also the kernel
    /// iface name unless `iface` is set explicitly.
    pub name: String,
    /// Kernel iface name (e.g. "wg0"). Defaults to `name`.
    #[serde(default)]
    pub iface: Option<String>,
    /// UDP port to bind on. Inbound traffic on the WAN iface to this
    /// port must be accepted by `[[firewall.rules]]` for the tunnel
    /// to establish — no magic hole-punch here.
    pub listen_port: u16,
    /// Path to the server's 32-byte Curve25519 private key (base64
    /// or raw 32 bytes — the installer accepts both, writing back
    /// in whichever was found). Auto-generated on first boot if
    /// missing, assuming the parent dir exists and is writable.
    #[serde(default = "default_wg_key_path")]
    pub key_path: String,
    /// Known peers. Add/remove via `oxctl wg-peer` RPC; this list is
    /// the canonical source of truth (persisted in oxwrt.toml).
    #[serde(default)]
    pub peers: Vec<WireguardPeer>,
}

fn default_wg_key_path() -> String {
    "/etc/oxwrt/wg0.key".to_string()
}

/// A single WireGuard peer (client). Keyed by `name` for CRUD; the
/// pubkey is the cryptographic identity. `allowed_ips` is a comma-
/// separated list of CIDRs that source-route through the tunnel
/// (conventionally a single /32 per client for roadwarrior setups).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireguardPeer {
    pub name: String,
    /// Base64-encoded Curve25519 public key (44 chars). Validated
    /// at CRUD add-time via the wg tool's parser so a typo here
    /// fails fast, not silently at install time.
    pub pubkey: String,
    /// CIDR list the peer is allowed to source from, comma-separated.
    /// Example: "10.8.0.2/32" for a single-client roadwarrior, or
    /// "10.8.0.0/24,192.168.100.0/24" for site-to-site.
    pub allowed_ips: String,
    /// Optional 32-byte preshared symmetric key (base64). Adds a
    /// second layer of post-quantum-ish security — not required
    /// for a working tunnel.
    #[serde(default)]
    pub preshared_key: Option<String>,
    /// Optional endpoint for dialing this peer (site-to-site only).
    /// Roadwarrior clients connect TO the server, so they leave
    /// this empty — the server learns the client's address at
    /// handshake time.
    #[serde(default)]
    pub endpoint: Option<String>,
    /// Keepalive interval in seconds. 25 is the canonical "NAT
    /// keepalive" value (keeps NAT mappings alive through most
    /// consumer routers). 0 / None = disabled.
    #[serde(default)]
    pub persistent_keepalive: Option<u16>,
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

/// WAN-mode configuration, flattened into the `Network::Wan` variant.
/// The `mode` tag selects between DHCP, static, and PPPoE.
/// Smart Queue Management (SQM) configuration for a WAN iface.
///
/// Today only the CAKE qdisc is supported — it's the Linux default
/// for bufferbloat mitigation and handles both shaping + fair-
/// queueing in one box. Upload bandwidth is shaped on eth1's egress
/// directly; download is shaped on a per-WAN IFB iface that we
/// mirror eth1's ingress to (standard Linux pattern — ingress qdiscs
/// can't shape, only egress can, so we redirect).
///
/// Bandwidths are in kilobits per second (kbit). Set either or both;
/// unset direction = unshaped. A typical home cable link might set
/// bandwidth_up_kbps = 18_000 (about 10% below the 20 Mbps uplink)
/// and bandwidth_down_kbps = 180_000 (10% below a 200 Mbps downlink)
/// — leaving headroom is what prevents the ISP's own queue from
/// filling up.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqmConfig {
    /// Egress-direction shaping rate in kbit/s. None = unshaped.
    #[serde(default)]
    pub bandwidth_up_kbps: Option<u32>,
    /// Ingress-direction shaping rate in kbit/s. Applied to an
    /// IFB iface fed by mirrored eth1 ingress. None = unshaped.
    #[serde(default)]
    pub bandwidth_down_kbps: Option<u32>,
    /// Extra `tc qdisc add ... cake` arguments appended verbatim to
    /// the command line. Useful for tuning (`docsis`, `ethernet`,
    /// `flows`, `nat`, `rtt Nms`, etc.) without us re-exposing every
    /// CAKE knob as a typed field. Example: `"besteffort ethernet"`.
    #[serde(default)]
    pub extra_args: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "lowercase")]
pub enum WanConfig {
    Dhcp,
    Static {
        address: Ipv4Addr,
        prefix: u8,
        gateway: Ipv4Addr,
        #[serde(default)]
        dns: Vec<IpAddr>,
    },
    Pppoe {
        username: String,
        password: String,
    },
}

/// Per-phy radio configuration. Maps to hostapd's phy-level options
/// (hw_mode, channel, country_code, HT/VHT/HE capability lists, etc.).
/// All options beyond `phy`, `band`, `channel` are optional; omitted
/// fields get sensible defaults from `wifi::build_hostapd_conf` based
/// on `band`. The `extra` field accepts raw hostapd.conf lines for
/// options not surfaced as typed fields.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Radio {
    pub phy: String,
    #[serde(default)]
    pub band: String,
    pub channel: u16,
    #[serde(default)]
    pub disabled: bool,

    // ── phy-level hostapd options ──
    /// ISO 3166-1 two-letter country code. Required for DFS channels
    /// and for correct regulatory power limits. Default "US".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country_code: Option<String>,
    /// Bracketed HT capability list, e.g. "[HT40+][SHORT-GI-40]".
    /// If unset, a band-appropriate default is emitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ht_capab: Option<String>,
    /// Bracketed VHT capability list (5 GHz only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vht_capab: Option<String>,
    /// Explicit VHT center channel (overrides auto-derivation from
    /// `channel`). Only applies on 5 GHz.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vht_oper_centr_freq_seg0_idx: Option<u16>,
    /// 0 = 20/40, 1 = 80, 2 = 160, 3 = 80+80. Default 1 on 5 GHz.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vht_oper_chwidth: Option<u8>,
    /// HE (Wi-Fi 6) center channel override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub he_oper_centr_freq_seg0_idx: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub he_oper_chwidth: Option<u8>,
    /// Explicit toggles for 802.11n/ac/ax. When unset, defaults are:
    /// 2g → n=true, ac=false, ax=true ; 5g → n=true, ac=true, ax=true.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ieee80211n: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ieee80211ac: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ieee80211ax: Option<bool>,
    /// Regulatory-domain announce (802.11d). Default on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ieee80211d: Option<bool>,
    /// Regulatory DFS/TPC (802.11h). Default on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ieee80211h: Option<bool>,
    /// Beacon interval in TU (1024 µs). Hostapd default 100.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub beacon_int: Option<u16>,
    /// DTIM period in beacons. Hostapd default 2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dtim_period: Option<u16>,
    /// Escape hatch: raw hostapd.conf lines appended verbatim to the
    /// phy-level section. Use for options not surfaced as typed fields
    /// (e.g. experimental caps, vendor-specific knobs).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra: Vec<String>,
}

/// One SSID/VAP. Maps to hostapd's BSS-level options. `radio` and
/// `network` are references; everything else is optional with defaults
/// derived from `security`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
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

    // ── BSS-level hostapd options ──
    /// Override the bridge this BSS joins. Default is the LAN bridge.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bridge: Option<String>,
    /// Override key management (e.g. "WPA-PSK SAE"). Unset → derived
    /// from `security`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wpa_key_mgmt: Option<String>,
    /// Pairwise cipher list. Default "CCMP".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rsn_pairwise: Option<String>,
    /// 802.11w / Management Frame Protection. 0=disabled, 1=optional,
    /// 2=required. Unset → derived (SAE→2, others→1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ieee80211w: Option<u8>,
    /// SAE requires MFP. Unset → true for SAE-capable security modes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sae_require_mfp: Option<bool>,
    /// 0 = open network, 1 = MAC allow list, 2 = MAC deny list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub macaddr_acl: Option<u8>,
    /// Authentication algorithms bitmask. 1=open, 2=shared, 3=both.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_algs: Option<u8>,
    /// Client-to-client isolation on this BSS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ap_isolate: Option<bool>,
    /// Max associated stations. Hostapd default 2007.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_num_sta: Option<u16>,
    /// 802.11 QoS / WMM on. Hostapd default 1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wmm_enabled: Option<bool>,
    /// Fast BSS transition (802.11r) — requires mobility domain setup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ft_over_ds: Option<bool>,
    /// SAE PWE method. 0=hunting-and-pecking, 1=H2E, 2=both.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sae_pwe: Option<u8>,
    /// Escape hatch: raw hostapd.conf lines appended verbatim to the
    /// BSS section. Use for any option not surfaced above.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra: Vec<String>,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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

/// A dynamic-DNS entry. One entry → one (provider, domain, credential)
/// triple. The `provider` tag selects which update URL + auth scheme
/// the runtime uses; other fields are provider-specific (see each
/// variant's doc).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "provider", rename_all = "lowercase")]
pub enum Ddns {
    /// DuckDNS — a free subdomain-on-duckdns.org provider. Update
    /// API is a single GET: https://www.duckdns.org/update?domains=
    /// {domain}&token={token}&ip={ip}
    Duckdns {
        /// Unique tag for CRUD + logs (not used in the request).
        name: String,
        /// Bare subdomain — "myrouter" for myrouter.duckdns.org.
        /// Multiple comma-separated subdomains are allowed by the
        /// provider; we pass the string through verbatim.
        domain: String,
        /// DuckDNS account token (UUID-style string).
        token: String,
    },
    /// Cloudflare — PUT /zones/{zone_id}/dns_records/{record_id} with
    /// Bearer token auth. The operator is expected to have created
    /// the A record once via the dashboard (or API); we only rotate
    /// its `content` as the WAN IP changes.
    Cloudflare {
        name: String,
        zone_id: String,
        record_id: String,
        /// FQDN of the A record — used verbatim as the PUT body's
        /// `name` field. Cloudflare requires this even on the
        /// record-specific PUT route to protect against typos.
        domain: String,
        /// API token with Zone.DNS:Edit scope for `zone_id`.
        api_token: String,
        /// TTL in seconds. 60 is Cloudflare's minimum on most plans.
        #[serde(default = "default_cf_ttl")]
        ttl: u32,
    },
}

fn default_cf_ttl() -> u32 {
    60
}

impl Ddns {
    /// Name tag — used in logs + CRUD. All variants carry it.
    pub fn name(&self) -> &str {
        match self {
            Ddns::Duckdns { name, .. } | Ddns::Cloudflare { name, .. } => name,
        }
    }
}

impl Wireguard {
    /// Render this server + its peers into the text format consumed by
    /// `wg setconf <iface>`. Does NOT include the PrivateKey line —
    /// the caller wires that in from disk. Separating keeps this fn
    /// pure + unit-testable without touching a real key on disk.
    ///
    /// The shape:
    ///   [Interface]
    ///   ListenPort = 51820
    ///   PrivateKey = <filled by caller>
    ///
    ///   [Peer]
    ///   PublicKey = ...
    ///   AllowedIPs = 10.8.0.2/32
    ///   (optional) PresharedKey / Endpoint / PersistentKeepalive
    ///
    /// Matches wg-quick(8)'s config format so an operator can also
    /// feed the output directly into the upstream tool if they want.
    pub fn render_config(&self, private_key_b64: &str) -> String {
        use std::fmt::Write as _;
        let mut s = String::new();
        writeln!(s, "[Interface]").unwrap();
        writeln!(s, "ListenPort = {}", self.listen_port).unwrap();
        writeln!(s, "PrivateKey = {}", private_key_b64).unwrap();
        for peer in &self.peers {
            writeln!(s).unwrap();
            writeln!(s, "[Peer]").unwrap();
            writeln!(s, "# {}", peer.name).unwrap();
            writeln!(s, "PublicKey = {}", peer.pubkey).unwrap();
            writeln!(s, "AllowedIPs = {}", peer.allowed_ips).unwrap();
            if let Some(psk) = &peer.preshared_key {
                writeln!(s, "PresharedKey = {}", psk).unwrap();
            }
            if let Some(ep) = &peer.endpoint {
                writeln!(s, "Endpoint = {}", ep).unwrap();
            }
            if let Some(ka) = peer.persistent_keepalive {
                if ka > 0 {
                    writeln!(s, "PersistentKeepalive = {}", ka).unwrap();
                }
            }
        }
        s
    }
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
    /// Path is relative to `CARGO_MANIFEST_DIR` (= `crates/oxwrt-api/`)
    /// so this works regardless of where `cargo test` is invoked from.
    #[test]
    fn example_config_parses() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../config/oxwrt.toml");
        let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
        let cfg: Config = toml::from_str(&text).unwrap_or_else(|e| panic!("parse {path}: {e}"));

        // A handful of spot checks that double as documentation:
        // future field additions can extend the example TOML AND the
        // assertions here without worrying about redundant coverage.
        assert_eq!(cfg.hostname, "flint2");
        assert_eq!(cfg.timezone.as_deref(), Some("Europe/Berlin"));
        // 4 networks: wan, lan, guest, iot
        assert_eq!(cfg.networks.len(), 4);
        assert!(cfg.primary_wan().is_some());
        assert!(cfg.lan().is_some());
        assert_eq!(cfg.lan().unwrap().iface(), "br-lan");
        assert_eq!(cfg.network("guest").unwrap().name(), "guest");
        assert_eq!(cfg.firewall.zones.len(), 3);
        assert_eq!(cfg.firewall.zones[0].name, "lan");
        assert_eq!(cfg.firewall.zones[2].name, "wan");
        assert!(cfg.firewall.zones[2].masquerade);
        assert!(!cfg.firewall.rules.is_empty());
        assert_eq!(cfg.wifi.len(), 2);
        assert_eq!(cfg.wifi[0].ssid, "oxwrt");
        assert_eq!(cfg.wifi[0].network, "lan");
        // 6 services now: dns, dhcp, hostapd-5g, hostapd-2g, corerad,
        // ntp, debug-ssh. Count might drift as bring-up progresses;
        // keep this loose check.
        assert!(cfg.services.len() >= 4);

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

[[networks]]
name = "wan"
type = "wan"
iface = "eth0"
mode = "dhcp"

[[networks]]
name = "lan"
type = "lan"
bridge = "br-lan"
members = ["eth1"]
address = "192.168.50.1"
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
        assert_eq!(lan.default_input, super::ChainPolicy::Accept);
        assert!(!lan.masquerade);
        let wan = &cfg.firewall.zones[1];
        assert_eq!(wan.name, "wan");
        assert!(wan.masquerade);

        assert_eq!(cfg.firewall.rules.len(), 3);
        let ct = &cfg.firewall.rules[0];
        assert_eq!(ct.ct_state, vec!["established", "related"]);
        assert_eq!(ct.action, super::Action::Accept);
        let dhcp = &cfg.firewall.rules[1];
        assert_eq!(dhcp.src.as_deref(), Some("guest"));
        assert!(matches!(dhcp.dest_port, Some(super::PortSpec::List(ref v)) if v == &[67, 68]));
        let dnat = &cfg.firewall.rules[2];
        assert_eq!(dnat.action, super::Action::Dnat);
        assert_eq!(dnat.dnat_target.as_deref(), Some("10.53.0.2:15353"));
    }

    /// WireGuard section parses, peer list defaults, `iface` defaults
    /// to name when absent, optional peer fields stay None.
    #[test]
    fn wireguard_section_roundtrip() {
        let toml_text = r#"
hostname = "r"

[[networks]]
name = "wan"
type = "wan"
iface = "eth0"
mode = "dhcp"

[[networks]]
name = "wg"
type = "simple"
iface = "wg0"
address = "10.8.0.1"
prefix = 24

[control]
listen = ["[::1]:51820"]
authorized_keys = "/x"

[[wireguard]]
name = "wg0"
listen_port = 51820

[[wireguard.peers]]
name = "alice"
pubkey = "aXlSNXL0yz8P6Fkb6Xa9W3Fkq7cLKgqx7qVqEHS9f00="
allowed_ips = "10.8.0.2/32"

[[wireguard.peers]]
name = "bob"
pubkey = "bbbbbFkq7cLKgqx7qVqEHS9f00NL0yz8P6Fkb6Xa9W3="
allowed_ips = "10.8.0.3/32"
persistent_keepalive = 25
"#;
        let cfg: Config = toml::from_str(toml_text).expect("parse");
        assert_eq!(cfg.wireguard.len(), 1);
        let wg = &cfg.wireguard[0];
        assert_eq!(wg.name, "wg0");
        assert!(wg.iface.is_none(), "iface defaults to None → use name");
        assert_eq!(wg.listen_port, 51820);
        assert_eq!(wg.key_path, "/etc/oxwrt/wg0.key", "default key_path");
        assert_eq!(wg.peers.len(), 2);
        assert_eq!(wg.peers[0].name, "alice");
        assert!(wg.peers[0].preshared_key.is_none());
        assert_eq!(wg.peers[1].persistent_keepalive, Some(25));

        // render_config output has the expected shape.
        let rendered = wg.render_config("SERVER_PRIVKEY_PLACEHOLDER");
        assert!(rendered.starts_with("[Interface]\n"));
        assert!(rendered.contains("ListenPort = 51820"));
        assert!(rendered.contains("PrivateKey = SERVER_PRIVKEY_PLACEHOLDER"));
        assert!(rendered.contains("# alice\n"));
        assert!(rendered.contains("AllowedIPs = 10.8.0.2/32"));
        assert!(rendered.contains("PersistentKeepalive = 25"));
        // no persistent_keepalive on alice, no line
        let alice_block = rendered.split("# alice").nth(1).unwrap();
        let alice_block = alice_block.split("[Peer]").next().unwrap_or(alice_block);
        assert!(
            !alice_block.contains("PersistentKeepalive"),
            "alice had no PersistentKeepalive, line must not appear"
        );
    }

    /// Port-forward section parses, applies serde defaults (`src = "wan"`
    /// when absent, `dest = None`), and preserves explicit overrides.
    #[test]
    fn port_forward_section_roundtrip() {
        let toml_text = r#"
hostname = "r"

[[networks]]
name = "wan"
type = "wan"
iface = "eth0"
mode = "dhcp"

[[networks]]
name = "lan"
type = "lan"
bridge = "br-lan"
members = []
address = "192.168.50.1"
prefix = 24

[control]
listen = ["[::1]:51820"]
authorized_keys = "/x"

# Minimal: defaults kick in (src=wan, dest=auto-detect).
[[port_forwards]]
name = "minecraft"
proto = "tcp"
external_port = 25565
internal = "192.168.50.50:25565"

# Explicit overrides.
[[port_forwards]]
name = "ssh-to-dmz"
proto = "tcp"
external_port = 2222
internal = "10.50.0.5:22"
src = "wan"
dest = "dmz"
"#;
        let cfg: Config = toml::from_str(toml_text).expect("parse");
        assert_eq!(cfg.port_forwards.len(), 2);

        let mc = &cfg.port_forwards[0];
        assert_eq!(mc.name, "minecraft");
        assert_eq!(mc.proto, Proto::Tcp);
        assert_eq!(mc.external_port, 25565);
        assert_eq!(mc.internal, "192.168.50.50:25565");
        assert_eq!(mc.src, "wan", "serde default applied");
        assert!(mc.dest.is_none(), "no dest → auto-detect at install");

        let ssh = &cfg.port_forwards[1];
        assert_eq!(ssh.dest.as_deref(), Some("dmz"));
    }

    // ── shipped-service-config regression tests ─────────────────────
    //
    // These guard the three service config files we ship under
    // config/services/{dns,ntp,dhcp}/ against silently regressing to
    // formats that crash-loop the service at runtime. Each test
    // captures a concrete bug we hit today during live bring-up:
    //
    //   - named.toml shipped `zone_type = "Forward"` (removed from
    //     hickory-dns 0.25 which now accepts only Primary/Secondary/
    //     External) and `protocol = "tls"` under name_servers (not a
    //     valid variant in 0.25).
    //   - coredhcp.yml shipped `lease_time: 3600` which coredhcp
    //     rejects with "invalid duration: 3600" — the plugin wants a
    //     Go time.Duration string like "12h".
    //
    // No crate-level parser checks here (would require heavy dev-deps
    // on hickory-server / ntpd / a Go-parser bridge); instead we do
    // cheap regex-ish string checks for the specific known-bad
    // tokens. That's narrower than a full parse but keeps the test
    // fast and dependency-free, and any future bug class can be
    // added by dropping another assertion here.

    fn read_service_config(rel: &str) -> String {
        let path = format!(
            "{}/../../config/services/{}",
            env!("CARGO_MANIFEST_DIR"),
            rel
        );
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"))
    }

    #[test]
    fn named_toml_avoids_known_hickory025_breakers() {
        let text = read_service_config("dns/named.toml");
        // First line of defense: must be valid TOML.
        let _: toml::Value =
            toml::from_str(&text).unwrap_or_else(|e| panic!("named.toml not valid TOML: {e}"));
        // hickory 0.25 removed `Forward` as a zone_type variant.
        assert!(
            !text.contains("zone_type = \"Forward\""),
            "named.toml uses `zone_type = \"Forward\"` which hickory 0.25 \
             rejects; use `External` for forwarding-only zones"
        );
        // hickory 0.25 removed the `tls` protocol string on name_servers.
        assert!(
            !text.contains("protocol = \"tls\""),
            "named.toml uses `protocol = \"tls\"` on a name_server which \
             hickory 0.25 no longer accepts; use `udp` or `tcp`, or move \
             to a dedicated `[[zones.stores]] type = \"tls\"` store when \
             we pin a newer hickory"
        );
        // Must declare at least one upstream (otherwise forwarding zone
        // has nowhere to send queries).
        assert!(
            text.contains("[[zones.stores.name_servers]]") || text.contains("name_servers = ["),
            "named.toml must declare at least one upstream name_server"
        );
    }

    #[test]
    fn coredhcp_yml_lease_time_is_duration_not_integer() {
        let text = read_service_config("dhcp/coredhcp.yml");
        // A `lease_time: <integer>` line is the bug: coredhcp wants a
        // Go time.Duration string ("12h", "1h30m", etc.), not a raw
        // number.
        //
        // Regex-free check: split on newlines, find any line where
        // the trimmed text is `- lease_time: <digits>` with no unit
        // suffix. This catches `- lease_time: 3600` but not
        // `- lease_time: 12h` or `lease_time: 1h`.
        for line in text.lines() {
            let t = line.trim();
            if let Some(rest) = t.strip_prefix("- lease_time:") {
                let val = rest.trim();
                assert!(
                    val.is_empty() || !val.chars().all(|c| c.is_ascii_digit()),
                    "coredhcp.yml has `{t}` with a bare integer; use a Go \
                     time.Duration string like \"12h\" instead — coredhcp \
                     rejects integers with `invalid duration: ...`"
                );
            }
        }
        // Also verify addresses point at the configured LAN subnet.
        // 192.168.50.x is the current LAN (changed from 192.168.1.x
        // after a subnet collision with upstream; 192.168.8.x was the
        // original GL.iNet shipped default we no longer use).
        assert!(
            !text.contains("192.168.8."),
            "coredhcp.yml references 192.168.8.x — stale GL.iNet default"
        );
        assert!(
            text.contains("192.168.50."),
            "coredhcp.yml doesn't reference 192.168.50.x — out of sync with \
             config/oxwrt.toml LAN definition"
        );
    }

    #[test]
    fn ntp_toml_is_valid_toml() {
        let text = read_service_config("ntp/ntp.toml");
        let _: toml::Value =
            toml::from_str(&text).unwrap_or_else(|e| panic!("ntp.toml not valid TOML: {e}"));
        // Minimum: at least one [[source]] block, otherwise ntpd
        // doesn't know who to sync against.
        assert!(
            text.contains("[[source]]"),
            "ntp.toml must declare at least one [[source]] pool/server"
        );
    }

    // ── Schema roundtrip tests for the four new features ───────────
    //
    // Each test parses a minimal TOML fragment into the relevant
    // struct, asserts required fields land where expected and that
    // documented defaults kick in when optional fields are omitted.
    // These are narrower than example_config_parses — catches
    // serde-attribute regressions (wrong rename, dropped default,
    // type mismatch) even when the example config happens to
    // exercise the wrong path.

    // --- Route ---

    #[test]
    fn route_minimal_fields_default_metric_and_no_gateway() {
        let toml = r#"
dest = "10.20.0.0"
prefix = 16
iface = "wg0"
"#;
        let r: Route = toml::from_str(toml).unwrap();
        assert_eq!(r.dest, std::net::Ipv4Addr::new(10, 20, 0, 0));
        assert_eq!(r.prefix, 16);
        assert_eq!(r.iface, "wg0");
        assert_eq!(r.gateway, None);
        assert_eq!(r.metric, 1024, "default_route_metric");
    }

    #[test]
    fn route_with_gateway_and_metric_roundtrips() {
        let toml = r#"
dest = "192.168.100.0"
prefix = 24
gateway = "10.8.0.1"
iface = "wg0"
metric = 200
"#;
        let r: Route = toml::from_str(toml).unwrap();
        assert_eq!(r.gateway, Some(std::net::Ipv4Addr::new(10, 8, 0, 1)));
        assert_eq!(r.metric, 200);
    }

    #[test]
    fn route_rejects_missing_iface() {
        let toml = r#"
dest = "10.20.0.0"
prefix = 16
"#;
        let err = toml::from_str::<Route>(toml).unwrap_err().to_string();
        assert!(err.contains("iface"), "err should mention iface: {err}");
    }

    #[test]
    fn route6_minimal_fields_default_metric_and_no_gateway() {
        let toml = r#"
dest = "2001:db8::"
prefix = 32
iface = "wg0"
"#;
        let r: Route6 = toml::from_str(toml).unwrap();
        assert_eq!(r.dest, "2001:db8::".parse::<std::net::Ipv6Addr>().unwrap());
        assert_eq!(r.prefix, 32);
        assert_eq!(r.iface, "wg0");
        assert_eq!(r.gateway, None);
        assert_eq!(r.metric, 1024);
    }

    #[test]
    fn route6_with_gateway_and_metric_roundtrips() {
        let toml = r#"
dest = "fd00:beef::"
prefix = 48
gateway = "fe80::1"
iface = "wg0"
metric = 200
"#;
        let r: Route6 = toml::from_str(toml).unwrap();
        assert_eq!(r.gateway, Some("fe80::1".parse::<std::net::Ipv6Addr>().unwrap()));
        assert_eq!(r.metric, 200);
    }

    #[test]
    fn route6_list_parses_and_routes_list_independent() {
        // Mixing [[routes]] + [[routes6]] in one doc must keep them
        // in separate collections — no cross-contamination from
        // serde's table-array handling.
        let toml = r#"
[[routes]]
dest = "10.0.0.0"
prefix = 8
iface = "wg0"

[[routes6]]
dest = "2001:db8::"
prefix = 32
iface = "wg0"
"#;
        #[derive(serde::Deserialize)]
        struct Wrapper {
            routes: Vec<Route>,
            routes6: Vec<Route6>,
        }
        let w: Wrapper = toml::from_str(toml).unwrap();
        assert_eq!(w.routes.len(), 1);
        assert_eq!(w.routes6.len(), 1);
    }

    #[test]
    fn route_eq_distinguishes_metric() {
        // The reconcile diff relies on PartialEq taking metric into
        // account — a metric change must be treated as a different
        // route so reload del+adds instead of silently leaving the
        // old kernel state.
        let a = Route {
            dest: "10.20.0.0".parse().unwrap(),
            prefix: 16,
            gateway: None,
            iface: "wg0".into(),
            metric: 100,
        };
        let mut b = a.clone();
        b.metric = 200;
        assert_ne!(a, b);
    }

    // --- Blocklist ---

    #[test]
    fn blocklist_minimal_defaults() {
        let toml = r#"
name = "firehol"
url = "https://example.com/list.txt"
"#;
        let b: Blocklist = toml::from_str(toml).unwrap();
        assert_eq!(b.name, "firehol");
        assert_eq!(b.refresh_seconds, 86400, "default = 24h");
        assert!(b.zones.is_empty(), "default = router-wide drop");
    }

    #[test]
    fn blocklist_zones_list_roundtrips() {
        let toml = r#"
name = "fh"
url = "http://x/"
refresh_seconds = 3600
zones = ["wan", "guest"]
"#;
        let b: Blocklist = toml::from_str(toml).unwrap();
        assert_eq!(b.refresh_seconds, 3600);
        assert_eq!(b.zones, vec!["wan".to_string(), "guest".to_string()]);
    }

    // --- UpnpConfig ---

    #[test]
    fn upnp_minimal_defaults() {
        let toml = r#"
wan = "eth1"
lan = "br-lan"
"#;
        let u: UpnpConfig = toml::from_str(toml).unwrap();
        assert_eq!(u.wan, "eth1");
        assert_eq!(u.lan, "br-lan");
        assert_eq!(u.min_port, 1024);
        assert_eq!(u.max_port, 65535);
        assert!(u.enable_natpmp);
    }

    #[test]
    fn upnp_explicit_overrides_apply() {
        let toml = r#"
wan = "ppp0"
lan = "br-lan"
min_port = 2000
max_port = 3000
enable_natpmp = false
"#;
        let u: UpnpConfig = toml::from_str(toml).unwrap();
        assert_eq!(u.min_port, 2000);
        assert_eq!(u.max_port, 3000);
        assert!(!u.enable_natpmp);
    }

    #[test]
    fn upnp_rejects_missing_wan_lan() {
        assert!(toml::from_str::<UpnpConfig>("").is_err(), "empty rejected");
        assert!(
            toml::from_str::<UpnpConfig>("wan = \"eth1\"\n").is_err(),
            "lan required"
        );
    }

    // --- Network::Simple VLAN fields ---

    #[test]
    fn simple_vlan_fields_roundtrip() {
        let toml = r#"
name = "voip"
type = "simple"
iface = "eth0.10"
address = "10.10.0.1"
prefix = 24
vlan = 10
vlan_parent = "eth0"
"#;
        let n: Network = toml::from_str(toml).unwrap();
        match n {
            Network::Simple {
                vlan,
                vlan_parent,
                address,
                ..
            } => {
                assert_eq!(vlan, Some(10));
                assert_eq!(vlan_parent.as_deref(), Some("eth0"));
                assert_eq!(address, std::net::Ipv4Addr::new(10, 10, 0, 1));
            }
            _ => panic!("expected Simple"),
        }
    }

    #[test]
    fn simple_without_vlan_defaults_to_none() {
        let toml = r#"
name = "guest"
type = "simple"
iface = "br-guest"
address = "10.99.0.1"
prefix = 24
"#;
        let n: Network = toml::from_str(toml).unwrap();
        match n {
            Network::Simple {
                vlan, vlan_parent, ..
            } => {
                assert_eq!(vlan, None);
                assert_eq!(vlan_parent, None);
            }
            _ => panic!("expected Simple"),
        }
    }

    // --- Config-level integration: every new field at once ---

    /// A single TOML document exercising routes + blocklists + upnp
    /// + a VLAN Simple network + metrics + wireguard. Confirms the
    /// four new top-level fields on Config don't interfere with
    /// each other under serde's flatten/default machinery — a
    /// regression here would mean a field collision (e.g. two
    /// `#[serde(default)]` optionals both matching an unknown key).
    #[test]
    fn config_all_new_features_together() {
        let toml = r#"
hostname = "combo"
timezone = "UTC"

[[networks]]
name = "wan"
type = "wan"
iface = "eth1"
mode = "dhcp"

[[networks]]
name = "lan"
type = "lan"
bridge = "br-lan"
address = "192.168.50.1"
prefix = 24

[[networks]]
name = "voip"
type = "simple"
iface = "eth0.10"
address = "10.10.0.1"
prefix = 24
vlan = 10
vlan_parent = "eth0"

[[routes]]
dest = "10.20.0.0"
prefix = 16
iface = "wg0"

[[blocklists]]
name = "fh"
url = "http://x/"

[[wireguard]]
name = "wg0"
listen_port = 51820

[upnp]
wan = "eth1"
lan = "br-lan"

[metrics]
listen = "192.168.50.1:9100"

[control]
listen = ["[::1]:51820"]
authorized_keys = "/etc/oxwrt/authorized_keys"
"#;
        let cfg: Config = toml::from_str(toml).unwrap_or_else(|e| panic!("parse: {e}"));
        assert_eq!(cfg.routes.len(), 1);
        assert_eq!(cfg.blocklists.len(), 1);
        assert_eq!(cfg.wireguard.len(), 1);
        assert!(cfg.upnp.is_some());
        assert!(cfg.metrics.is_some());
        // Confirm the VLAN Simple round-tripped through the full Config.
        let vlan_net = cfg
            .networks
            .iter()
            .find(|n| n.name() == "voip")
            .expect("voip network");
        match vlan_net {
            Network::Simple { vlan, .. } => assert_eq!(*vlan, Some(10)),
            _ => panic!("voip should be Simple"),
        }
    }
}
