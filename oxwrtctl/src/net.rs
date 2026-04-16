//! rtnetlink-driven link/addr programming + rustables-driven nftables.
//! No shelling out to `ip(8)` or `nft(8)` — everything is direct netlink.
//!
//! v0.1 scope (this landing):
//! - `Net` struct owns the rtnetlink handle and worker task.
//! - `bring_up(&Config)`: loopback up, `br-lan` bridge create/up, LAN address
//!   assigned, LAN members enslaved, WAN link up.
//! - `create_veth_pair(svc)`: host-side veth pair ready for container attach.
//! - `install_firewall(&Config)`: minimal inet nftables ruleset — INPUT drops
//!   by default, accepts established / lo / sQUIC control on LAN, FORWARD
//!   accepts, OUTPUT accepts.
//!
//! Deferred to a follow-up landing:
//! - NAT masquerade on WAN
//! - Per-service forward rules (LAN ↔ container netns)
//! - WAN DHCP client, route programming, PPPoE
//! - IPv6 (ICMPv6 RA, ND)

use std::net::{IpAddr, Ipv4Addr};

use futures_util::stream::TryStreamExt;
use rtnetlink::{Handle, LinkBridge, LinkUnspec, LinkVeth, new_connection};

use crate::config::{Config, Lan, Service, Wan};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("rtnetlink: {0}")]
    Rtnetlink(#[from] rtnetlink::Error),
    #[error("netlink socket: {0}")]
    Socket(#[from] std::io::Error),
    #[error("link {0} not found")]
    LinkNotFound(String),
    #[error("firewall: {0}")]
    Firewall(String),
}

/// Owns the rtnetlink handle and the background worker task that services it.
/// Dropping `Net` aborts the worker.
pub struct Net {
    handle: Handle,
    worker: tokio::task::JoinHandle<()>,
}

impl Net {
    pub fn new() -> Result<Self, Error> {
        let (connection, handle, _messages) = new_connection()?;
        let worker = tokio::spawn(async move {
            connection.await;
        });
        Ok(Self { handle, worker })
    }

    pub fn handle(&self) -> &Handle {
        &self.handle
    }

    pub async fn bring_up(&self, cfg: &Config) -> Result<(), Error> {
        self.up_link("lo").await?;
        self.setup_lan(&cfg.lan).await?;
        self.setup_wan(&cfg.wan).await?;
        Ok(())
    }

    async fn up_link(&self, name: &str) -> Result<(), Error> {
        let idx = self.link_index(name).await?;
        self.handle
            .link()
            .set(LinkUnspec::new_with_index(idx).up().build())
            .execute()
            .await?;
        Ok(())
    }

    async fn link_index(&self, name: &str) -> Result<u32, Error> {
        let mut stream = self
            .handle
            .link()
            .get()
            .match_name(name.to_string())
            .execute();
        match stream.try_next().await {
            Ok(Some(msg)) => Ok(msg.header.index),
            Ok(None) => Err(Error::LinkNotFound(name.to_string())),
            // RTM_GETLINK for a nonexistent name returns -ENODEV (19) rather
            // than an empty response. Map that to our LinkNotFound so callers
            // can use the match!() pattern.
            Err(e) if is_nodev(&e) => Err(Error::LinkNotFound(name.to_string())),
            Err(e) => Err(Error::Rtnetlink(e)),
        }
    }

    async fn setup_lan(&self, lan: &Lan) -> Result<(), Error> {
        if matches!(self.link_index(&lan.bridge).await, Err(Error::LinkNotFound(_))) {
            self.handle
                .link()
                .add(LinkBridge::new(&lan.bridge).build())
                .execute()
                .await?;
        }
        let bridge_idx = self.link_index(&lan.bridge).await?;

        self.handle
            .link()
            .set(LinkUnspec::new_with_index(bridge_idx).up().build())
            .execute()
            .await?;

        let addr_res = self
            .handle
            .address()
            .add(bridge_idx, IpAddr::V4(lan.address), lan.prefix)
            .execute()
            .await;
        if let Err(e) = addr_res {
            if !is_exists(&e) {
                return Err(e.into());
            }
            tracing::debug!(bridge = %lan.bridge, "lan address already present");
        }

        // Enslave LAN members to the bridge. Missing members are warned and
        // skipped — hardware may lack a given port, or the config may refer
        // to an interface that's renamed by the board-files.
        for member in &lan.members {
            let member_idx = match self.link_index(member).await {
                Ok(idx) => idx,
                Err(Error::LinkNotFound(_)) => {
                    tracing::warn!(iface = %member, "lan member not present — skipping");
                    continue;
                }
                Err(e) => return Err(e),
            };
            self.handle
                .link()
                .set(
                    LinkUnspec::new_with_index(member_idx)
                        .controller(bridge_idx)
                        .up()
                        .build(),
                )
                .execute()
                .await?;
        }
        Ok(())
    }

    async fn setup_wan(&self, wan: &Wan) -> Result<(), Error> {
        let iface = match wan {
            Wan::Dhcp { iface } => iface,
            Wan::Static { iface, .. } => iface,
            Wan::Pppoe { iface, .. } => iface,
        };
        self.up_link(iface).await?;

        // DHCP: wan_dhcp::acquire handles addressing.
        // Pppoe: not yet implemented, link-only.
        // Static: apply the configured address + default route here so a
        // static-WAN router actually comes up with the operator's
        // configured IP without needing a reload. EEXIST on address / route
        // is tolerated so re-running this is idempotent.
        if let Wan::Static {
            iface,
            address,
            prefix,
            gateway,
            ..
        } = wan
        {
            let idx = self.link_index(iface).await?;
            let add_res = self
                .handle
                .address()
                .add(idx, IpAddr::V4(*address), *prefix)
                .execute()
                .await;
            if let Err(e) = add_res {
                if !is_exists(&e) {
                    return Err(e.into());
                }
                tracing::debug!(%iface, %address, "static wan address already present");
            }
            // Default route via the configured gateway.
            let route = rtnetlink::RouteMessageBuilder::<std::net::Ipv4Addr>::new()
                .destination_prefix(std::net::Ipv4Addr::UNSPECIFIED, 0)
                .gateway(*gateway)
                .build();
            match self.handle.route().add(route).execute().await {
                Ok(()) => {
                    tracing::info!(%iface, %gateway, "static wan: default route installed");
                }
                Err(e) if is_exists(&e) => {
                    tracing::debug!(%iface, %gateway, "default route already present");
                }
                Err(e) => return Err(e.into()),
            }
            tracing::info!(%iface, %address, prefix = %prefix, "static wan: address applied");
        }
        Ok(())
    }

    /// Create a host-side veth pair for a service container. The peer end
    /// will later be moved into the container's network namespace by the
    /// supervisor (not yet wired). Returns `(host_end, peer_end)` names.
    pub async fn create_veth_pair(&self, svc_name: &str) -> Result<(String, String), Error> {
        let host_name = format!("veth-{svc_name}");
        let peer_name = format!("veth-{svc_name}-p");
        self.handle
            .link()
            .add(LinkVeth::new(&host_name, &peer_name).build())
            .execute()
            .await?;
        Ok((host_name, peer_name))
    }

    /// Full host-side veth setup: create the pair, assign `host_ip/prefix`
    /// to the host end, bring the host end up. Returns `(host_name, peer_name)`.
    /// Idempotent on repeat runs (`EEXIST` on address is swallowed).
    pub async fn setup_host_veth(
        &self,
        svc_name: &str,
        host_ip: Ipv4Addr,
        prefix: u8,
    ) -> Result<(String, String), Error> {
        let (host_name, peer_name) = self.create_veth_pair(svc_name).await?;

        let host_idx = self.link_index(&host_name).await?;

        match self
            .handle
            .address()
            .add(host_idx, IpAddr::V4(host_ip), prefix)
            .execute()
            .await
        {
            Ok(()) => {}
            Err(e) if is_exists(&e) => {
                tracing::debug!(iface = %host_name, "veth host ip already present");
            }
            Err(e) => return Err(e.into()),
        }

        self.handle
            .link()
            .set(LinkUnspec::new_with_index(host_idx).up().build())
            .execute()
            .await?;

        Ok((host_name, peer_name))
    }
}

impl Drop for Net {
    fn drop(&mut self) {
        self.worker.abort();
    }
}

fn is_exists(err: &rtnetlink::Error) -> bool {
    // rtnetlink 0.20 wraps the kernel's -errno in NetlinkError. EEXIST = 17
    // on Linux (all arches), and the kernel negates it before sending.
    netlink_errno(err) == Some(-17)
}

fn is_nodev(err: &rtnetlink::Error) -> bool {
    // ENODEV = 19. RTM_GETLINK with a name that doesn't exist returns this.
    netlink_errno(err) == Some(-19)
}

fn netlink_errno(err: &rtnetlink::Error) -> Option<i32> {
    if let rtnetlink::Error::NetlinkError(msg) = err {
        msg.code.map(|c| c.get())
    } else {
        None
    }
}

/// Enable IPv4 forwarding in the current netns. Idempotent — safe to call
/// more than once. Required for packets from service netns containers to
/// egress through the outer netns's upstream interface.
pub fn enable_ipv4_forwarding() -> Result<(), Error> {
    std::fs::write("/proc/sys/net/ipv4/ip_forward", "1\n")?;
    Ok(())
}

/// Install an unconditional IPv4 NAT postrouting MASQUERADE rule in its own
/// `ip oxwrt-nat` table. Rewrites src for every packet egressing the outer
/// netns so services in `Isolated` netns containers can reach upstream via
/// whatever physical/bridge interface the outer netns holds. Idempotent —
/// tears down any prior `oxwrt-nat` table before recreating.
pub fn install_nat_masquerade() -> Result<(), Error> {
    use rustables::expr::Masquerade;
    use rustables::{
        Batch, Chain, ChainPolicy, ChainType, Hook, HookClass, MsgType, ProtocolFamily, Rule,
        Table,
    };

    let mut batch = Batch::new();
    let table = Table::new(ProtocolFamily::Ipv4).with_name("oxwrt-nat");
    batch.add(&table, MsgType::Add);
    batch.add(&table, MsgType::Del);
    batch.add(&table, MsgType::Add);

    let postrouting = Chain::new(&table)
        .with_name("postrouting")
        .with_hook(Hook::new(HookClass::PostRouting, 100))
        .with_type(ChainType::Nat)
        .with_policy(ChainPolicy::Accept)
        .add_to_batch(&mut batch);

    Rule::new(&postrouting)
        .map_err(|e| Error::Firewall(e.to_string()))?
        .with_expr(Masquerade::default())
        .add_to_batch(&mut batch);

    batch.send().map_err(|e| Error::Firewall(e.to_string()))?;
    tracing::info!("nftables NAT MASQUERADE rule installed");
    Ok(())
}

/// A single DNAT rule: packets destined to `listen_addr:listen_port` (TCP
/// and UDP) are rewritten to `target_ip:target_port`. Used to expose an
/// isolated-netns service on a conventional LAN-facing port while the
/// container listens on an alternate one.
#[derive(Debug, Clone)]
pub struct DnatRule {
    pub listen_addr: Ipv4Addr,
    pub listen_port: u16,
    pub target_ip: Ipv4Addr,
    pub target_port: u16,
}

/// Install all DNAT rules as one atomic rustables batch into a dedicated
/// `ip oxwrt-dnat` NAT table. Two chains are installed per rule so that
/// both remote clients (prerouting hook) and the router's own local
/// processes (output hook) trigger the rewrite. Idempotent: tears down any
/// prior `oxwrt-dnat` table before recreating. No-op if `rules` is empty.
pub fn install_dnat_rules(rules: &[DnatRule]) -> Result<(), Error> {
    use rustables::expr::{Immediate, Nat, NatType, Register};
    use rustables::{
        Batch, Chain, ChainPolicy, ChainType, Hook, HookClass, MsgType, Protocol, ProtocolFamily,
        Rule, Table,
    };

    if rules.is_empty() {
        return Ok(());
    }

    let mut batch = Batch::new();
    let table = Table::new(ProtocolFamily::Ipv4).with_name("oxwrt-dnat");
    batch.add(&table, MsgType::Add);
    batch.add(&table, MsgType::Del);
    batch.add(&table, MsgType::Add);

    // PREROUTING catches packets arriving from elsewhere (LAN clients).
    // OUTPUT catches packets originated by local processes on the router
    // — DNAT in PREROUTING is never seen by the local path. We install
    // matching rules into both so the router itself resolves via its own
    // DNS service and regular LAN clients do the same.
    //
    // Priority -100 is the conventional "dstnat" priority in both chains.
    let prerouting = Chain::new(&table)
        .with_name("prerouting")
        .with_hook(Hook::new(HookClass::PreRouting, -100))
        .with_type(ChainType::Nat)
        .with_policy(ChainPolicy::Accept)
        .add_to_batch(&mut batch);

    let output = Chain::new(&table)
        .with_name("output")
        .with_hook(Hook::new(HookClass::Out, -100))
        .with_type(ChainType::Nat)
        .with_policy(ChainPolicy::Accept)
        .add_to_batch(&mut batch);

    for dnat in rules {
        for proto in [Protocol::TCP, Protocol::UDP] {
            for chain in [&prerouting, &output] {
                let ip_bytes = dnat.target_ip.octets().to_vec();
                let port_bytes = dnat.target_port.to_be_bytes().to_vec();
                let nat_expr = Nat::default()
                    .with_nat_type(NatType::DNat)
                    .with_family(ProtocolFamily::Ipv4)
                    .with_ip_register(Register::Reg1)
                    .with_port_register(Register::Reg2);

                Rule::new(chain)
                    .map_err(|e| Error::Firewall(e.to_string()))?
                    .daddr(IpAddr::V4(dnat.listen_addr))
                    .dport(dnat.listen_port, proto)
                    .with_expr(Immediate::new_data(ip_bytes, Register::Reg1))
                    .with_expr(Immediate::new_data(port_bytes, Register::Reg2))
                    .with_expr(nat_expr)
                    .add_to_batch(&mut batch);
            }
        }
    }

    batch.send().map_err(|e| Error::Firewall(e.to_string()))?;
    tracing::info!(count = rules.len(), "nftables DNAT ruleset installed");
    Ok(())
}

/// Install the baseline inet nftables ruleset. Synchronous: rustables's
/// `Batch::send()` does one blocking netlink round-trip. Safe to call from
/// an async context — the call finishes in microseconds.
pub fn install_firewall(cfg: &Config) -> Result<(), Error> {
    use rustables::{
        Batch, Chain, ChainPolicy, Hook, HookClass, MsgType, Protocol, ProtocolFamily, Rule, Table,
    };

    let mut batch = Batch::new();
    let table = Table::new(ProtocolFamily::Inet).with_name("oxwrt");

    // Tear down any existing ruleset from a previous run, then recreate.
    batch.add(&table, MsgType::Add);
    batch.add(&table, MsgType::Del);
    batch.add(&table, MsgType::Add);

    let input = Chain::new(&table)
        .with_name("input")
        .with_hook(Hook::new(HookClass::In, 0))
        .with_policy(ChainPolicy::Drop)
        .add_to_batch(&mut batch);
    let forward = Chain::new(&table)
        .with_name("forward")
        .with_hook(Hook::new(HookClass::Forward, 0))
        .with_policy(ChainPolicy::Drop)
        .add_to_batch(&mut batch);
    let _output = Chain::new(&table)
        .with_name("output")
        .with_hook(Hook::new(HookClass::Out, 0))
        .with_policy(ChainPolicy::Accept)
        .add_to_batch(&mut batch);

    // -------- INPUT chain --------

    // INPUT: established/related → accept (return traffic for every
    // outbound connection).
    Rule::new(&input)
        .map_err(|e| Error::Firewall(e.to_string()))?
        .established()
        .map_err(|e| Error::Firewall(e.to_string()))?
        .accept()
        .add_to_batch(&mut batch);

    // INPUT: loopback → accept.
    Rule::new(&input)
        .map_err(|e| Error::Firewall(e.to_string()))?
        .iiface("lo")
        .map_err(|e| Error::Firewall(e.to_string()))?
        .accept()
        .add_to_batch(&mut batch);

    // Parse the unique set of ports the control plane is listening on
    // from `cfg.control.listen`, so the firewall rule stays in sync
    // when the operator changes the listen address.
    let control_ports = control_listen_ports(&cfg.control.listen);
    if control_ports.is_empty() {
        tracing::warn!(
            "no parseable ports in cfg.control.listen — control plane will be unreachable"
        );
    }

    // INPUT: sQUIC control plane from trusted LAN → accept (one rule
    // per control listen port). Skipped only if the operator has
    // explicitly disabled it on the trusted LAN, which is a footgun.
    if cfg.lan.allow_control_plane {
        for &port in &control_ports {
            Rule::new(&input)
                .map_err(|e| Error::Firewall(e.to_string()))?
                .iiface(&cfg.lan.bridge)
                .map_err(|e| Error::Firewall(e.to_string()))?
                .dport(port, Protocol::UDP)
                .accept()
                .add_to_batch(&mut batch);
        }
    } else {
        tracing::warn!(
            "lan.allow_control_plane = false — make sure another subnet has it enabled"
        );
    }

    // INPUT: per-isolated-subnet explicit allows. Default stance is
    // drop (the chain's default policy), so an isolated subnet gets
    // NOTHING into the router except what its flags punch through.
    for iso in &cfg.isolated_subnets {
        if iso.allow_dhcp {
            // DHCPv4 server listens on UDP/67; clients send from UDP/68.
            // Both endpoints of the exchange need to be accepted because
            // in the BROADCAST case the conntrack "established" rule
            // may not match.
            for port in [67u16, 68u16] {
                Rule::new(&input)
                    .map_err(|e| Error::Firewall(e.to_string()))?
                    .iiface(&iso.iface)
                    .map_err(|e| Error::Firewall(e.to_string()))?
                    .dport(port, Protocol::UDP)
                    .accept()
                    .add_to_batch(&mut batch);
            }
            tracing::info!(subnet = %iso.name, iface = %iso.iface, "input: DHCP allow");
        }
        if iso.allow_dns {
            // DNS over UDP and TCP on port 53. These reach the router
            // IP on this subnet; the oxwrt-dnat table DNATs them to
            // the DNS container.
            Rule::new(&input)
                .map_err(|e| Error::Firewall(e.to_string()))?
                .iiface(&iso.iface)
                .map_err(|e| Error::Firewall(e.to_string()))?
                .dport(53, Protocol::UDP)
                .accept()
                .add_to_batch(&mut batch);
            Rule::new(&input)
                .map_err(|e| Error::Firewall(e.to_string()))?
                .iiface(&iso.iface)
                .map_err(|e| Error::Firewall(e.to_string()))?
                .dport(53, Protocol::TCP)
                .accept()
                .add_to_batch(&mut batch);
            tracing::info!(subnet = %iso.name, iface = %iso.iface, "input: DNS allow");
        }
        if iso.allow_control_plane {
            for &port in &control_ports {
                Rule::new(&input)
                    .map_err(|e| Error::Firewall(e.to_string()))?
                    .iiface(&iso.iface)
                    .map_err(|e| Error::Firewall(e.to_string()))?
                    .dport(port, Protocol::UDP)
                    .accept()
                    .add_to_batch(&mut batch);
            }
            tracing::info!(
                subnet = %iso.name,
                iface = %iso.iface,
                ports = ?control_ports,
                "input: control-plane allow"
            );
        }
        // Arbitrary additional INPUT punches.
        for rule_spec in &iso.input_allow {
            for proto in port_proto_to_list(rule_spec.proto) {
                Rule::new(&input)
                    .map_err(|e| Error::Firewall(e.to_string()))?
                    .iiface(&iso.iface)
                    .map_err(|e| Error::Firewall(e.to_string()))?
                    .dport(rule_spec.port, proto)
                    .accept()
                    .add_to_batch(&mut batch);
            }
            tracing::info!(
                subnet = %iso.name,
                iface = %iso.iface,
                proto = ?rule_spec.proto,
                port = rule_spec.port,
                "input: custom allow"
            );
        }
    }

    // -------- FORWARD chain --------
    //
    // Default policy is now `drop`. Every allowed forwarding path is
    // an explicit accept rule, in this order:
    //
    //   1. ct state established/related → universal return path
    //   2. trusted LAN → WAN                          (lan.allow_wan)
    //   3. trusted LAN → each service-netns veth
    //   4. each service-netns veth → WAN              (services egress)
    //   5. each service → declared `depends_on` peer  (svc-to-svc)
    //   6. per isolated subnet:
    //        a. → WAN                                 (iso.allow_wan)
    //        b. → each service whose `expose` port matches the
    //             subnet's allow_dns / allow_dhcp flags
    //        c. → itself                              (only if !client_isolation)
    //
    // Everything else (cross-subnet, untrusted-to-LAN, untrusted to
    // a service the subnet hasn't been told to reach) falls through
    // to the chain default policy and is dropped.

    let wan_iface = wan_iface_name(&cfg.wan);

    // 1. Universal return path.
    Rule::new(&forward)
        .map_err(|e| Error::Firewall(e.to_string()))?
        .established()
        .map_err(|e| Error::Firewall(e.to_string()))?
        .accept()
        .add_to_batch(&mut batch);

    // 2. Trusted LAN → WAN.
    if cfg.lan.allow_wan {
        Rule::new(&forward)
            .map_err(|e| Error::Firewall(e.to_string()))?
            .iiface(&cfg.lan.bridge)
            .map_err(|e| Error::Firewall(e.to_string()))?
            .oiface(wan_iface)
            .map_err(|e| Error::Firewall(e.to_string()))?
            .accept()
            .add_to_batch(&mut batch);
        tracing::info!(lan = %cfg.lan.bridge, wan = %wan_iface, "forward: lan→wan");
    }

    // 3 + 4 + 5: per-service forward rules.
    for svc in &cfg.services {
        if svc.veth.is_none() {
            continue;
        }
        let veth_host = veth_host_name(svc);

        // 3. Trusted LAN → service-netns veth, gated by `lan.allow_services`.
        //    None = all services reachable (historical behavior). Some(list)
        //    = only the named services. The LAN never loses the ability
        //    to reach a service via the established/related rule (1) once
        //    the service initiates the conversation, but inbound new
        //    connections from the LAN are gated here.
        let lan_allowed = cfg
            .lan
            .allow_services
            .as_ref()
            .map(|list| list.iter().any(|n| n == &svc.name))
            .unwrap_or(true);
        if lan_allowed {
            Rule::new(&forward)
                .map_err(|e| Error::Firewall(e.to_string()))?
                .iiface(&cfg.lan.bridge)
                .map_err(|e| Error::Firewall(e.to_string()))?
                .oiface(&veth_host)
                .map_err(|e| Error::Firewall(e.to_string()))?
                .accept()
                .add_to_batch(&mut batch);
        }

        // 4. Service → WAN.
        Rule::new(&forward)
            .map_err(|e| Error::Firewall(e.to_string()))?
            .iiface(&veth_host)
            .map_err(|e| Error::Firewall(e.to_string()))?
            .oiface(wan_iface)
            .map_err(|e| Error::Firewall(e.to_string()))?
            .accept()
            .add_to_batch(&mut batch);

        // 5. Service → declared dependencies (e.g. ntpd → dns).
        for dep_name in &svc.depends_on {
            if let Some(dep_svc) = cfg.services.iter().find(|s| &s.name == dep_name) {
                if dep_svc.veth.is_none() {
                    continue;
                }
                let dep_host = veth_host_name(dep_svc);
                Rule::new(&forward)
                    .map_err(|e| Error::Firewall(e.to_string()))?
                    .iiface(&veth_host)
                    .map_err(|e| Error::Firewall(e.to_string()))?
                    .oiface(&dep_host)
                    .map_err(|e| Error::Firewall(e.to_string()))?
                    .accept()
                    .add_to_batch(&mut batch);
                tracing::info!(
                    svc = %svc.name,
                    dep = %dep_name,
                    "forward: service-to-service dep"
                );
            }
        }
        tracing::info!(svc = %svc.name, veth = %veth_host, "forward: lan↔svc + svc→wan");
    }

    // 6. Per-isolated-subnet forwarding rules.
    for iso in &cfg.isolated_subnets {
        // 6a. → WAN.
        if iso.allow_wan {
            Rule::new(&forward)
                .map_err(|e| Error::Firewall(e.to_string()))?
                .iiface(&iso.iface)
                .map_err(|e| Error::Firewall(e.to_string()))?
                .oiface(wan_iface)
                .map_err(|e| Error::Firewall(e.to_string()))?
                .accept()
                .add_to_batch(&mut batch);
            tracing::info!(subnet = %iso.name, wan = %wan_iface, "forward: iso→wan");
        }

        // 6b. → service-netns veths. Two modes:
        //
        //   - `allow_services = Some(list)`: explicit per-name whitelist,
        //     ignores the implicit port matching entirely. Set to
        //     `Some(vec![])` for "no services."
        //
        //   - `allow_services = None`: the implicit port-match logic
        //     applies — `allow_dns` permits any service exposing port
        //     53, `allow_dhcp` permits 67/68. (DHCP servers usually
        //     run host-net so the DHCP branch won't usually match;
        //     harmless if a future Rust DHCP server lives in a netns
        //     and exposes 67.)
        for svc in &cfg.services {
            if svc.veth.is_none() {
                continue;
            }
            let allowed = match &iso.allow_services {
                Some(list) => list.iter().any(|n| n == &svc.name),
                None => svc.expose.iter().any(|e| {
                    (iso.allow_dns && e.lan_port == 53)
                        || (iso.allow_dhcp && (e.lan_port == 67 || e.lan_port == 68))
                }),
            };
            if !allowed {
                continue;
            }
            let veth_host = veth_host_name(svc);
            Rule::new(&forward)
                .map_err(|e| Error::Firewall(e.to_string()))?
                .iiface(&iso.iface)
                .map_err(|e| Error::Firewall(e.to_string()))?
                .oiface(&veth_host)
                .map_err(|e| Error::Firewall(e.to_string()))?
                .accept()
                .add_to_batch(&mut batch);
            tracing::info!(
                subnet = %iso.name,
                svc = %svc.name,
                mode = if iso.allow_services.is_some() { "explicit" } else { "port-match" },
                "forward: iso→svc"
            );
        }

        // 6d. Per-peer forwarding: an iso subnet can declare a list of
        //     OTHER iso subnet names it's allowed to talk to. Each entry
        //     emits a one-way `iif=this oif=peer` accept; the reverse
        //     direction must be declared separately on the peer side.
        //     A typo in `peers` produces a warn (not an error) so a
        //     subnet rename doesn't take down the entire firewall install.
        for peer_name in &iso.peers {
            let Some(peer) = cfg.isolated_subnets.iter().find(|p| &p.name == peer_name)
            else {
                tracing::warn!(
                    subnet = %iso.name,
                    peer = %peer_name,
                    "forward: peer not found in isolated_subnets; skipping"
                );
                continue;
            };
            if peer.iface == iso.iface {
                // Same interface ⇒ this is the same as setting
                // `client_isolation = false`. Skip the duplicate.
                continue;
            }
            Rule::new(&forward)
                .map_err(|e| Error::Firewall(e.to_string()))?
                .iiface(&iso.iface)
                .map_err(|e| Error::Firewall(e.to_string()))?
                .oiface(&peer.iface)
                .map_err(|e| Error::Firewall(e.to_string()))?
                .accept()
                .add_to_batch(&mut batch);
            tracing::info!(
                subnet = %iso.name,
                peer = %peer.name,
                "forward: iso→peer"
            );
        }

        // 6c. Client isolation = false → emit explicit iif=iso oif=iso
        //     accept. With the default-drop policy, leaving this off
        //     already gives the operator client isolation for free
        //     at the L3 layer.
        if !iso.client_isolation {
            Rule::new(&forward)
                .map_err(|e| Error::Firewall(e.to_string()))?
                .iiface(&iso.iface)
                .map_err(|e| Error::Firewall(e.to_string()))?
                .oiface(&iso.iface)
                .map_err(|e| Error::Firewall(e.to_string()))?
                .accept()
                .add_to_batch(&mut batch);
            tracing::info!(
                subnet = %iso.name,
                "forward: iso↔iso allowed (client_isolation=false)"
            );
        }
    }

    batch.send().map_err(|e| Error::Firewall(e.to_string()))?;
    tracing::info!(
        isolated_subnets = cfg.isolated_subnets.len(),
        control_ports = ?control_ports,
        "nftables ruleset installed"
    );
    Ok(())
}

/// Build a human-readable dump of the firewall rules `install_firewall`
/// would emit for `cfg`. Mirrors the structure of `install_firewall` —
/// kept as a parallel walker rather than threading description-pushes
/// through every Rule emit site, which would clutter the kernel-install
/// hot path. The risk of drift between the two functions is mitigated
/// by `firewall_dump_matches_install_count` in tests below.
///
/// Used by the `Diag::firewall` RPC so an operator can inspect the
/// active ruleset over the control plane without `nft list ruleset` —
/// which doesn't exist in the firmware image (no shell, no nft binary).
/// This dump is the rules WE INSTALLED, not a live kernel readout, but
/// since nothing else can mutate the ruleset (no shell, no nft) the two
/// stay in sync as long as `install_firewall` is the sole writer.
pub fn format_firewall_dump(cfg: &Config) -> Vec<String> {
    let mut out = Vec::new();
    let wan_iface = wan_iface_name(&cfg.wan);
    let control_ports = control_listen_ports(&cfg.control.listen);

    out.push("table inet oxwrt {".to_string());

    // -------- INPUT --------
    out.push("  chain input {".to_string());
    out.push("    type filter hook input priority 0; policy drop;".to_string());
    out.push("    ct state established,related accept".to_string());
    out.push("    iif \"lo\" accept".to_string());
    if cfg.lan.allow_control_plane {
        for &port in &control_ports {
            out.push(format!(
                "    iif \"{}\" udp dport {} accept   # lan control plane",
                cfg.lan.bridge, port
            ));
        }
    }
    for iso in &cfg.isolated_subnets {
        if iso.allow_dhcp {
            for port in [67u16, 68u16] {
                out.push(format!(
                    "    iif \"{}\" udp dport {} accept   # iso {} dhcp",
                    iso.iface, port, iso.name
                ));
            }
        }
        if iso.allow_dns {
            out.push(format!(
                "    iif \"{}\" udp dport 53 accept   # iso {} dns",
                iso.iface, iso.name
            ));
            out.push(format!(
                "    iif \"{}\" tcp dport 53 accept   # iso {} dns",
                iso.iface, iso.name
            ));
        }
        if iso.allow_control_plane {
            for &port in &control_ports {
                out.push(format!(
                    "    iif \"{}\" udp dport {} accept   # iso {} control",
                    iso.iface, port, iso.name
                ));
            }
        }
        for spec in &iso.input_allow {
            for proto in port_proto_to_list(spec.proto) {
                let pname = match proto {
                    rustables::Protocol::TCP => "tcp",
                    rustables::Protocol::UDP => "udp",
                };
                out.push(format!(
                    "    iif \"{}\" {} dport {} accept   # iso {} custom",
                    iso.iface, pname, spec.port, iso.name
                ));
            }
        }
    }
    out.push("  }".to_string());

    // -------- FORWARD --------
    out.push("  chain forward {".to_string());
    out.push("    type filter hook forward priority 0; policy drop;".to_string());
    out.push("    ct state established,related accept".to_string());
    if cfg.lan.allow_wan {
        out.push(format!(
            "    iif \"{}\" oif \"{}\" accept   # lan→wan",
            cfg.lan.bridge, wan_iface
        ));
    }
    for svc in &cfg.services {
        if svc.veth.is_none() {
            continue;
        }
        let veth = veth_host_name(svc);
        let lan_allowed = cfg
            .lan
            .allow_services
            .as_ref()
            .map(|list| list.iter().any(|n| n == &svc.name))
            .unwrap_or(true);
        if lan_allowed {
            out.push(format!(
                "    iif \"{}\" oif \"{}\" accept   # lan→svc {}",
                cfg.lan.bridge, veth, svc.name
            ));
        }
        out.push(format!(
            "    iif \"{}\" oif \"{}\" accept   # svc {}→wan",
            veth, wan_iface, svc.name
        ));
        for dep_name in &svc.depends_on {
            if let Some(dep) = cfg.services.iter().find(|s| &s.name == dep_name) {
                if dep.veth.is_some() {
                    out.push(format!(
                        "    iif \"{}\" oif \"{}\" accept   # svc {}→dep {}",
                        veth,
                        veth_host_name(dep),
                        svc.name,
                        dep_name
                    ));
                }
            }
        }
    }
    for iso in &cfg.isolated_subnets {
        if iso.allow_wan {
            out.push(format!(
                "    iif \"{}\" oif \"{}\" accept   # iso {}→wan",
                iso.iface, wan_iface, iso.name
            ));
        }
        for svc in &cfg.services {
            if svc.veth.is_none() {
                continue;
            }
            let allowed = match &iso.allow_services {
                Some(list) => list.iter().any(|n| n == &svc.name),
                None => svc.expose.iter().any(|e| {
                    (iso.allow_dns && e.lan_port == 53)
                        || (iso.allow_dhcp && (e.lan_port == 67 || e.lan_port == 68))
                }),
            };
            if !allowed {
                continue;
            }
            out.push(format!(
                "    iif \"{}\" oif \"{}\" accept   # iso {}→svc {}",
                iso.iface,
                veth_host_name(svc),
                iso.name,
                svc.name
            ));
        }
        for peer_name in &iso.peers {
            if let Some(peer) = cfg.isolated_subnets.iter().find(|p| &p.name == peer_name) {
                if peer.iface != iso.iface {
                    out.push(format!(
                        "    iif \"{}\" oif \"{}\" accept   # iso {}→peer {}",
                        iso.iface, peer.iface, iso.name, peer.name
                    ));
                }
            }
        }
        if !iso.client_isolation {
            out.push(format!(
                "    iif \"{}\" oif \"{}\" accept   # iso {} client isolation off",
                iso.iface, iso.iface, iso.name
            ));
        }
    }
    out.push("  }".to_string());

    // OUTPUT chain is policy accept with no rules — note it explicitly
    // so the operator doesn't think we forgot it.
    out.push("  chain output {".to_string());
    out.push("    type filter hook output priority 0; policy accept;".to_string());
    out.push("  }".to_string());

    out.push("}".to_string());
    out
}

/// Extract the unique set of ports the control plane is listening on
/// from `cfg.control.listen` strings. Tolerates malformed entries
/// (logged at warn) so a typo in one entry doesn't take down the
/// whole firewall install.
fn control_listen_ports(listen: &[String]) -> Vec<u16> {
    use std::collections::BTreeSet;
    use std::net::SocketAddr;
    let mut ports: BTreeSet<u16> = BTreeSet::new();
    for entry in listen {
        match entry.parse::<SocketAddr>() {
            Ok(addr) => {
                ports.insert(addr.port());
            }
            Err(e) => {
                tracing::warn!(
                    listen = %entry,
                    error = %e,
                    "control listen entry not parseable; skipping for firewall rule"
                );
            }
        }
    }
    ports.into_iter().collect()
}

/// Expand a `PortProto` to the underlying `rustables::Protocol`
/// enum values. `Both` produces TCP and UDP; the rest produce one.
fn port_proto_to_list(proto: crate::config::PortProto) -> Vec<rustables::Protocol> {
    use crate::config::PortProto;
    use rustables::Protocol;
    match proto {
        PortProto::Udp => vec![Protocol::UDP],
        PortProto::Tcp => vec![Protocol::TCP],
        PortProto::Both => vec![Protocol::UDP, Protocol::TCP],
    }
}

/// Extract the WAN interface name from any `Wan` variant. All three
/// variants carry an `iface` field; this is just a pattern match that
/// borrows it.
fn wan_iface_name(wan: &Wan) -> &str {
    match wan {
        Wan::Dhcp { iface }
        | Wan::Static { iface, .. }
        | Wan::Pppoe { iface, .. } => iface,
    }
}

/// Convention for the host-side end of a service's veth pair, defined
/// once here and matching `container::PreparedContainer`'s naming.
fn veth_host_name(svc: &Service) -> String {
    format!("veth-{}", svc.name)
}
