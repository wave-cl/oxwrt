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

use oxwrt_api::config::{Action, Config, Network, PortSpec, Proto, Service, WanConfig};

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
        for net in &cfg.networks {
            match net {
                Network::Lan { .. } => self.setup_lan(net).await?,
                Network::Wan { .. } => self.setup_wan(net).await?,
                Network::Simple { .. } => {
                    // Simple networks are bridges created by the platform;
                    // no additional setup needed at boot.
                }
            }
        }
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

    async fn setup_lan(&self, net: &Network) -> Result<(), Error> {
        let Network::Lan { bridge, members, address, prefix, .. } = net else {
            return Ok(());
        };
        if matches!(self.link_index(bridge).await, Err(Error::LinkNotFound(_))) {
            self.handle
                .link()
                .add(LinkBridge::new(bridge).build())
                .execute()
                .await?;
        }
        let bridge_idx = self.link_index(bridge).await?;

        self.handle
            .link()
            .set(LinkUnspec::new_with_index(bridge_idx).up().build())
            .execute()
            .await?;

        let addr_res = self
            .handle
            .address()
            .add(bridge_idx, IpAddr::V4(*address), *prefix)
            .execute()
            .await;
        if let Err(e) = addr_res {
            if !is_exists(&e) {
                return Err(e.into());
            }
            tracing::debug!(%bridge, "lan address already present");
        }

        // Enslave LAN members to the bridge. Missing members are warned and
        // skipped — hardware may lack a given port, or the config may refer
        // to an interface that's renamed by the board-files.
        for member in members {
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

    async fn setup_wan(&self, net: &Network) -> Result<(), Error> {
        let Network::Wan { iface, wan, .. } = net else {
            return Ok(());
        };
        self.up_link(iface).await?;

        // DHCP: wan_dhcp::acquire handles addressing.
        // Pppoe: not yet implemented, link-only.
        // Static: apply the configured address + default route here so a
        // static-WAN router actually comes up with the operator's
        // configured IP without needing a reload. EEXIST on address / route
        // is tolerated so re-running this is idempotent.
        if let WanConfig::Static {
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

/// Enable IPv6 forwarding. Required for corerad's RA emission to make
/// sense — the kernel will emit the "no global IPv6" warning and drop
/// packets that would need to route otherwise. Also flips
/// `accept_ra=2` on `all` so forwarding hosts keep learning from
/// upstream RAs (the default is 1 on non-forwarding, 0 on forwarding).
/// Idempotent.
pub fn enable_ipv6_forwarding() -> Result<(), Error> {
    std::fs::write("/proc/sys/net/ipv6/conf/all/forwarding", "1\n")?;
    // Best-effort; on a freshly booted box these may not exist for every
    // interface yet. Ignore errors (the write above is the essential one).
    let _ = std::fs::write("/proc/sys/net/ipv6/conf/all/accept_ra", "2\n");
    Ok(())
}

/// Install the complete nftables ruleset: inet filter (input/forward/
/// output), NAT masquerade for zones with `masquerade = true`, and DNAT
/// rules for `action = "dnat"` rules. Everything in one function —
/// replaces the old `install_firewall` + `install_nat_masquerade` +
/// `install_dnat_rules` trio.
///
/// Synchronous: rustables `Batch::send()` does one blocking netlink
/// round-trip. Safe to call from an async context.
pub fn install_firewall(cfg: &Config) -> Result<(), Error> {
    use rustables::expr::{Immediate, Masquerade, Nat, NatType, Register};
    use rustables::{
        Batch, Chain, ChainType, Hook, HookClass, MsgType, ProtocolFamily, Rule, Table,
    };
    // Alias to avoid confusion with config::ChainPolicy.
    use rustables::ChainPolicy as NfChainPolicy;

    let mut batch = Batch::new();

    // ── 1. inet oxwrt: INPUT + FORWARD + OUTPUT filter ──────────────

    let table = Table::new(ProtocolFamily::Inet).with_name("oxwrt");
    batch.add(&table, MsgType::Add);
    batch.add(&table, MsgType::Del);
    batch.add(&table, MsgType::Add);

    let input = Chain::new(&table)
        .with_name("input")
        .with_hook(Hook::new(HookClass::In, 0))
        .with_policy(NfChainPolicy::Drop)
        .add_to_batch(&mut batch);
    let forward = Chain::new(&table)
        .with_name("forward")
        .with_hook(Hook::new(HookClass::Forward, 0))
        .with_policy(NfChainPolicy::Drop)
        .add_to_batch(&mut batch);
    let _output = Chain::new(&table)
        .with_name("output")
        .with_hook(Hook::new(HookClass::Out, 0))
        .with_policy(NfChainPolicy::Accept)
        .add_to_batch(&mut batch);

    // INPUT/FORWARD: loopback accept (always).
    Rule::new(&input)
        .map_err(|e| Error::Firewall(e.to_string()))?
        .iiface("lo")
        .map_err(|e| Error::Firewall(e.to_string()))?
        .accept()
        .add_to_batch(&mut batch);

    // Accept DHCPv4 OFFER/ACK on the WAN iface. Our DHCP client sends
    // DISCOVER/REQUEST via AF_PACKET raw socket (bypasses iptables)
    // but RECEIVES via a UDP socket bound 0.0.0.0:68. The replies land
    // in the INPUT chain before the client has an IP, so conntrack has
    // no "established" entry yet, and without this rule the default-
    // drop policy silently swallows every OFFER. Symptom: wan_dhcp
    // acquire() times out on every retry even though the link is up
    // and the upstream has a working DHCP server.
    //
    // Gated on WAN being in DHCP mode — static WAN doesn't need it,
    // and inserting it on a static WAN would needlessly accept DHCP
    // chatter arriving on that iface.
    if let Some(Network::Wan { iface: wan_if, wan: WanConfig::Dhcp, .. }) =
        cfg.primary_wan()
    {
        let mut r = Rule::new(&input)
            .map_err(|e| Error::Firewall(e.to_string()))?
            .iiface(wan_if)
            .map_err(|e| Error::Firewall(e.to_string()))?;
        r = r.dport(68, rustables::Protocol::UDP);
        r.accept().add_to_batch(&mut batch);
    }

    // Emit each config rule into the right chain.
    for rule in &cfg.firewall.rules {
        // ct_state rules go into both input + forward.
        if !rule.ct_state.is_empty() {
            // Only established/related is supported by rustables' `.established()`.
            Rule::new(&input)
                .map_err(|e| Error::Firewall(e.to_string()))?
                .established()
                .map_err(|e| Error::Firewall(e.to_string()))?
                .accept()
                .add_to_batch(&mut batch);
            Rule::new(&forward)
                .map_err(|e| Error::Firewall(e.to_string()))?
                .established()
                .map_err(|e| Error::Firewall(e.to_string()))?
                .accept()
                .add_to_batch(&mut batch);
            continue;
        }

        // DNAT rules are handled in the NAT table below.
        if rule.action == Action::Dnat {
            continue;
        }

        // Determine which chain this rule targets:
        //   - src + dest → FORWARD (iif=src, oif=dest)
        //   - src only, no dest → INPUT (iif=src)
        //   - neither → both INPUT and FORWARD (global rule)
        let src_ifaces = rule
            .src
            .as_deref()
            .map(|z| zone_ifaces(cfg, z))
            .unwrap_or_default();
        let dest_ifaces = rule
            .dest
            .as_deref()
            .map(|z| zone_ifaces(cfg, z))
            .unwrap_or_default();

        let protos = proto_to_nf_list(rule.proto);
        let ports = port_spec_to_list(&rule.dest_port);
        let is_icmp = rule.proto == Some(Proto::Icmp);

        let emit_rule = |chain: &Chain, batch: &mut Batch, iif: Option<&str>, oif: Option<&str>| -> Result<(), Error> {
            if is_icmp {
                // ICMP rules: no port, just iif match + accept/drop.
                let mut r = Rule::new(chain)
                    .map_err(|e| Error::Firewall(e.to_string()))?;
                if let Some(iif) = iif {
                    r = r.iiface(iif).map_err(|e| Error::Firewall(e.to_string()))?;
                }
                match rule.action {
                    Action::Accept => r.accept().add_to_batch(batch),
                    Action::Drop | Action::Reject => r.drop().add_to_batch(batch),
                    Action::Dnat => unreachable!(),
                };
                return Ok(());
            }
            if ports.is_empty() && protos.is_empty() {
                // No port, no proto — just iif/oif match.
                let mut r = Rule::new(chain)
                    .map_err(|e| Error::Firewall(e.to_string()))?;
                if let Some(iif) = iif {
                    r = r.iiface(iif).map_err(|e| Error::Firewall(e.to_string()))?;
                }
                if let Some(oif) = oif {
                    r = r.oiface(oif).map_err(|e| Error::Firewall(e.to_string()))?;
                }
                match rule.action {
                    Action::Accept => r.accept().add_to_batch(batch),
                    Action::Drop | Action::Reject => r.drop().add_to_batch(batch),
                    Action::Dnat => unreachable!(),
                };
            } else if ports.is_empty() {
                // Proto but no port — unusual, skip silently.
            } else {
                for &proto in &protos {
                    for &port in &ports {
                        let mut r = Rule::new(chain)
                            .map_err(|e| Error::Firewall(e.to_string()))?;
                        if let Some(iif) = iif {
                            r = r.iiface(iif).map_err(|e| Error::Firewall(e.to_string()))?;
                        }
                        if let Some(oif) = oif {
                            r = r.oiface(oif).map_err(|e| Error::Firewall(e.to_string()))?;
                        }
                        r = r.dport(port, proto);
                        match rule.action {
                            Action::Accept => r.accept().add_to_batch(batch),
                            Action::Drop | Action::Reject => r.drop().add_to_batch(batch),
                            Action::Dnat => unreachable!(),
                        };
                    }
                }
            }
            Ok(())
        };

        if rule.src.is_some() && rule.dest.is_some() {
            // FORWARD rule: iif=src, oif=dest.
            if src_ifaces.is_empty() || dest_ifaces.is_empty() {
                tracing::warn!(rule = %rule.name, "zone has no resolvable ifaces; skipping");
                continue;
            }
            for src_if in &src_ifaces {
                for dest_if in &dest_ifaces {
                    emit_rule(&forward, &mut batch, Some(src_if), Some(dest_if))?;
                }
            }
        } else if rule.src.is_some() {
            // INPUT rule: iif=src.
            if src_ifaces.is_empty() {
                tracing::warn!(rule = %rule.name, "source zone has no resolvable ifaces; skipping");
                continue;
            }
            for src_if in &src_ifaces {
                emit_rule(&input, &mut batch, Some(src_if), None)?;
            }
        } else {
            // Global rule (no src, no dest) — emit into both chains.
            emit_rule(&input, &mut batch, None, None)?;
            emit_rule(&forward, &mut batch, None, None)?;
        }

        tracing::debug!(rule = %rule.name, "filter rule emitted");
    }

    // Per-service automatic forward rules: LAN → service veth,
    // service veth → WAN, service → depends_on peers. These are
    // implicit from service topology, not explicit firewall rules.
    let wan_iface = cfg.primary_wan().map(|n| n.iface());
    let lan_iface = cfg.lan().map(|n| n.iface());
    for svc in &cfg.services {
        if svc.veth.is_none() {
            continue;
        }
        let veth_host = veth_host_name(svc);

        // LAN → service
        if let Some(lan_if) = lan_iface {
            Rule::new(&forward)
                .map_err(|e| Error::Firewall(e.to_string()))?
                .iiface(lan_if)
                .map_err(|e| Error::Firewall(e.to_string()))?
                .oiface(&veth_host)
                .map_err(|e| Error::Firewall(e.to_string()))?
                .accept()
                .add_to_batch(&mut batch);
        }

        // Service → WAN
        if let Some(wan_if) = wan_iface {
            Rule::new(&forward)
                .map_err(|e| Error::Firewall(e.to_string()))?
                .iiface(&veth_host)
                .map_err(|e| Error::Firewall(e.to_string()))?
                .oiface(wan_if)
                .map_err(|e| Error::Firewall(e.to_string()))?
                .accept()
                .add_to_batch(&mut batch);
        }

        // Service → depends_on peers
        for dep_name in &svc.depends_on {
            if let Some(dep_svc) = cfg.services.iter().find(|s| &s.name == dep_name) {
                if dep_svc.veth.is_none() {
                    continue;
                }
                Rule::new(&forward)
                    .map_err(|e| Error::Firewall(e.to_string()))?
                    .iiface(&veth_host)
                    .map_err(|e| Error::Firewall(e.to_string()))?
                    .oiface(&veth_host_name(dep_svc))
                    .map_err(|e| Error::Firewall(e.to_string()))?
                    .accept()
                    .add_to_batch(&mut batch);
            }
        }
    }

    // Port forwards: companion FORWARD accept for every port-forward
    // entry. Without this the default-drop FORWARD policy silently
    // swallows the post-DNAT packet and the operator sees "the DNAT
    // rule is right there in `diag nft`, why doesn't the service
    // respond?". Each port-forward installed here is guaranteed to
    // have its FORWARD half wired — the whole point of the dedicated
    // [[port_forwards]] section vs loose firewall.rules DNAT.
    for pf in &cfg.port_forwards {
        let Some((target_ip, target_port)) = parse_dnat_target(&pf.internal) else {
            tracing::warn!(pf = %pf.name, internal = %pf.internal, "invalid port-forward internal target; skipping FORWARD");
            continue;
        };
        // Src zone ifaces — typically one (wan). `pf.src` always
        // populated (serde default `"wan"`).
        let src_ifaces = zone_ifaces(cfg, &pf.src);
        if src_ifaces.is_empty() {
            tracing::warn!(pf = %pf.name, src = %pf.src, "port-forward src zone has no ifaces; skipping FORWARD");
            continue;
        }
        // Dest zone: explicit if given, else auto-detect from the
        // internal IP's subnet membership. The CRUD validator
        // rejects a port-forward whose IP sits in no LAN/Simple
        // subnet when `dest` is None, so an unresolvable case
        // here means the config was pushed through ConfigPush
        // bypassing CRUD — degrade by logging, not by failing
        // the whole install.
        let dest_zone_name = pf
            .dest
            .clone()
            .or_else(|| find_dest_zone_for_ip(cfg, target_ip));
        let Some(dest_zone_name) = dest_zone_name else {
            tracing::warn!(pf = %pf.name, ip = %target_ip, "cannot resolve dest zone for port-forward; skipping FORWARD");
            continue;
        };
        let dest_ifaces = zone_ifaces(cfg, &dest_zone_name);
        let protos = proto_to_nf_list(Some(pf.proto));

        for &proto in &protos {
            for src_if in &src_ifaces {
                for dst_if in &dest_ifaces {
                    let mut r = Rule::new(&forward)
                        .map_err(|e| Error::Firewall(e.to_string()))?
                        .iiface(src_if)
                        .map_err(|e| Error::Firewall(e.to_string()))?
                        .oiface(dst_if)
                        .map_err(|e| Error::Firewall(e.to_string()))?
                        .daddr(IpAddr::V4(target_ip));
                    r = r.dport(target_port, proto);
                    r.accept().add_to_batch(&mut batch);
                }
            }
        }
    }

    batch.send().map_err(|e| Error::Firewall(e.to_string()))?;
    tracing::info!(
        zones = cfg.firewall.zones.len(),
        rules = cfg.firewall.rules.len(),
        port_forwards = cfg.port_forwards.len(),
        "nftables inet filter installed"
    );

    // ── 2. ip oxwrt-nat: MASQUERADE for zones with masquerade=true ──
    //
    // Requires kmod-nft-nat in the image (nft_chain_nat / nft_masq).
    // That package ships with firewall4; if the image drops firewall4
    // without explicitly including kmod-nft-nat, every `type nat
    // hook ...` chain here fails with a generic "Error received from
    // the kernel" and the table never appears in `nft list tables`.

    let has_masq = cfg.firewall.zones.iter().any(|z| z.masquerade);
    if has_masq {
        let nat_table = Table::new(ProtocolFamily::Ipv4).with_name("oxwrt-nat");
        let mut nat_batch = Batch::new();
        nat_batch.add(&nat_table, MsgType::Add);
        nat_batch.add(&nat_table, MsgType::Del);
        nat_batch.add(&nat_table, MsgType::Add);

        let postrouting = Chain::new(&nat_table)
            .with_name("postrouting")
            .with_hook(Hook::new(HookClass::PostRouting, 100))
            .with_type(ChainType::Nat)
            .with_policy(NfChainPolicy::Accept)
            .add_to_batch(&mut nat_batch);

        Rule::new(&postrouting)
            .map_err(|e| Error::Firewall(e.to_string()))?
            .with_expr(Masquerade::default())
            .add_to_batch(&mut nat_batch);

        // Error path logs inline: the generic kernel error comes back
        // as a bare io::Error, and losing it to `?` alone means the
        // operator sees only "install_firewall failed" upstream with
        // no hint about which of the three table installs went wrong.
        nat_batch.send().map_err(|e| {
            tracing::error!(error = %e, "nftables NAT MASQUERADE batch send failed");
            Error::Firewall(e.to_string())
        })?;
        tracing::info!("nftables NAT MASQUERADE installed");
    }

    // ── 3. ip oxwrt-dnat: DNAT rules ────────────────────────────────

    let dnat_rules: Vec<&oxwrt_api::config::Rule> = cfg
        .firewall
        .rules
        .iter()
        .filter(|r| r.action == Action::Dnat && r.dnat_target.is_some())
        .collect();

    // Build the DNAT table if EITHER legacy DNAT rules or port-forwards
    // need it. Two sources, one table.
    if !dnat_rules.is_empty() || !cfg.port_forwards.is_empty() {
        let dnat_table = Table::new(ProtocolFamily::Ipv4).with_name("oxwrt-dnat");
        let mut dnat_batch = Batch::new();
        dnat_batch.add(&dnat_table, MsgType::Add);
        dnat_batch.add(&dnat_table, MsgType::Del);
        dnat_batch.add(&dnat_table, MsgType::Add);

        let prerouting = Chain::new(&dnat_table)
            .with_name("prerouting")
            .with_hook(Hook::new(HookClass::PreRouting, -100))
            .with_type(ChainType::Nat)
            .with_policy(NfChainPolicy::Accept)
            .add_to_batch(&mut dnat_batch);
        let dnat_output = Chain::new(&dnat_table)
            .with_name("output")
            .with_hook(Hook::new(HookClass::Out, -100))
            .with_type(ChainType::Nat)
            .with_policy(NfChainPolicy::Accept)
            .add_to_batch(&mut dnat_batch);

        // Collect all router IPs for DNAT matching: every network that
        // has a local address (LAN + Simple variants).
        let mut listen_addrs: Vec<Ipv4Addr> = Vec::new();
        for net in &cfg.networks {
            match net {
                Network::Lan { address, .. } | Network::Simple { address, .. } => {
                    listen_addrs.push(*address);
                }
                Network::Wan { .. } => {}
            }
        }

        for rule in &dnat_rules {
            let target_str = rule.dnat_target.as_deref().unwrap();
            let Some((target_ip, target_port)) = parse_dnat_target(target_str) else {
                tracing::warn!(rule = %rule.name, target = %target_str, "invalid dnat_target; skipping");
                continue;
            };
            let protos = proto_to_nf_list(rule.proto);
            let ports = port_spec_to_list(&rule.dest_port);

            for &proto in &protos {
                for &port in &ports {
                    for &listen_addr in &listen_addrs {
                        for chain in [&prerouting, &dnat_output] {
                            let ip_bytes = target_ip.octets().to_vec();
                            let port_bytes = target_port.to_be_bytes().to_vec();
                            let nat_expr = Nat::default()
                                .with_nat_type(NatType::DNat)
                                .with_family(ProtocolFamily::Ipv4)
                                .with_ip_register(Register::Reg1)
                                .with_port_register(Register::Reg2);

                            Rule::new(chain)
                                .map_err(|e| Error::Firewall(e.to_string()))?
                                .daddr(IpAddr::V4(listen_addr))
                                .dport(port, proto)
                                .with_expr(Immediate::new_data(ip_bytes, Register::Reg1))
                                .with_expr(Immediate::new_data(port_bytes, Register::Reg2))
                                .with_expr(nat_expr)
                                .add_to_batch(&mut dnat_batch);
                        }
                    }
                }
            }
            tracing::info!(rule = %rule.name, target = %target_str, "DNAT rule emitted");
        }

        // Port forwards: WAN-facing DNAT keyed on src-zone iifname
        // (not on a router IP). Accepts traffic arriving on the
        // source zone's iface on `external_port` and rewrites dest
        // to `internal`. Typical: WAN eth1 → LAN 192.168.50.50:80.
        for pf in &cfg.port_forwards {
            let Some((target_ip, target_port)) = parse_dnat_target(&pf.internal) else {
                tracing::warn!(pf = %pf.name, internal = %pf.internal, "invalid port-forward target; skipping");
                continue;
            };
            let src_ifaces = zone_ifaces(cfg, &pf.src);
            if src_ifaces.is_empty() {
                tracing::warn!(pf = %pf.name, src = %pf.src, "port-forward src zone has no ifaces; skipping DNAT");
                continue;
            }
            let protos = proto_to_nf_list(Some(pf.proto));

            for &proto in &protos {
                for src_if in &src_ifaces {
                    let ip_bytes = target_ip.octets().to_vec();
                    let port_bytes = target_port.to_be_bytes().to_vec();
                    let nat_expr = Nat::default()
                        .with_nat_type(NatType::DNat)
                        .with_family(ProtocolFamily::Ipv4)
                        .with_ip_register(Register::Reg1)
                        .with_port_register(Register::Reg2);

                    let mut r = Rule::new(&prerouting)
                        .map_err(|e| Error::Firewall(e.to_string()))?
                        .iiface(src_if)
                        .map_err(|e| Error::Firewall(e.to_string()))?;
                    r = r.dport(pf.external_port, proto);
                    r.with_expr(Immediate::new_data(ip_bytes, Register::Reg1))
                        .with_expr(Immediate::new_data(port_bytes, Register::Reg2))
                        .with_expr(nat_expr)
                        .add_to_batch(&mut dnat_batch);
                }
            }
            tracing::info!(pf = %pf.name, external = pf.external_port, target = %pf.internal, "port-forward DNAT emitted");
        }

        dnat_batch.send().map_err(|e| {
            tracing::error!(error = %e, "nftables DNAT batch send failed");
            Error::Firewall(e.to_string())
        })?;
        tracing::info!(
            rule_dnat = dnat_rules.len(),
            port_forwards = cfg.port_forwards.len(),
            "nftables DNAT installed"
        );
    }

    Ok(())
}

/// Build a human-readable dump of the firewall rules `install_firewall`
/// would emit for `cfg`. Used by the `Diag::firewall` RPC so an operator
/// can inspect the active ruleset over the control plane.
pub fn format_firewall_dump(cfg: &Config) -> Vec<String> {
    let mut out = Vec::new();
    let wan_iface = cfg.primary_wan().map(|n| n.iface()).unwrap_or("(no-wan)");

    out.push("table inet oxwrt {".to_string());

    // -------- INPUT --------
    out.push("  chain input {".to_string());
    out.push("    type filter hook input priority 0; policy drop;".to_string());
    out.push("    iif \"lo\" accept".to_string());

    for rule in &cfg.firewall.rules {
        if !rule.ct_state.is_empty() {
            out.push("    ct state established,related accept".to_string());
            continue;
        }
        if rule.action == Action::Dnat {
            continue;
        }
        // INPUT rules: src only (no dest).
        if rule.src.is_some() && rule.dest.is_none() {
            let src_ifaces = zone_ifaces(cfg, rule.src.as_deref().unwrap());
            let protos = proto_to_nf_list(rule.proto);
            let ports = port_spec_to_list(&rule.dest_port);
            let is_icmp = rule.proto == Some(Proto::Icmp);
            let action_str = match rule.action {
                Action::Accept => "accept",
                Action::Drop => "drop",
                Action::Reject => "reject",
                Action::Dnat => unreachable!(),
            };
            for src_if in &src_ifaces {
                if is_icmp {
                    out.push(format!(
                        "    iif \"{src_if}\" {action_str}   # {}", rule.name
                    ));
                } else if ports.is_empty() && protos.is_empty() {
                    out.push(format!(
                        "    iif \"{src_if}\" {action_str}   # {}", rule.name
                    ));
                } else {
                    for proto in &protos {
                        let pname = match proto {
                            rustables::Protocol::TCP => "tcp",
                            rustables::Protocol::UDP => "udp",
                        };
                        for &port in &ports {
                            out.push(format!(
                                "    iif \"{src_if}\" {pname} dport {port} {action_str}   # {}",
                                rule.name
                            ));
                        }
                    }
                }
            }
        }
    }
    out.push("  }".to_string());

    // -------- FORWARD --------
    out.push("  chain forward {".to_string());
    out.push("    type filter hook forward priority 0; policy drop;".to_string());

    for rule in &cfg.firewall.rules {
        if !rule.ct_state.is_empty() {
            out.push("    ct state established,related accept".to_string());
            continue;
        }
        if rule.action == Action::Dnat {
            continue;
        }
        if rule.src.is_some() && rule.dest.is_some() {
            let src_ifaces = zone_ifaces(cfg, rule.src.as_deref().unwrap());
            let dest_ifaces = zone_ifaces(cfg, rule.dest.as_deref().unwrap());
            let action_str = match rule.action {
                Action::Accept => "accept",
                Action::Drop => "drop",
                Action::Reject => "reject",
                Action::Dnat => unreachable!(),
            };
            for src_if in &src_ifaces {
                for dest_if in &dest_ifaces {
                    out.push(format!(
                        "    iif \"{src_if}\" oif \"{dest_if}\" {action_str}   # {}",
                        rule.name
                    ));
                }
            }
        }
    }

    // Per-service implicit forward rules.
    let lan_iface = cfg.lan().map(|n| n.iface()).unwrap_or("(no-lan)");
    for svc in &cfg.services {
        if svc.veth.is_none() {
            continue;
        }
        let veth = veth_host_name(svc);
        out.push(format!(
            "    iif \"{}\" oif \"{}\" accept   # lan→svc {}",
            lan_iface, veth, svc.name
        ));
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
    out.push("  }".to_string());

    out.push("  chain output {".to_string());
    out.push("    type filter hook output priority 0; policy accept;".to_string());
    out.push("  }".to_string());

    out.push("}".to_string());

    // DNAT dump
    let dnat_rules: Vec<&oxwrt_api::config::Rule> = cfg
        .firewall
        .rules
        .iter()
        .filter(|r| r.action == Action::Dnat && r.dnat_target.is_some())
        .collect();
    if !dnat_rules.is_empty() {
        out.push("table ip oxwrt-dnat {".to_string());
        for rule in &dnat_rules {
            let target = rule.dnat_target.as_deref().unwrap();
            let ports = port_spec_to_list(&rule.dest_port);
            let protos_str = match rule.proto {
                Some(Proto::Tcp) => "tcp",
                Some(Proto::Udp) => "udp",
                Some(Proto::Both) => "tcp+udp",
                _ => "?",
            };
            for &port in &ports {
                out.push(format!(
                    "  {protos_str} dport {port} dnat to {target}   # {}",
                    rule.name
                ));
            }
        }
        out.push("}".to_string());
    }

    out
}

/// Find the firewall zone whose network-list contains a LAN/Simple
/// subnet that includes `ip`. Used for port-forward dest auto-detect
/// when the operator hasn't pinned `dest` explicitly.
fn find_dest_zone_for_ip(cfg: &Config, ip: Ipv4Addr) -> Option<String> {
    for net in &cfg.networks {
        let (net_name, subnet_ip, prefix) = match net {
            Network::Lan {
                name,
                address,
                prefix,
                ..
            }
            | Network::Simple {
                name,
                address,
                prefix,
                ..
            } => (name.as_str(), *address, *prefix),
            Network::Wan { .. } => continue,
        };
        if !ipv4_in_subnet(ip, subnet_ip, prefix) {
            continue;
        }
        for z in &cfg.firewall.zones {
            if z.networks.iter().any(|n| n == net_name) {
                return Some(z.name.clone());
            }
        }
    }
    None
}

fn ipv4_in_subnet(ip: Ipv4Addr, subnet: Ipv4Addr, prefix: u8) -> bool {
    if prefix > 32 {
        return false;
    }
    if prefix == 0 {
        return true;
    }
    let mask: u32 = u32::MAX.checked_shl(32 - prefix as u32).unwrap_or(0);
    (u32::from(ip) & mask) == (u32::from(subnet) & mask)
}

/// Resolve a zone name to the set of interface names it covers.
/// Uses the unified `cfg.network(name)` helper to look up any network.
fn zone_ifaces(cfg: &Config, zone_name: &str) -> Vec<String> {
    // First check if a firewall zone with this name exists; if so,
    // resolve its `networks` list.
    if let Some(zone) = cfg.firewall.zones.iter().find(|z| z.name == zone_name) {
        let mut ifaces = Vec::new();
        for net_name in &zone.networks {
            if let Some(net) = cfg.network(net_name) {
                ifaces.push(net.iface().to_string());
            }
        }
        return ifaces;
    }
    // Fallback: direct name lookup.
    if let Some(net) = cfg.network(zone_name) {
        vec![net.iface().to_string()]
    } else {
        Vec::new()
    }
}

/// Expand a `Proto` to `rustables::Protocol` values.
fn proto_to_nf_list(proto: Option<Proto>) -> Vec<rustables::Protocol> {
    use rustables::Protocol;
    match proto {
        None => vec![],
        Some(Proto::Tcp) => vec![Protocol::TCP],
        Some(Proto::Udp) => vec![Protocol::UDP],
        Some(Proto::Both) => vec![Protocol::UDP, Protocol::TCP],
        Some(Proto::Icmp) => vec![], // ICMP handled separately
    }
}

/// Expand a `PortSpec` to a list of ports.
fn port_spec_to_list(spec: &Option<PortSpec>) -> Vec<u16> {
    match spec {
        None => vec![],
        Some(PortSpec::Single(p)) => vec![*p],
        Some(PortSpec::List(ps)) => ps.clone(),
    }
}

/// Parse a DNAT target string "ip:port" into (Ipv4Addr, u16).
fn parse_dnat_target(s: &str) -> Option<(Ipv4Addr, u16)> {
    let (ip_str, port_str) = s.rsplit_once(':')?;
    let ip = ip_str.parse::<Ipv4Addr>().ok()?;
    let port = port_str.parse::<u16>().ok()?;
    Some((ip, port))
}

/// Convention for the host-side end of a service's veth pair, defined
/// once here and matching `container::PreparedContainer`'s naming.
fn veth_host_name(svc: &Service) -> String {
    format!("veth-{}", svc.name)
}

#[cfg(test)]
mod tests {
    //! Pure-function unit tests for the helpers at the bottom of this
    //! file. Compiles and runs only on Linux targets (the whole module
    //! is `#[cfg(target_os = "linux")]`), so `cargo test` on a macOS
    //! dev box skips them — re-run via `cargo test --target
    //! aarch64-unknown-linux-musl` when iterating, or rely on CI that
    //! builds for Linux.
    //!
    //! The four helpers tested here are the glue between the declarative
    //! `Config` (from config.rs) and the rustables / nftables wire types
    //! used by `install_firewall`. They're pure functions of their
    //! inputs, so the tests don't need any mock netlink / cgroup /
    //! seccomp infrastructure.
    use super::*;
    use oxwrt_api::config::{
        Config, Control, Firewall, Network, PortSpec, Proto, Service, Zone,
    };
    use std::collections::BTreeMap;
    use std::net::Ipv4Addr;
    use std::path::PathBuf;

    fn minimal_config() -> Config {
        Config {
            hostname: "t".to_string(),
            timezone: None,
            networks: vec![
                Network::Lan {
                    name: "lan".to_string(),
                    bridge: "br-lan".to_string(),
                    members: vec![],
                    address: Ipv4Addr::new(192, 168, 1, 1),
                    prefix: 24,
                },
                Network::Simple {
                    name: "guest".to_string(),
                    iface: "br-guest".to_string(),
                    address: Ipv4Addr::new(10, 99, 0, 1),
                    prefix: 24,
                },
            ],
            firewall: Firewall {
                zones: vec![Zone {
                    name: "trusted".to_string(),
                    networks: vec!["lan".to_string(), "guest".to_string()],
                    default_input: oxwrt_api::config::ChainPolicy::Accept,
                    default_forward: oxwrt_api::config::ChainPolicy::Drop,
                    masquerade: false,
                }],
                rules: vec![],
            },
            radios: vec![],
            wifi: vec![],
            services: vec![],
            control: Control {
                listen: vec!["[::1]:51820".to_string()],
                authorized_keys: PathBuf::from("/x"),
            },
        }
    }

    // ── parse_dnat_target ──────────────────────────────────────────

    #[test]
    fn parse_dnat_target_ipv4_port() {
        assert_eq!(
            parse_dnat_target("10.53.0.2:15353"),
            Some((Ipv4Addr::new(10, 53, 0, 2), 15353))
        );
        assert_eq!(
            parse_dnat_target("127.0.0.1:53"),
            Some((Ipv4Addr::new(127, 0, 0, 1), 53))
        );
    }

    #[test]
    fn parse_dnat_target_rejects_bad_inputs() {
        assert_eq!(parse_dnat_target(""), None);
        assert_eq!(parse_dnat_target("nope"), None);
        assert_eq!(parse_dnat_target("not.an.ip:80"), None);
        assert_eq!(parse_dnat_target("1.2.3.4"), None, "missing port");
        assert_eq!(parse_dnat_target("1.2.3.4:"), None, "empty port");
        // u16 overflow
        assert_eq!(parse_dnat_target("1.2.3.4:99999"), None);
        // Colon absent
        assert_eq!(parse_dnat_target("1.2.3.4.80"), None);
    }

    #[test]
    fn parse_dnat_target_ipv6_not_supported() {
        // rsplit_once(':') on a v6 address splits at the last colon,
        // which doesn't yield a valid v4. Document intent.
        assert_eq!(parse_dnat_target("[::1]:53"), None);
        assert_eq!(parse_dnat_target("fe80::1:53"), None);
    }

    // ── port_spec_to_list ──────────────────────────────────────────

    #[test]
    fn port_spec_to_list_variants() {
        assert_eq!(port_spec_to_list(&None), Vec::<u16>::new());
        assert_eq!(port_spec_to_list(&Some(PortSpec::Single(53))), vec![53u16]);
        assert_eq!(
            port_spec_to_list(&Some(PortSpec::List(vec![67, 68]))),
            vec![67u16, 68]
        );
        // Empty list is preserved (caller decides whether that's an error).
        assert_eq!(
            port_spec_to_list(&Some(PortSpec::List(vec![]))),
            Vec::<u16>::new()
        );
    }

    // ── proto_to_nf_list ───────────────────────────────────────────

    #[test]
    fn proto_to_nf_list_variants() {
        use rustables::Protocol;
        assert_eq!(proto_to_nf_list(None), Vec::<Protocol>::new());
        assert_eq!(proto_to_nf_list(Some(Proto::Tcp)), vec![Protocol::TCP]);
        assert_eq!(proto_to_nf_list(Some(Proto::Udp)), vec![Protocol::UDP]);
        // "both" expands UDP first, TCP second (the install loop
        // iterates in order and UDP is more common for our ports).
        assert_eq!(
            proto_to_nf_list(Some(Proto::Both)),
            vec![Protocol::UDP, Protocol::TCP]
        );
        // ICMP is handled via a different code path; this helper
        // returns empty so the port-iteration loop skips it.
        assert_eq!(proto_to_nf_list(Some(Proto::Icmp)), Vec::<Protocol>::new());
    }

    // ── zone_ifaces ────────────────────────────────────────────────

    #[test]
    fn zone_ifaces_expands_firewall_zone_networks() {
        let cfg = minimal_config();
        // "trusted" zone covers lan + guest → br-lan + br-guest.
        let ifaces = zone_ifaces(&cfg, "trusted");
        assert_eq!(ifaces, vec!["br-lan".to_string(), "br-guest".to_string()]);
    }

    #[test]
    fn zone_ifaces_falls_back_to_direct_network_name() {
        let cfg = minimal_config();
        // No zone named "guest", but there's a network named "guest" —
        // helper falls back to the direct network lookup.
        assert_eq!(zone_ifaces(&cfg, "guest"), vec!["br-guest".to_string()]);
    }

    #[test]
    fn zone_ifaces_unknown_returns_empty() {
        let cfg = minimal_config();
        assert_eq!(zone_ifaces(&cfg, "nowhere"), Vec::<String>::new());
    }

    // ── veth_host_name ─────────────────────────────────────────────

    #[test]
    fn veth_host_name_stable() {
        let svc = Service {
            name: "dns".to_string(),
            rootfs: PathBuf::from("/x"),
            entrypoint: vec![],
            env: BTreeMap::new(),
            net_mode: Default::default(),
            veth: None,
            memory_max: None,
            cpu_max: None,
            pids_max: None,
            binds: vec![],
            depends_on: vec![],
            security: Default::default(),
        };
        assert_eq!(veth_host_name(&svc), "veth-dns");
        // Name with hyphens must round-trip into the interface name
        // unchanged — Linux allows hyphens in iface names.
        let svc2 = Service {
            name: "debug-ssh".to_string(),
            ..svc
        };
        assert_eq!(veth_host_name(&svc2), "veth-debug-ssh");
    }

    // ── ipv4_in_subnet / find_dest_zone_for_ip ─────────────────────

    #[test]
    fn ipv4_in_subnet_basic() {
        let net = Ipv4Addr::new(192, 168, 1, 0);
        assert!(ipv4_in_subnet(Ipv4Addr::new(192, 168, 1, 50), net, 24));
        assert!(ipv4_in_subnet(Ipv4Addr::new(192, 168, 1, 255), net, 24));
        assert!(!ipv4_in_subnet(Ipv4Addr::new(192, 168, 2, 1), net, 24));
        // /32 matches only itself.
        assert!(ipv4_in_subnet(net, net, 32));
        assert!(!ipv4_in_subnet(Ipv4Addr::new(192, 168, 1, 1), net, 32));
        // /0 matches everything.
        assert!(ipv4_in_subnet(Ipv4Addr::new(8, 8, 8, 8), net, 0));
    }

    #[test]
    fn find_dest_zone_for_ip_finds_lan() {
        let cfg = minimal_config();
        // minimal_config's "trusted" zone covers both lan + guest.
        // 192.168.1.42 → in lan subnet → trusted zone.
        assert_eq!(
            find_dest_zone_for_ip(&cfg, Ipv4Addr::new(192, 168, 1, 42)),
            Some("trusted".to_string())
        );
        // 10.99.0.50 → in guest subnet → trusted zone.
        assert_eq!(
            find_dest_zone_for_ip(&cfg, Ipv4Addr::new(10, 99, 0, 50)),
            Some("trusted".to_string())
        );
        // Outside any subnet.
        assert_eq!(
            find_dest_zone_for_ip(&cfg, Ipv4Addr::new(8, 8, 8, 8)),
            None
        );
    }
}
