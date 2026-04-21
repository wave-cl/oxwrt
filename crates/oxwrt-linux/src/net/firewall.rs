//! Firewall + raw-nft installation + dump helpers.
//!
//! Split out of net.rs in late 2025 after the file crossed 1900
//! lines. The split boundary is simple: anything that consumes
//! `rustables` / emits nft rules / is only needed by install /
//! dump paths lives here; link + bringup + netlink glue stay in
//! the parent `net` module.
//!
//! External callers continue to reach these functions through
//! `crate::net::{install_firewall, format_firewall_dump,
//! zone_ifaces, build_raw_nft_script}` — `net/mod.rs` re-exports
//! them so the split is source-compatible.

// Types referenced outside of per-function `use` blocks live here.
// The in-body `use rustables::...` statements (kept as-is from the
// pre-split shape) handle rustables imports to minimise churn.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use oxwrt_api::config::{
    Action, ChainPolicy, Config, Network, PortSpec, Proto, Service, WanConfig,
};

/// A rule needs the nft-text path (instead of rustables) when it
/// uses any primitive that rustables' builder doesn't expose
/// cleanly: IP/MAC/port matching, family restriction, rate limit,
/// logging, ICMP-type matching, or a schedule. Basic rules (zone+
/// proto+dport+ct_state) stay on the fast rustables path.
pub(crate) fn rule_needs_text_path(r: &oxwrt_api::config::Rule) -> bool {
    use oxwrt_api::config::{Family, PortSpec, Proto};
    // Port ranges on either src_port or dest_port: rustables has
    // no range builder, so render `tcp dport 22-80` via text.
    let dport_is_range = matches!(r.dest_port, Some(PortSpec::Range(_)));
    let sport_is_range = matches!(r.src_port, Some(PortSpec::Range(_)));
    // Proto-only rules (proto = tcp/udp/both, no dest_port).
    // The rustables path's emit-rule closure only knows how to
    // add `.dport()` pairs — without a port it silently skips,
    // which was a latent bug ("accept all UDP" rules vanished).
    // Route to text so render_proto_port emits `meta l4proto tcp`.
    // ICMP stays on the rustables path (handled specially via
    // .accept/.drop without a port).
    let proto_only =
        r.dest_port.is_none() && matches!(r.proto, Some(Proto::Tcp | Proto::Udp | Proto::Both));
    !r.src_ip.is_empty()
        || !r.dest_ip.is_empty()
        || !r.src_mac.is_empty()
        || r.src_port.is_some()
        || r.icmp_type.is_some()
        || r.limit.is_some()
        || r.log.is_some()
        || r.schedule.is_some()
        || r.family != Family::Any
        || r.match_set.is_some()
        || dport_is_range
        || sport_is_range
        || proto_only
        // fw4-parity rule primitives added in v0.2 pass 2. All
        // four are native nft syntax with no rustables builder
        // (counter, limit burst suffix, reject-with-reason, raw
        // iface match), so they route via the text path.
        || r.counter
        || r.limit_burst.is_some()
        || r.reject_with.is_some()
        || r.device.is_some()
}

use super::Error;

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
    // OUTPUT policy: default accept unless at least one zone
    // has default_output=drop, in which case policy-drop + we
    // install per-zone oifname-accept rules for the zones that
    // chose accept. This mirrors how INPUT/FORWARD work: policy
    // plus zone-specific overrides.
    let any_output_drop = cfg
        .firewall
        .zones
        .iter()
        .any(|z| z.default_output == ChainPolicy::Drop);
    let output_policy = if any_output_drop {
        NfChainPolicy::Drop
    } else {
        NfChainPolicy::Accept
    };
    let output = Chain::new(&table)
        .with_name("output")
        .with_hook(Hook::new(HookClass::Out, 0))
        .with_policy(output_policy)
        .add_to_batch(&mut batch);

    // OUTPUT: always accept loopback (the daemon's own
    // inter-component comms run here — control plane on [::1]).
    Rule::new(&output)
        .map_err(|e| Error::Firewall(e.to_string()))?
        .oiface("lo")
        .map_err(|e| Error::Firewall(e.to_string()))?
        .accept()
        .add_to_batch(&mut batch);
    // Accept established+related on OUTPUT so reply traffic from
    // the router's own connections isn't cut by the default-drop
    // policy.
    if any_output_drop {
        Rule::new(&output)
            .map_err(|e| Error::Firewall(e.to_string()))?
            .established()
            .map_err(|e| Error::Firewall(e.to_string()))?
            .accept()
            .add_to_batch(&mut batch);
    }
    // Per-zone OUTPUT accept: for every zone whose default_output
    // is accept (the non-drop case), emit oifname-accept so its
    // member ifaces aren't caught by the policy drop.
    if any_output_drop {
        for zone in &cfg.firewall.zones {
            if zone.default_output == ChainPolicy::Accept {
                for zif in zone_ifaces(cfg, &zone.name) {
                    Rule::new(&output)
                        .map_err(|e| Error::Firewall(e.to_string()))?
                        .oiface(&zif)
                        .map_err(|e| Error::Firewall(e.to_string()))?
                        .accept()
                        .add_to_batch(&mut batch);
                }
            }
        }
    }

    // INPUT/FORWARD: loopback accept (always).
    Rule::new(&input)
        .map_err(|e| Error::Firewall(e.to_string()))?
        .iiface("lo")
        .map_err(|e| Error::Firewall(e.to_string()))?
        .accept()
        .add_to_batch(&mut batch);

    // ── Baseline defaults (always-on, fire before operator rules) ──
    //
    // These cover things no operator should have to remember:
    //   - ct state established,related → accept (INPUT + FORWARD).
    //     Without this, every stateful accept rule needs its own
    //     return-path permit. fw4 does the same implicitly.
    //   - ct state invalid → drop. Malformed / out-of-window
    //     packets (TCP segments outside the window, non-RST after
    //     a RST, etc.) serve no legitimate purpose.
    //   - ICMPv6 NDP / MLD / packet-too-big → accept on INPUT +
    //     FORWARD. v6 is broken without NDP; PMTU-D breaks the
    //     web on >1500-MTU paths without packet-too-big.
    //
    // Emitted in text because rustables has no clean builder for
    // ct state + icmpv6 type matches. Appended to the raw_nft +
    // scheduled-rule pipe later in install_firewall.

    // DHCPv4 OFFER/ACK on WAN (legacy comment preserved above).

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
    if let Some(Network::Wan {
        iface: wan_if,
        wan: WanConfig::Dhcp { .. },
        ..
    }) = cfg.primary_wan()
    {
        let mut r = Rule::new(&input)
            .map_err(|e| Error::Firewall(e.to_string()))?
            .iiface(wan_if)
            .map_err(|e| Error::Firewall(e.to_string()))?;
        r = r.dport(68, rustables::Protocol::UDP);
        r.accept().add_to_batch(&mut batch);
    }

    // Auto-open WireGuard listen ports on the WAN iface. A declared
    // `[[wireguard]]` entry is pointless if the matching UDP port
    // can't reach the server — previously the operator had to add
    // an explicit `[[firewall.rules]]` UDP accept, and forgetting
    // was the canonical "I enrolled a peer, why doesn't it connect"
    // support ticket. Emitted only when there's a WAN iface (no
    // accept needed on a LAN-only dev setup where WG traffic
    // arrives via br-lan and the LAN zone's default_input=accept
    // already lets it through).
    if let Some(wan) = cfg.primary_wan() {
        let wan_if = wan.iface().to_string();
        for wg in &cfg.wireguard {
            let mut r = Rule::new(&input)
                .map_err(|e| Error::Firewall(e.to_string()))?
                .iiface(&wan_if)
                .map_err(|e| Error::Firewall(e.to_string()))?;
            r = r.dport(wg.listen_port, rustables::Protocol::UDP);
            r.accept().add_to_batch(&mut batch);
        }
    }

    // Declarative zone-to-zone forwardings (fw4 `config forwarding`).
    // Each entry expands into a FORWARD accept keyed on
    // iifname(src) + oifname(dest). Family restriction optionally
    // narrows to v4 or v6 via a meta-nfproto match added by the
    // text path — if set, we defer to the text path by synthesizing
    // a rule; otherwise rustables handles the straight accept.
    //
    // Emitted BEFORE operator rules so forwardings land as the
    // early "allow this direction by default" while rules can
    // still override with a narrower drop afterwards.
    use oxwrt_api::config::Family;
    for fwd in &cfg.firewall.forwardings {
        let src_ifaces = zone_ifaces(cfg, &fwd.src);
        let dest_ifaces = zone_ifaces(cfg, &fwd.dest);
        if src_ifaces.is_empty() || dest_ifaces.is_empty() {
            tracing::warn!(
                src = %fwd.src,
                dest = %fwd.dest,
                "forwarding: zone has no resolvable ifaces; skipping"
            );
            continue;
        }
        // Family=Any: rustables fast path. Family=Ipv4/Ipv6:
        // the nfproto match lives on the text path; skip here
        // and let a generated text rule handle it.
        if fwd.family != Family::Any {
            continue; // handled by build_forwardings_script
        }
        for src_if in &src_ifaces {
            for dest_if in &dest_ifaces {
                Rule::new(&forward)
                    .map_err(|e| Error::Firewall(e.to_string()))?
                    .iiface(src_if)
                    .map_err(|e| Error::Firewall(e.to_string()))?
                    .oiface(dest_if)
                    .map_err(|e| Error::Firewall(e.to_string()))?
                    .accept()
                    .add_to_batch(&mut batch);
            }
        }
    }

    // Emit each config rule into the right chain.
    for rule in &cfg.firewall.rules {
        // Skip disabled rules entirely — no text, no rustables emit.
        // The validator still ran against them, so a typo surfaces
        // at reload time (not at re-enable time).
        if !rule.enabled {
            continue;
        }
        // Skip rules that take the text path (ip/mac/port match,
        // limit, log, icmp_type, family, schedule). They're emitted
        // below by build_text_rules_script through `nft -f -`.
        if rule_needs_text_path(rule) {
            continue;
        }
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

        let emit_rule = |chain: &Chain,
                         batch: &mut Batch,
                         iif: Option<&str>,
                         oif: Option<&str>|
         -> Result<(), Error> {
            if is_icmp {
                // ICMP rules: no port, just iif match + accept/drop.
                let mut r = Rule::new(chain).map_err(|e| Error::Firewall(e.to_string()))?;
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
                let mut r = Rule::new(chain).map_err(|e| Error::Firewall(e.to_string()))?;
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
                        let mut r = Rule::new(chain).map_err(|e| Error::Firewall(e.to_string()))?;
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

    // Kill-switch for via_vpn zones. For each zone × each declared
    // vpn_client iface, emit a FORWARD accept (so packets routed
    // through the tunnel by the ip rule above leave cleanly).
    // Then a final `iifname $zone_iface drop` catches anything
    // that tried to leave by some other oif — the accept rules
    // above, the kernel's blackhole fallback in table 51, AND
    // this drop layer mean a broken tunnel takes three
    // misconfigurations to leak.
    //
    // Return-path traffic (established flows initiated by LAN
    // clients and coming back in) is accepted earlier by the
    // ct-state rules — nftables evaluates rules top-down and
    // takes the first verdict, so established accept beats this
    // drop for response packets.
    if cfg.firewall.zones.iter().any(|z| z.via_vpn) {
        let vpn_ifaces: Vec<String> = cfg.vpn_client.iter().map(|v| v.iface.clone()).collect();
        for zone in &cfg.firewall.zones {
            if !zone.via_vpn {
                continue;
            }
            for zone_if in zone_ifaces(cfg, &zone.name) {
                // Accept-first for each vpn iface.
                for vpn_if in &vpn_ifaces {
                    Rule::new(&forward)
                        .map_err(|e| Error::Firewall(e.to_string()))?
                        .iiface(&zone_if)
                        .map_err(|e| Error::Firewall(e.to_string()))?
                        .oiface(vpn_if)
                        .map_err(|e| Error::Firewall(e.to_string()))?
                        .accept()
                        .add_to_batch(&mut batch);
                }
                // Drop everything else out of this zone.
                Rule::new(&forward)
                    .map_err(|e| Error::Firewall(e.to_string()))?
                    .iiface(&zone_if)
                    .map_err(|e| Error::Firewall(e.to_string()))?
                    .drop()
                    .add_to_batch(&mut batch);
                tracing::debug!(
                    zone = %zone.name,
                    iface = %zone_if,
                    vpn_ifaces = vpn_ifaces.len(),
                    "via_vpn killswitch rules emitted"
                );
            }
        }
    }

    batch.send().map_err(|e| Error::Firewall(e.to_string()))?;
    tracing::info!(
        zones = cfg.firewall.zones.len(),
        rules = cfg.firewall.rules.len(),
        port_forwards = cfg.port_forwards.len(),
        wg_ports = cfg.wireguard.len(),
        via_vpn_zones = cfg.firewall.zones.iter().filter(|z| z.via_vpn).count(),
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
    // Additional postrouting masquerades for port-forward reflection
    // (hairpin NAT): when a LAN client hits the router's WAN IP on a
    // port-forward, we want the return path to go back through the
    // router instead of direct LAN → LAN. SNAT'ing on lan-egress to
    // the internal target forces that detour. Collected here so the
    // NAT table is installed if we need it even when no zone has
    // masquerade=true.
    let need_reflection = cfg.port_forwards.iter().any(|pf| {
        pf.reflection
            && parse_dnat_target_any(&pf.internal)
                .is_some_and(|(ip, _)| matches!(ip, IpAddr::V4(_)))
    });
    let need_reflection6 = cfg.port_forwards.iter().any(|pf| {
        pf.reflection
            && parse_dnat_target_any(&pf.internal)
                .is_some_and(|(ip, _)| matches!(ip, IpAddr::V6(_)))
    });
    if has_masq || need_reflection {
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

        if has_masq {
            Rule::new(&postrouting)
                .map_err(|e| Error::Firewall(e.to_string()))?
                .with_expr(Masquerade::default())
                .add_to_batch(&mut nat_batch);
        }

        // Hairpin SNAT: for each reflection-enabled port-forward,
        // install a MASQUERADE on packets egressing the dest-zone's
        // iface toward the internal target. Narrowed to daddr +
        // proto + dport so we don't over-apply to unrelated traffic.
        if need_reflection {
            for pf in &cfg.port_forwards {
                if !pf.reflection {
                    continue;
                }
                let Some((IpAddr::V4(target_ip), target_port)) =
                    parse_dnat_target_any(&pf.internal)
                else {
                    continue;
                };
                let dest_zone_name = pf
                    .dest
                    .clone()
                    .or_else(|| find_dest_zone_for_ip(cfg, target_ip));
                let Some(dest_zone_name) = dest_zone_name else {
                    continue;
                };
                let dest_ifaces = zone_ifaces(cfg, &dest_zone_name);
                let protos = proto_to_nf_list(Some(pf.proto));
                for &proto in &protos {
                    for oif in &dest_ifaces {
                        let mut r = Rule::new(&postrouting)
                            .map_err(|e| Error::Firewall(e.to_string()))?
                            .oiface(oif)
                            .map_err(|e| Error::Firewall(e.to_string()))?
                            .daddr(IpAddr::V4(target_ip));
                        r = r.dport(target_port, proto);
                        r.with_expr(Masquerade::default())
                            .add_to_batch(&mut nat_batch);
                    }
                }
            }
        }

        // Error path logs inline: the generic kernel error comes back
        // as a bare io::Error, and losing it to `?` alone means the
        // operator sees only "install_firewall failed" upstream with
        // no hint about which of the three table installs went wrong.
        nat_batch.send().map_err(|e| {
            tracing::error!(error = %e, "nftables NAT MASQUERADE batch send failed");
            Error::Firewall(e.to_string())
        })?;
        tracing::info!(
            reflection_forwards = cfg.port_forwards.iter().filter(|p| p.reflection).count(),
            "nftables NAT MASQUERADE installed"
        );
    }

    // ── 2b. ip6 oxwrt-nat6: IPv6 MASQUERADE ──────────────────────────
    //
    // Mirror of the v4 NAT table for operators who want NAT66 (e.g.
    // ISPs that only hand out a /128 or rotate prefixes frequently
    // and you want stable internal addressing). Gated on ANY zone
    // with masquerade=true AND ANY LAN/Simple network carrying a v6
    // address — no point installing an empty table.
    let any_v6_net = cfg.networks.iter().any(|n| match n {
        Network::Lan { ipv6_address, .. } | Network::Simple { ipv6_address, .. } => {
            ipv6_address.is_some()
        }
        _ => false,
    });
    if (has_masq && any_v6_net) || need_reflection6 {
        let nat6 = Table::new(ProtocolFamily::Ipv6).with_name("oxwrt-nat6");
        let mut nat6_batch = Batch::new();
        nat6_batch.add(&nat6, MsgType::Add);
        nat6_batch.add(&nat6, MsgType::Del);
        nat6_batch.add(&nat6, MsgType::Add);
        let postrouting6 = Chain::new(&nat6)
            .with_name("postrouting")
            .with_hook(Hook::new(HookClass::PostRouting, 100))
            .with_type(ChainType::Nat)
            .with_policy(NfChainPolicy::Accept)
            .add_to_batch(&mut nat6_batch);
        if has_masq && any_v6_net {
            Rule::new(&postrouting6)
                .map_err(|e| Error::Firewall(e.to_string()))?
                .with_expr(Masquerade::default())
                .add_to_batch(&mut nat6_batch);
        }
        // Hairpin SNAT for v6 port-forwards with reflection=true.
        // Mirror of the v4 path immediately above: match oiface +
        // daddr + proto + dport so the SNAT only fires on the
        // packet heading back to the internal v6 target, not on
        // unrelated traffic egressing the dest zone.
        if need_reflection6 {
            for pf in &cfg.port_forwards {
                if !pf.reflection {
                    continue;
                }
                let Some((IpAddr::V6(target_ip), target_port)) =
                    parse_dnat_target_any(&pf.internal)
                else {
                    continue;
                };
                let dest_zone_name = pf
                    .dest
                    .clone()
                    .or_else(|| find_dest_zone_for_ipv6(cfg, target_ip));
                let Some(dest_zone_name) = dest_zone_name else {
                    continue;
                };
                let dest_ifaces = zone_ifaces(cfg, &dest_zone_name);
                let protos = proto_to_nf_list(Some(pf.proto));
                for &proto in &protos {
                    for oif in &dest_ifaces {
                        let mut r = Rule::new(&postrouting6)
                            .map_err(|e| Error::Firewall(e.to_string()))?
                            .oiface(oif)
                            .map_err(|e| Error::Firewall(e.to_string()))?
                            .daddr(IpAddr::V6(target_ip));
                        r = r.dport(target_port, proto);
                        r.with_expr(Masquerade::default())
                            .add_to_batch(&mut nat6_batch);
                    }
                }
            }
        }
        nat6_batch.send().map_err(|e| {
            tracing::error!(error = %e, "nftables NAT6 MASQUERADE batch send failed");
            Error::Firewall(e.to_string())
        })?;
        tracing::info!(
            reflection6_forwards = cfg
                .port_forwards
                .iter()
                .filter(|p| p.reflection
                    && parse_dnat_target_any(&p.internal)
                        .is_some_and(|(ip, _)| matches!(ip, IpAddr::V6(_))))
                .count(),
            "nftables NAT6 MASQUERADE installed"
        );
    }

    // ── 3. ip oxwrt-dnat: DNAT rules ────────────────────────────────

    let dnat_rules: Vec<&oxwrt_api::config::Rule> = cfg
        .firewall
        .rules
        .iter()
        .filter(|r| r.action == Action::Dnat && r.dnat_target.is_some())
        .collect();

    // Via-VPN DNS redirection: for every `via_vpn = true` zone,
    // rewrite outbound port-53 (udp + tcp) to the highest-priority
    // vpn_client profile's `dns[0]`. Catches hardcoded-8.8.8.8
    // clients that ignore the DHCP-pushed resolver; their query
    // packet's destination is rewritten to the provider DNS, then
    // the ip rule at the iif layer routes it through the tunnel.
    //
    // When the active profile changes, the DNAT target doesn't —
    // clients transiently resolve via whatever DNS this points at,
    // which is correct for same-provider failover and suboptimal
    // but not leaky for cross-provider. Runtime DNAT rewriting is
    // deferred to a follow-up.
    let via_vpn_dns_target: Option<Ipv4Addr> = cfg
        .vpn_client
        .iter()
        .min_by_key(|v| v.priority)
        .and_then(|v| v.dns.first().copied());
    let need_via_vpn_dns =
        via_vpn_dns_target.is_some() && cfg.firewall.zones.iter().any(|z| z.via_vpn);

    // Partition port forwards by target family. v4 targets land in
    // the v4 `oxwrt-dnat` table; v6 targets get their own
    // `oxwrt-dnat6` table below. Cheap-enough to compute twice (the
    // parse is pure, low-hundreds-of-ns) rather than thread a
    // typed collection through the rustables batch code.
    let any_v4_pf = cfg.port_forwards.iter().any(|pf| {
        parse_dnat_target_any(&pf.internal).is_some_and(|(ip, _)| matches!(ip, IpAddr::V4(_)))
    });
    let any_v6_pf = cfg.port_forwards.iter().any(|pf| {
        parse_dnat_target_any(&pf.internal).is_some_and(|(ip, _)| matches!(ip, IpAddr::V6(_)))
    });

    // Build the DNAT table if EITHER legacy DNAT rules or v4 port-
    // forwards or via_vpn-DNS redirection need it. Three sources,
    // one table. v6 port-forwards go through the v6 section below.
    if !dnat_rules.is_empty() || any_v4_pf || need_via_vpn_dns {
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
        // has a local address (LAN + Simple variants) PLUS every
        // isolated service's host-veth IP. The latter matters for
        // DNS — a service in an isolated netns only has a route to
        // its veth gateway, so when the service resolves a domain it
        // sends the query to the gateway on port 53. Without the
        // host-veth IP in listen_addrs, the DNS DNAT rule wouldn't
        // match that packet and it would drop in the INPUT chain.
        //
        // Observed pre-2026-04-20 as silent degradation: ntp's log
        // spammed "failed to lookup address information" for every
        // pool.ntp.org resolution attempt because 10.123.0.1 (ntp's
        // gateway) wasn't in the DNAT listen set.
        let mut listen_addrs: Vec<Ipv4Addr> = Vec::new();
        for net in &cfg.networks {
            match net {
                Network::Lan { address, .. } | Network::Simple { address, .. } => {
                    listen_addrs.push(*address);
                }
                Network::Wan { .. } => {}
            }
        }
        for svc in &cfg.services {
            if svc.net_mode != oxwrt_api::config::NetMode::Isolated {
                continue;
            }
            if let Some(veth) = &svc.veth {
                listen_addrs.push(veth.host_ip);
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
            let Some((target_any, target_port)) = parse_dnat_target_any(&pf.internal) else {
                tracing::warn!(pf = %pf.name, internal = %pf.internal, "invalid port-forward target; skipping");
                continue;
            };
            // v6 targets are rendered in the `oxwrt-dnat6` section
            // below; skip them here.
            let IpAddr::V4(target_ip) = target_any else {
                continue;
            };
            let src_ifaces = zone_ifaces(cfg, &pf.src);
            if src_ifaces.is_empty() {
                tracing::warn!(pf = %pf.name, src = %pf.src, "port-forward src zone has no ifaces; skipping DNAT");
                continue;
            }
            let protos = proto_to_nf_list(Some(pf.proto));
            let ip_bytes = target_ip.octets().to_vec();
            let port_bytes = target_port.to_be_bytes().to_vec();

            for &proto in &protos {
                for src_if in &src_ifaces {
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
                    r.with_expr(Immediate::new_data(ip_bytes.clone(), Register::Reg1))
                        .with_expr(Immediate::new_data(port_bytes.clone(), Register::Reg2))
                        .with_expr(nat_expr)
                        .add_to_batch(&mut dnat_batch);
                }
            }

            // Hairpin/reflection DNAT. When reflection is enabled:
            //   (a) output chain, dport-only match, DNAT to target —
            //       covers router-originated traffic to its own WAN
            //       IP (rare but legitimate, e.g. the daemon's own
            //       probes).
            //   (b) prerouting chain, daddr = router's LAN/Simple
            //       address + dport — catches a LAN client that
            //       resolved DDNS → WAN IP, sent to router MAC, and
            //       the router received on the LAN bridge.
            //   Companion hairpin SNAT in oxwrt-nat postrouting
            //   forces the return path via the router so the LAN
            //   client sees the correct source IP.
            //
            // Narrowing daddr to listen_addrs avoids catching LAN →
            // LAN traffic that happens to target the same external
            // port on an unrelated host.
            if pf.reflection {
                for &proto in &protos {
                    // (a) output chain — router → WAN IP:external
                    let nat_expr = Nat::default()
                        .with_nat_type(NatType::DNat)
                        .with_family(ProtocolFamily::Ipv4)
                        .with_ip_register(Register::Reg1)
                        .with_port_register(Register::Reg2);
                    let mut r =
                        Rule::new(&dnat_output).map_err(|e| Error::Firewall(e.to_string()))?;
                    r = r.dport(pf.external_port, proto);
                    r.with_expr(Immediate::new_data(ip_bytes.clone(), Register::Reg1))
                        .with_expr(Immediate::new_data(port_bytes.clone(), Register::Reg2))
                        .with_expr(nat_expr)
                        .add_to_batch(&mut dnat_batch);
                    // (b) prerouting, daddr = listen_addrs
                    for &laddr in &listen_addrs {
                        let nat_expr = Nat::default()
                            .with_nat_type(NatType::DNat)
                            .with_family(ProtocolFamily::Ipv4)
                            .with_ip_register(Register::Reg1)
                            .with_port_register(Register::Reg2);
                        let mut r = Rule::new(&prerouting)
                            .map_err(|e| Error::Firewall(e.to_string()))?
                            .daddr(IpAddr::V4(laddr));
                        r = r.dport(pf.external_port, proto);
                        r.with_expr(Immediate::new_data(ip_bytes.clone(), Register::Reg1))
                            .with_expr(Immediate::new_data(port_bytes.clone(), Register::Reg2))
                            .with_expr(nat_expr)
                            .add_to_batch(&mut dnat_batch);
                    }
                }
            }
            tracing::info!(pf = %pf.name, external = pf.external_port, target = %pf.internal, reflection = pf.reflection, "port-forward DNAT emitted");
        }

        // Via-VPN DNS DNAT. Rewrite port-53 from via_vpn zones to
        // the provider DNS. Emitted on the prerouting chain so
        // the rewrite happens before the routing decision (the
        // iif ip rule then diverts the rewritten packet into the
        // VPN table). Both UDP and TCP since some resolvers fall
        // through to TCP on large responses.
        if let Some(vpn_dns) = via_vpn_dns_target {
            let dns_ip_bytes = vpn_dns.octets().to_vec();
            let dns_port_bytes = 53u16.to_be_bytes().to_vec();
            for zone in &cfg.firewall.zones {
                if !zone.via_vpn {
                    continue;
                }
                for zone_if in zone_ifaces(cfg, &zone.name) {
                    for &proto in &[rustables::Protocol::UDP, rustables::Protocol::TCP] {
                        let nat_expr = Nat::default()
                            .with_nat_type(NatType::DNat)
                            .with_family(ProtocolFamily::Ipv4)
                            .with_ip_register(Register::Reg1)
                            .with_port_register(Register::Reg2);
                        Rule::new(&prerouting)
                            .map_err(|e| Error::Firewall(e.to_string()))?
                            .iiface(&zone_if)
                            .map_err(|e| Error::Firewall(e.to_string()))?
                            .dport(53, proto)
                            .with_expr(Immediate::new_data(dns_ip_bytes.clone(), Register::Reg1))
                            .with_expr(Immediate::new_data(dns_port_bytes.clone(), Register::Reg2))
                            .with_expr(nat_expr)
                            .add_to_batch(&mut dnat_batch);
                    }
                    tracing::debug!(zone = %zone.name, iface = %zone_if, target = %vpn_dns, "via_vpn DNS DNAT emitted");
                }
            }
        }

        dnat_batch.send().map_err(|e| {
            tracing::error!(error = %e, "nftables DNAT batch send failed");
            Error::Firewall(e.to_string())
        })?;
        tracing::info!(
            rule_dnat = dnat_rules.len(),
            port_forwards = cfg.port_forwards.len(),
            via_vpn_dns = via_vpn_dns_target.is_some(),
            "nftables DNAT installed"
        );
    }

    // ── 3b. ip6 oxwrt-dnat6: v6 port-forward DNAT ────────────────────
    //
    // Mirror of the v4 oxwrt-dnat table above, scoped to IPv6 targets.
    // Operators who hand out GUA addresses to LAN hosts and want a
    // single port exposed (e.g. a public-facing HTTP service on
    // `[fd00:…::50]:80`) declare `[[port_forwards]]` with a bracketed
    // IPv6 internal; this table handles them. Reflection for v6 works
    // the same as v4: output-chain DNAT covers router-originated
    // traffic, and per-listen-addr prerouting DNAT handles LAN clients
    // that resolve DDNS → router v6 and send to the router MAC.
    if any_v6_pf {
        let dnat6_table = Table::new(ProtocolFamily::Ipv6).with_name("oxwrt-dnat6");
        let mut dnat6_batch = Batch::new();
        dnat6_batch.add(&dnat6_table, MsgType::Add);
        dnat6_batch.add(&dnat6_table, MsgType::Del);
        dnat6_batch.add(&dnat6_table, MsgType::Add);

        let prerouting6 = Chain::new(&dnat6_table)
            .with_name("prerouting")
            .with_hook(Hook::new(HookClass::PreRouting, -100))
            .with_type(ChainType::Nat)
            .with_policy(NfChainPolicy::Accept)
            .add_to_batch(&mut dnat6_batch);
        let dnat6_output = Chain::new(&dnat6_table)
            .with_name("output")
            .with_hook(Hook::new(HookClass::Out, -100))
            .with_type(ChainType::Nat)
            .with_policy(NfChainPolicy::Accept)
            .add_to_batch(&mut dnat6_batch);

        // v6 listen addresses: every LAN/Simple network that carries
        // an ipv6_address. Isolated-service veth IPs are v4-only
        // today (see `svc_resolv`), so no need to extend the set
        // with those here.
        let mut listen_addrs6: Vec<Ipv6Addr> = Vec::new();
        for net in &cfg.networks {
            match net {
                Network::Lan { ipv6_address, .. } | Network::Simple { ipv6_address, .. } => {
                    if let Some(a) = ipv6_address {
                        listen_addrs6.push(*a);
                    }
                }
                Network::Wan { .. } => {}
            }
        }

        for pf in &cfg.port_forwards {
            let Some((target_any, target_port)) = parse_dnat_target_any(&pf.internal) else {
                continue;
            };
            let IpAddr::V6(target_ip) = target_any else {
                continue;
            };
            let src_ifaces = zone_ifaces(cfg, &pf.src);
            if src_ifaces.is_empty() {
                tracing::warn!(pf = %pf.name, src = %pf.src, "v6 port-forward src zone has no ifaces; skipping DNAT");
                continue;
            }
            let protos = proto_to_nf_list(Some(pf.proto));
            let ip_bytes = target_ip.octets().to_vec();
            let port_bytes = target_port.to_be_bytes().to_vec();

            for &proto in &protos {
                for src_if in &src_ifaces {
                    let nat_expr = Nat::default()
                        .with_nat_type(NatType::DNat)
                        .with_family(ProtocolFamily::Ipv6)
                        .with_ip_register(Register::Reg1)
                        .with_port_register(Register::Reg2);
                    let mut r = Rule::new(&prerouting6)
                        .map_err(|e| Error::Firewall(e.to_string()))?
                        .iiface(src_if)
                        .map_err(|e| Error::Firewall(e.to_string()))?;
                    r = r.dport(pf.external_port, proto);
                    r.with_expr(Immediate::new_data(ip_bytes.clone(), Register::Reg1))
                        .with_expr(Immediate::new_data(port_bytes.clone(), Register::Reg2))
                        .with_expr(nat_expr)
                        .add_to_batch(&mut dnat6_batch);
                }
            }

            if pf.reflection {
                for &proto in &protos {
                    // (a) output chain — router → router's v6 addr:external
                    let nat_expr = Nat::default()
                        .with_nat_type(NatType::DNat)
                        .with_family(ProtocolFamily::Ipv6)
                        .with_ip_register(Register::Reg1)
                        .with_port_register(Register::Reg2);
                    let mut r =
                        Rule::new(&dnat6_output).map_err(|e| Error::Firewall(e.to_string()))?;
                    r = r.dport(pf.external_port, proto);
                    r.with_expr(Immediate::new_data(ip_bytes.clone(), Register::Reg1))
                        .with_expr(Immediate::new_data(port_bytes.clone(), Register::Reg2))
                        .with_expr(nat_expr)
                        .add_to_batch(&mut dnat6_batch);
                    // (b) prerouting, daddr = listen_addrs6
                    for &laddr in &listen_addrs6 {
                        let nat_expr = Nat::default()
                            .with_nat_type(NatType::DNat)
                            .with_family(ProtocolFamily::Ipv6)
                            .with_ip_register(Register::Reg1)
                            .with_port_register(Register::Reg2);
                        let mut r = Rule::new(&prerouting6)
                            .map_err(|e| Error::Firewall(e.to_string()))?
                            .daddr(IpAddr::V6(laddr));
                        r = r.dport(pf.external_port, proto);
                        r.with_expr(Immediate::new_data(ip_bytes.clone(), Register::Reg1))
                            .with_expr(Immediate::new_data(port_bytes.clone(), Register::Reg2))
                            .with_expr(nat_expr)
                            .add_to_batch(&mut dnat6_batch);
                    }
                }
            }
            tracing::info!(pf = %pf.name, external = pf.external_port, target = %pf.internal, reflection = pf.reflection, "v6 port-forward DNAT emitted");
        }

        dnat6_batch.send().map_err(|e| {
            tracing::error!(error = %e, "nftables DNAT6 batch send failed");
            Error::Firewall(e.to_string())
        })?;
        tracing::info!(
            v6_port_forwards = cfg
                .port_forwards
                .iter()
                .filter(|p| parse_dnat_target_any(&p.internal)
                    .is_some_and(|(ip, _)| matches!(ip, IpAddr::V6(_))))
                .count(),
            "nftables DNAT6 installed"
        );
    }

    // Scheduled firewall rules: each [[firewall.rules]] with a
    // `schedule` field bypasses the rustables path and renders as
    // nft text, piped through `nft -f -` alongside raw_nft. nft's
    // `meta day` + `meta hour` predicates enforce the window —
    // no userspace timer, the kernel flips the rule in/out
    // naturally.
    let scheduled_script = build_scheduled_rules_script(cfg);
    let forwardings_script = build_forwardings_script(cfg);

    // Baseline defaults: ct state, ICMPv6 NDP/MLD, ICMP echo —
    // these are unconditional and emitted in text (rustables has
    // no clean builder for ct-state or icmpv6 type). Prepended
    // so they land before operator rules in the chain order.
    let baseline_script = build_baseline_defaults_script(cfg);

    // IP sets: declare every `[[ipsets]]` entry as an nftables
    // named set inside `inet oxwrt`, then populate it. Emitted
    // BEFORE any rule that might reference `@<setname>` via a
    // `match_set = { … }` predicate — `nft -f -` processes its
    // input top-to-bottom and a forward reference to an unknown
    // set would reject the whole script.
    let ipsets_prologue = build_ipsets_prologue(cfg);

    // Raw-nft escape hatch: pipe every [[firewall.raw_nft]] entry
    // through `nft -f -` once the structured batches have all
    // landed. Non-fatal if nft is missing or a rule fails to
    // parse — we log and continue, because a bad raw-rule line
    // shouldn't prevent the rest of the firewall from coming up.
    // The operator's fix is an oxwrt.toml edit + reload.
    let combined =
        format!("{ipsets_prologue}{baseline_script}{forwardings_script}{scheduled_script}");
    if !cfg.firewall.raw_nft.is_empty() || !combined.is_empty() {
        apply_nft_text(&cfg.firewall.raw_nft, &combined);
    }

    Ok(())
}

/// Baseline nft rules every oxwrt firewall installs. Rendered as
/// text because most primitives here (ct-state, icmpv6 type,
/// TCP-flags, MSS clamping) have no clean rustables builder.
/// Emitted BEFORE the operator's text rules so they land first in
/// each chain — nft evaluates top-down and first verdict wins.
///
/// Takes `cfg` so per-config knobs can gate: `synflood_protect`,
/// `drop_invalid` (both in `firewall.defaults`), and per-zone
/// `mtu_fix` (TCP MSS clamping).
pub(crate) fn build_baseline_defaults_script(cfg: &Config) -> String {
    let mut s = String::new();
    let defaults = &cfg.firewall.defaults;
    // ct state established,related → accept. fw4-equivalent of
    // "option input ACCEPT but only for return traffic".
    for chain in ["input", "forward", "output"] {
        s.push_str(&format!(
            "add rule inet oxwrt {chain} ct state established,related accept\n"
        ));
    }
    // ct state invalid → drop. TCP out-of-window, post-RST
    // noise, unexpected ACKs — nothing legitimate matches.
    // Gated on `defaults.drop_invalid` (default true; on matches
    // fw4 behaviour). Off trades the belt for tcpdump-visibility.
    if defaults.drop_invalid {
        for chain in ["input", "forward"] {
            s.push_str(&format!(
                "add rule inet oxwrt {chain} ct state invalid drop\n"
            ));
        }
    }
    // SYN flood protection: rate-limit new-state TCP SYNs on
    // INPUT to 25/second with burst 50. Overflow drops. Matches
    // fw4's `synflood_protect = 1` default. Guards the router's
    // own listeners (sQUIC control plane, in-router DNS) — the
    // FORWARD chain doesn't need this because forwarded SYN
    // floods are an end-host problem.
    //
    // Expression: SYN-only flag mask, so the rule matches only
    // the initial SYN (not SYN-ACK return traffic).
    if defaults.synflood_protect {
        s.push_str(
            "add rule inet oxwrt input tcp flags syn ct state new \
             limit rate over 25/second burst 50 packets drop\n",
        );
    }
    // ICMPv6 NDP: neighbour + router discovery. Without these,
    // v6 neighbor resolution breaks and nothing works.
    let ndp_types = [
        "nd-neighbor-solicit",
        "nd-neighbor-advert",
        "nd-router-solicit",
        "nd-router-advert",
        "nd-redirect",
    ];
    for chain in ["input", "forward", "output"] {
        for t in &ndp_types {
            s.push_str(&format!(
                "add rule inet oxwrt {chain} icmpv6 type {t} accept\n"
            ));
        }
        // MLD (multicast listener discovery): essential for IPv6
        // multicast group joins — SSDP, mDNS-over-v6, RA-consuming
        // hosts all need it.
        s.push_str(&format!(
            "add rule inet oxwrt {chain} icmpv6 type {{ mld-listener-query, mld-listener-report, mld-listener-done, mld2-listener-report }} accept\n"
        ));
        // PMTU discovery. Silently dropping packet-too-big is a
        // classic "the web is slow over this VPN" footgun.
        s.push_str(&format!(
            "add rule inet oxwrt {chain} icmpv6 type packet-too-big accept\n"
        ));
    }
    // ICMP echo-request (ping). Accept on INPUT so the router
    // answers pings from anywhere — diagnostic value > noise.
    // Operators who want to drop WAN pings add an explicit rule
    // with higher-priority iifname=wan drop ahead of this.
    s.push_str("add rule inet oxwrt input icmp type echo-request accept\n");
    s.push_str("add rule inet oxwrt input icmpv6 type echo-request accept\n");
    // TCP MSS clamping per zone with `mtu_fix = true`. Rewrites
    // the SYN packet's MSS option to the path MTU minus 40 so
    // downstream fragmentation / path-MTU-black-hole problems
    // stop on arrival. Emitted in the FORWARD chain matched on
    // both iifname and oifname of each zone member iface — zone
    // traffic in either direction gets clamped.
    //
    // `size set rt mtu` is nft's native "use the routing decision's
    // MTU" helper, equivalent to iptables TCPMSS --clamp-mss-to-pmtu.
    // Needs the `rt` module at kernel level; present in any
    // reasonably-recent mainline kernel (5.x+).
    for zone in &cfg.firewall.zones {
        if !zone.mtu_fix {
            continue;
        }
        for iface in zone_ifaces(cfg, &zone.name) {
            s.push_str(&format!(
                "add rule inet oxwrt forward iifname \"{iface}\" tcp flags syn \
                 tcp option maxseg size set rt mtu\n"
            ));
            s.push_str(&format!(
                "add rule inet oxwrt forward oifname \"{iface}\" tcp flags syn \
                 tcp option maxseg size set rt mtu\n"
            ));
        }
    }
    s
}

/// Render family-restricted `[[firewall.forwardings]]` entries as
/// nft text. Family=Any forwardings went through the rustables
/// batch above; v4-/v6-pinned ones need the `meta nfproto` match
/// which rustables doesn't expose cleanly, so they land here.
///
/// Each entry becomes one `add rule inet oxwrt forward iifname
/// "<src>" oifname "<dest>" meta nfproto ipv4 accept` per
/// (src-iface, dest-iface) pair. Zones with multiple ifaces
/// expand the cartesian product.
pub(crate) fn build_forwardings_script(cfg: &Config) -> String {
    use oxwrt_api::config::Family;
    let mut out = String::new();
    for fwd in &cfg.firewall.forwardings {
        if fwd.family == Family::Any {
            continue; // handled by the rustables path
        }
        let family_str = match fwd.family {
            Family::Ipv4 => "ipv4",
            Family::Ipv6 => "ipv6",
            Family::Any => unreachable!(),
        };
        let src_ifaces = zone_ifaces(cfg, &fwd.src);
        let dest_ifaces = zone_ifaces(cfg, &fwd.dest);
        if src_ifaces.is_empty() || dest_ifaces.is_empty() {
            continue;
        }
        for src_if in &src_ifaces {
            for dest_if in &dest_ifaces {
                out.push_str(&format!(
                    "add rule inet oxwrt forward iifname \"{src_if}\" oifname \"{dest_if}\" \
                     meta nfproto {family_str} accept\n"
                ));
            }
        }
    }
    out
}

/// Render every `[[ipsets]]` entry as an nft `add set …` + `add
/// element …` pair inside the existing `inet oxwrt` table. Sets are
/// idempotent under `nft -f -`: the prior `Del`/`Add` of the inet
/// table in the rustables batch wipes any leftover set definition
/// before we reach this script, so there's no "set already exists"
/// race.
///
/// Format notes:
/// - `type ipv4_addr` / `type ipv6_addr` depending on `family`.
/// - `flags interval` auto-enabled when any entry contains `/` (CIDR).
///   nft refuses prefix matches on non-interval sets; auto-detecting
///   avoids a `set must have flag interval to add CIDR` footgun that
///   would otherwise only surface at reload time.
/// - `timeout` applies to the SET (default expiry); elements inherit
///   unless they specify their own. Config keeps it simple: one
///   timeout per set, every element expires the same way.
///
/// Empty `entries` is legal — the set is still declared so rules
/// referencing it parse cleanly; they just never match until an
/// element arrives (future `oxctl ipset add` RPC).
pub(crate) fn build_ipsets_prologue(cfg: &Config) -> String {
    use oxwrt_api::config::Family;
    let mut out = String::new();
    for set in &cfg.ipsets {
        let type_str = match set.family {
            Family::Ipv4 => "ipv4_addr",
            Family::Ipv6 => "ipv6_addr",
            // `any` isn't a valid nft set family. The validator
            // rejects this at reload; we defensively skip here so
            // a misconfigured entry doesn't emit garbage nft.
            Family::Any => {
                tracing::warn!(set = %set.name, "ipset family=any is invalid; skipping");
                continue;
            }
        };
        let needs_interval = set.entries.iter().any(|e| e.contains('/'));
        let mut flags: Vec<&str> = Vec::new();
        if needs_interval {
            flags.push("interval");
        }
        let mut spec = format!("type {type_str}; ");
        if !flags.is_empty() {
            spec.push_str(&format!("flags {}; ", flags.join(",")));
        }
        if let Some(to) = set.timeout.as_deref() {
            spec.push_str(&format!("timeout {}; ", to.trim()));
        }
        out.push_str(&format!(
            "add set inet oxwrt {} {{ {} }}\n",
            set.name,
            spec.trim_end()
        ));
        if !set.entries.is_empty() {
            let elements = set.entries.join(", ");
            out.push_str(&format!(
                "add element inet oxwrt {} {{ {} }}\n",
                set.name, elements
            ));
        }
    }
    out
}

/// Build the `nft -f -` script for every rule that carries a
/// `schedule` field. Rules without schedules go through the
/// rustables batch in install_firewall; this path only picks up
/// the scheduled ones.
///
/// Rendered to the `inet oxwrt` `forward` chain (the common
/// zone-crossing chain). DNAT + scheduled is out of scope v1 —
/// port forwards with time windows would need their own path
/// into `ip oxwrt-dnat`.
///
/// Malformed schedules are skipped with a warn. The reload-dry-
/// run validator catches them earlier; this is belt + braces for
/// a reload triggered by an external path.
pub(crate) fn build_scheduled_rules_script(cfg: &Config) -> String {
    use oxwrt_api::firewall_schedule::{parse_schedule, render_nft_predicate};
    let mut out = String::new();
    for rule in &cfg.firewall.rules {
        if !rule.enabled {
            continue;
        }
        // We cover every rule that needs the text path here, not
        // just `schedule`. Rules with `src_ip` / `dest_ip` /
        // `src_mac` / `src_port` / `icmp_type` / `limit` / `log`
        // / `family != any` all render as text too — they share
        // the same nft syntax machinery as scheduled rules.
        if !rule_needs_text_path(rule) {
            continue;
        }

        // Target chain: FORWARD when both src + dest zones set,
        // INPUT when only src, OUTPUT when only dest (i.e.
        // router-originated traffic to a zone), both when
        // neither. Mirrors the rustables-path logic.
        let target_chains: &[&str] = if rule.src.is_some() && rule.dest.is_some() {
            &["forward"]
        } else if rule.src.is_some() {
            &["input"]
        } else if rule.dest.is_some() {
            &["output"]
        } else {
            &["input", "forward"]
        };

        // Optional schedule prefix (when the rule also has a
        // time window). Parsed once; we only emit for the
        // chains we target above.
        let sched_frag: Option<String> =
            rule.schedule
                .as_deref()
                .and_then(|s| match parse_schedule(s) {
                    Ok(sc) => Some(render_nft_predicate(&sc)),
                    Err(e) => {
                        tracing::warn!(
                            rule = %rule.name,
                            schedule = %s,
                            error = %e,
                            "rule: schedule parse failed; skipping rule"
                        );
                        None
                    }
                });
        // Parse failure on a scheduled rule: skip entirely so we
        // don't emit a rule missing its time gate.
        if rule.schedule.is_some() && sched_frag.is_none() {
            continue;
        }

        for chain in target_chains {
            out.push_str(&format!("add rule inet oxwrt {chain} "));
            if let Some(sf) = sched_frag.as_deref() {
                out.push_str(sf);
            }
            render_rule_body(&mut out, rule, cfg);
            out.push('\n');
        }
    }
    out
}

/// Append the nft predicate + action for a rule's fields. Shared
/// by the scheduled-rule renderer AND the advanced-primitive
/// renderer — any rule that `rule_needs_text_path` picks up goes
/// through here.
///
/// Emission order follows nft's parser expectations: iifname →
/// oifname → family-specific address matches → mac → ct state →
/// l4proto+ports → icmp type → limit → log → verdict.
fn render_rule_body(out: &mut String, rule: &oxwrt_api::config::Rule, cfg: &Config) {
    use oxwrt_api::config::{Action, Family};
    // Raw `device` match wins over the zone lookup. Used when a
    // rule targets a single iface not captured by any zone (a
    // fresh wg tunnel, a debug iface). When both `device` and
    // `src` are set, device's iif match takes precedence; src is
    // silently ignored — the validator warns on the overlap.
    if let Some(dev) = rule.device.as_deref() {
        out.push_str(&format!("iifname \"{dev}\" "));
    } else if let Some(src) = rule.src.as_deref() {
        let ifaces = zone_ifaces(cfg, src);
        if !ifaces.is_empty() {
            out.push_str(&fmt_iifname(&ifaces, /*oif=*/ false));
            out.push(' ');
        }
    }
    if let Some(dest) = rule.dest.as_deref() {
        let ifaces = zone_ifaces(cfg, dest);
        if !ifaces.is_empty() {
            out.push_str(&fmt_iifname(&ifaces, /*oif=*/ true));
            out.push(' ');
        }
    }
    // src_ip / dest_ip. Family is auto-detected per entry; we
    // emit `ip saddr` for v4 entries and `ip6 saddr` for v6.
    // When `family` is explicitly set, we still match that
    // family's addresses — a mismatch (e.g. v6 CIDRs with
    // family=ipv4) is caught by the validator.
    emit_addr_match(out, &rule.src_ip, /*is_src=*/ true, rule.family);
    emit_addr_match(out, &rule.dest_ip, /*is_src=*/ false, rule.family);
    // Named ipset match — render as `ip saddr @set` / `ip6 daddr
    // != @set` etc. The set's family (looked up on cfg.ipsets) drives
    // the `ip` vs `ip6` prefix; direction drives saddr/daddr; `negate`
    // inserts `!=`. Unknown set names were supposed to be caught by
    // the validator — if we reach this branch with an unresolvable
    // name, log and skip (emitting `@unknown` would produce an nft
    // parse error that rejects the whole script).
    if let Some(ms) = rule.match_set.as_ref() {
        emit_match_set(out, ms, cfg);
    }
    if !rule.src_mac.is_empty() {
        if rule.src_mac.len() == 1 {
            out.push_str(&format!("ether saddr {} ", rule.src_mac[0]));
        } else {
            let list = rule.src_mac.join(", ");
            out.push_str(&format!("ether saddr {{ {list} }} "));
        }
    }
    // ct state must precede proto for nft's parser to be happy.
    if !rule.ct_state.is_empty() {
        out.push_str("ct state { ");
        out.push_str(&rule.ct_state.join(", "));
        out.push_str(" } ");
    }
    // Family restriction without addresses: emit `meta nfproto`
    // when the rule asked for a specific family but has no
    // src_ip/dest_ip to carry it. Without this, family=ipv6
    // would match v4 traffic too.
    if rule.src_ip.is_empty() && rule.dest_ip.is_empty() {
        match rule.family {
            Family::Ipv4 => out.push_str("meta nfproto ipv4 "),
            Family::Ipv6 => out.push_str("meta nfproto ipv6 "),
            Family::Any => {}
        }
    }
    render_proto_port(out, rule);
    if let Some(icmp_t) = rule.icmp_type.as_deref() {
        // Heuristic: ICMPv6 type names start with "nd-" or "mld" or
        // contain "router-" / "packet-too-big". Use icmpv6 keyword
        // for those, icmp for the rest.
        let is_v6 = icmp_t.starts_with("nd-")
            || icmp_t.starts_with("mld")
            || icmp_t == "packet-too-big"
            || icmp_t == "router-solicit"
            || icmp_t == "router-advertisement"
            || rule.family == Family::Ipv6;
        let kw = if is_v6 { "icmpv6" } else { "icmp" };
        out.push_str(&format!("{kw} type {icmp_t} "));
    }
    // src port: after proto+dport so nft's parser sees the base
    // proto first. Emitted as `<proto> sport <ports>` or
    // `meta l4proto { tcp, udp } th sport ...` for Both.
    if let Some(sport) = &rule.src_port {
        let proto = rule.proto.unwrap_or(oxwrt_api::config::Proto::Tcp);
        let port_fragment = render_port_fragment(sport);
        match proto {
            Proto::Tcp => out.push_str(&format!("tcp sport {port_fragment} ")),
            Proto::Udp => out.push_str(&format!("udp sport {port_fragment} ")),
            Proto::Both => out.push_str(&format!("th sport {port_fragment} ")),
            Proto::Icmp => {} // icmp has no sport
        }
    }
    if let Some(limit_str) = rule.limit.as_deref() {
        // nft accepts the same "N/second" etc. syntax literally,
        // so we pass through verbatim (stripped of whitespace).
        // Optional burst suffix: `burst N packets` after the rate.
        let clean = limit_str.trim();
        match rule.limit_burst {
            Some(n) => out.push_str(&format!("limit rate {clean} burst {n} packets ")),
            None => out.push_str(&format!("limit rate {clean} ")),
        }
    }
    if let Some(log_prefix) = rule.log.as_deref() {
        // Cap prefix at 128 chars — nft silently truncates, but
        // we want the log to match what the operator typed.
        let p = if log_prefix.is_empty() {
            String::new()
        } else {
            format!(
                "prefix \"{}\" ",
                log_prefix.chars().take(128).collect::<String>()
            )
        };
        out.push_str(&format!("log {p}"));
    }
    // Per-rule counter. nft's `counter` keyword goes before the
    // verdict; tracked by the kernel and surfaced via `nft list
    // ruleset` / future `oxctl diag firewall`.
    if rule.counter {
        out.push_str("counter ");
    }
    match rule.action {
        Action::Accept => out.push_str("accept"),
        Action::Drop => out.push_str("drop"),
        Action::Reject => {
            // Optional reject reason: `reject with tcp reset`,
            // `reject with icmp type port-unreachable`, etc. nft
            // accepts the string after `with` verbatim, so the
            // config passes through. Bare `reject` when unset
            // uses the platform default (icmp-port-unreachable
            // for IPv4, icmpv6-port-unreachable for IPv6).
            match rule.reject_with.as_deref() {
                Some(reason) => out.push_str(&format!("reject with {}", reason.trim())),
                None => out.push_str("reject"),
            }
        }
        Action::Dnat => out.push_str("# dnat via text path unsupported — use [[port_forwards]]"),
    }
}

/// Emit `ip saddr` / `ip6 daddr` / etc. for a list of CIDR strings.
/// v4 + v6 entries in the same list are split into two predicates
/// (nft needs the family prefix). Single entry → bare match; multiple
/// of the same family → anonymous set.
fn emit_addr_match(
    out: &mut String,
    addrs: &[String],
    is_src: bool,
    family: oxwrt_api::config::Family,
) {
    use oxwrt_api::config::Family;
    if addrs.is_empty() {
        return;
    }
    let dir = if is_src { "saddr" } else { "daddr" };
    let (v4, v6): (Vec<&String>, Vec<&String>) = addrs.iter().partition(|a| !a.contains(':'));
    // Filter by declared family restriction, if any.
    let emit_v4 = family != Family::Ipv6 && !v4.is_empty();
    let emit_v6 = family != Family::Ipv4 && !v6.is_empty();
    if emit_v4 {
        if v4.len() == 1 {
            out.push_str(&format!("ip {dir} {} ", v4[0]));
        } else {
            let list = v4.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ");
            out.push_str(&format!("ip {dir} {{ {list} }} "));
        }
    }
    if emit_v6 {
        if v6.len() == 1 {
            out.push_str(&format!("ip6 {dir} {} ", v6[0]));
        } else {
            let list = v6.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ");
            out.push_str(&format!("ip6 {dir} {{ {list} }} "));
        }
    }
}

/// Emit `ip saddr @set`, `ip6 daddr != @set`, etc. for a named ipset
/// reference. Family comes from the set definition, not the rule —
/// the rule's `family` restriction is enforced separately via the
/// address-family `meta nfproto` prefix upstream.
fn emit_match_set(out: &mut String, ms: &oxwrt_api::config::MatchSet, cfg: &Config) {
    use oxwrt_api::config::{Family, MatchSetDir};
    let Some(set) = cfg.ipsets.iter().find(|s| s.name == ms.name) else {
        tracing::warn!(set = %ms.name, "rule references unknown ipset; skipping match");
        return;
    };
    let prefix = match set.family {
        Family::Ipv4 => "ip",
        Family::Ipv6 => "ip6",
        Family::Any => {
            tracing::warn!(set = %ms.name, "ipset family=any is invalid; skipping match");
            return;
        }
    };
    let dir = match ms.direction {
        MatchSetDir::Src => "saddr",
        MatchSetDir::Dst => "daddr",
    };
    let op = if ms.negate { "!= " } else { "" };
    out.push_str(&format!("{prefix} {dir} {op}@{} ", ms.name));
}

/// Render just the `<proto> dport <port>` (or Both / ICMP) fragment.
/// Split out so render_rule_body stays readable.
fn render_proto_port(out: &mut String, rule: &oxwrt_api::config::Rule) {
    if let Some(proto) = rule.proto {
        let proto_s = match proto {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
            Proto::Icmp => "icmp",
            Proto::Both => "meta-both",
        };
        if proto_s == "meta-both" {
            if let Some(port) = &rule.dest_port {
                let port_fragment = render_port_fragment(port);
                out.push_str(&format!(
                    "meta l4proto {{ tcp, udp }} th dport {port_fragment} "
                ));
            } else {
                out.push_str("meta l4proto { tcp, udp } ");
            }
        } else if let Some(port) = &rule.dest_port {
            let port_fragment = render_port_fragment(port);
            out.push_str(&format!("{proto_s} dport {port_fragment} "));
        } else if proto != Proto::Icmp {
            // ICMP doesn't need the meta prefix — icmp type match
            // handles it. Emit meta l4proto only for tcp/udp.
            // This branch is the "proto-only" rule: rustables path
            // silently skipped these (firewall.rs "Proto but no port
            // — skip silently"), so rule_needs_text_path routes them
            // here to get `meta l4proto tcp` / `… udp` rendered.
            out.push_str(&format!("meta l4proto {proto_s} "));
        }
    }
}

/// Render a port match value to the nft syntax fragment. `Single` =
/// bare integer, `List` = `{ 22, 53, 80 }` anonymous set, `Range` =
/// `22-80` native nft range syntax.
///
/// Range strings are assumed pre-validated (by `check_rule_zone_refs`
/// calling `PortSpec::parse_range`). A malformed range that reaches
/// here emits the literal string — nft will reject the whole script
/// and the error lands in the operator's reload log.
fn render_port_fragment(spec: &PortSpec) -> String {
    match spec {
        PortSpec::Single(p) => format!("{p}"),
        PortSpec::List(ps) => format!(
            "{{ {} }}",
            ps.iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ),
        PortSpec::Range(s) => {
            // Re-parse into canonical `A-B` form so stray whitespace
            // doesn't leak into the nft script (`"22 - 80"` works in
            // config, but nft wants `22-80`).
            match PortSpec::parse_range(s) {
                Ok((a, b)) => format!("{a}-{b}"),
                Err(_) => s.clone(),
            }
        }
    }
}

fn fmt_iifname(ifaces: &[String], oif: bool) -> String {
    let key = if oif { "oifname" } else { "iifname" };
    if ifaces.len() == 1 {
        format!("{key} \"{}\"", ifaces[0])
    } else {
        let list = ifaces
            .iter()
            .map(|i| format!("\"{i}\""))
            .collect::<Vec<_>>()
            .join(", ");
        format!("{key} {{ {list} }}")
    }
}

/// Render the `nft -f -` script for a slice of raw entries. Split
/// out for testability — `apply_raw_nft` handles the actual
/// subprocess glue.
pub(crate) fn build_raw_nft_script(entries: &[oxwrt_api::config::RawNft]) -> String {
    let mut s = String::new();
    for e in entries {
        s.push_str(&format!("add rule {} {} {}\n", e.table, e.chain, e.rule));
    }
    s
}

/// Pipe the concatenated (raw-nft + scheduled-rule) script
/// through `nft -f -`. One invocation for both, so rule ordering
/// stays deterministic: scheduled-rule lines sit below raw_nft
/// ones (operators expect their raw escape hatches to land
/// first).
fn apply_nft_text(entries: &[oxwrt_api::config::RawNft], scheduled_script: &str) {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let mut script = build_raw_nft_script(entries);
    script.push_str(scheduled_script);
    if script.is_empty() {
        return;
    }

    let mut child = match Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(
                error = %e,
                entries = entries.len(),
                "raw_nft: couldn't invoke `nft` binary; skipping"
            );
            return;
        }
    };
    if let Some(mut stdin) = child.stdin.take() {
        if let Err(e) = stdin.write_all(script.as_bytes()) {
            tracing::error!(error = %e, "raw_nft: stdin write failed");
            return;
        }
    }
    let out = match child.wait_with_output() {
        Ok(o) => o,
        Err(e) => {
            tracing::error!(error = %e, "raw_nft: wait failed");
            return;
        }
    };
    if !out.status.success() {
        tracing::error!(
            status = ?out.status.code(),
            stderr = %String::from_utf8_lossy(&out.stderr).trim(),
            entries = entries.len(),
            "raw_nft: `nft -f -` exited non-zero; one or more rules rejected"
        );
    } else {
        tracing::info!(count = entries.len(), "raw_nft: installed");
    }
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
                // ICMP rules + no-port-no-proto rules both render as
                // bare iif+action (no proto/dport bits to add).
                if is_icmp || (ports.is_empty() && protos.is_empty()) {
                    out.push(format!(
                        "    iif \"{src_if}\" {action_str}   # {}",
                        rule.name
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

/// IPv6 analogue of `find_dest_zone_for_ip`. Matches the target v6
/// address against every LAN/Simple network's `(ipv6_address,
/// ipv6_prefix)` pair; returns the first firewall zone whose
/// `networks` list references a matching network. Used by v6 port-
/// forward hairpin SNAT to discover the dest zone when the operator
/// hasn't pinned `dest` explicitly.
fn find_dest_zone_for_ipv6(cfg: &Config, ip: Ipv6Addr) -> Option<String> {
    for net in &cfg.networks {
        let (net_name, subnet_ip, prefix) = match net {
            Network::Lan {
                name,
                ipv6_address,
                ipv6_prefix,
                ..
            }
            | Network::Simple {
                name,
                ipv6_address,
                ipv6_prefix,
                ..
            } => {
                let Some(addr) = ipv6_address else { continue };
                let prefix = ipv6_prefix.unwrap_or(64);
                (name.as_str(), *addr, prefix)
            }
            Network::Wan { .. } => continue,
        };
        if !ipv6_in_subnet(ip, subnet_ip, prefix) {
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

fn ipv6_in_subnet(ip: Ipv6Addr, subnet: Ipv6Addr, prefix: u8) -> bool {
    if prefix > 128 {
        return false;
    }
    if prefix == 0 {
        return true;
    }
    let ip_bits = u128::from(ip);
    let sn_bits = u128::from(subnet);
    let mask: u128 = u128::MAX.checked_shl(128 - prefix as u32).unwrap_or(0);
    (ip_bits & mask) == (sn_bits & mask)
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
pub fn zone_ifaces(cfg: &Config, zone_name: &str) -> Vec<String> {
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
        // Range on the rustables path: `rule_needs_text_path` is
        // supposed to shunt these to text rendering (nft accepts
        // `tcp dport A-B` natively; rustables has no range builder
        // and expanding would emit hundreds of rules). Reaching
        // here means either a caller forgot to filter or a new
        // call-site was added without the guard — return empty so
        // the rustables emit loop skips cleanly rather than
        // fabricating bogus single-port rules.
        Some(PortSpec::Range(_)) => vec![],
    }
}

/// Parse a DNAT target string "ip:port" into (Ipv4Addr, u16). Used
/// only by legacy `[[firewall.rules]] action="dnat"` entries, which
/// are v4-only by design (operators wanting v6 port-forwards use
/// `[[port_forwards]]` with bracketed syntax). Kept distinct from
/// `parse_dnat_target_any` so the legacy path can't accidentally
/// accept a v6 literal and try to install it into the v4 table.
fn parse_dnat_target(s: &str) -> Option<(Ipv4Addr, u16)> {
    let (ip_str, port_str) = s.rsplit_once(':')?;
    let ip = ip_str.parse::<Ipv4Addr>().ok()?;
    let port = port_str.parse::<u16>().ok()?;
    Some((ip, port))
}

/// Parse a port-forward `internal` string into (IpAddr, u16). Accepts
/// both forms:
/// - `1.2.3.4:80` → IPv4
/// - `[fd00:dead:beef::5]:80` → IPv6 (brackets required for unambiguous
///   port separation)
///
/// Implementation leans on `SocketAddr::from_str`, which handles both
/// shapes natively. Returns None for any parse failure (malformed
/// address, missing port, out-of-range port, unbracketed v6).
pub(crate) fn parse_dnat_target_any(s: &str) -> Option<(IpAddr, u16)> {
    let sa: std::net::SocketAddr = s.parse().ok()?;
    Some((sa.ip(), sa.port()))
}

/// Convention for the host-side end of a service's veth pair, defined
/// once here and matching `container::PreparedContainer`'s naming.
fn veth_host_name(svc: &Service) -> String {
    format!("veth-{}", svc.name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_nft_script_renders_one_line_per_entry() {
        let entries = vec![
            oxwrt_api::config::RawNft {
                table: "inet oxwrt".into(),
                chain: "forward".into(),
                rule: "ct state new tcp dport 22 accept".into(),
            },
            oxwrt_api::config::RawNft {
                table: "ip oxwrt-nat".into(),
                chain: "postrouting".into(),
                rule: "oifname \"wg0\" masquerade".into(),
            },
        ];
        let script = build_raw_nft_script(&entries);
        assert_eq!(script.lines().count(), 2);
        assert!(script.contains("add rule inet oxwrt forward ct state new tcp dport 22 accept"));
        assert!(script.contains("add rule ip oxwrt-nat postrouting"));
    }

    #[test]
    fn raw_nft_script_empty_on_no_entries() {
        assert!(build_raw_nft_script(&[]).is_empty());
    }

    fn basic_rule(name: &str) -> oxwrt_api::config::Rule {
        oxwrt_api::config::Rule {
            name: name.into(),
            enabled: true,
            family: oxwrt_api::config::Family::Any,
            src: None,
            dest: None,
            src_ip: vec![],
            dest_ip: vec![],
            src_mac: vec![],
            src_port: None,
            proto: None,
            dest_port: None,
            icmp_type: None,
            ct_state: vec![],
            limit: None,
            log: None,
            action: oxwrt_api::config::Action::Accept,
            dnat_target: None,
            schedule: None,
            match_set: None,
            counter: false,
            limit_burst: None,
            reject_with: None,
            device: None,
        }
    }

    #[test]
    fn rule_needs_text_path_detects_advanced_primitives() {
        let mut r = basic_rule("t");
        assert!(!rule_needs_text_path(&r));
        r.src_ip = vec!["192.168.1.1".into()];
        assert!(rule_needs_text_path(&r));
        r = basic_rule("t");
        r.limit = Some("10/second".into());
        assert!(rule_needs_text_path(&r));
        r = basic_rule("t");
        r.icmp_type = Some("echo-request".into());
        assert!(rule_needs_text_path(&r));
        r = basic_rule("t");
        r.family = oxwrt_api::config::Family::Ipv6;
        assert!(rule_needs_text_path(&r));
    }

    #[test]
    fn disabled_rules_emit_nothing() {
        let mut cfg = minimal_config();
        let mut r = basic_rule("disabled");
        r.enabled = false;
        r.src_ip = vec!["10.0.0.0/8".into()]; // would take text path if enabled
        r.action = oxwrt_api::config::Action::Drop;
        cfg.firewall.rules.push(r);
        let s = build_scheduled_rules_script(&cfg);
        assert!(s.is_empty(), "disabled rule leaked into script: {s}");
    }

    #[test]
    fn render_src_ip_v4_cidr_accept() {
        let mut cfg = minimal_config();
        let mut r = basic_rule("allow-mgmt");
        r.src_ip = vec!["192.168.50.10/32".into()];
        r.proto = Some(oxwrt_api::config::Proto::Tcp);
        r.dest_port = Some(PortSpec::Single(22));
        r.action = oxwrt_api::config::Action::Accept;
        cfg.firewall.rules.push(r);
        let s = build_scheduled_rules_script(&cfg);
        // Global rule (no src/dest zone) renders into both input + forward.
        assert!(
            s.contains("add rule inet oxwrt input ip saddr 192.168.50.10/32 tcp dport 22 accept")
        );
        assert!(
            s.contains("add rule inet oxwrt forward ip saddr 192.168.50.10/32 tcp dport 22 accept")
        );
    }

    #[test]
    fn render_v6_family_only_nfproto_prefix() {
        let mut cfg = minimal_config();
        let mut r = basic_rule("icmpv6-ndp");
        r.family = oxwrt_api::config::Family::Ipv6;
        r.proto = Some(oxwrt_api::config::Proto::Icmp);
        r.icmp_type = Some("nd-neighbor-solicit".into());
        r.action = oxwrt_api::config::Action::Accept;
        cfg.firewall.rules.push(r);
        let s = build_scheduled_rules_script(&cfg);
        // meta nfproto ipv6 prefix present + icmpv6 type selector.
        assert!(
            s.contains("meta nfproto ipv6"),
            "expected v6 family prefix: {s}"
        );
        assert!(
            s.contains("icmpv6 type nd-neighbor-solicit"),
            "expected icmpv6 type: {s}"
        );
    }

    #[test]
    fn render_limit_and_log_prefix() {
        let mut cfg = minimal_config();
        let mut r = basic_rule("rate-ssh");
        r.proto = Some(oxwrt_api::config::Proto::Tcp);
        r.dest_port = Some(PortSpec::Single(22));
        r.limit = Some("3/minute".into());
        r.log = Some("ssh-flood ".into());
        r.action = oxwrt_api::config::Action::Drop;
        cfg.firewall.rules.push(r);
        let s = build_scheduled_rules_script(&cfg);
        assert!(s.contains("limit rate 3/minute"), "missing limit: {s}");
        assert!(
            s.contains("log prefix \"ssh-flood \""),
            "missing log prefix: {s}"
        );
        // Emission order: limit before log before verdict.
        let li = s.find("limit rate").unwrap();
        let lo = s.find("log prefix").unwrap();
        let dr = s.find(" drop").unwrap();
        assert!(li < lo && lo < dr, "expected limit < log < drop order: {s}");
    }

    #[test]
    fn render_src_mac_set() {
        let mut cfg = minimal_config();
        let mut r = basic_rule("printer-bypass");
        r.src_mac = vec!["aa:bb:cc:dd:ee:ff".into(), "11:22:33:44:55:66".into()];
        r.action = oxwrt_api::config::Action::Accept;
        cfg.firewall.rules.push(r);
        let s = build_scheduled_rules_script(&cfg);
        assert!(
            s.contains("ether saddr { aa:bb:cc:dd:ee:ff, 11:22:33:44:55:66 }"),
            "{s}"
        );
    }
    use oxwrt_api::config::{Config, Control, Firewall, Network, PortSpec, Proto, Service, Zone};
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
                    vlan_filtering: false,
                    vlan_ports: vec![],
                    address: Ipv4Addr::new(192, 168, 1, 1),
                    prefix: 24,
                    ipv6_address: None,
                    ipv6_prefix: None,
                    ipv6_subnet_id: None,
                    router_advertisements: None,
                },
                Network::Simple {
                    name: "guest".to_string(),
                    iface: "br-guest".to_string(),
                    address: Ipv4Addr::new(10, 99, 0, 1),
                    prefix: 24,
                    ipv6_address: None,
                    ipv6_prefix: None,
                    ipv6_subnet_id: None,
                    vlan: None,
                    vlan_parent: None,
                    router_advertisements: None,
                },
            ],
            firewall: Firewall {
                zones: vec![Zone {
                    name: "trusted".to_string(),
                    networks: vec!["lan".to_string(), "guest".to_string()],
                    default_input: oxwrt_api::config::ChainPolicy::Accept,
                    default_forward: oxwrt_api::config::ChainPolicy::Drop,
                    default_output: ChainPolicy::Accept,
                    masquerade: false,
                    via_vpn: false,
                    wan: None,
                    mtu_fix: false,
                }],
                rules: vec![],
                raw_nft: vec![],
                defaults: Default::default(),
                forwardings: vec![],
            },
            radios: vec![],
            wifi: vec![],
            services: vec![],
            port_forwards: vec![],
            wireguard: vec![],
            ddns: vec![],
            metrics: None,
            routes: vec![],
            routes6: vec![],
            blocklists: vec![],
            ipsets: vec![],
            upnp: None,
            vpn_client: vec![],
            backup_sftp: None,
            dns: None,
            dhcp: None,
            ntp: None,
            control: Control {
                listen: vec!["[::1]:51820".to_string()],
                max_connections: 32,
                max_rpcs_per_sec: 20,
                authorized_keys: PathBuf::from("/x"),
                clients: vec![],
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

    // ── parse_dnat_target_any: supports both v4 and bracketed v6 ──

    #[test]
    fn parse_dnat_target_any_accepts_v4() {
        let (ip, port) = parse_dnat_target_any("10.0.0.5:8080").unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)));
        assert_eq!(port, 8080);
    }

    #[test]
    fn parse_dnat_target_any_accepts_bracketed_v6() {
        let (ip, port) = parse_dnat_target_any("[fd00::50]:80").unwrap();
        assert_eq!(ip, IpAddr::V6("fd00::50".parse::<Ipv6Addr>().unwrap()));
        assert_eq!(port, 80);
        // Link-local with scope would be rejected by SocketAddr; we
        // don't support scoped v6 port-forwards (they wouldn't make
        // sense through a WAN-facing DNAT anyway).
        assert!(parse_dnat_target_any("[::1]:53").is_some());
    }

    #[test]
    fn parse_dnat_target_any_rejects_unbracketed_v6() {
        // Without brackets, `rsplit_once(':')` can't disambiguate
        // host-vs-port; SocketAddr's parser rejects it cleanly.
        assert!(parse_dnat_target_any("fd00::1:80").is_none());
    }

    // ── ipsets prologue ────────────────────────────────────────────

    #[test]
    fn ipsets_prologue_empty_when_no_sets() {
        let cfg = minimal_config();
        assert!(build_ipsets_prologue(&cfg).is_empty());
    }

    #[test]
    fn ipsets_prologue_renders_v4_bare_addresses() {
        use oxwrt_api::config::{Family, IpSet};
        let mut cfg = minimal_config();
        cfg.ipsets.push(IpSet {
            name: "allow".into(),
            family: Family::Ipv4,
            entries: vec!["1.2.3.4".into(), "5.6.7.8".into()],
            timeout: None,
        });
        let s = build_ipsets_prologue(&cfg);
        // No interval flag (no slash in entries).
        assert!(
            s.contains("add set inet oxwrt allow { type ipv4_addr; }"),
            "{s}"
        );
        assert!(
            s.contains("add element inet oxwrt allow { 1.2.3.4, 5.6.7.8 }"),
            "{s}"
        );
    }

    #[test]
    fn ipsets_prologue_auto_enables_interval_on_cidr() {
        use oxwrt_api::config::{Family, IpSet};
        let mut cfg = minimal_config();
        cfg.ipsets.push(IpSet {
            name: "blocklist".into(),
            family: Family::Ipv4,
            entries: vec!["10.0.0.0/8".into(), "192.168.0.0/16".into()],
            timeout: None,
        });
        let s = build_ipsets_prologue(&cfg);
        assert!(s.contains("flags interval"), "{s}");
    }

    #[test]
    fn ipsets_prologue_renders_v6_with_timeout() {
        use oxwrt_api::config::{Family, IpSet};
        let mut cfg = minimal_config();
        cfg.ipsets.push(IpSet {
            name: "tempban6".into(),
            family: Family::Ipv6,
            entries: vec!["fd00::/8".into()],
            timeout: Some("1h".into()),
        });
        let s = build_ipsets_prologue(&cfg);
        assert!(s.contains("type ipv6_addr"), "{s}");
        assert!(s.contains("flags interval"), "{s}");
        assert!(s.contains("timeout 1h"), "{s}");
    }

    // ── match_set rendering ────────────────────────────────────────

    #[test]
    fn render_match_set_src_v4() {
        use oxwrt_api::config::{Family, IpSet, MatchSet, MatchSetDir};
        let mut cfg = minimal_config();
        cfg.ipsets.push(IpSet {
            name: "bad".into(),
            family: Family::Ipv4,
            entries: vec!["1.2.3.0/24".into()],
            timeout: None,
        });
        let mut r = basic_rule("drop-bad");
        r.match_set = Some(MatchSet {
            name: "bad".into(),
            direction: MatchSetDir::Src,
            negate: false,
        });
        r.action = oxwrt_api::config::Action::Drop;
        cfg.firewall.rules.push(r);
        let s = build_scheduled_rules_script(&cfg);
        assert!(s.contains("ip saddr @bad"), "{s}");
        assert!(s.contains(" drop"), "{s}");
    }

    #[test]
    fn render_match_set_negated_v6_dst() {
        use oxwrt_api::config::{Family, IpSet, MatchSet, MatchSetDir};
        let mut cfg = minimal_config();
        cfg.ipsets.push(IpSet {
            name: "trusted6".into(),
            family: Family::Ipv6,
            entries: vec!["fd00::/8".into()],
            timeout: None,
        });
        let mut r = basic_rule("drop-untrusted");
        r.match_set = Some(MatchSet {
            name: "trusted6".into(),
            direction: MatchSetDir::Dst,
            negate: true,
        });
        r.action = oxwrt_api::config::Action::Drop;
        cfg.firewall.rules.push(r);
        let s = build_scheduled_rules_script(&cfg);
        assert!(s.contains("ip6 daddr != @trusted6"), "{s}");
    }

    #[test]
    fn match_set_forces_text_path() {
        use oxwrt_api::config::{MatchSet, MatchSetDir};
        let mut r = basic_rule("t");
        assert!(!rule_needs_text_path(&r));
        r.match_set = Some(MatchSet {
            name: "x".into(),
            direction: MatchSetDir::Src,
            negate: false,
        });
        assert!(rule_needs_text_path(&r));
    }

    // ── find_dest_zone_for_ipv6 ────────────────────────────────────

    // ── port ranges + proto-only rules ─────────────────────────────

    #[test]
    fn range_port_forces_text_path() {
        let mut r = basic_rule("t");
        assert!(!rule_needs_text_path(&r));
        r.dest_port = Some(PortSpec::Range("22-80".into()));
        assert!(rule_needs_text_path(&r), "range dest_port should take text");
        // src_port Range should also trigger.
        let mut r = basic_rule("t");
        r.src_port = Some(PortSpec::Range("1024-65535".into()));
        assert!(rule_needs_text_path(&r));
    }

    #[test]
    fn proto_only_rule_forces_text_path() {
        // "accept all UDP from lan to wan" — used to silently
        // vanish on the rustables path. Now routes to text.
        let mut r = basic_rule("allow-udp");
        r.proto = Some(oxwrt_api::config::Proto::Udp);
        assert!(
            rule_needs_text_path(&r),
            "proto=udp without dest_port must take text path"
        );
        // Same for TCP.
        let mut r = basic_rule("t");
        r.proto = Some(oxwrt_api::config::Proto::Tcp);
        assert!(rule_needs_text_path(&r));
        // Same for Both.
        let mut r = basic_rule("t");
        r.proto = Some(oxwrt_api::config::Proto::Both);
        assert!(rule_needs_text_path(&r));
        // Proto::Icmp stays on the rustables path (handled by the
        // is_icmp special-case there).
        let mut r = basic_rule("t");
        r.proto = Some(oxwrt_api::config::Proto::Icmp);
        assert!(!rule_needs_text_path(&r));
        // Proto + port stays on rustables (the common case).
        let mut r = basic_rule("t");
        r.proto = Some(oxwrt_api::config::Proto::Tcp);
        r.dest_port = Some(PortSpec::Single(22));
        assert!(!rule_needs_text_path(&r));
    }

    #[test]
    fn render_range_dest_port_tcp() {
        let mut cfg = minimal_config();
        let mut r = basic_rule("allow-dev-ports");
        r.proto = Some(oxwrt_api::config::Proto::Tcp);
        r.dest_port = Some(PortSpec::Range("3000-3010".into()));
        r.action = oxwrt_api::config::Action::Accept;
        cfg.firewall.rules.push(r);
        let s = build_scheduled_rules_script(&cfg);
        assert!(s.contains("tcp dport 3000-3010"), "{s}");
        assert!(s.contains(" accept"), "{s}");
    }

    #[test]
    fn render_range_src_port_udp() {
        let mut cfg = minimal_config();
        let mut r = basic_rule("dhcp-reply-filter");
        r.proto = Some(oxwrt_api::config::Proto::Udp);
        r.src_port = Some(PortSpec::Range("1024-65535".into()));
        r.action = oxwrt_api::config::Action::Accept;
        cfg.firewall.rules.push(r);
        let s = build_scheduled_rules_script(&cfg);
        assert!(s.contains("udp sport 1024-65535"), "{s}");
    }

    #[test]
    fn render_range_normalizes_whitespace() {
        // Operator typed "22 - 80" with stray spaces; nft wants
        // "22-80". render_port_fragment re-parses + re-emits.
        let mut cfg = minimal_config();
        let mut r = basic_rule("t");
        r.proto = Some(oxwrt_api::config::Proto::Tcp);
        r.dest_port = Some(PortSpec::Range("22 - 80".into()));
        r.action = oxwrt_api::config::Action::Accept;
        cfg.firewall.rules.push(r);
        let s = build_scheduled_rules_script(&cfg);
        assert!(s.contains("tcp dport 22-80"), "{s}");
        assert!(!s.contains("22 - 80"), "stray whitespace leaked: {s}");
    }

    #[test]
    fn render_proto_only_tcp_accept() {
        let mut cfg = minimal_config();
        let mut r = basic_rule("allow-tcp");
        r.proto = Some(oxwrt_api::config::Proto::Tcp);
        // No dest_port — proto-only rule.
        r.action = oxwrt_api::config::Action::Accept;
        cfg.firewall.rules.push(r);
        let s = build_scheduled_rules_script(&cfg);
        assert!(s.contains("meta l4proto tcp"), "{s}");
        assert!(s.contains(" accept"), "{s}");
    }

    #[test]
    fn render_proto_only_udp_drop() {
        let mut cfg = minimal_config();
        let mut r = basic_rule("block-all-udp");
        r.proto = Some(oxwrt_api::config::Proto::Udp);
        r.action = oxwrt_api::config::Action::Drop;
        cfg.firewall.rules.push(r);
        let s = build_scheduled_rules_script(&cfg);
        assert!(s.contains("meta l4proto udp"), "{s}");
        assert!(s.contains(" drop"), "{s}");
    }

    #[test]
    fn render_proto_only_both_accept() {
        let mut cfg = minimal_config();
        let mut r = basic_rule("allow-l4");
        r.proto = Some(oxwrt_api::config::Proto::Both);
        r.action = oxwrt_api::config::Action::Accept;
        cfg.firewall.rules.push(r);
        let s = build_scheduled_rules_script(&cfg);
        assert!(s.contains("meta l4proto { tcp, udp }"), "{s}");
    }

    #[test]
    fn port_spec_range_serde() {
        // TOML round-trip: a string "22-80" must land as Range.
        let cfg_toml = r#"
hostname = "t"
[[networks]]
name = "lan"
type = "lan"
bridge = "br-lan"
address = "192.168.1.1"
prefix = 24
[[firewall.rules]]
name = "r"
proto = "tcp"
dest_port = "22-80"
action = "accept"
[control]
listen = ["[::1]:51820"]
authorized_keys = "/x"
"#;
        let cfg: Config = toml::from_str(cfg_toml).unwrap();
        let dp = cfg.firewall.rules[0].dest_port.as_ref().unwrap();
        match dp {
            PortSpec::Range(s) => assert_eq!(s, "22-80"),
            other => panic!("expected Range, got {other:?}"),
        }
    }

    #[test]
    fn port_spec_parse_range_roundtrip() {
        use oxwrt_api::config::PortSpec as Ps;
        assert_eq!(Ps::parse_range("22-80"), Ok((22, 80)));
        assert_eq!(Ps::parse_range("1-65535"), Ok((1, 65535)));
        // Whitespace tolerant.
        assert_eq!(Ps::parse_range(" 100 - 200 "), Ok((100, 200)));
        // start == end is legal (equivalent to Single, but not an
        // error — operators use it for "range syntax with one port"
        // when building templated configs).
        assert_eq!(Ps::parse_range("53-53"), Ok((53, 53)));
    }

    #[test]
    fn port_spec_parse_range_rejects_bad_inputs() {
        use oxwrt_api::config::PortSpec as Ps;
        assert!(Ps::parse_range("").is_err());
        assert!(Ps::parse_range("22").is_err(), "missing dash");
        assert!(Ps::parse_range("22--80").is_err(), "double dash");
        assert!(Ps::parse_range("abc-80").is_err(), "bad start");
        assert!(Ps::parse_range("22-abc").is_err(), "bad end");
        assert!(Ps::parse_range("80-22").is_err(), "start > end");
        assert!(Ps::parse_range("22-99999").is_err(), "end overflows u16");
    }

    // ── fw4-parity pass 2: counter, limit_burst, reject_with, device ──

    #[test]
    fn counter_and_limit_burst_and_reject_with_force_text_path() {
        let mut r = basic_rule("t");
        assert!(!rule_needs_text_path(&r));
        r.counter = true;
        assert!(rule_needs_text_path(&r));

        let mut r = basic_rule("t");
        r.limit = Some("10/second".into());
        r.limit_burst = Some(20);
        assert!(rule_needs_text_path(&r));

        let mut r = basic_rule("t");
        r.reject_with = Some("tcp reset".into());
        r.action = oxwrt_api::config::Action::Reject;
        assert!(rule_needs_text_path(&r));

        let mut r = basic_rule("t");
        r.device = Some("wg0".into());
        assert!(rule_needs_text_path(&r));
    }

    #[test]
    fn render_rule_with_counter() {
        let mut cfg = minimal_config();
        let mut r = basic_rule("log-ssh-hits");
        r.proto = Some(oxwrt_api::config::Proto::Tcp);
        r.dest_port = Some(PortSpec::Single(22));
        r.counter = true;
        r.action = oxwrt_api::config::Action::Accept;
        cfg.firewall.rules.push(r);
        let s = build_scheduled_rules_script(&cfg);
        // counter goes immediately before the verdict.
        assert!(s.contains("counter accept"), "{s}");
    }

    #[test]
    fn render_rule_with_limit_burst() {
        let mut cfg = minimal_config();
        let mut r = basic_rule("rate-http");
        r.proto = Some(oxwrt_api::config::Proto::Tcp);
        r.dest_port = Some(PortSpec::Single(80));
        r.limit = Some("100/second".into());
        r.limit_burst = Some(200);
        r.action = oxwrt_api::config::Action::Accept;
        cfg.firewall.rules.push(r);
        let s = build_scheduled_rules_script(&cfg);
        assert!(s.contains("limit rate 100/second burst 200 packets"), "{s}");
    }

    #[test]
    fn render_rule_reject_with_tcp_reset() {
        let mut cfg = minimal_config();
        let mut r = basic_rule("reject-ssh");
        r.proto = Some(oxwrt_api::config::Proto::Tcp);
        r.dest_port = Some(PortSpec::Single(22));
        r.action = oxwrt_api::config::Action::Reject;
        r.reject_with = Some("tcp reset".into());
        cfg.firewall.rules.push(r);
        let s = build_scheduled_rules_script(&cfg);
        assert!(s.contains("reject with tcp reset"), "{s}");
        // Plain `reject` must NOT also appear in the same rule.
        let rule_line = s.lines().find(|l| l.contains("dport 22")).unwrap();
        assert_eq!(rule_line.matches("reject").count(), 1);
    }

    #[test]
    fn render_rule_device_bypasses_zone() {
        let mut cfg = minimal_config();
        let mut r = basic_rule("wg-accept");
        r.device = Some("wg0".into());
        r.proto = Some(oxwrt_api::config::Proto::Udp);
        r.dest_port = Some(PortSpec::Single(51820));
        r.action = oxwrt_api::config::Action::Accept;
        cfg.firewall.rules.push(r);
        let s = build_scheduled_rules_script(&cfg);
        assert!(s.contains(r#"iifname "wg0""#), "{s}");
    }

    // ── forwardings ────────────────────────────────────────────────

    #[test]
    fn build_forwardings_script_family_any_skipped() {
        use oxwrt_api::config::{Family, Forwarding};
        let mut cfg = minimal_config();
        cfg.firewall.forwardings.push(Forwarding {
            src: "trusted".into(),
            dest: "trusted".into(), // same zone for minimal setup
            family: Family::Any,
        });
        // Family=Any is handled in the rustables path; text path
        // produces nothing for it.
        assert!(build_forwardings_script(&cfg).is_empty());
    }

    #[test]
    fn build_forwardings_script_family_v4_emits_nfproto() {
        use oxwrt_api::config::{Family, Forwarding};
        let mut cfg = minimal_config();
        // Add a second zone so we can forward trusted→elsewhere.
        cfg.firewall.zones.push(oxwrt_api::config::Zone {
            name: "elsewhere".into(),
            networks: vec!["guest".into()],
            default_input: oxwrt_api::config::ChainPolicy::Drop,
            default_forward: oxwrt_api::config::ChainPolicy::Drop,
            default_output: oxwrt_api::config::ChainPolicy::Accept,
            masquerade: false,
            via_vpn: false,
            wan: None,
            mtu_fix: false,
        });
        cfg.firewall.forwardings.push(Forwarding {
            src: "trusted".into(),
            dest: "elsewhere".into(),
            family: Family::Ipv4,
        });
        let s = build_forwardings_script(&cfg);
        assert!(s.contains("meta nfproto ipv4 accept"), "{s}");
    }

    // ── baseline defaults: synflood + drop_invalid + mtu_fix ─────

    #[test]
    fn baseline_emits_synflood_by_default() {
        let cfg = minimal_config();
        let s = build_baseline_defaults_script(&cfg);
        assert!(s.contains("tcp flags syn"), "{s}");
        assert!(s.contains("limit rate over 25/second"), "{s}");
        assert!(s.contains("burst 50 packets drop"), "{s}");
    }

    #[test]
    fn baseline_synflood_can_be_disabled() {
        let mut cfg = minimal_config();
        cfg.firewall.defaults.synflood_protect = false;
        let s = build_baseline_defaults_script(&cfg);
        assert!(!s.contains("tcp flags syn"), "synflood leaked: {s}");
    }

    #[test]
    fn baseline_drop_invalid_can_be_disabled() {
        let mut cfg = minimal_config();
        cfg.firewall.defaults.drop_invalid = false;
        let s = build_baseline_defaults_script(&cfg);
        assert!(!s.contains("ct state invalid drop"), "{s}");
    }

    #[test]
    fn baseline_mtu_fix_emits_mss_clamp() {
        let mut cfg = minimal_config();
        cfg.firewall.zones[0].mtu_fix = true; // the "trusted" zone
        let s = build_baseline_defaults_script(&cfg);
        // Matches on both iifname and oifname of the zone's ifaces.
        // The "trusted" zone covers lan (br-lan) + guest (br-guest).
        assert!(
            s.contains("tcp option maxseg size set rt mtu"),
            "MSS clamp not emitted: {s}"
        );
        assert!(s.contains(r#"iifname "br-lan""#), "{s}");
        assert!(s.contains(r#"oifname "br-lan""#), "{s}");
    }

    #[test]
    fn baseline_mtu_fix_off_by_default() {
        let cfg = minimal_config();
        let s = build_baseline_defaults_script(&cfg);
        assert!(
            !s.contains("maxseg size set rt mtu"),
            "MSS clamp leaked when mtu_fix is off: {s}"
        );
    }

    // ── find_dest_zone_for_ipv6 ────────────────────────────────────

    #[test]
    fn find_dest_zone_for_ipv6_matches_lan_prefix() {
        let mut cfg = minimal_config();
        // Swap in a v6 address on the lan network.
        if let Network::Lan {
            ipv6_address,
            ipv6_prefix,
            ..
        } = &mut cfg.networks[0]
        {
            *ipv6_address = Some("fd00:1::1".parse().unwrap());
            *ipv6_prefix = Some(64);
        }
        assert_eq!(
            find_dest_zone_for_ipv6(&cfg, "fd00:1::50".parse().unwrap()),
            Some("trusted".to_string())
        );
        // Outside the /64.
        assert_eq!(
            find_dest_zone_for_ipv6(&cfg, "fd00:2::1".parse().unwrap()),
            None
        );
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
        assert_eq!(find_dest_zone_for_ip(&cfg, Ipv4Addr::new(8, 8, 8, 8)), None);
    }
}
