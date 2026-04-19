//! DHCPv6-PD client — acquires a delegated prefix (typically /56 or
//! /60) from the WAN iface and applies it to LAN/Simple subnets
//! using each network's `ipv6_subnet_id` config field.
//!
//! Scope: Solicit → Advertise → Request → Reply, extracting the
//! IA_PD option + its contained IAPrefix. No IA_NA (we don't ask the
//! ISP for a WAN-side address; link-local suffices for routing).
//! No Rapid Commit. No Reconfigure. No relay-agent mode.
//!
//! DUID: hand-built DUID-LL (RFC 8415 § 11.4) from the WAN MAC,
//! persisted at `/etc/oxwrt/dhcp6-duid` (covered by sysupgrade.conf)
//! alongside the IAID. ISPs key the delegated prefix on (DUID,
//! IAID), so persisting means the same /56 survives reboots +
//! sysupgrades; regenerating would force every boot to be a fresh
//! allocation, wasteful and potentially billable on per-lease ISPs.
//!
//! Socket: bound to `[::]:546` with SO_BINDTODEVICE to the WAN
//! iface, destination `ff02::1:2` (DHCP_All-Servers-and-Relays)
//! port 547 with scope_id = wan iface index. The kernel picks a
//! link-local source automatically.

use std::net::{Ipv6Addr, SocketAddrV6};
use std::time::{Duration, Instant};

use dhcproto::Decodable as _;
use dhcproto::Encodable as _;
use dhcproto::v6::{
    DhcpOption, DhcpOptions, IAAddr, IANA, IAPD, Message, MessageType, ORO, OptionCode,
};

use oxwrt_api::config::{Config, Network};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("timeout waiting for {0}")]
    Timeout(&'static str),
    #[error("bad reply: {0}")]
    BadReply(String),
    #[error("encode: {0}")]
    Encode(String),
    #[error("decode: {0}")]
    Decode(String),
}

/// One PD lease. Fresh values of each per DHCPv6 transaction.
#[derive(Debug, Clone)]
pub struct DhcpV6Lease {
    /// Network portion of the delegated prefix (host bits zeroed).
    pub prefix: Ipv6Addr,
    pub prefix_len: u8,
    pub preferred_lifetime: u32,
    pub valid_lifetime: u32,
    pub t1: u32,
    pub t2: u32,
    pub iaid: u32,
    pub server_id: Vec<u8>,
    pub client_duid: Vec<u8>,
    pub acquired_at: Instant,
    /// Optional WAN-side /128 address from the IA_NA option. Many
    /// ISPs only grant IA_PD and expect the router to use SLAAC
    /// for its own WAN v6 address; others hand out both. None = no
    /// IA_NA in the Reply (or the Reply's IA_NA was empty).
    pub wan_address: Option<Ipv6Addr>,
    /// Lifetimes for `wan_address`. Ignored when None.
    pub wan_preferred_lifetime: u32,
    pub wan_valid_lifetime: u32,
}

/// Shared across the renewal loop + diag + apply. Same Arc<RwLock<Option<_>>>
/// shape as the v4 `SharedLease` — one more of these won't break anyone.
pub type SharedV6Lease = std::sync::Arc<std::sync::RwLock<Option<DhcpV6Lease>>>;

/// Run the Solicit/Request/Reply dance and return the resulting
/// prefix lease. Best-effort — errors are propagated so the caller
/// (init) decides whether to retry or continue without v6.
pub async fn acquire(iface: &str, timeout: Duration) -> Result<DhcpV6Lease, Error> {
    let mac = read_iface_mac(iface)?;
    let ifindex = read_iface_index(iface)?;

    let sock = build_socket(ifindex)?;
    // DUID + IAID must be stable across reboots: ISPs key the
    // delegated prefix on (DUID, IAID), so regenerating on every
    // boot means every boot gets a fresh /56 allocation. That's
    // painful if the ISP has per-customer quotas or billing on
    // leases, and just plain wasteful otherwise. Persist at
    // /etc/oxwrt/dhcp6-duid (which is in sysupgrade.conf) so the
    // identity survives reboots + sysupgrades.
    let (duid, iaid) = load_or_create_duid_iaid(mac)?;

    let (server_id, advertised_iapd, advertised_iana) =
        solicit_phase(&sock, ifindex, &duid, iaid, timeout).await?;

    let parsed = request_phase(
        &sock,
        ifindex,
        &duid,
        iaid,
        &server_id,
        &advertised_iapd,
        advertised_iana.as_ref(),
        timeout,
    )
    .await?;

    Ok(DhcpV6Lease {
        prefix: mask_v6_prefix(parsed.prefix, parsed.prefix_len),
        prefix_len: parsed.prefix_len,
        preferred_lifetime: parsed.preferred_lifetime,
        valid_lifetime: parsed.valid_lifetime,
        t1: parsed.t1,
        t2: parsed.t2,
        iaid,
        server_id,
        client_duid: duid,
        acquired_at: Instant::now(),
        wan_address: parsed.wan_address,
        wan_preferred_lifetime: parsed.wan_preferred_lifetime,
        wan_valid_lifetime: parsed.wan_valid_lifetime,
    })
}

// Everything extracted from a Reply: the PD half (prefix + lifetimes
// + T1/T2) always required, the NA half (wan address + lifetimes)
// optional. Callers map from this into a DhcpV6Lease.
#[derive(Debug, Clone)]
struct ReplyContents {
    prefix: Ipv6Addr,
    prefix_len: u8,
    preferred_lifetime: u32,
    valid_lifetime: u32,
    t1: u32,
    t2: u32,
    wan_address: Option<Ipv6Addr>,
    wan_preferred_lifetime: u32,
    wan_valid_lifetime: u32,
}

/// Return a `Config` where each Lan/Simple with `ipv6_subnet_id`
/// has its `ipv6_address` rewritten to the per-subnet host address
/// derived from the delegated prefix. Used by the init code to
/// regenerate corerad.toml after acquisition so the RA prefix
/// matches what got assigned to the bridge. No mutation of the
/// persisted oxwrt.toml — the swap is ephemeral, lives only in the
/// spawned task's cfg_clone.
pub fn cfg_with_delegated_prefix(cfg: &Config, lease: &DhcpV6Lease) -> Config {
    let mut out = cfg.clone();
    for net in &mut out.networks {
        let subnet_id = net.ipv6_subnet_id();
        let Some(subnet_id) = subnet_id else {
            continue;
        };
        let Some(host) = subnet_host_address(lease.prefix, lease.prefix_len, subnet_id) else {
            continue;
        };
        match net {
            Network::Lan {
                ipv6_address,
                ipv6_prefix,
                ..
            }
            | Network::Simple {
                ipv6_address,
                ipv6_prefix,
                ..
            } => {
                *ipv6_address = Some(host);
                *ipv6_prefix = Some(64);
            }
            Network::Wan { .. } => {}
        }
    }
    out
}

/// Assign per-subnet v6 addresses derived from the delegated prefix.
/// For each LAN/Simple in cfg with `ipv6_subnet_id`, compute the
/// /64 `(delegated | (subnet_id << (128-64))) | ::1` and add it to
/// the bridge/iface. Idempotent — EEXIST is tolerated.
pub async fn apply_delegation(
    handle: &rtnetlink::Handle,
    cfg: &Config,
    lease: &DhcpV6Lease,
) -> Result<(), Error> {
    use std::net::IpAddr;

    // WAN-side IA_NA address, if the server granted one. /128 on the
    // WAN iface — the ISP handles the link subnet; we just need a
    // routable address for outbound v6 connectivity.
    if let Some(wan_addr) = lease.wan_address {
        if let Some(Network::Wan { iface, .. }) = cfg.primary_wan() {
            match link_index(handle, iface).await {
                Ok(idx) => {
                    let res = handle
                        .address()
                        .add(idx, IpAddr::V6(wan_addr), 128)
                        .execute()
                        .await;
                    match res {
                        Ok(()) => {
                            tracing::info!(iface, %wan_addr, "v6 apply: WAN address assigned (from IA_NA)");
                        }
                        Err(e) if format!("{e}").contains("File exists") => {
                            tracing::debug!(iface, %wan_addr, "v6 apply: WAN address already present");
                        }
                        Err(e) => {
                            tracing::warn!(iface, error = %e, "v6 apply: WAN address add failed");
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(iface, error = %e, "v6 apply: WAN link lookup failed");
                }
            }
        }
    }

    for net in &cfg.networks {
        let Some(subnet_id) = net.ipv6_subnet_id() else {
            continue;
        };
        let Some(subnet_addr) = subnet_host_address(lease.prefix, lease.prefix_len, subnet_id)
        else {
            tracing::warn!(
                net = %net.name(),
                subnet_id,
                prefix = %lease.prefix,
                prefix_len = lease.prefix_len,
                "subnet_id out of range for delegated prefix length; skipping"
            );
            continue;
        };
        let iface = match net {
            Network::Lan { bridge, .. } => bridge.clone(),
            Network::Simple { iface, .. } => iface.clone(),
            Network::Wan { .. } => continue,
        };
        let idx = match link_index(handle, &iface).await {
            Ok(i) => i,
            Err(e) => {
                tracing::warn!(iface, error = %e, "v6 apply: link lookup failed");
                continue;
            }
        };
        let add_res = handle
            .address()
            .add(idx, IpAddr::V6(subnet_addr), 64)
            .execute()
            .await;
        match add_res {
            Ok(()) => {
                tracing::info!(
                    iface,
                    %subnet_addr,
                    "v6 apply: delegated /64 assigned"
                );
            }
            Err(e) if format!("{e}").contains("File exists") => {
                tracing::debug!(iface, %subnet_addr, "v6 apply: address already present");
            }
            Err(e) => {
                tracing::warn!(iface, error = %e, "v6 apply: address add failed");
            }
        }
    }
    Ok(())
}

async fn link_index(handle: &rtnetlink::Handle, name: &str) -> Result<u32, String> {
    use futures_util::stream::TryStreamExt as _;
    let mut stream = handle.link().get().match_name(name.to_string()).execute();
    match stream.try_next().await {
        Ok(Some(msg)) => Ok(msg.header.index),
        Ok(None) => Err(format!("{name}: no link")),
        Err(e) => Err(e.to_string()),
    }
}

/// Compute the per-subnet host address `<prefix>:<subnet_id>::1/64`
/// given the delegated prefix + its length. Returns None if subnet_id
/// doesn't fit in the available slicing bits.
pub fn subnet_host_address(
    delegated: Ipv6Addr,
    delegated_len: u8,
    subnet_id: u16,
) -> Option<Ipv6Addr> {
    if delegated_len > 64 {
        return None;
    }
    let bits_available = 64 - u32::from(delegated_len);
    if bits_available < 16 && (u32::from(subnet_id) >> bits_available) != 0 {
        return None;
    }
    let prefix_bits = u128::from_be_bytes(delegated.octets());
    let subnet_bits = (u128::from(subnet_id)) << 64;
    let host_bits: u128 = 1;
    let result = prefix_bits | subnet_bits | host_bits;
    Some(Ipv6Addr::from(result.to_be_bytes()))
}

fn mask_v6_prefix(addr: Ipv6Addr, prefix: u8) -> Ipv6Addr {
    if prefix >= 128 {
        return addr;
    }
    let bits = u128::from_be_bytes(addr.octets());
    let shift = 128 - u32::from(prefix);
    let mask = !((1u128 << shift) - 1);
    Ipv6Addr::from((bits & mask).to_be_bytes())
}

// ── Phase 1: Solicit / Advertise ───────────────────────────────────

async fn solicit_phase(
    sock: &tokio::net::UdpSocket,
    ifindex: u32,
    duid: &[u8],
    iaid: u32,
    timeout: Duration,
) -> Result<(Vec<u8>, IAPD, Option<IANA>), Error> {
    let solicit = build_message(MessageType::Solicit, duid, iaid);
    let mut buf = Vec::new();
    solicit
        .encode(&mut dhcproto::Encoder::new(&mut buf))
        .map_err(|e| Error::Encode(e.to_string()))?;
    let dst = SocketAddrV6::new(
        Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0x1, 0x2),
        547,
        0,
        ifindex,
    );
    sock.send_to(&buf, dst).await?;

    let deadline = Instant::now() + timeout;
    let mut rx = [0u8; 2048];
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(Error::Timeout("Advertise"))?;
        let (n, _from) = tokio::time::timeout(remaining, sock.recv_from(&mut rx))
            .await
            .map_err(|_| Error::Timeout("Advertise"))??;
        let msg = Message::decode(&mut dhcproto::Decoder::new(&rx[..n]))
            .map_err(|e| Error::Decode(e.to_string()))?;
        if msg.msg_type() != MessageType::Advertise {
            continue;
        }
        let server_id = option_raw(msg.opts(), OptionCode::ServerId)
            .ok_or_else(|| Error::BadReply("Advertise missing ServerId".into()))?;
        let iapd = find_iapd(msg.opts())
            .ok_or_else(|| Error::BadReply("Advertise missing IA_PD".into()))?;
        if find_iaprefix(&iapd.opts).is_none() {
            return Err(Error::BadReply("IA_PD missing IAPrefix".into()));
        }
        // IA_NA is optional — some ISPs deliver it alongside IA_PD,
        // many don't. Preserve whatever the server sent (or None)
        // and echo it back in the Request so we stay in-sync.
        let iana = find_iana(msg.opts());
        return Ok((server_id, iapd, iana));
    }
}

// ── Phase 2: Request / Reply ───────────────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn request_phase(
    sock: &tokio::net::UdpSocket,
    ifindex: u32,
    duid: &[u8],
    iaid: u32,
    server_id: &[u8],
    advertised_iapd: &IAPD,
    advertised_iana: Option<&IANA>,
    timeout: Duration,
) -> Result<ReplyContents, Error> {
    let request = build_request(duid, iaid, server_id, advertised_iapd, advertised_iana);
    let mut buf = Vec::new();
    request
        .encode(&mut dhcproto::Encoder::new(&mut buf))
        .map_err(|e| Error::Encode(e.to_string()))?;
    let dst = SocketAddrV6::new(
        Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0x1, 0x2),
        547,
        0,
        ifindex,
    );
    sock.send_to(&buf, dst).await?;

    recv_reply(sock, timeout).await
}

// ── Phase 3: Renew / Rebind ────────────────────────────────────────
//
// Renew (RFC 8415 § 18.2.4): Sent from the client to the server that
// issued the current lease when T1 elapses. Includes ClientId +
// ServerId + IA_PD with the current prefix in an IAPrefix — the
// server confirms by echoing it in its Reply with updated lifetimes.
//
// Rebind (RFC 8415 § 18.2.5): Sent when T1→T2 passes without a
// Renew Reply. Same shape as Renew but WITHOUT ServerId (we've
// given up on the original server; any server that recognizes our
// IA_PD can answer). Always multicast to ff02::1:2.
//
// Both share the Reply-parsing logic from request_phase, refactored
// into `recv_reply_ia_pd` below.

async fn recv_reply(
    sock: &tokio::net::UdpSocket,
    timeout: Duration,
) -> Result<ReplyContents, Error> {
    let deadline = Instant::now() + timeout;
    let mut rx = [0u8; 2048];
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(Error::Timeout("Reply"))?;
        let (n, _from) = tokio::time::timeout(remaining, sock.recv_from(&mut rx))
            .await
            .map_err(|_| Error::Timeout("Reply"))??;
        let msg = Message::decode(&mut dhcproto::Decoder::new(&rx[..n]))
            .map_err(|e| Error::Decode(e.to_string()))?;
        if msg.msg_type() != MessageType::Reply {
            continue;
        }
        let iapd =
            find_iapd(msg.opts()).ok_or_else(|| Error::BadReply("Reply missing IA_PD".into()))?;
        let iaprefix = find_iaprefix(&iapd.opts)
            .ok_or_else(|| Error::BadReply("IA_PD missing IAPrefix".into()))?;
        // IA_NA is optional. If present, its IAAddr provides the
        // WAN-side /128. If the server's IANA is empty (no IAAddr),
        // treat as "no v6 WAN address" — not an error.
        let (wan_address, wan_preferred_lifetime, wan_valid_lifetime) = find_iana(msg.opts())
            .and_then(|iana| find_iaaddr(&iana.opts))
            .map(|addr| (Some(addr.addr), addr.preferred_life, addr.valid_life))
            .unwrap_or((None, 0, 0));
        return Ok(ReplyContents {
            prefix: iaprefix.prefix_ip,
            prefix_len: iaprefix.prefix_len,
            preferred_lifetime: iaprefix.preferred_lifetime,
            valid_lifetime: iaprefix.valid_lifetime,
            t1: iapd.t1,
            t2: iapd.t2,
            wan_address,
            wan_preferred_lifetime,
            wan_valid_lifetime,
        });
    }
}

/// Send a Renew (unicast-or-multicast, we always multicast) and
/// await a Reply with the refreshed lease.
pub async fn renew(
    iface: &str,
    prev: &DhcpV6Lease,
    timeout: Duration,
) -> Result<DhcpV6Lease, Error> {
    renew_or_rebind(iface, prev, timeout, MessageType::Renew).await
}

/// Send a Rebind (multicast, no ServerId) and await a Reply from
/// whichever server responds. Used when Renew failed for T1→T2.
pub async fn rebind(
    iface: &str,
    prev: &DhcpV6Lease,
    timeout: Duration,
) -> Result<DhcpV6Lease, Error> {
    renew_or_rebind(iface, prev, timeout, MessageType::Rebind).await
}

async fn renew_or_rebind(
    iface: &str,
    prev: &DhcpV6Lease,
    timeout: Duration,
    mt: MessageType,
) -> Result<DhcpV6Lease, Error> {
    let ifindex = read_iface_index(iface)?;
    let sock = build_socket(ifindex)?;
    let server_id = match mt {
        MessageType::Renew => Some(prev.server_id.as_slice()),
        _ => None, // Rebind includes no ServerId per RFC 8415 § 18.2.5
    };
    let msg = build_renew_or_rebind(
        mt,
        &prev.client_duid,
        prev.iaid,
        server_id,
        prev.prefix,
        prev.prefix_len,
        prev.wan_address,
    );
    send_multicast(&sock, ifindex, &msg).await?;
    let parsed = recv_reply(&sock, timeout).await?;
    Ok(DhcpV6Lease {
        prefix: mask_v6_prefix(parsed.prefix, parsed.prefix_len),
        prefix_len: parsed.prefix_len,
        preferred_lifetime: parsed.preferred_lifetime,
        valid_lifetime: parsed.valid_lifetime,
        t1: parsed.t1,
        t2: parsed.t2,
        iaid: prev.iaid,
        server_id: prev.server_id.clone(),
        client_duid: prev.client_duid.clone(),
        acquired_at: Instant::now(),
        wan_address: parsed.wan_address,
        wan_preferred_lifetime: parsed.wan_preferred_lifetime,
        wan_valid_lifetime: parsed.wan_valid_lifetime,
    })
}

async fn send_multicast(
    sock: &tokio::net::UdpSocket,
    ifindex: u32,
    msg: &Message,
) -> Result<(), Error> {
    let mut buf = Vec::new();
    msg.encode(&mut dhcproto::Encoder::new(&mut buf))
        .map_err(|e| Error::Encode(e.to_string()))?;
    let dst = SocketAddrV6::new(
        Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0x1, 0x2),
        547,
        0,
        ifindex,
    );
    sock.send_to(&buf, dst).await?;
    Ok(())
}

/// Spawn the renewal loop. Follows the RFC 8415 § 18.2.10 state
/// machine: after `t1` secs, Renew; if no Reply by `t2`, Rebind;
/// if no Reply by `valid_lifetime`, re-acquire via Solicit. Applies
/// each new lease via `apply_delegation` + regenerates corerad so
/// an ISP prefix rotation is transparent to LAN clients.
pub fn spawn_renewal_loop(
    iface: String,
    initial: DhcpV6Lease,
    shared: SharedV6Lease,
    cfg: Config,
    handle: rtnetlink::Handle,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut lease = initial;
        *shared.write().unwrap() = Some(lease.clone());
        loop {
            // Sleep until T1. Values of 0 mean "use discretion"
            // (RFC 8415 § 14.2). For IA_PD a missing/zero T1 is
            // common; default to 0.5 * valid_lifetime, capped at
            // 1 day to avoid re-renewing a dead lease forever.
            let t1 = if lease.t1 == 0 || lease.t1 == u32::MAX {
                (lease.valid_lifetime / 2).min(86400)
            } else {
                lease.t1
            };
            let t2 = if lease.t2 == 0 || lease.t2 == u32::MAX {
                (lease.valid_lifetime * 4 / 5).min(86400)
            } else {
                lease.t2
            };
            let renew_at = lease.acquired_at + Duration::from_secs(u64::from(t1));
            let rebind_at = lease.acquired_at + Duration::from_secs(u64::from(t2));
            let expire_at =
                lease.acquired_at + Duration::from_secs(u64::from(lease.valid_lifetime));

            // Sleep until renew_at.
            if let Some(wait) = renew_at.checked_duration_since(Instant::now()) {
                tokio::time::sleep(wait).await;
            }

            // Try Renew up to a few times spread between now and rebind_at.
            let mut renewed = None;
            while Instant::now() < rebind_at {
                match renew(&iface, &lease, Duration::from_secs(5)).await {
                    Ok(new_lease) => {
                        tracing::info!(
                            prefix = %new_lease.prefix,
                            valid = new_lease.valid_lifetime,
                            "dhcpv6-pd: Renew ok"
                        );
                        renewed = Some(new_lease);
                        break;
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "dhcpv6-pd: Renew failed; retry");
                        tokio::time::sleep(Duration::from_secs(10)).await;
                    }
                }
            }

            // If Renew window passed with no luck, Rebind.
            if renewed.is_none() {
                while Instant::now() < expire_at {
                    match rebind(&iface, &lease, Duration::from_secs(5)).await {
                        Ok(new_lease) => {
                            tracing::warn!(
                                prefix = %new_lease.prefix,
                                "dhcpv6-pd: Rebind ok (original server down)"
                            );
                            renewed = Some(new_lease);
                            break;
                        }
                        Err(e) => {
                            tracing::debug!(error = %e, "dhcpv6-pd: Rebind failed; retry");
                            tokio::time::sleep(Duration::from_secs(15)).await;
                        }
                    }
                }
            }

            // If both failed and valid_lifetime expired, re-Solicit
            // from scratch. This is the "ISP dropped our state and
            // needs us to start over" path. The new prefix may differ,
            // apply_delegation + corerad regen take care of that.
            let new_lease = match renewed {
                Some(l) => l,
                None => {
                    tracing::warn!(
                        "dhcpv6-pd: lease expired without successful Renew/Rebind; \
                         restarting Solicit"
                    );
                    match acquire(&iface, Duration::from_secs(30)).await {
                        Ok(l) => l,
                        Err(e) => {
                            tracing::error!(error = %e, "dhcpv6-pd: re-Solicit failed; giving up for 60s");
                            tokio::time::sleep(Duration::from_secs(60)).await;
                            continue;
                        }
                    }
                }
            };

            // If the prefix changed, re-apply delegation + regen
            // corerad so everything downstream reflects the new /56.
            let prefix_changed =
                new_lease.prefix != lease.prefix || new_lease.prefix_len != lease.prefix_len;
            lease = new_lease;
            *shared.write().unwrap() = Some(lease.clone());
            if prefix_changed {
                if let Err(e) = apply_delegation(&handle, &cfg, &lease).await {
                    tracing::warn!(error = %e, "dhcpv6-pd: apply_delegation (post-renew) failed");
                }
                let new_cfg = cfg_with_delegated_prefix(&cfg, &lease);
                if let Err(e) = crate::corerad::write_config(&new_cfg) {
                    tracing::warn!(error = %e, "dhcpv6-pd: corerad regen (post-renew) failed");
                }
            }
        }
    })
}

fn build_renew_or_rebind(
    mt: MessageType,
    duid: &[u8],
    iaid: u32,
    server_id: Option<&[u8]>,
    prefix: Ipv6Addr,
    prefix_len: u8,
    wan_address: Option<Ipv6Addr>,
) -> Message {
    use dhcproto::v6::IAPrefix;
    let mut msg = Message::new(mt);
    msg.opts_mut().insert(DhcpOption::ClientId(duid.to_vec()));
    if let Some(sid) = server_id {
        msg.opts_mut().insert(DhcpOption::ServerId(sid.to_vec()));
    }
    msg.opts_mut().insert(DhcpOption::ElapsedTime(0));
    // IA_PD carrying the prefix we already hold.
    let iaprefix = IAPrefix {
        preferred_lifetime: 0,
        valid_lifetime: 0,
        prefix_len,
        prefix_ip: prefix,
        opts: DhcpOptions::new(),
    };
    let mut iapd_opts = DhcpOptions::new();
    iapd_opts.insert(DhcpOption::IAPrefix(iaprefix));
    let iapd = IAPD {
        id: iaid,
        t1: 0,
        t2: 0,
        opts: iapd_opts,
    };
    msg.opts_mut().insert(DhcpOption::IAPD(iapd));
    // If we already have an IA_NA address, ask to refresh it; else
    // empty IA_NA gives the server a chance to grant on Renew even
    // if we never had one before.
    let mut iana_opts = DhcpOptions::new();
    if let Some(addr) = wan_address {
        iana_opts.insert(DhcpOption::IAAddr(IAAddr {
            addr,
            preferred_life: 0,
            valid_life: 0,
            opts: DhcpOptions::new(),
        }));
    }
    let iana = IANA {
        id: iaid,
        t1: 0,
        t2: 0,
        opts: iana_opts,
    };
    msg.opts_mut().insert(DhcpOption::IANA(iana));
    msg
}

// ── Message builders ────────────────────────────────────────────────

fn build_message(mt: MessageType, duid: &[u8], iaid: u32) -> Message {
    let mut msg = Message::new(mt);
    msg.opts_mut().insert(DhcpOption::ClientId(duid.to_vec()));
    msg.opts_mut().insert(DhcpOption::ElapsedTime(0));
    let iapd = IAPD {
        id: iaid,
        t1: 0,
        t2: 0,
        opts: DhcpOptions::new(),
    };
    msg.opts_mut().insert(DhcpOption::IAPD(iapd));
    // Also solicit IA_NA — an ISP-granted v6 address on the WAN
    // iface. Reuses the same IAID as IA_PD for simplicity; RFC 8415
    // allows separate IAIDs but nobody cares in practice. If the
    // server doesn't support NA allocation it won't echo IA_NA in
    // the Reply; we just proceed without a WAN address.
    let iana = IANA {
        id: iaid,
        t1: 0,
        t2: 0,
        opts: DhcpOptions::new(),
    };
    msg.opts_mut().insert(DhcpOption::IANA(iana));
    // Option Request: DNS + search list.
    msg.opts_mut().insert(DhcpOption::ORO(ORO {
        opts: vec![OptionCode::DomainNameServers, OptionCode::DomainSearchList],
    }));
    msg
}

fn build_request(
    duid: &[u8],
    iaid: u32,
    server_id: &[u8],
    advertised_iapd: &IAPD,
    advertised_iana: Option<&IANA>,
) -> Message {
    let mut msg = Message::new(MessageType::Request);
    msg.opts_mut().insert(DhcpOption::ClientId(duid.to_vec()));
    msg.opts_mut()
        .insert(DhcpOption::ServerId(server_id.to_vec()));
    msg.opts_mut().insert(DhcpOption::ElapsedTime(0));
    // Re-present the advertised IA_PD verbatim.
    let iapd = IAPD {
        id: iaid,
        t1: advertised_iapd.t1,
        t2: advertised_iapd.t2,
        opts: advertised_iapd.opts.clone(),
    };
    msg.opts_mut().insert(DhcpOption::IAPD(iapd));
    // Echo the advertised IA_NA if present — confirms the same
    // WAN address allocation. If the server didn't advertise one,
    // include an empty IA_NA so it has a chance to grant on Request
    // even if it didn't on Advertise.
    let iana = if let Some(a) = advertised_iana {
        IANA {
            id: iaid,
            t1: a.t1,
            t2: a.t2,
            opts: a.opts.clone(),
        }
    } else {
        IANA {
            id: iaid,
            t1: 0,
            t2: 0,
            opts: DhcpOptions::new(),
        }
    };
    msg.opts_mut().insert(DhcpOption::IANA(iana));
    msg
}

fn find_iana(opts: &DhcpOptions) -> Option<IANA> {
    for o in opts.iter() {
        if let DhcpOption::IANA(iana) = o {
            return Some(iana.clone());
        }
    }
    None
}

fn find_iaaddr(opts: &DhcpOptions) -> Option<IAAddr> {
    for o in opts.iter() {
        if let DhcpOption::IAAddr(a) = o {
            return Some(a.clone());
        }
    }
    None
}

// ── DUID + helpers ─────────────────────────────────────────────────

/// Persistent DUID+IAID storage for the DHCPv6 client. The ISP keys
/// the delegated prefix on this pair; regenerating across reboots
/// means a fresh /56 every time — wasteful and potentially billable.
/// File format: [4 bytes IAID, big-endian][DUID bytes to EOF].
const DUID_PATH: &str = "/etc/oxwrt/dhcp6-duid";

fn load_or_create_duid_iaid(mac: [u8; 6]) -> Result<(Vec<u8>, u32), Error> {
    match std::fs::read(DUID_PATH) {
        Ok(bytes) if bytes.len() > 4 => {
            let iaid = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            let duid = bytes[4..].to_vec();
            return Ok((duid, iaid));
        }
        Ok(_) => {
            tracing::warn!("dhcp6-duid: file too short to parse; regenerating");
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // First boot — fall through to generate.
        }
        Err(e) => {
            return Err(Error::Io(e));
        }
    }
    // Generate a fresh DUID-LL from the WAN MAC + random IAID,
    // persist both.
    let duid = build_duid_ll(mac);
    let iaid: u32 = rand::random();
    if let Some(parent) = std::path::Path::new(DUID_PATH).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let mut buf = Vec::with_capacity(4 + duid.len());
    buf.extend_from_slice(&iaid.to_be_bytes());
    buf.extend_from_slice(&duid);
    if let Err(e) = std::fs::write(DUID_PATH, &buf) {
        tracing::warn!(
            path = DUID_PATH, error = %e,
            "dhcp6-duid: write failed; proceeding with ephemeral DUID"
        );
    } else {
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(DUID_PATH, std::fs::Permissions::from_mode(0o600));
        }
        tracing::info!(
            path = DUID_PATH,
            duid_len = duid.len(),
            iaid,
            "dhcp6-duid: generated + persisted"
        );
    }
    Ok((duid, iaid))
}

/// DUID-LL per RFC 8415 § 11.4 for Ethernet:
///   [ 00 03 ][ 00 01 ][ 6 bytes of MAC ]  → 10 bytes total.
/// (dhcproto's Duid::link_layer helper writes 16 MAC bytes which is
/// wrong for Ethernet — we hand-build a correct one.)
fn build_duid_ll(mac: [u8; 6]) -> Vec<u8> {
    let mut d = Vec::with_capacity(10);
    d.extend_from_slice(&3u16.to_be_bytes()); // type = LL
    d.extend_from_slice(&1u16.to_be_bytes()); // htype = Ethernet
    d.extend_from_slice(&mac);
    d
}

fn build_socket(ifindex: u32) -> Result<tokio::net::UdpSocket, Error> {
    use socket2::{Domain, Protocol, Socket, Type};
    let sock = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_only_v6(true)?;
    sock.set_reuse_address(true)?;
    sock.bind(&SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 546, 0, 0).into())?;
    sock.set_multicast_hops_v6(1)?;
    sock.set_multicast_if_v6(ifindex)?;
    sock.set_nonblocking(true)?;
    let std_sock: std::net::UdpSocket = sock.into();
    Ok(tokio::net::UdpSocket::from_std(std_sock)?)
}

fn read_iface_mac(iface: &str) -> Result<[u8; 6], Error> {
    let s = std::fs::read_to_string(format!("/sys/class/net/{iface}/address"))?;
    let parts: Vec<u8> = s
        .trim()
        .split(':')
        .filter_map(|h| u8::from_str_radix(h, 16).ok())
        .collect();
    if parts.len() != 6 {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unexpected MAC: {s:?}"),
        )));
    }
    let mut out = [0u8; 6];
    out.copy_from_slice(&parts);
    Ok(out)
}

fn read_iface_index(iface: &str) -> Result<u32, Error> {
    let s = std::fs::read_to_string(format!("/sys/class/net/{iface}/ifindex"))?;
    s.trim().parse::<u32>().map_err(|e| {
        Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("ifindex parse: {e}"),
        ))
    })
}

fn option_raw(opts: &DhcpOptions, code: OptionCode) -> Option<Vec<u8>> {
    // dhcproto stores decoded values; for ServerId/ClientId we stored
    // them as Vec<u8>. Reach in, find the matching variant.
    for o in opts.iter() {
        match o {
            DhcpOption::ServerId(v) if code == OptionCode::ServerId => return Some(v.clone()),
            DhcpOption::ClientId(v) if code == OptionCode::ClientId => return Some(v.clone()),
            _ => {}
        }
    }
    None
}

fn find_iapd(opts: &DhcpOptions) -> Option<IAPD> {
    for o in opts.iter() {
        if let DhcpOption::IAPD(iapd) = o {
            return Some(iapd.clone());
        }
    }
    None
}

fn find_iaprefix(opts: &DhcpOptions) -> Option<dhcproto::v6::IAPrefix> {
    for o in opts.iter() {
        if let DhcpOption::IAPrefix(p) = o {
            return Some(p.clone());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subnet_host_address_56() {
        // /56 delegation leaves bits 56..63 (byte 7) for slicing.
        // subnet_id=1 sets byte 7 = 0x01, which is the LOW nibble of
        // hextet 3. Result: 2001:db8:abcd:0001::1 → `2001:db8:abcd:1::1`
        // (hextet 3 displays its leading zeros stripped).
        let p: Ipv6Addr = "2001:db8:abcd::".parse().unwrap();
        let got = subnet_host_address(p, 56, 1).unwrap();
        assert_eq!(got, "2001:db8:abcd:1::1".parse::<Ipv6Addr>().unwrap());
        // subnet_id=0xab should put 0xab into byte 7 → hextet 3 = 0x00ab
        // → `2001:db8:abcd:ab::1`.
        let got = subnet_host_address(p, 56, 0xab).unwrap();
        assert_eq!(got, "2001:db8:abcd:ab::1".parse::<Ipv6Addr>().unwrap());
        // subnet_id=0xff fits; 0x100 overflows the 8-bit slicing space.
        assert!(subnet_host_address(p, 56, 0xff).is_some());
        assert!(subnet_host_address(p, 56, 0x100).is_none());
    }

    #[test]
    fn subnet_host_address_60() {
        // /60 allows 4 bits of slicing.
        let p: Ipv6Addr = "2001:db8:abcd:1230::".parse().unwrap();
        // subnet 0x5 → 2001:db8:abcd:1235::1
        let got = subnet_host_address(p, 60, 5).unwrap();
        assert_eq!(got, "2001:db8:abcd:1235::1".parse::<Ipv6Addr>().unwrap());
        // subnet 0x10 overflows /60's 4-bit space.
        assert!(subnet_host_address(p, 60, 16).is_none());
    }

    #[test]
    fn subnet_host_address_64_no_slicing() {
        // With /64 delegation there are 0 bits of slicing room.
        let p: Ipv6Addr = "2001:db8:abcd:1::".parse().unwrap();
        // subnet 0 fits (no-op); subnet 1 doesn't.
        assert!(subnet_host_address(p, 64, 0).is_some());
        assert!(subnet_host_address(p, 64, 1).is_none());
    }

    #[test]
    fn duid_ll_shape() {
        let mac = [0x94, 0x83, 0xc4, 0xca, 0x5c, 0x78];
        let duid = build_duid_ll(mac);
        assert_eq!(duid.len(), 10);
        assert_eq!(&duid[0..2], &[0, 3]); // LL
        assert_eq!(&duid[2..4], &[0, 1]); // Ethernet
        assert_eq!(&duid[4..10], &mac);
    }

    /// Persisted DUID file round-trip: write [IAID BE][DUID], read
    /// it back, the bytes decompose into the same iaid + duid. We
    /// don't exercise load_or_create_duid_iaid directly because it
    /// uses /etc/oxwrt paths; this test validates the format
    /// contract the function relies on.
    #[test]
    fn duid_file_format_roundtrip() {
        let iaid: u32 = 0xdeadbeef;
        let duid = build_duid_ll([0x94, 0x83, 0xc4, 0xca, 0x5c, 0x78]);
        let mut buf = Vec::new();
        buf.extend_from_slice(&iaid.to_be_bytes());
        buf.extend_from_slice(&duid);
        // Decode.
        let got_iaid = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let got_duid = &buf[4..];
        assert_eq!(got_iaid, iaid);
        assert_eq!(got_duid, duid.as_slice());
    }
}
