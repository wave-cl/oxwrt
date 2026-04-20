//! DHCPv4 client for WAN address acquisition + renewal.
//!
//! Two entry points:
//! - `acquire()` — one-shot DISCOVER → OFFER → REQUEST → ACK. Used by init
//!   at boot so service startup blocks on having an IP.
//! - `spawn_renewal_loop()` — long-running tokio task that re-runs the
//!   handshake at T1 (lease/2) and reapplies the lease so the router
//!   doesn't silently go dark when the lease expires.
//!
//! Still v0: no unicast renewal (we always rebroadcast DISCOVER), no
//! T2/REBINDING distinction, no RELEASE on shutdown, no DECLINE on address
//! conflict. The renewal loop just re-runs the full handshake — wasteful
//! by RFC 2131 standards but correct for any compliant server, and ~30
//! lines instead of the ~200 a proper renewal state machine takes.
//!
//! Uses `dhcproto` for the packet codec and a raw `SO_BROADCAST` +
//! `SO_BINDTODEVICE` UDP socket for the wire transport. The client has no
//! IP yet, so it cannot use source-IP-based routing — the socket must be
//! tied to the interface directly.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use dhcproto::v4::{DhcpOption, Flags, HType, Message, MessageType, OptionCode};
use dhcproto::{Decodable, Decoder, Encodable, Encoder};
use futures_util::stream::TryStreamExt;
use rtnetlink::packet_route::link::LinkAttribute;
use rtnetlink::{Handle, LinkUnspec};
use tokio::net::UdpSocket;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("rtnetlink: {0}")]
    Rtnetlink(#[from] rtnetlink::Error),
    #[error("dhcp decode: {0}")]
    Decode(String),
    #[error("dhcp encode: {0}")]
    Encode(String),
    #[error("timeout waiting for {0}")]
    Timeout(&'static str),
    #[error("unexpected DHCP message type for xid {xid}")]
    UnexpectedMessageType { xid: u32 },
    #[error("missing option {0:?}")]
    MissingOption(OptionCode),
    #[error("interface {0} has no hardware address")]
    NoHwAddr(String),
    #[error("interface {0} not found")]
    NoInterface(String),
}

#[derive(Debug, Clone)]
pub struct DhcpLease {
    pub address: Ipv4Addr,
    pub prefix: u8,
    pub gateway: Option<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
    pub lease_seconds: u32,
    pub server: Ipv4Addr,
}

/// Shared WAN lease state. `None` until the boot-time DHCP `acquire`
/// succeeds, then mutated in place by `spawn_renewal_loop` on every
/// renewal. The control plane's `diag dhcp` RPC reads it.
/// Wrapped in an `Arc<RwLock<...>>` so the renewal loop and the
/// control-plane side can hold independent clones — the renewal loop
/// is spawned before ControlState exists, so it can't share via the
/// ControlState Arc itself.
///
/// Lives alongside [`DhcpLease`] here (not in the daemon's
/// `control.rs`) so oxwrt-linux can own the type and `spawn_renewal_
/// loop` takes a `SharedLease` without a cross-crate circularity.
pub type SharedLease = Arc<RwLock<Option<DhcpLease>>>;

/// Identity bits the client sends to the ISP's DHCP server in
/// DISCOVER + REQUEST. All optional — `None` means omit the
/// corresponding option entirely. Derived from `WanConfig::Dhcp`
/// fields at the call site; see init::run for that wiring.
#[derive(Debug, Clone, Default)]
pub struct DhcpClientOpts {
    /// Option 12 (hostname). Some ISPs refuse to lease without it.
    pub hostname: Option<String>,
    /// Option 60 (vendor-class-identifier). Business + cable
    /// circuits sometimes key their DHCP pool on this.
    pub vendor_class_id: Option<String>,
}

/// Run one full DHCPv4 handshake on `iface_name`. Returns the lease on
/// success, or an error on timeout / protocol failure. Does **not** apply
/// the lease to the interface — that's `apply_lease`'s job, called
/// separately so callers can log / gate on the lease first.
pub async fn acquire(
    handle: &Handle,
    iface_name: &str,
    overall_timeout: Duration,
    opts: &DhcpClientOpts,
) -> Result<DhcpLease, Error> {
    let start = Instant::now();
    let result = acquire_inner(handle, iface_name, overall_timeout, opts).await;
    let elapsed = start.elapsed();
    let label: &'static str = match &result {
        Ok(_) => "ok",
        Err(Error::Timeout(_)) => "timeout",
        Err(_) => "error",
    };
    let latency = result.is_ok().then_some(elapsed);
    crate::metrics_state::record_dhcp_acquire(iface_name, label, latency);
    result
}

async fn acquire_inner(
    handle: &Handle,
    iface_name: &str,
    overall_timeout: Duration,
    opts: &DhcpClientOpts,
) -> Result<DhcpLease, Error> {
    let (iface_idx, hw_addr) = get_iface_mac(handle, iface_name).await?;

    // Wait for the iface to have a carrier before firing DISCOVER.
    // Without this, the supervisor task races the kernel's ethernet
    // driver probe + phy autoneg: our DISCOVER goes out over a
    // link that's admin-UP but carrier-DOWN (or still negotiating),
    // the frame never reaches the ISP, we wait 15s for an OFFER
    // that can't arrive, then retry with 10s backoff — adding
    // ~20-25s of avoidable boot-to-internet latency on every cold
    // start. Polling /sys/class/net/<iface>/carrier is the cheap,
    // standard way to gate on "link is usable" without wiring up
    // rtnetlink link-up notifications for one caller.
    //
    // 10s budget is generous; MT7986 + RTL8221B negotiate ~2-3 s.
    // On longer delays we fall through and let the acquire path
    // run normally (it'll hit the same timeout, but at least we
    // tried).
    wait_for_carrier(iface_name, Duration::from_secs(10)).await;

    // UDP socket for RECEIVING responses. The server replies via UDP
    // broadcast (or unicast if it can route back) to port 68, and the
    // kernel delivers it to this socket bound on 0.0.0.0:68. DISCOVER
    // and REQUEST are sent via the AF_PACKET raw socket below so the
    // IP header source is 0.0.0.0 (RFC 2131 §4.1).
    let socket = create_broadcast_socket(iface_name)?;

    let xid: u32 = rand::random();
    tracing::info!(iface = %iface_name, xid, ?hw_addr, "wan dhcp: DISCOVER");

    let discover = build_discover(xid, &hw_addr, opts);
    let discover_bytes = encode_dhcp(&discover)?;
    let deadline = Instant::now() + overall_timeout;

    // Retransmit DISCOVER at RFC 2131-style widening intervals
    // (2s, 4s, 8s, ...) within the same acquire window, instead of
    // relying on a single send + long wait. The first frame can be
    // lost on the WAN in several ways: PHY flap late in autoneg
    // that wait_for_carrier didn't catch, ISP DHCP relay still
    // learning our MAC, transient link congestion. A single retry
    // 2 s later usually gets an OFFER immediately, cutting cold-
    // boot DHCP latency from ~15 s (one timeout) to 2–4 s.
    let offer = {
        let mut next_retrans = Duration::from_secs(2);
        let mut offer: Option<Message> = None;
        send_raw_dhcp_broadcast(iface_idx, &hw_addr, &discover_bytes)?;
        while offer.is_none() {
            let wait_until = (Instant::now() + next_retrans).min(deadline);
            match recv_expected(&socket, xid, MessageType::Offer, wait_until).await {
                Ok(m) => offer = Some(m),
                Err(Error::Timeout(what)) => {
                    if Instant::now() >= deadline {
                        return Err(Error::Timeout(what));
                    }
                    tracing::info!(
                        iface = %iface_name, xid,
                        next_retrans_s = next_retrans.as_secs(),
                        "wan dhcp: no OFFER yet, retransmitting DISCOVER"
                    );
                    send_raw_dhcp_broadcast(iface_idx, &hw_addr, &discover_bytes)?;
                    next_retrans = (next_retrans * 2).min(Duration::from_secs(8));
                }
                Err(e) => return Err(e),
            }
        }
        offer.unwrap()
    };

    let offered_ip = offer.yiaddr();
    let server_id =
        find_server_id(&offer).ok_or(Error::MissingOption(OptionCode::ServerIdentifier))?;
    tracing::info!(iface = %iface_name, %offered_ip, %server_id, "wan dhcp: OFFER received");

    let request = build_request(xid, &hw_addr, offered_ip, server_id, opts);
    let request_bytes = encode_dhcp(&request)?;
    send_raw_dhcp_broadcast(iface_idx, &hw_addr, &request_bytes)?;

    let ack = recv_expected(&socket, xid, MessageType::Ack, deadline).await?;
    parse_lease(&ack, server_id)
}

fn encode_dhcp(msg: &Message) -> Result<Vec<u8>, Error> {
    let mut buf = Vec::with_capacity(1024);
    let mut enc = Encoder::new(&mut buf);
    msg.encode(&mut enc)
        .map_err(|e| Error::Encode(e.to_string()))?;
    Ok(buf)
}

/// Apply a previously-acquired lease to `iface_name`: assign the address
/// and, if present, add a default route via the gateway. DNS servers on
/// the lease aren't written anywhere by this function — hickory's config
/// comes from the bind-mounted `named.toml`, not from DHCP. The caller
/// can read `lease.dns` if it wants them.
pub async fn apply_lease(
    handle: &Handle,
    iface_name: &str,
    lease: &DhcpLease,
) -> Result<(), Error> {
    let (idx, _mac) = get_iface_mac(handle, iface_name).await?;

    handle
        .link()
        .set(LinkUnspec::new_with_index(idx).up().build())
        .execute()
        .await?;

    match handle
        .address()
        .add(idx, std::net::IpAddr::V4(lease.address), lease.prefix)
        .execute()
        .await
    {
        Ok(()) => {}
        Err(e) if is_exists(&e) => {
            tracing::warn!(iface = %iface_name, addr = %lease.address, "wan dhcp: address already present, reusing");
        }
        Err(e) => return Err(Error::Rtnetlink(e)),
    }

    // NOTE: default route installation is owned by the failover
    // coordinator (wan_failover::spawn), not here. The coordinator
    // sees all per-WAN leases via the shared WanLeases map plus
    // per-WAN health from ICMP probes, and picks exactly one to
    // install. If we also installed the default here, we'd race
    // the coordinator on every lease renewal (the EEXIST warning
    // we used to log — "add default failed ... File exists").
    // Single-WAN setups are unaffected: the coordinator still runs
    // and installs the default from the single lease.

    tracing::info!(
        iface = %iface_name,
        addr = %lease.address,
        prefix = lease.prefix,
        dns = ?lease.dns,
        lease_s = lease.lease_seconds,
        "wan dhcp: lease applied"
    );
    Ok(())
}

/// Spawn a long-running tokio task that handles DHCP lease renewals on
/// `iface`. The task takes the initial lease's T1 (50% of lease_seconds,
/// clamped to a sane window) as the next renewal time, sleeps until then,
/// re-runs the full handshake, applies the new lease, and loops forever.
///
/// On renewal failure, exponential backoff (10s → 5min) keeps trying —
/// the alternative is silently letting the lease expire and the router
/// going dark. The task is fire-and-forget; the returned `JoinHandle` is
/// only kept so a future shutdown path can abort it.
///
/// **Address-change behavior:** if the renewal returns a different
/// address than the current lease, we log a `warn!` and apply the new
/// one. The OLD address remains on the interface — `apply_lease` doesn't
/// remove it, so the box has both addresses until the next reboot. This
/// is a known v0 limitation. In practice, DHCP servers almost always
/// hand back the same lease for the same MAC across renewals.
pub fn spawn_renewal_loop(
    handle: Handle,
    iface: String,
    initial_lease: DhcpLease,
    shared_lease: SharedLease,
    client_opts: DhcpClientOpts,
) -> tokio::task::JoinHandle<()> {
    // Shared wake signal from the link-watch task → renewal loop. Fires
    // on link-down→up edges so the renewal doesn't sit asleep for half
    // a lease interval (typically 12h) after WAN reconnects.
    let wake = std::sync::Arc::new(tokio::sync::Notify::new());

    // Link-state watcher. Polls /sys/class/net/<iface>/carrier every 3s
    // (cheaper + simpler than subscribing to RTMGRP_LINK multicast, and
    // fast enough for WAN reconnect UX). Transitions:
    //   up → down: clear the shared lease slot so `diag dhcp` no longer
    //              advertises a stale address; DO NOT deconfigure the
    //              iface (we'll re-DISCOVER on re-up and may get the
    //              same address back).
    //   down → up: notify the renewal loop; it drops out of sleep and
    //              re-acquires immediately with backoff.
    {
        let iface = iface.clone();
        let shared_lease = shared_lease.clone();
        let wake = wake.clone();
        tokio::spawn(async move {
            let mut prev_up = true; // we were just handed a lease, assume up
            loop {
                tokio::time::sleep(Duration::from_secs(3)).await;
                let now_up = carrier_up(&iface);
                if prev_up && !now_up {
                    tracing::warn!(
                        iface = %iface,
                        "wan dhcp: carrier lost; clearing lease state"
                    );
                    if let Ok(mut slot) = shared_lease.write() {
                        *slot = None;
                    }
                } else if !prev_up && now_up {
                    tracing::info!(
                        iface = %iface,
                        "wan dhcp: carrier returned; waking renewal loop"
                    );
                    wake.notify_one();
                }
                prev_up = now_up;
            }
        });
    }

    tokio::spawn(async move {
        let mut current = initial_lease;
        loop {
            // T1 = lease/2 per RFC 2131. Clamp to [30s, 1 day] so a
            // pathologically short lease doesn't busy-loop and a
            // pathologically long one isn't ignored across a reboot.
            let t1 = current.lease_seconds.clamp(60, 86_400) / 2;
            tracing::info!(
                iface = %iface,
                t1_s = t1,
                lease_s = current.lease_seconds,
                "wan dhcp: next renewal scheduled"
            );
            // Wake early if the link-watcher says carrier just came
            // back. Otherwise sleep the full T1.
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(t1 as u64)) => {}
                _ = wake.notified() => {
                    tracing::info!(
                        iface = %iface,
                        "wan dhcp: early renewal triggered by carrier event"
                    );
                }
            }

            tracing::info!(iface = %iface, "wan dhcp: renewing lease");
            let mut backoff = Duration::from_secs(10);
            loop {
                match acquire(&handle, &iface, Duration::from_secs(15), &client_opts).await {
                    Ok(lease) => {
                        if lease.address != current.address {
                            tracing::warn!(
                                iface = %iface,
                                old = %current.address,
                                new = %lease.address,
                                "wan dhcp: lease address changed across renewal; old address remains until reboot"
                            );
                        }
                        if let Err(e) = apply_lease(&handle, &iface, &lease).await {
                            tracing::error!(
                                iface = %iface,
                                error = %e,
                                "wan dhcp: apply_lease failed during renewal"
                            );
                        }
                        current = lease.clone();
                        // Publish to the shared state so `diag dhcp`
                        // sees the renewed lease.
                        if let Ok(mut slot) = shared_lease.write() {
                            *slot = Some(lease);
                        }
                        break;
                    }
                    Err(e) => {
                        tracing::warn!(
                            iface = %iface,
                            error = %e,
                            backoff_s = backoff.as_secs(),
                            "wan dhcp: renewal attempt failed; will retry"
                        );
                        tokio::time::sleep(backoff).await;
                        backoff = (backoff * 2).min(Duration::from_secs(300));
                    }
                }
            }
        }
    })
}

/// Read /sys/class/net/<iface>/carrier. Returns true iff the file
/// exists AND its contents start with "1". Any other case (file
/// missing, IO error, "0", unreadable) → false. Matches the kernel's
/// IFF_LOWER_UP bit in userspace-friendly form without a netlink
/// round-trip.
fn carrier_up(iface: &str) -> bool {
    let path = format!("/sys/class/net/{iface}/carrier");
    match std::fs::read_to_string(&path) {
        Ok(s) => s.trim() == "1",
        Err(_) => false,
    }
}

// -------------- implementation details --------------

fn create_broadcast_socket(iface: &str) -> Result<UdpSocket, Error> {
    use socket2::{Domain, Protocol, Socket, Type};
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_broadcast(true)?;
    sock.set_reuse_address(true)?;
    #[cfg(target_os = "linux")]
    sock.bind_device(Some(iface.as_bytes()))?;
    sock.set_nonblocking(true)?;
    let bind_addr: SocketAddr = "0.0.0.0:68".parse().unwrap();
    sock.bind(&bind_addr.into())?;
    let std_sock: std::net::UdpSocket = sock.into();
    Ok(UdpSocket::from_std(std_sock)?)
}

async fn get_iface_mac(handle: &Handle, iface: &str) -> Result<(u32, [u8; 6]), Error> {
    let mut stream = handle.link().get().match_name(iface.to_string()).execute();
    let msg = stream
        .try_next()
        .await
        .map_err(Error::Rtnetlink)?
        .ok_or_else(|| Error::NoInterface(iface.to_string()))?;
    let idx = msg.header.index;
    for attr in msg.attributes {
        if let LinkAttribute::Address(bytes) = attr {
            if bytes.len() == 6 {
                let mut mac = [0u8; 6];
                mac.copy_from_slice(&bytes);
                return Ok((idx, mac));
            }
        }
    }
    Err(Error::NoHwAddr(iface.to_string()))
}

fn build_discover(xid: u32, hw_addr: &[u8; 6], client_opts: &DhcpClientOpts) -> Message {
    let mut msg = Message::default();
    msg.set_htype(HType::Eth)
        .set_xid(xid)
        .set_chaddr(hw_addr)
        .set_flags(Flags::default().set_broadcast());
    let opts = msg.opts_mut();
    opts.insert(DhcpOption::MessageType(MessageType::Discover));
    opts.insert(DhcpOption::ClientIdentifier({
        let mut v = Vec::with_capacity(7);
        v.push(1); // Ethernet htype
        v.extend_from_slice(hw_addr);
        v
    }));
    insert_client_opts(opts, client_opts);
    opts.insert(DhcpOption::ParameterRequestList(vec![
        OptionCode::SubnetMask,
        OptionCode::Router,
        OptionCode::DomainNameServer,
        OptionCode::DomainName,
        OptionCode::AddressLeaseTime,
        OptionCode::ServerIdentifier,
    ]));
    msg
}

fn build_request(
    xid: u32,
    hw_addr: &[u8; 6],
    offered_ip: Ipv4Addr,
    server_id: Ipv4Addr,
    client_opts: &DhcpClientOpts,
) -> Message {
    let mut msg = Message::default();
    msg.set_htype(HType::Eth)
        .set_xid(xid)
        .set_chaddr(hw_addr)
        .set_flags(Flags::default().set_broadcast());
    let opts = msg.opts_mut();
    opts.insert(DhcpOption::MessageType(MessageType::Request));
    opts.insert(DhcpOption::RequestedIpAddress(offered_ip));
    opts.insert(DhcpOption::ServerIdentifier(server_id));
    opts.insert(DhcpOption::ClientIdentifier({
        let mut v = Vec::with_capacity(7);
        v.push(1);
        v.extend_from_slice(hw_addr);
        v
    }));
    insert_client_opts(opts, client_opts);
    opts.insert(DhcpOption::ParameterRequestList(vec![
        OptionCode::SubnetMask,
        OptionCode::Router,
        OptionCode::DomainNameServer,
        OptionCode::DomainName,
        OptionCode::AddressLeaseTime,
        OptionCode::ServerIdentifier,
    ]));
    msg
}

/// Shared helper: insert the operator-supplied hostname (opt 12)
/// and vendor-class-id (opt 60) into a DHCP message's option set.
/// Both are no-ops when their respective config field is None.
fn insert_client_opts(opts: &mut dhcproto::v4::DhcpOptions, client_opts: &DhcpClientOpts) {
    if let Some(h) = client_opts.hostname.as_deref() {
        if !h.is_empty() {
            opts.insert(DhcpOption::Hostname(h.to_string()));
        }
    }
    if let Some(vci) = client_opts.vendor_class_id.as_deref() {
        if !vci.is_empty() {
            opts.insert(DhcpOption::ClassIdentifier(vci.as_bytes().to_vec()));
        }
    }
}

/// RFC 2131 compliant broadcast send: builds the full Ethernet+IP+UDP
/// frame and sends via `AF_PACKET SOCK_RAW`. This is the ONLY way on
/// Linux to emit a packet with IP source `0.0.0.0` — `SOCK_RAW +
/// IPPROTO_RAW` silently substitutes a routable source address per
/// `raw(7)` ("the source address can be zero, which means the kernel
/// will fill it in with a valid source address for the destination"),
/// and any `SOCK_DGRAM` send goes through the same source selection.
///
/// A strict DHCP server (uncommon in the wild but they exist) rejects
/// DISCOVER/REQUEST frames whose IP `saddr` is non-zero. Most routers
/// accept our non-zero source because the DHCP-level `ciaddr` is still
/// zero, but we can't afford to depend on that charity on unknown
/// hardware.
///
/// Requires `CAP_NET_RAW` in the caller's effective set. PID 1 has
/// the full cap set (hardening applies to children, not to oxwrtd
/// itself), so this works from `init::async_main`.
fn send_raw_dhcp_broadcast(iface_idx: u32, hw_addr: &[u8; 6], payload: &[u8]) -> Result<(), Error> {
    // -------- Ethernet header (14 bytes) --------
    // dst = ff:ff:ff:ff:ff:ff (L2 broadcast)
    // src = iface MAC
    // type = 0x0800 (IPv4)
    let mut pkt: Vec<u8> = Vec::with_capacity(14 + 20 + 8 + payload.len());
    pkt.extend_from_slice(&[0xff; 6]);
    pkt.extend_from_slice(hw_addr);
    pkt.extend_from_slice(&0x0800u16.to_be_bytes());

    // -------- IPv4 header (20 bytes) --------
    let ip_start = pkt.len();
    let ip_len = 20 + 8 + payload.len();
    if ip_len > u16::MAX as usize {
        return Err(Error::Encode(format!("dhcp payload too large: {ip_len}")));
    }
    pkt.push(0x45); // version=4, IHL=5 (20 bytes, no options)
    pkt.push(0); // DSCP/ECN
    pkt.extend_from_slice(&(ip_len as u16).to_be_bytes()); // Total Length
    pkt.extend_from_slice(&0u16.to_be_bytes()); // Identification
    pkt.extend_from_slice(&0u16.to_be_bytes()); // Flags + Fragment Offset
    pkt.push(64); // TTL
    pkt.push(17); // Protocol = UDP
    pkt.extend_from_slice(&0u16.to_be_bytes()); // Header Checksum (patched below)
    pkt.extend_from_slice(&[0, 0, 0, 0]); // Source = 0.0.0.0  ← the whole point
    pkt.extend_from_slice(&[255, 255, 255, 255]); // Destination = 255.255.255.255

    // Patch in IP header checksum.
    let ip_end = ip_start + 20;
    let ip_cksum = ip_checksum(&pkt[ip_start..ip_end]);
    pkt[ip_start + 10..ip_start + 12].copy_from_slice(&ip_cksum.to_be_bytes());

    // -------- UDP header (8 bytes) + payload --------
    let udp_len = 8 + payload.len();
    let udp_start = pkt.len();
    pkt.extend_from_slice(&68u16.to_be_bytes()); // Source Port (bootpc)
    pkt.extend_from_slice(&67u16.to_be_bytes()); // Destination Port (bootps)
    pkt.extend_from_slice(&(udp_len as u16).to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes()); // Checksum (patched below)
    pkt.extend_from_slice(payload);

    // UDP checksum over pseudo-header || UDP header || payload.
    let mut pseudo = [0u8; 12];
    // src = 0.0.0.0, already zero
    pseudo[4..8].copy_from_slice(&[255, 255, 255, 255]);
    pseudo[8] = 0;
    pseudo[9] = 17;
    pseudo[10..12].copy_from_slice(&(udp_len as u16).to_be_bytes());
    let udp_cksum = udp_checksum(&pseudo, &pkt[udp_start..]);
    pkt[udp_start + 6..udp_start + 8].copy_from_slice(&udp_cksum.to_be_bytes());

    // -------- AF_PACKET send --------
    // SAFETY: we're constructing a `sockaddr_ll` and passing it to
    // `sendto` with the matching length. The fd is closed on every
    // return path. `unsafe` boundary is the syscall pair.
    unsafe {
        let eth_p_ip: libc::c_int = (libc::ETH_P_IP as u16).to_be() as libc::c_int;
        let fd = libc::socket(libc::AF_PACKET, libc::SOCK_RAW, eth_p_ip);
        if fd < 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }

        let mut addr: libc::sockaddr_ll = std::mem::zeroed();
        addr.sll_family = libc::AF_PACKET as u16;
        addr.sll_protocol = (libc::ETH_P_IP as u16).to_be();
        addr.sll_ifindex = iface_idx as i32;
        addr.sll_halen = 6;
        addr.sll_addr[..6].copy_from_slice(&[0xff; 6]);

        let sent = libc::sendto(
            fd,
            pkt.as_ptr() as *const libc::c_void,
            pkt.len(),
            0,
            &addr as *const libc::sockaddr_ll as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        );
        let err = if sent < 0 {
            Some(std::io::Error::last_os_error())
        } else {
            None
        };
        libc::close(fd);
        if let Some(e) = err {
            return Err(Error::Io(e));
        }
    }
    Ok(())
}

/// 16-bit one's complement checksum over a byte slice. Used for the IPv4
/// header (where `data` is the 20-byte header with the checksum field
/// zeroed). Works for any even length; odd lengths add a zero pad.
fn ip_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// UDP checksum over pseudo-header || UDP header || payload. Reuses the
/// same one's complement reduction. A computed value of `0` is a valid
/// UDP checksum and should NOT be replaced with `0xffff` for IPv4 (that
/// special case only applies when the UDP checksum is disabled, which
/// is signalled by sending `0` literally — for IPv4 that's allowed).
fn udp_checksum(pseudo: &[u8], udp_and_payload: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in pseudo.chunks(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    let mut i = 0;
    while i + 1 < udp_and_payload.len() {
        sum += u16::from_be_bytes([udp_and_payload[i], udp_and_payload[i + 1]]) as u32;
        i += 2;
    }
    if i < udp_and_payload.len() {
        sum += (udp_and_payload[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

async fn recv_expected(
    socket: &UdpSocket,
    xid: u32,
    want: MessageType,
    deadline: Instant,
) -> Result<Message, Error> {
    let mut buf = vec![0u8; 2048];
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(match want {
                MessageType::Offer => Error::Timeout("OFFER"),
                MessageType::Ack => Error::Timeout("ACK"),
                _ => Error::Timeout("reply"),
            })?;
        let res = tokio::time::timeout(remaining, socket.recv_from(&mut buf)).await;
        let (n, _) = match res {
            Ok(Ok((n, peer))) => (n, peer),
            Ok(Err(e)) => return Err(Error::Io(e)),
            Err(_) => {
                return Err(match want {
                    MessageType::Offer => Error::Timeout("OFFER"),
                    MessageType::Ack => Error::Timeout("ACK"),
                    _ => Error::Timeout("reply"),
                });
            }
        };
        let msg = Message::decode(&mut Decoder::new(&buf[..n]))
            .map_err(|e| Error::Decode(e.to_string()))?;
        if msg.xid() != xid {
            continue;
        }
        let got = msg
            .opts()
            .get(OptionCode::MessageType)
            .and_then(|o| match o {
                DhcpOption::MessageType(t) => Some(*t),
                _ => None,
            });
        if got != Some(want) {
            continue;
        }
        return Ok(msg);
    }
}

fn find_server_id(msg: &Message) -> Option<Ipv4Addr> {
    match msg.opts().get(OptionCode::ServerIdentifier) {
        Some(DhcpOption::ServerIdentifier(ip)) => Some(*ip),
        _ => None,
    }
}

fn parse_lease(ack: &Message, server: Ipv4Addr) -> Result<DhcpLease, Error> {
    let address = ack.yiaddr();
    let netmask = match ack.opts().get(OptionCode::SubnetMask) {
        Some(DhcpOption::SubnetMask(m)) => *m,
        _ => return Err(Error::MissingOption(OptionCode::SubnetMask)),
    };
    let prefix = netmask_to_prefix(netmask);
    let gateway = match ack.opts().get(OptionCode::Router) {
        Some(DhcpOption::Router(list)) => list.first().copied(),
        _ => None,
    };
    let dns = match ack.opts().get(OptionCode::DomainNameServer) {
        Some(DhcpOption::DomainNameServer(list)) => list.clone(),
        _ => Vec::new(),
    };
    let lease_seconds = match ack.opts().get(OptionCode::AddressLeaseTime) {
        Some(DhcpOption::AddressLeaseTime(s)) => *s,
        _ => 0,
    };
    Ok(DhcpLease {
        address,
        prefix,
        gateway,
        dns,
        lease_seconds,
        server,
    })
}

/// Poll /sys/class/net/<iface>/carrier until it reads `1` (link up)
/// for `STABLE_POLLS` consecutive samples, or the budget expires.
/// Returns either way — the caller proceeds unconditionally; this
/// is a best-effort delay, not a gate.
///
/// Stability requirement matters: MT7986 + RTL8221B flaps the link
/// on initial autoneg, observed as Link Up → Link Down → Link Up
/// over ~3 seconds on a cold boot. Returning on the first `1` read
/// sends DISCOVER into the void during the flap window; the frame
/// is lost and we burn the full 15 s acquire timeout before
/// retrying. Requiring N=10 consecutive reads at 100 ms cadence
/// means we wait until the carrier has held steady for 1 s before
/// firing — empirically enough to clear the autoneg flap.
///
/// Why sysfs: a single stat+read syscall per poll. Alternatives
/// (rtnetlink link-up subscription) would require wiring a second
/// event stream for exactly one caller. Polling at 100 ms adds
/// at most ~900 ms of extra latency over the "already stable"
/// path — negligible vs. the 15 s DHCP timeout we're avoiding.
///
/// Edge cases handled:
/// - iface missing → return immediately; downstream `get_iface_mac`
///   or `send_raw_dhcp_broadcast` will surface the real error
/// - sysfs read returns "" or garbage → treat as no-carrier, reset
///   the stable counter
/// - /sys not mounted (unit-test env) → open fails → return fast
async fn wait_for_carrier(iface_name: &str, budget: Duration) {
    const STABLE_POLLS: u32 = 10; // 10 × 100 ms = 1 s of stable carrier
    let deadline = Instant::now() + budget;
    let path = format!("/sys/class/net/{iface_name}/carrier");
    let mut stable = 0u32;
    loop {
        match std::fs::read_to_string(&path) {
            Ok(s) if s.trim() == "1" => {
                stable += 1;
                if stable >= STABLE_POLLS {
                    tracing::debug!(
                        iface = iface_name,
                        "wan dhcp: carrier stable, sending DISCOVER"
                    );
                    return;
                }
            }
            _ => {
                // carrier=0 (link down), read error, or missing file:
                // reset the stable counter so the next run of UP
                // starts counting fresh.
                stable = 0;
            }
        }
        if Instant::now() >= deadline {
            tracing::warn!(
                iface = iface_name,
                budget_ms = budget.as_millis() as u64,
                "wan dhcp: carrier wait budget exceeded; sending DISCOVER anyway"
            );
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn netmask_to_prefix(mask: Ipv4Addr) -> u8 {
    u32::from(mask).count_ones() as u8
}

/// Match the kernel's negated-errno wrapping for EEXIST (-17) in a
/// `rtnetlink::Error::NetlinkError`. Same pattern as `net::is_exists`
/// but scoped to this module so `wan_dhcp` doesn't have to reach into
/// `net`'s private helpers.
fn is_exists(err: &rtnetlink::Error) -> bool {
    const EEXIST_NEG: i32 = -17;
    if let rtnetlink::Error::NetlinkError(msg) = err {
        if let Some(code) = msg.code {
            return code.get() == EEXIST_NEG;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hw() -> [u8; 6] {
        [0x02, 0x11, 0x22, 0x33, 0x44, 0x55]
    }

    /// Default opts (both fields None) → the DISCOVER carries
    /// neither option 12 nor option 60. Baseline — matches
    /// pre-feature behaviour.
    #[test]
    fn discover_without_opts_omits_both() {
        let msg = build_discover(0xdead_beef, &hw(), &DhcpClientOpts::default());
        let opts = msg.opts();
        assert!(!opts.iter().any(|(c, _)| *c == OptionCode::Hostname));
        assert!(!opts.iter().any(|(c, _)| *c == OptionCode::ClassIdentifier));
    }

    /// hostname: Some("...") → option 12 present with the value.
    #[test]
    fn discover_emits_hostname_when_set() {
        let opts = DhcpClientOpts {
            hostname: Some("flint2".into()),
            vendor_class_id: None,
        };
        let msg = build_discover(0, &hw(), &opts);
        let hostname = msg
            .opts()
            .iter()
            .find_map(|(c, o)| {
                if *c == OptionCode::Hostname {
                    match o {
                        DhcpOption::Hostname(h) => Some(h.clone()),
                        _ => None,
                    }
                } else {
                    None
                }
            })
            .expect("hostname option must be present");
        assert_eq!(hostname, "flint2");
    }

    /// vendor_class_id: Some("...") → option 60 present.
    #[test]
    fn request_emits_vendor_class_when_set() {
        let opts = DhcpClientOpts {
            hostname: None,
            vendor_class_id: Some("MSFT 5.0".into()),
        };
        let msg = build_request(
            0,
            &hw(),
            std::net::Ipv4Addr::new(10, 0, 0, 5),
            std::net::Ipv4Addr::new(10, 0, 0, 1),
            &opts,
        );
        let vci = msg
            .opts()
            .iter()
            .find_map(|(c, o)| {
                if *c == OptionCode::ClassIdentifier {
                    match o {
                        DhcpOption::ClassIdentifier(v) => Some(v.clone()),
                        _ => None,
                    }
                } else {
                    None
                }
            })
            .expect("class-identifier option must be present");
        assert_eq!(vci, b"MSFT 5.0");
    }

    /// Empty strings treated as "not set" — operators pasting
    /// empty TOML values shouldn't silently produce zero-length
    /// options that some DHCP servers choke on.
    #[test]
    fn empty_strings_suppress_emission() {
        let opts = DhcpClientOpts {
            hostname: Some(String::new()),
            vendor_class_id: Some(String::new()),
        };
        let msg = build_discover(0, &hw(), &opts);
        assert!(!msg.opts().iter().any(|(c, _)| *c == OptionCode::Hostname));
        assert!(
            !msg.opts()
                .iter()
                .any(|(c, _)| *c == OptionCode::ClassIdentifier)
        );
    }
}
