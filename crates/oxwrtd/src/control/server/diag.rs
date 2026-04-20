//! Diag RPC dispatch + per-op implementations. Split out in step 7.

use super::*;

pub(super) async fn handle_diag(state: &ControlState, name: &str, args: &[String]) -> Response {
    match name {
        "links" => match diag_links().await {
            Ok(text) => Response::Value { value: text },
            Err(e) => Response::Err {
                message: format!("diag links: {e}"),
            },
        },
        "routes" => match diag_routes().await {
            Ok(text) => Response::Value { value: text },
            Err(e) => Response::Err {
                message: format!("diag routes: {e}"),
            },
        },
        "firewall" => {
            let dump = state.firewall_dump.read().unwrap();
            Response::Value {
                value: dump.join("\n"),
            }
        }
        "addresses" => match diag_addresses().await {
            Ok(text) => Response::Value { value: text },
            Err(e) => Response::Err {
                message: format!("diag addresses: {e}"),
            },
        },
        "ping" | "traceroute" | "drill" | "ss" => {
            // Look up the whitelist entry for this op. The whitelist is
            // compile-time (Rust const), so a typo or unknown name here
            // is a routing bug, not an operator mistake — we'd have
            // already matched one of the known arm labels above.
            let entry = match DIAG_BINARIES.iter().find(|b| b.name == name) {
                Some(e) => e,
                None => {
                    return Response::Err {
                        message: format!(
                            "diag: {name} is in the dispatch match but missing from DIAG_BINARIES"
                        ),
                    };
                }
            };
            match diag_exec(entry, args).await {
                Ok(text) => Response::Value { value: text },
                Err(e) => Response::Err {
                    message: format!("diag {name}: {e}"),
                },
            }
        }
        "dhcp" => {
            let lease = state.wan_lease.read().unwrap();
            let value = match &*lease {
                Some(l) => format!(
                    "address: {}/{}\n\
                     gateway: {}\n\
                     dns:     {}\n\
                     server:  {}\n\
                     lease_s: {}\n",
                    l.address,
                    l.prefix,
                    l.gateway
                        .map(|g| g.to_string())
                        .unwrap_or_else(|| "none".to_string()),
                    if l.dns.is_empty() {
                        "none".to_string()
                    } else {
                        l.dns
                            .iter()
                            .map(|d| d.to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    },
                    l.server,
                    l.lease_seconds,
                ),
                None => "no DHCP lease (static WAN, or initial acquire failed)\n".to_string(),
            };
            Response::Value { value }
        }
        "modules" => {
            // Read /proc/modules (kernel-global, not pid-ns specific, but
            // still readable from the init process). Useful to see what
            // load_modules actually landed on boot.
            match std::fs::read_to_string("/proc/modules") {
                Ok(s) if s.is_empty() => Response::Value {
                    value: "(no modules loaded)\n".to_string(),
                },
                Ok(s) => Response::Value { value: s },
                Err(e) => Response::Err {
                    message: format!("diag modules: {e}"),
                },
            }
        }
        "nft" => {
            // Dump the live nftables ruleset from the host netns. Uses
            // /usr/sbin/nft (shipped by the `nftables` package in the
            // base image), runs in-process from pid-1 context — no
            // container / namespace dance needed, it's just looking at
            // the same kernel state oxwrtd installed.
            use std::process::Command;
            let out = Command::new("/usr/sbin/nft")
                .args(["list", "ruleset"])
                .output();
            match out {
                Ok(o) if o.status.success() => Response::Value {
                    value: String::from_utf8_lossy(&o.stdout).into_owned(),
                },
                Ok(o) => Response::Err {
                    message: format!(
                        "diag nft: exit {:?}: {}",
                        o.status.code(),
                        String::from_utf8_lossy(&o.stderr)
                    ),
                },
                Err(e) => Response::Err {
                    message: format!("diag nft: spawn: {e}"),
                },
            }
        }
        "nft-summary" => {
            // Condensed snapshot of the nftables ruleset: one line per
            // table with chain + rule + set counts, one line per chain
            // with hook/prio/policy, and for any set with elements a
            // count + up-to-5 sample elements. Built from `nft -j list
            // ruleset` (shipped with nftables; same binary as above).
            // Easier to grep than the full ruleset when operators are
            // just asking "are my blocklist sets populated" or "did
            // the forward chain's default really land as drop?"
            use std::process::Command;
            // The shipped nftables package on OpenWrt 25.x is built
            // without JSON support (-j), so we parse the plain-text
            // `nft list ruleset` instead. Brittle in principle but
            // the libnftables formatter is effectively an ABI —
            // distros depend on stable output.
            let out = Command::new("/usr/sbin/nft")
                .args(["list", "ruleset"])
                .output();
            match out {
                Ok(o) if o.status.success() => {
                    match summarize_nft_text(&String::from_utf8_lossy(&o.stdout)) {
                        Ok(text) => Response::Value { value: text },
                        Err(e) => Response::Err {
                            message: format!("diag nft-summary: parse: {e}"),
                        },
                    }
                }
                Ok(o) => Response::Err {
                    message: format!(
                        "diag nft-summary: exit {:?}: {}",
                        o.status.code(),
                        String::from_utf8_lossy(&o.stderr)
                    ),
                },
                Err(e) => Response::Err {
                    message: format!("diag nft-summary: spawn: {e}"),
                },
            }
        }
        "sysctl" => {
            // With an argument, read that specific sysctl key (dot or
            // slash form): `diag sysctl net.ipv6.conf.eth1.accept_ra`
            // translates to reading /proc/sys/net/ipv6/conf/eth1/accept_ra.
            // Without an argument, emit a curated snapshot of the
            // networking flags the router relies on.
            if let Some(key) = args.first() {
                // Safety: reject anything that could escape /proc/sys —
                // no absolute paths, no `..`, only alphanumerics +
                // dots/slashes/underscores/hyphens. sysctl keys in the
                // wild follow that alphabet; rejecting anything else
                // keeps this diag RPC out of arbitrary-file-read
                // territory.
                let is_safe = key
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '/' | '_' | '-'));
                if !is_safe || key.starts_with('/') || key.contains("..") {
                    return Response::Err {
                        message: format!("diag sysctl: invalid key {key:?}"),
                    };
                }
                let path = format!("/proc/sys/{}", key.replace('.', "/"));
                return match std::fs::read_to_string(&path) {
                    Ok(s) => Response::Value {
                        value: format!("{path}: {}\n", s.trim()),
                    },
                    Err(e) => Response::Err {
                        message: format!("{path}: {e}"),
                    },
                };
            }
            // Argument-less default snapshot: the classic flags.
            const ENTRIES: &[&str] = &[
                "/proc/sys/net/ipv4/ip_forward",
                "/proc/sys/net/ipv4/conf/all/forwarding",
                "/proc/sys/net/ipv4/conf/all/rp_filter",
                "/proc/sys/net/ipv6/conf/all/forwarding",
                "/proc/sys/net/ipv6/conf/all/accept_ra",
                "/proc/sys/net/bridge/bridge-nf-call-iptables",
            ];
            let mut out = String::new();
            for p in ENTRIES {
                match std::fs::read_to_string(p) {
                    Ok(s) => {
                        out.push_str(&format!("{p}: {}\n", s.trim()));
                    }
                    Err(e) => {
                        out.push_str(&format!("{p}: ERR {e}\n"));
                    }
                }
            }
            Response::Value { value: out }
        }
        "ping-many" => {
            // Parallel ICMP to a list of IPs FROM the router's
            // vantage. Complements `vpn-auto-switch`'s client-
            // side ping-race for when "which Mullvad relay is
            // actually fastest from the router" matters — the
            // operator's laptop is usually close in latency, but
            // not for split-horizon ISPs or asymmetric routing.
            //
            // Arg format: each IP as its own positional, e.g.
            //   oxctl … diag ping-many 1.1.1.1 8.8.8.8 9.9.9.9
            // Returns lines of "ip <space> latency_ms" sorted
            // ascending. Failed pings emit "ip ERR" instead of
            // being silently dropped so the operator can tell a
            // "timeout" from "not tried" downstream.
            use std::fmt::Write as _;
            if args.is_empty() {
                return Response::Err {
                    message: "diag ping-many: expected one or more IP args".into(),
                };
            }
            // Cap at 32 to avoid a thundering-herd if someone
            // pipes the full 550-Mullvad-relay list in.
            const MAX: usize = 32;
            if args.len() > MAX {
                return Response::Err {
                    message: format!("diag ping-many: at most {MAX} IPs per call"),
                };
            }
            let targets: Vec<String> = args.to_vec();
            let results = ping_many(targets).await;
            let mut out = String::new();
            for (ip, res) in &results {
                match res {
                    Some(ms) => writeln!(out, "{} {:.2}", ip, ms).ok(),
                    None => writeln!(out, "{} ERR", ip).ok(),
                };
            }
            Response::Value { value: out }
        }
        "wg" => {
            use std::process::Command;
            let iface = args.first().map(|s| s.as_str()).unwrap_or("wg0");
            match Command::new("wg").args(["show", iface]).output() {
                Ok(o) if o.status.success() => Response::Value {
                    value: format!(
                        "--- wg show {iface} ---\n{}\n--- wg show {iface} dump ---\n{}",
                        String::from_utf8_lossy(&o.stdout),
                        {
                            let d = Command::new("wg").args(["show", iface, "dump"]).output();
                            match d {
                                Ok(dd) => String::from_utf8_lossy(&dd.stdout).to_string(),
                                Err(e) => format!("(dump: {e})"),
                            }
                        }
                    ),
                },
                Ok(o) => Response::Err {
                    message: format!(
                        "diag wg: wg show {iface} failed: {}",
                        String::from_utf8_lossy(&o.stderr)
                    ),
                },
                Err(e) => Response::Err {
                    message: format!("diag wg: spawn wg: {e}"),
                },
            }
        }
        "qdisc" => {
            // Dump the tc qdisc state for every iface. Useful for
            // verifying SQM/CAKE is actually installed, checking
            // queue depths under load, etc. Shells out to `tc`
            // rather than duplicating its formatting.
            use std::process::Command;
            match Command::new("tc").args(["qdisc", "show"]).output() {
                Ok(o) if o.status.success() => Response::Value {
                    value: String::from_utf8_lossy(&o.stdout).to_string(),
                },
                Ok(o) => Response::Err {
                    message: format!(
                        "diag qdisc: tc qdisc show failed: {}",
                        String::from_utf8_lossy(&o.stderr)
                    ),
                },
                Err(e) => Response::Err {
                    message: format!("diag qdisc: spawn tc: {e} (tc-tiny installed?)"),
                },
            }
        }
        "resolv" => {
            // Dump /etc/resolv.conf so operators can confirm the
            // router's own libc resolver is pointing at the LAN IP
            // (which DNATs to the hickory DoH forwarder). Missing
            // file isn't an error — it just means write_self_resolv_conf
            // ran with no LAN/Simple network declared and skipped.
            match std::fs::read_to_string("/etc/resolv.conf") {
                Ok(s) if s.is_empty() => Response::Value {
                    value: "(empty /etc/resolv.conf)\n".to_string(),
                },
                Ok(s) => Response::Value { value: s },
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Response::Value {
                    value: "(no /etc/resolv.conf — router has no LAN/Simple network to point at, or write_self_resolv_conf failed at boot)\n".to_string(),
                },
                Err(e) => Response::Err {
                    message: format!("diag resolv: {e}"),
                },
            }
        }
        "conntrack" => {
            // Dump the kernel's conntrack table. Useful for tracing
            // "packet left the client but did it reach NAT?" — a LAN
            // IP never appearing here means the packet didn't traverse
            // FORWARD; an entry with original src=LAN-ip but no reply
            // means egress worked but no return.
            match std::fs::read_to_string("/proc/net/nf_conntrack") {
                Ok(s) if s.is_empty() => Response::Value {
                    value: "(conntrack table empty — is nf_conntrack loaded?)\n".to_string(),
                },
                Ok(s) => Response::Value { value: s },
                Err(e) => Response::Err {
                    message: format!("diag conntrack: {e}"),
                },
            }
        }
        "dmesg" => {
            // Read the kernel ring buffer via klogctl(SYSLOG_ACTION_READ_ALL).
            // Needs CAP_SYSLOG (we have it as pid 1). A 256KB buffer fits
            // the default kmsg sizes. Output is one message per line.
            let mut buf = vec![0u8; 256 * 1024];
            // SYSLOG_ACTION_READ_ALL = 3
            let n = unsafe { libc::klogctl(3, buf.as_mut_ptr() as *mut _, buf.len() as _) };
            if n < 0 {
                Response::Err {
                    message: format!("diag dmesg: klogctl: {}", std::io::Error::last_os_error()),
                }
            } else {
                buf.truncate(n as usize);
                Response::Value {
                    value: String::from_utf8_lossy(&buf).into_owned(),
                }
            }
        }
        // Saturate every tokio worker thread with a blocking sleep
        // so NO task can run — including the watchdog heartbeat.
        // After STALL_THRESHOLD (20s) the pet loop withholds the
        // /dev/watchdog write and the kernel hardware watchdog
        // fires (31s default on MT7986) → board resets. Used to
        // verify the watchdog's stall-detection path end-to-end.
        //
        // Single-task stalls (blocking one worker) don't wedge a
        // multi_thread runtime — tokio schedules other tasks on
        // free workers, the heartbeat keeps ticking, watchdog
        // keeps feeding. That's the correct behavior; this op
        // simulates the RARE "all workers deadlocked" failure
        // mode instead.
        //
        // Safety cap 1..=60 seconds so a typo can't brick the
        // router for a week; 30s default covers the 20 + 31 = 51s
        // expected time-to-reboot with headroom.
        "stall" => {
            let secs: u64 = args
                .first()
                .and_then(|s| s.parse().ok())
                .filter(|&n: &u64| (1..=60).contains(&n))
                .unwrap_or(30);
            // Spawn workers+1 blocking tasks: if tokio's default
            // worker_threads is N, N+1 parallel thread::sleeps
            // guarantee we hold every worker plus one more in the
            // queue. Empirically on dual-core MT7986 with tokio's
            // default N=num_cpus, 4-8 spawns cover every sizing.
            tracing::warn!(
                secs,
                "diag: saturating tokio workers (watchdog should fire if stall > 20s)"
            );
            let mut handles = Vec::new();
            for _ in 0..16 {
                handles.push(tokio::spawn(async move {
                    std::thread::sleep(std::time::Duration::from_secs(secs));
                }));
            }
            for h in handles {
                let _ = h.await;
            }
            Response::Value {
                value: format!(
                    "stalled for {secs}s (if you see this, watchdog didn't fire — \
                     maybe runtime has more than 16 workers)"
                ),
            }
        }
        "wol" => match diag_wol(state, args).await {
            Ok(text) => Response::Value { value: text },
            Err(e) => Response::Err {
                message: format!("diag wol: {e}"),
            },
        },
        "devices" => match diag_devices(state).await {
            Ok(text) => Response::Value { value: text },
            Err(e) => Response::Err {
                message: format!("diag devices: {e}"),
            },
        },
        other => Response::Err {
            message: format!(
                "diag: unknown op {other:?} (supported: links, routes, addresses, firewall, dhcp, \
                 modules, dmesg, nft, nft-summary, conntrack, resolv, qdisc, sysctl, ping, ping-many, \
                 traceroute, drill, ss, stall, wol, devices)"
            ),
        },
    }
}

/// Send a Wake-on-LAN magic packet to `<mac>` via UDP broadcast on
/// the LAN. Bound to the LAN's IPv4 address so the kernel picks
/// the right iface (on a router, the default route leaves via WAN
/// — a bare `255.255.255.255` send would go the wrong way).
///
/// Magic packet per the WoL spec: 6 bytes of 0xFF followed by 16
/// repetitions of the target MAC (102 bytes total). Sent to UDP
/// port 9 (discard) at the LAN's directed broadcast address.
async fn diag_wol(state: &ControlState, args: &[String]) -> Result<String, String> {
    use oxwrt_api::config::Network;
    let mac_str = args
        .first()
        .ok_or("missing <mac> (e.g. aa:bb:cc:dd:ee:ff)")?;
    let mac = crate::net::parse_mac(mac_str).map_err(|e| e.to_string())?;

    // First LAN/Simple network defines the broadcast domain.
    let cfg = state.config_snapshot();
    let (lan_addr, lan_prefix) = cfg
        .networks
        .iter()
        .find_map(|n| match n {
            Network::Lan {
                address, prefix, ..
            }
            | Network::Simple {
                address, prefix, ..
            } => Some((*address, *prefix)),
            _ => None,
        })
        .ok_or("no LAN / Simple network configured to send from")?;
    let broadcast = directed_broadcast(lan_addr, lan_prefix);

    let mut packet = Vec::with_capacity(6 + 16 * 6);
    packet.extend_from_slice(&[0xff; 6]);
    for _ in 0..16 {
        packet.extend_from_slice(&mac);
    }

    let sock = tokio::net::UdpSocket::bind((lan_addr, 0))
        .await
        .map_err(|e| format!("bind {lan_addr}:0: {e}"))?;
    sock.set_broadcast(true)
        .map_err(|e| format!("set_broadcast: {e}"))?;
    sock.send_to(&packet, (broadcast, 9))
        .await
        .map_err(|e| format!("send_to {broadcast}:9: {e}"))?;

    Ok(format!(
        "sent WoL magic packet to {mac_str} via {broadcast}:9 (from {lan_addr})\n"
    ))
}

/// "Who's on my LAN?" — parse `/proc/net/arp` into a table of
/// (iface, ip, mac, state) filtered to the LAN-side bridges that
/// this device serves.
///
/// The ARP cache is transient — entries only appear for hosts the
/// kernel has recently needed to address, and get pruned after a
/// few minutes of silence. So this is a "currently active or
/// recently active" list, not an inventory of every device that
/// ever joined. For a lease-authoritative view once a device's
/// hostname matters, pair with `oxctl diag dhcp` (follow-up:
/// merging both into one view requires parsing the coredhcp
/// SQLite lease DB, which needs an rusqlite dep).
///
/// Filtered to LAN/Simple ifaces so WAN-side noise (the upstream
/// router, any DMZ peers) doesn't clutter the view.
async fn diag_devices(state: &ControlState) -> Result<String, String> {
    use oxwrt_api::config::Network;
    use std::fmt::Write;

    let cfg = state.config_snapshot();
    let lan_ifaces: std::collections::HashSet<String> = cfg
        .networks
        .iter()
        .filter_map(|n| match n {
            Network::Lan { bridge, .. } => Some(bridge.clone()),
            Network::Simple { iface, .. } => Some(iface.clone()),
            Network::Wan { .. } => None,
        })
        .collect();

    let text =
        std::fs::read_to_string("/proc/net/arp").map_err(|e| format!("read /proc/net/arp: {e}"))?;

    // First line is the column header; skip it.
    let mut rows: Vec<Row> = text
        .lines()
        .skip(1)
        .filter_map(parse_arp_row)
        .filter(|r| lan_ifaces.contains(&r.iface))
        .collect();

    // Stable order: iface, then numeric-aware IP sort (so
    // 192.168.50.9 < 192.168.50.10).
    rows.sort_by(|a, b| {
        a.iface
            .cmp(&b.iface)
            .then_with(|| a.ip_key().cmp(&b.ip_key()))
    });

    if rows.is_empty() {
        return Ok(format!(
            "no LAN-side devices in ARP cache (LAN ifaces: {})\n",
            lan_ifaces.iter().cloned().collect::<Vec<_>>().join(", ")
        ));
    }

    let mut out = String::new();
    writeln!(out, "{:<16}  {:<17}  {:<10}  IFACE", "IP", "MAC", "STATE").unwrap();
    for r in &rows {
        writeln!(
            out,
            "{:<16}  {:<17}  {:<10}  {}",
            r.ip, r.mac, r.state, r.iface
        )
        .unwrap();
    }
    writeln!(out, "\n{} device(s) on LAN", rows.len()).unwrap();
    Ok(out)
}

#[derive(Debug)]
struct Row {
    ip: String,
    mac: String,
    state: String,
    iface: String,
}

impl Row {
    /// Numeric IPv4 for sort; non-IPv4 strings sort as u32::MAX
    /// (clumped at the end).
    fn ip_key(&self) -> u32 {
        self.ip
            .parse::<std::net::Ipv4Addr>()
            .map(u32::from)
            .unwrap_or(u32::MAX)
    }
}

/// Parse one line of `/proc/net/arp`:
/// `IP  HW-type  Flags  HW-address       Mask  Device`
/// Skip incomplete entries (flag=0x0, HW=00:00:00:00:00:00 —
/// "failed to resolve" noise).
fn parse_arp_row(line: &str) -> Option<Row> {
    let cols: Vec<&str> = line.split_whitespace().collect();
    if cols.len() < 6 {
        return None;
    }
    let ip = cols[0].to_string();
    let flags = u32::from_str_radix(cols[2].trim_start_matches("0x"), 16).ok()?;
    let mac = cols[3].to_string();
    let iface = cols[5].to_string();

    // Flag 0x2 = ATF_COM (entry resolved). Anything else is
    // "cache still pending" — skip to avoid listing ghost IPs.
    let state = match flags {
        0x2 => "reachable",
        0x4 => "permanent",
        0x0 => return None, // incomplete
        _ => "other",
    }
    .to_string();

    // Filter out the 00:00:00:00:00:00 sentinel some kernels
    // emit for incomplete entries even with flags=0x2.
    if mac == "00:00:00:00:00:00" {
        return None;
    }

    Some(Row {
        ip,
        mac,
        state,
        iface,
    })
}

/// Directed-broadcast address for a /prefix network containing
/// `addr` (e.g. 192.168.50.1/24 → 192.168.50.255). `/32` returns
/// the address itself; no-op at prefix=0 since the whole
/// universe is one "network".
fn directed_broadcast(addr: std::net::Ipv4Addr, prefix: u8) -> std::net::Ipv4Addr {
    if prefix >= 32 {
        return addr;
    }
    let shift = 32 - u32::from(prefix);
    let mask = !((1u32 << shift) - 1);
    let base = u32::from(addr) & mask;
    let bcast = base | !mask;
    std::net::Ipv4Addr::from(bcast)
}

async fn diag_links() -> Result<String, String> {
    use futures_util::stream::TryStreamExt;
    use rtnetlink::packet_route::link::{LinkAttribute, State};

    let (connection, handle, _messages) = rtnetlink::new_connection().map_err(|e| e.to_string())?;
    let conn_task = tokio::spawn(connection);

    let mut links = handle.link().get().execute();
    let mut out = String::new();
    while let Some(msg) = links.try_next().await.map_err(|e| e.to_string())? {
        let mut name = String::new();
        let mut mtu: Option<u32> = None;
        let mut state: Option<State> = None;
        let mut mac: Option<Vec<u8>> = None;
        for attr in &msg.attributes {
            match attr {
                LinkAttribute::IfName(n) => name = n.clone(),
                LinkAttribute::Mtu(m) => mtu = Some(*m),
                LinkAttribute::OperState(s) => state = Some(*s),
                LinkAttribute::Address(a) => mac = Some(a.clone()),
                _ => {}
            }
        }
        out.push_str(&format!(
            "{}: {} state {:?} mtu {}",
            msg.header.index,
            if name.is_empty() { "(no-name)" } else { &name },
            state.unwrap_or(State::Unknown),
            mtu.map(|m| m.to_string())
                .unwrap_or_else(|| "?".to_string()),
        ));
        if let Some(mac) = mac {
            if !mac.is_empty() {
                out.push_str(&format!(
                    " link/{}",
                    mac.iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<Vec<_>>()
                        .join(":"),
                ));
            }
        }
        out.push('\n');
    }
    conn_task.abort();
    Ok(out)
}

/// Whitelist of upstream-C operator diagnostic binaries that `diag`
/// may exec. This is a compile-time Rust const, NOT a TOML-visible
/// config — the set of executable binaries is a security boundary
/// and must not be runtime-mutable. See plan §6.
///
/// Each entry supplies:
/// - `name` — the diag op name the operator passes (e.g. "ping")
/// - `rootfs` — absolute path to a mini-rootfs containing `bin`
///   and any required libs. In production, this directory lives on
///   the squashfs/dm-verity-protected system partition.
/// - `bin` — absolute path inside the rootfs to the binary
/// - `arg_builder` — a Rust fn that parses operator `args` and returns
///   a fixed argv. Each builder validates its inputs (IP parse,
///   count range, etc.) and produces a closed set of flags. Operators
///   cannot inject arbitrary flags.
/// - `caps_retain` — extra capability names (beyond the default four)
///   needed for the binary to work. ping needs `NET_RAW`, etc.
/// - `timeout_secs` — wall-clock limit on the exec. Enforced via
///   `tokio::time::timeout` in `diag_exec`.
struct DiagBinary {
    name: &'static str,
    rootfs: &'static str,
    bin: &'static str,
    arg_builder: fn(&[String]) -> Result<Vec<String>, String>,
    caps_retain: &'static [&'static str],
    timeout_secs: u64,
}

const DIAG_BINARIES: &[DiagBinary] = &[
    DiagBinary {
        name: "ping",
        rootfs: "/usr/lib/oxwrt/diag",
        bin: "/bin/ping",
        arg_builder: build_ping_args,
        caps_retain: &["NET_RAW"],
        timeout_secs: 15,
    },
    DiagBinary {
        name: "traceroute",
        rootfs: "/usr/lib/oxwrt/diag",
        bin: "/bin/traceroute",
        arg_builder: build_traceroute_args,
        caps_retain: &["NET_RAW"],
        timeout_secs: 30, // traceroute can hit 30 hops × ~2s each
    },
    DiagBinary {
        name: "drill",
        rootfs: "/usr/lib/oxwrt/diag",
        bin: "/bin/drill",
        arg_builder: build_drill_args,
        caps_retain: &[], // regular UDP sockets, no extra caps
        timeout_secs: 10,
    },
    DiagBinary {
        name: "ss",
        rootfs: "/usr/lib/oxwrt/diag",
        bin: "/bin/ss",
        arg_builder: build_ss_args,
        caps_retain: &["NET_ADMIN"], // needed for socket diag netlink
        timeout_secs: 5,
    },
];

/// Parse `[target, count?]` into an argv for iputils-ping. Target
/// accepts IPv4 OR IPv6 (iputils-ping auto-detects and picks the
/// right socket family when given a literal); we validate both
/// to close off argv injection (`-anything` as a target would
/// otherwise flow through as a flag).
///
/// Count is clamped `1..=10`, default 3. Per-probe timeout is 2s
/// via `-W 2`; deadline covers the whole invocation via the
/// tokio timeout and the binary's own `-c`.
pub fn build_ping_args(args: &[String]) -> Result<Vec<String>, String> {
    let Some(target_s) = args.first() else {
        return Err("ping: missing target (e.g. 1.1.1.1 or 2606:4700:4700::1111)".to_string());
    };
    if target_s.parse::<std::net::IpAddr>().is_err() {
        return Err(format!(
            "ping: invalid target {target_s:?}: not an IP address"
        ));
    }
    let count: u16 = match args.get(1).map(|s| s.parse::<u16>()) {
        None => 3,
        Some(Ok(n)) if (1..=10).contains(&n) => n,
        _ => return Err("ping: count must be 1..=10".to_string()),
    };
    Ok(vec![
        "-c".to_string(),
        count.to_string(),
        "-W".to_string(),
        "2".to_string(),
        "-n".to_string(), // numeric output, no reverse DNS
        target_s.clone(),
    ])
}

/// Parse `[target, maxhops?]` into argv for Butskoy's `traceroute`.
/// Target may be v4 or v6 — traceroute picks the right family from
/// the address literal. Max-hops clamped 1..=30 (default 30).
pub fn build_traceroute_args(args: &[String]) -> Result<Vec<String>, String> {
    let Some(target_s) = args.first() else {
        return Err(
            "traceroute: missing target (e.g. 1.1.1.1 or 2606:4700:4700::1111)".to_string(),
        );
    };
    if target_s.parse::<std::net::IpAddr>().is_err() {
        return Err(format!(
            "traceroute: invalid target {target_s:?}: not an IP address"
        ));
    }
    let max_hops: u8 = match args.get(1).map(|s| s.parse::<u8>()) {
        None => 30,
        Some(Ok(n)) if (1..=30).contains(&n) => n,
        _ => return Err("traceroute: max_hops must be 1..=30".to_string()),
    };
    Ok(vec![
        "-n".to_string(), // numeric, no reverse DNS
        "-m".to_string(),
        max_hops.to_string(),
        "-w".to_string(),
        "2".to_string(), // per-hop timeout 2s
        target_s.clone(),
    ])
}

/// Parse `[name, @server?, type?]` into argv for ldns `drill`.
/// drill syntax: `drill [type] name [@server]`
/// Name validated as non-empty, server as `@<ip>`, type as a known
/// DNS record type (default A). No arbitrary flags.
pub fn build_drill_args(args: &[String]) -> Result<Vec<String>, String> {
    let Some(name) = args.first() else {
        return Err("drill: missing name (e.g. example.com)".to_string());
    };
    if name.starts_with('-') {
        return Err(format!("drill: name must not start with '-': {name:?}"));
    }
    let valid_types = [
        "A", "AAAA", "CNAME", "MX", "NS", "TXT", "SRV", "PTR", "SOA", "ANY",
    ];
    let mut argv = Vec::new();
    let mut rtype = None;
    let mut server = None;

    // Parse remaining args: @server and/or record type.
    for arg in args.iter().skip(1) {
        if let Some(stripped) = arg.strip_prefix('@') {
            let _ = stripped
                .parse::<std::net::IpAddr>()
                .map_err(|e| format!("drill: invalid server {arg:?}: {e}"))?;
            server = Some(arg.clone());
        } else {
            let upper = arg.to_uppercase();
            if valid_types.contains(&upper.as_str()) {
                rtype = Some(upper);
            } else {
                return Err(format!(
                    "drill: arg must be @server or record type, got {arg:?}"
                ));
            }
        }
    }

    // drill syntax: drill [type] name [@server]
    if let Some(t) = rtype {
        argv.push(t);
    }
    argv.push(name.clone());
    if let Some(s) = server {
        argv.push(s);
    }
    Ok(argv)
}

/// Parse optional flags for `ss`. No positional args — just a curated
/// set of safe flags. Default: `-tunlp` (TCP+UDP, listening, numeric,
/// show process). Accepts an optional filter like "state listening".
pub fn build_ss_args(args: &[String]) -> Result<Vec<String>, String> {
    // Default flags when no args given: show all listening sockets
    if args.is_empty() {
        return Ok(vec!["-tunlp".to_string()]);
    }
    // Allow a curated set of single-letter flag groups.
    let allowed_flags = [
        "-t", "-u", "-l", "-a", "-n", "-p", "-s", "-e", "-m", "-o", "-tl", "-ul", "-tu", "-tul",
        "-tunl", "-tunlp", "-tan", "-uan", "-tlnp", "-ulnp", "-s",
    ];
    let flag = &args[0];
    if flag.starts_with('-') {
        if !allowed_flags.contains(&flag.as_str()) {
            return Err(format!(
                "ss: flag {flag:?} not in allowed set. Use: {}",
                allowed_flags.join(", ")
            ));
        }
        Ok(vec![flag.clone()])
    } else {
        // Treat as a filter expression: "state listening" etc.
        // Only allow safe filter keywords, not arbitrary strings.
        let safe_words = [
            "state",
            "listening",
            "established",
            "connected",
            "synchronized",
            "close-wait",
            "time-wait",
            "fin-wait-1",
            "fin-wait-2",
            "sport",
            "dport",
            "src",
            "dst",
        ];
        for word in args {
            if word.starts_with('-') {
                return Err(format!("ss: flags must come first: {word:?}"));
            }
            // Allow numeric ports and IP addresses in filter expressions
            if word.parse::<u16>().is_ok() || word.parse::<std::net::IpAddr>().is_ok() {
                continue;
            }
            if !safe_words.contains(&word.as_str()) {
                return Err(format!("ss: unknown filter word {word:?}"));
            }
        }
        let mut argv = vec!["-tunlp".to_string()];
        argv.extend(args.iter().cloned());
        Ok(argv)
    }
}

/// Stdout cap. iputils-ping produces ~60 bytes per probe plus a short
/// summary — `count <= 10` gives us well under 2 KB. 32 KB is a
/// comfortable ceiling for any diag binary output we'd want to ship
/// back through a sQUIC Value frame.
const DIAG_STDOUT_MAX: usize = 32 * 1024;
/// Stderr cap. Usage error messages are short; bound at 4 KB.
const DIAG_STDERR_MAX: usize = 4 * 1024;

/// Exec a whitelisted diag binary inside the standard hardening
/// pipeline (caps drop + no_new_privs + seccomp + landlock) via
/// `container::oneshot_exec`. Returns the formatted output (stdout
/// + any stderr preamble) for the `Value` frame.
///
/// The Service spec is built on the fly from the `DiagBinary` entry —
/// `net_mode = Host` so the diagnostic sees the real network, no bind
/// mounts (rootfs is read-only), `security` derived from the entry's
/// `caps_retain` additions on top of the default four.
async fn diag_exec(entry: &DiagBinary, args: &[String]) -> Result<String, String> {
    use crate::config::{NetMode, SecurityProfile, Service};
    use std::path::PathBuf;
    use std::time::Duration;

    // Pre-flight: check the binary actually exists in the diag rootfs
    // before spawning the container. On stock mediatek/filogic +
    // side-binary deployments `drill` and `ss` are provisioned only
    // if the host OpenWrt image shipped them — many minimal images
    // don't, and the operator would otherwise see a confusing
    // "No such file or directory (os error 2)" from the spawn.
    // An explicit "not provisioned on this image" points at the
    // right fix (bake it in via openwrt-packages or the uci-default
    // diag-rootfs provisioner).
    let bin_path = format!("{}{}", entry.rootfs, entry.bin);
    if !std::path::Path::new(&bin_path).exists() {
        return Err(format!(
            "diag {}: {bin_path} not provisioned on this image — add the \
             relevant OpenWrt package (ldns-utils for drill, iproute2 for ss) \
             to IMAGEBUILDER_PACKAGES, or stage the binary into \
             /usr/lib/oxwrt/diag/bin/ via a custom overlay",
            entry.name
        ));
    }

    let argv = (entry.arg_builder)(args)?;

    let mut caps: Vec<String> = crate::config::default_retained_caps();
    for extra in entry.caps_retain {
        let as_string = extra.to_string();
        if !caps.contains(&as_string) {
            caps.push(as_string);
        }
    }
    let mut entrypoint = vec![entry.bin.to_string()];
    entrypoint.extend(argv);

    let spec = Service {
        name: format!("diag-{}", entry.name),
        rootfs: PathBuf::from(entry.rootfs),
        entrypoint,
        env: Default::default(),
        net_mode: NetMode::Host,
        veth: None,
        memory_max: None,
        cpu_max: None,
        pids_max: None,
        binds: Vec::new(),
        depends_on: Vec::new(),
        security: SecurityProfile {
            caps,
            ..Default::default()
        },
    };

    let output = match tokio::time::timeout(
        Duration::from_secs(entry.timeout_secs),
        crate::container::oneshot_exec(&spec),
    )
    .await
    {
        Ok(Ok(out)) => out,
        Ok(Err(e)) => return Err(format!("oneshot_exec: {e}")),
        Err(_) => {
            return Err(format!("timeout after {}s", entry.timeout_secs));
        }
    };

    let stdout = clip_output(&output.stdout, DIAG_STDOUT_MAX);
    let stderr = clip_output(&output.stderr, DIAG_STDERR_MAX);

    let mut combined = String::new();
    if !stdout.is_empty() {
        combined.push_str(&stdout);
        if !stdout.ends_with('\n') {
            combined.push('\n');
        }
    }
    if !stderr.is_empty() {
        combined.push_str("--- stderr ---\n");
        combined.push_str(&stderr);
        if !stderr.ends_with('\n') {
            combined.push('\n');
        }
    }
    if !output.status.success() {
        combined.push_str(&format!(
            "--- exit: {} ---\n",
            output.status.code().unwrap_or(-1)
        ));
    }
    Ok(combined)
}

/// Truncate output at `max` bytes, appending a clear marker if any
/// bytes were dropped. Done after capturing everything so the child's
/// pipe doesn't block on a full buffer. `from_utf8_lossy` handles any
/// mid-UTF-8 cut at the boundary.
fn clip_output(bytes: &[u8], max: usize) -> String {
    if bytes.len() <= max {
        return String::from_utf8_lossy(bytes).into_owned();
    }
    let head = &bytes[..max];
    let mut s = String::from_utf8_lossy(head).into_owned();
    s.push_str(&format!(
        "\n[... output truncated, {} bytes dropped ...]\n",
        bytes.len() - max
    ));
    s
}

async fn diag_addresses() -> Result<String, String> {
    use futures_util::stream::TryStreamExt;
    use rtnetlink::packet_route::{AddressFamily, address::AddressAttribute};

    let (connection, handle, _messages) = rtnetlink::new_connection().map_err(|e| e.to_string())?;
    let conn_task = tokio::spawn(connection);

    let mut addrs = handle.address().get().execute();
    let mut out = String::new();
    while let Some(msg) = addrs.try_next().await.map_err(|e| e.to_string())? {
        let mut addr: Option<String> = None;
        let mut label: Option<String> = None;
        for attr in &msg.attributes {
            match attr {
                AddressAttribute::Address(a) => addr = Some(a.to_string()),
                AddressAttribute::Label(l) => label = Some(l.clone()),
                _ => {}
            }
        }
        let family = match msg.header.family {
            AddressFamily::Inet => "inet",
            AddressFamily::Inet6 => "inet6",
            _ => "other",
        };
        // `dev` shows the kernel link index — cross-reference with
        // `diag links` to map back to a name. Label (when present) is
        // the ifname-like alias stored by the kernel for IPv4.
        out.push_str(&format!(
            "{}: dev {} {} {}/{}\n",
            label.as_deref().unwrap_or("(no-label)"),
            msg.header.index,
            family,
            addr.as_deref().unwrap_or("?"),
            msg.header.prefix_len,
        ));
    }
    conn_task.abort();
    Ok(out)
}

async fn diag_routes() -> Result<String, String> {
    use futures_util::stream::TryStreamExt;
    use rtnetlink::packet_route::{
        AddressFamily,
        route::{RouteAddress, RouteAttribute, RouteMessage},
    };

    let (connection, handle, _messages) = rtnetlink::new_connection().map_err(|e| e.to_string())?;
    let conn_task = tokio::spawn(connection);

    // Empty RouteMessage with INET family triggers an IPv4 dump.
    let mut req = RouteMessage::default();
    req.header.address_family = AddressFamily::Inet;
    let mut routes = handle.route().get(req).execute();
    let mut out = String::new();
    while let Some(msg) = routes.try_next().await.map_err(|e| e.to_string())? {
        let mut dst: Option<String> = None;
        let mut gw: Option<String> = None;
        let mut oif: Option<u32> = None;
        let mut prio: Option<u32> = None;
        for attr in &msg.attributes {
            match attr {
                RouteAttribute::Destination(RouteAddress::Inet(a)) => dst = Some(a.to_string()),
                RouteAttribute::Gateway(RouteAddress::Inet(a)) => gw = Some(a.to_string()),
                RouteAttribute::Oif(i) => oif = Some(*i),
                RouteAttribute::Priority(p) => prio = Some(*p),
                _ => {}
            }
        }
        let dst = match dst {
            Some(d) => format!("{}/{}", d, msg.header.destination_prefix_length),
            None => "default".to_string(),
        };
        out.push_str(&dst);
        if let Some(gw) = gw {
            out.push_str(&format!(" via {gw}"));
        }
        if let Some(oif) = oif {
            out.push_str(&format!(" dev {oif}"));
        }
        if let Some(prio) = prio {
            out.push_str(&format!(" metric {prio}"));
        }
        out.push_str(&format!(" proto {:?}", msg.header.protocol));
        out.push('\n');
    }
    conn_task.abort();
    Ok(out)
}

/// Turn `nft list ruleset` plain-text output into a compact
/// summary: one line per table with chain/rule/set counts, one
/// indented line per chain with hook/prio/policy, one per set
/// with type/element-count + sample. Line-based state machine —
/// the nft formatter is stable across versions and distros.
fn summarize_nft_text(text: &str) -> Result<String, String> {
    use std::collections::BTreeMap;
    #[derive(Default)]
    struct TableAgg {
        family: String,
        name: String,
        chain_count: usize,
        rule_count: usize,
        set_count: usize,
        chains: Vec<String>,
        sets: Vec<String>,
    }
    let mut tables: BTreeMap<String, TableAgg> = BTreeMap::new();

    #[derive(Clone, Copy, PartialEq)]
    enum Where {
        Top,
        Chain,
        Set,
    }
    let mut cur_table: Option<(String, String)> = None; // (family, name)
    let mut cur_chain_name: Option<String> = None;
    let mut cur_chain_buf: Option<String> = None; // "  chain NAME ..." being built
    let mut cur_set_name: Option<String> = None;
    let mut cur_set_type: Option<String> = None;
    let mut cur_set_elements: Vec<String> = Vec::new();
    let mut depth: i32 = 0;
    let mut state = Where::Top;

    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        // Closing braces: decrement and transition.
        if line == "}" {
            depth -= 1;
            match state {
                Where::Chain => {
                    if let (Some((fam, tab)), Some(buf)) =
                        (cur_table.as_ref(), cur_chain_buf.take())
                    {
                        tables
                            .entry(format!("{fam}:{tab}"))
                            .or_insert_with(|| TableAgg {
                                family: fam.clone(),
                                name: tab.clone(),
                                ..Default::default()
                            })
                            .chains
                            .push(buf);
                    }
                    cur_chain_name = None;
                    state = Where::Top;
                }
                Where::Set => {
                    if let (Some((fam, tab)), Some(name)) =
                        (cur_table.as_ref(), cur_set_name.take())
                    {
                        let typ = cur_set_type.take().unwrap_or_default();
                        let entry =
                            tables
                                .entry(format!("{fam}:{tab}"))
                                .or_insert_with(|| TableAgg {
                                    family: fam.clone(),
                                    name: tab.clone(),
                                    ..Default::default()
                                });
                        let mut line = format!(
                            "  set {} type={} elements={}",
                            name,
                            typ,
                            cur_set_elements.len()
                        );
                        if !cur_set_elements.is_empty() {
                            let sample: Vec<&str> = cur_set_elements
                                .iter()
                                .take(5)
                                .map(|s| s.as_str())
                                .collect();
                            line.push_str(&format!(" sample=[{}]", sample.join(", ")));
                            if cur_set_elements.len() > 5 {
                                line.push_str(&format!(" +{} more", cur_set_elements.len() - 5));
                            }
                        }
                        entry.sets.push(line);
                    }
                    cur_set_elements.clear();
                    state = Where::Top;
                }
                Where::Top => {
                    cur_table = None;
                }
            }
            continue;
        }
        // Opening containers.
        if state == Where::Top {
            if let Some(rest) = line.strip_prefix("table ") {
                // "table ip oxwrt {"
                let rest = rest.trim_end_matches('{').trim();
                let mut parts = rest.split_whitespace();
                let fam = parts.next().unwrap_or("?").to_string();
                let name = parts.next().unwrap_or("?").to_string();
                tables
                    .entry(format!("{fam}:{name}"))
                    .or_insert_with(|| TableAgg {
                        family: fam.clone(),
                        name: name.clone(),
                        ..Default::default()
                    });
                cur_table = Some((fam, name));
                depth += 1;
                continue;
            }
            if line.starts_with("chain ") && line.ends_with('{') {
                let body = line
                    .trim_start_matches("chain ")
                    .trim_end_matches('{')
                    .trim();
                let name = body.split_whitespace().next().unwrap_or("?").to_string();
                if let Some((fam, tab)) = cur_table.as_ref() {
                    let entry = tables
                        .entry(format!("{fam}:{tab}"))
                        .or_insert_with(|| TableAgg {
                            family: fam.clone(),
                            name: tab.clone(),
                            ..Default::default()
                        });
                    entry.chain_count += 1;
                }
                cur_chain_name = Some(name.clone());
                cur_chain_buf = Some(format!("  chain {name}"));
                state = Where::Chain;
                depth += 1;
                continue;
            }
            if line.starts_with("set ") && line.ends_with('{') {
                let body = line.trim_start_matches("set ").trim_end_matches('{').trim();
                let name = body.split_whitespace().next().unwrap_or("?").to_string();
                if let Some((fam, tab)) = cur_table.as_ref() {
                    let entry = tables
                        .entry(format!("{fam}:{tab}"))
                        .or_insert_with(|| TableAgg {
                            family: fam.clone(),
                            name: tab.clone(),
                            ..Default::default()
                        });
                    entry.set_count += 1;
                }
                cur_set_name = Some(name);
                state = Where::Set;
                depth += 1;
                continue;
            }
        }
        // Inside a chain: pull hook/prio/policy, count rules.
        if state == Where::Chain {
            // Chain base spec: "type filter hook input priority 0; policy drop;"
            if let Some(idx) = line.find("hook ") {
                let rest = &line[idx..];
                let mut hook = None;
                let mut prio = None;
                let mut policy = None;
                // Tokenize coarsely.
                let toks: Vec<&str> = rest
                    .split(|c: char| c == ';' || c.is_whitespace())
                    .filter(|s| !s.is_empty())
                    .collect();
                let mut i = 0;
                while i < toks.len() {
                    match toks[i] {
                        "hook" => {
                            hook = toks.get(i + 1).map(|s| s.to_string());
                            i += 2;
                        }
                        "priority" => {
                            prio = toks.get(i + 1).map(|s| s.to_string());
                            i += 2;
                        }
                        "policy" => {
                            policy = toks.get(i + 1).map(|s| s.to_string());
                            i += 2;
                        }
                        _ => i += 1,
                    }
                }
                if let Some(buf) = cur_chain_buf.as_mut() {
                    if let Some(h) = hook {
                        buf.push_str(&format!(" hook={h}"));
                    }
                    if let Some(p) = prio {
                        buf.push_str(&format!(" prio={p}"));
                    }
                    if let Some(pol) = policy {
                        buf.push_str(&format!(" policy={pol}"));
                    }
                }
                continue;
            }
            // A comment or policy-only line we haven't matched.
            // Any other line inside a chain that isn't empty and
            // doesn't start with "type " counts as a rule.
            if !line.starts_with("type ") && !line.starts_with("#") {
                if let Some((fam, tab)) = cur_table.as_ref() {
                    tables
                        .entry(format!("{fam}:{tab}"))
                        .or_insert_with(|| TableAgg {
                            family: fam.clone(),
                            name: tab.clone(),
                            ..Default::default()
                        })
                        .rule_count += 1;
                }
            }
            continue;
        }
        // Inside a set.
        if state == Where::Set {
            if let Some(typ) = line.strip_prefix("type ") {
                cur_set_type = Some(typ.trim_end_matches(';').to_string());
                continue;
            }
            if let Some(rest) = line.strip_prefix("elements = {") {
                // "elements = { 1.2.3.4, 5.6.7.8 }" on one line, or
                // could span lines — collect what's on this line and
                // keep reading subsequent lines (fall through by
                // continuing) until we see a "}". Simpler: strip
                // trailing "}" and parse CSV. nft tends to pretty-
                // print so a one-line block is common.
                let inner = rest.trim_end_matches('}').trim();
                for tok in inner.split(',') {
                    let t = tok.trim();
                    if !t.is_empty() {
                        cur_set_elements.push(t.to_string());
                    }
                }
                continue;
            }
            // Continuation line of a multi-line elements block —
            // just another comma-separated segment, maybe with a
            // trailing "}" closing the set.
            let inner = line.trim_end_matches('}').trim_end_matches('{').trim();
            for tok in inner.split(',') {
                let t = tok.trim();
                if !t.is_empty()
                    && !t.starts_with("type ")
                    && !t.starts_with("flags ")
                    && t != "elements"
                    && t != "="
                {
                    cur_set_elements.push(t.to_string());
                }
            }
            continue;
        }
    }
    let _ = (depth, cur_chain_name); // quiet unused-assigned if we hit an error path

    let mut out = String::new();
    for agg in tables.values() {
        out.push_str(&format!(
            "table {} {} chains={} rules={} sets={}\n",
            agg.family, agg.name, agg.chain_count, agg.rule_count, agg.set_count,
        ));
        for line in &agg.chains {
            out.push_str(line);
            out.push('\n');
        }
        for line in &agg.sets {
            out.push_str(line);
            out.push('\n');
        }
    }
    if out.is_empty() {
        out.push_str("(no tables)\n");
    }
    Ok(out)
}

#[cfg(test)]
mod devices_tests {
    use super::parse_arp_row;

    #[test]
    fn reachable_entry_parsed() {
        let line = "192.168.50.100   0x1         0x2         aa:bb:cc:dd:ee:ff     *        br-lan";
        let r = parse_arp_row(line).expect("reachable entry");
        assert_eq!(r.ip, "192.168.50.100");
        assert_eq!(r.mac, "aa:bb:cc:dd:ee:ff");
        assert_eq!(r.state, "reachable");
        assert_eq!(r.iface, "br-lan");
    }

    #[test]
    fn permanent_entry_parsed() {
        let line = "192.168.50.1     0x1         0x4         02:11:22:33:44:55     *        br-lan";
        let r = parse_arp_row(line).expect("permanent entry");
        assert_eq!(r.state, "permanent");
    }

    #[test]
    fn incomplete_entry_skipped() {
        // Flags = 0x0 = incomplete resolution.
        let line = "192.168.50.99    0x1         0x0         00:00:00:00:00:00     *        br-lan";
        assert!(parse_arp_row(line).is_none());
    }

    #[test]
    fn zero_mac_skipped_even_with_reachable_flag() {
        // Some kernels emit flag=0x2 with an all-zero MAC during
        // the half-resolved window — treat as noise.
        let line = "192.168.50.99    0x1         0x2         00:00:00:00:00:00     *        br-lan";
        assert!(parse_arp_row(line).is_none());
    }

    #[test]
    fn header_row_skipped_by_column_count_check() {
        // The /proc/net/arp header has 8 columns and parses, but
        // trimming to its first column "IP" fails at the flags
        // hex-parse step → returns None.
        let line = "IP address       HW type     Flags       HW address            Mask     Device";
        assert!(parse_arp_row(line).is_none());
    }
}

#[cfg(test)]
mod wol_tests {
    use super::directed_broadcast;
    use std::net::Ipv4Addr;

    #[test]
    fn slash_24_broadcast() {
        assert_eq!(
            directed_broadcast(Ipv4Addr::new(192, 168, 50, 1), 24),
            Ipv4Addr::new(192, 168, 50, 255)
        );
    }

    #[test]
    fn slash_16_broadcast() {
        assert_eq!(
            directed_broadcast(Ipv4Addr::new(10, 0, 0, 1), 16),
            Ipv4Addr::new(10, 0, 255, 255)
        );
    }

    #[test]
    fn slash_30_broadcast() {
        assert_eq!(
            directed_broadcast(Ipv4Addr::new(10, 0, 0, 1), 30),
            Ipv4Addr::new(10, 0, 0, 3)
        );
    }

    #[test]
    fn slash_32_returns_self() {
        assert_eq!(
            directed_broadcast(Ipv4Addr::new(10, 0, 0, 5), 32),
            Ipv4Addr::new(10, 0, 0, 5)
        );
    }
}

#[cfg(test)]
mod nft_summary_tests {
    use super::summarize_nft_text;

    #[test]
    fn empty_ruleset() {
        let out = summarize_nft_text("").unwrap();
        assert_eq!(out, "(no tables)\n");
    }

    #[test]
    fn single_table_chain_rule() {
        let text = r#"
table ip oxwrt {
    chain input {
        type filter hook input priority 0; policy drop;
        iif "lo" accept
        ct state established,related accept
    }
}
"#;
        let out = summarize_nft_text(text).unwrap();
        assert!(
            out.contains("table ip oxwrt chains=1 rules=2 sets=0"),
            "got: {out}"
        );
        assert!(
            out.contains("chain input hook=input prio=0 policy=drop"),
            "got: {out}"
        );
    }

    #[test]
    fn set_with_elements() {
        let text = r#"
table ip oxwrt-bl {
    set blk {
        type ipv4_addr
        elements = { 10.0.0.1, 10.0.0.2 }
    }
}
"#;
        let out = summarize_nft_text(text).unwrap();
        assert!(
            out.contains("table ip oxwrt-bl chains=0 rules=0 sets=1"),
            "got: {out}"
        );
        assert!(
            out.contains("set blk type=ipv4_addr elements=2"),
            "got: {out}"
        );
        assert!(out.contains("sample=[10.0.0.1, 10.0.0.2]"), "got: {out}");
    }
}

/// Parallel-ping a list of targets, return (ip, latency_ms) in
/// ascending-latency order with None for failures (sorted to the
/// end). Uses the system `ping` binary: `-c 1 -W 1 <ip>` — single
/// echo, 1-second per-reply timeout. Kept crude because this is a
/// coarse "is this relay faster than that one" signal, not a
/// precision measurement.
///
/// Caps concurrency implicitly by the caller's arg count (diag
/// handler gates at MAX=32).
async fn ping_many(targets: Vec<String>) -> Vec<(String, Option<f64>)> {
    use futures_util::future::join_all;
    let futs = targets.into_iter().map(|ip| async move {
        let latency = one_ping(&ip).await;
        (ip, latency)
    });
    let mut results: Vec<(String, Option<f64>)> = join_all(futs).await;
    results.sort_by(|a, b| match (a.1, b.1) {
        (Some(x), Some(y)) => x.partial_cmp(&y).unwrap_or(std::cmp::Ordering::Equal),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    });
    results
}

async fn one_ping(ip: &str) -> Option<f64> {
    let out = tokio::process::Command::new("ping")
        .args(["-c", "1", "-W", "1", "-q", ip])
        .output()
        .await
        .ok()?;
    if !out.status.success() {
        return None;
    }
    // BusyBox ping summary: "round-trip min/avg/max = 12.3/12.3/12.3 ms"
    // (or "rtt min/avg/max/mdev = ..." on iputils). Pull the
    // first number after "min/avg".
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        if let Some(after) = line.split_once("min/avg") {
            // after = "max = 12.3/12.3/12.3 ms" or "max/mdev = 12.3/12.3/..."
            if let Some(eq) = after.1.split_once('=') {
                let nums = eq.1.trim();
                if let Some(first) = nums.split('/').next() {
                    return first.trim().parse::<f64>().ok();
                }
            }
        }
        // iputils-style per-reply line: "64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=12.3 ms"
        if let Some((_, rest)) = line.split_once("time=") {
            if let Some(ms_str) = rest.split_whitespace().next() {
                if let Ok(ms) = ms_str.parse::<f64>() {
                    return Some(ms);
                }
            }
        }
    }
    None
}
