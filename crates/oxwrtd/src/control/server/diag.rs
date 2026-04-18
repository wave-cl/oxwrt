//! Diag RPC dispatch + per-op implementations. Split out in step 7.

use super::*;

pub(super) async fn handle_diag(state: &ControlState, name: &str, args: &[String]) -> Response {
    let _ = args; // reserved for future ops with parameters
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
        "sysctl" => {
            // Tiny networking-sysctl snapshot for troubleshooting. Reads
            // a fixed set of flags the router relies on — forwarding,
            // rp_filter, accept_ra, etc. Returns one line per flag.
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
        "conntrack" => {
            // Dump the kernel's conntrack table. Useful for tracing
            // "packet left the client but did it reach NAT?" — a LAN
            // IP never appearing here means the packet didn't traverse
            // FORWARD; an entry with original src=LAN-ip but no reply
            // means egress worked but no return.
            match std::fs::read_to_string("/proc/net/nf_conntrack") {
                Ok(s) if s.is_empty() => Response::Value {
                    value: "(conntrack table empty — is nf_conntrack loaded?)\n"
                        .to_string(),
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
            let n = unsafe {
                libc::klogctl(3, buf.as_mut_ptr() as *mut _, buf.len() as _)
            };
            if n < 0 {
                Response::Err {
                    message: format!(
                        "diag dmesg: klogctl: {}",
                        std::io::Error::last_os_error()
                    ),
                }
            } else {
                buf.truncate(n as usize);
                Response::Value {
                    value: String::from_utf8_lossy(&buf).into_owned(),
                }
            }
        }
        other => Response::Err {
            message: format!(
                "diag: unknown op {other:?} (supported: links, routes, addresses, firewall, dhcp, \
                 modules, dmesg, nft, conntrack, sysctl, ping, traceroute, dig)"
            ),
        },
    }
}

async fn diag_links() -> Result<String, String> {
    use futures_util::stream::TryStreamExt;
    use rtnetlink::packet_route::link::{LinkAttribute, State};

    let (connection, handle, _messages) =
        rtnetlink::new_connection().map_err(|e| e.to_string())?;
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

/// Parse `[target, count?]` into an argv for iputils-ping. Target must
/// be a valid IPv4 (v6 comes with a separate "ping6" entry later).
/// Count is clamped `1..=10`, default 3. Per-probe timeout is 2s via
/// `-W 2`; deadline covers the whole invocation via `-w <count*3+5>`
/// as a belt-and-suspenders on top of our tokio timeout.
pub fn build_ping_args(args: &[String]) -> Result<Vec<String>, String> {
    let Some(target_s) = args.first() else {
        return Err("ping: missing target (e.g. 1.1.1.1)".to_string());
    };
    // Validate as IPv4 to close off argv injection. A shell/args
    // injection via the TARGET string is possible in theory (e.g.
    // `--privileged`) but iputils-ping's argv parser treats anything
    // starting with `-` as a flag; we reject non-IPv4 up front.
    let _ = target_s
        .parse::<std::net::Ipv4Addr>()
        .map_err(|e| format!("ping: invalid target {target_s:?}: {e}"))?;
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
/// Target validated as IPv4, max-hops clamped 1..=30 (default 30).
pub fn build_traceroute_args(args: &[String]) -> Result<Vec<String>, String> {
    let Some(target_s) = args.first() else {
        return Err("traceroute: missing target (e.g. 1.1.1.1)".to_string());
    };
    let _ = target_s
        .parse::<std::net::Ipv4Addr>()
        .map_err(|e| format!("traceroute: invalid target {target_s:?}: {e}"))?;
    let max_hops: u8 = match args.get(1).map(|s| s.parse::<u8>()) {
        None => 30,
        Some(Ok(n)) if (1..=30).contains(&n) => n,
        _ => return Err("traceroute: max_hops must be 1..=30".to_string()),
    };
    Ok(vec![
        "-n".to_string(),                // numeric, no reverse DNS
        "-m".to_string(),
        max_hops.to_string(),
        "-w".to_string(),
        "2".to_string(),                  // per-hop timeout 2s
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
        "-t", "-u", "-l", "-a", "-n", "-p", "-s", "-e", "-m", "-o",
        "-tl", "-ul", "-tu", "-tul", "-tunl", "-tunlp", "-tan", "-uan",
        "-tlnp", "-ulnp", "-s",
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
            "state", "listening", "established", "connected", "synchronized",
            "close-wait", "time-wait", "fin-wait-1", "fin-wait-2",
            "sport", "dport", "src", "dst",
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
            return Err(format!(
                "timeout after {}s",
                entry.timeout_secs
            ));
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
    use rtnetlink::packet_route::{address::AddressAttribute, AddressFamily};

    let (connection, handle, _messages) =
        rtnetlink::new_connection().map_err(|e| e.to_string())?;
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
        route::{RouteAddress, RouteAttribute, RouteMessage},
        AddressFamily,
    };

    let (connection, handle, _messages) =
        rtnetlink::new_connection().map_err(|e| e.to_string())?;
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
                RouteAttribute::Destination(RouteAddress::Inet(a)) => {
                    dst = Some(a.to_string())
                }
                RouteAttribute::Gateway(RouteAddress::Inet(a)) => {
                    gw = Some(a.to_string())
                }
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
