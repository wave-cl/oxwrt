mod config;
mod control;
mod logd;
mod rpc;

#[cfg(target_os = "linux")]
mod container;
#[cfg(target_os = "linux")]
mod init;
#[cfg(target_os = "linux")]
mod net;
#[cfg(target_os = "linux")]
mod wan_dhcp;

use std::process::ExitCode;

fn main() -> ExitCode {
    init_tracing();
    let mut args = std::env::args().skip(1);
    let mode = args.next();

    // Auto-detect PID 1: when the kernel invokes /sbin/init (our
    // symlink), there's no --init argument. Detect via getpid() == 1
    // so the binary works as a direct init replacement without flags.
    let is_pid1 = std::process::id() == 1;

    match mode.as_deref() {
        Some("--init") => run_init(),
        _ if is_pid1 => run_init(),
        Some("--client") => run_client(args.collect()),
        Some("--smoke") => run_smoke(args.collect()),
        Some("--smoke-ns") => run_smoke_ns(args.collect()),
        Some("--attach-netns") => run_attach_netns(args.collect()),
        Some("--print-server-key") => run_print_server_key(args.collect()),
        Some("--version") => {
            println!("oxwrtctl {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!(
                "usage: oxwrtctl --init\n\
                        oxwrtctl --client <remote> <cmd> [args...]\n\
                        oxwrtctl --smoke <rootfs> <entrypoint> [args...]\n\
                        oxwrtctl --smoke-ns <rootfs> <host_ip> <peer_ip> <entrypoint> [args...]\n\
                        oxwrtctl --attach-netns <pid> <peer_name> <peer_ip> <prefix> <gateway_ip>\n\
                        oxwrtctl --print-server-key [path]\n\
                        oxwrtctl --version"
            );
            ExitCode::from(2)
        }
    }
}

/// Read the Ed25519 signing-key seed from disk and print the derived
/// **public** key as hex to stdout. Used to bootstrap sQUIC clients — the
/// public key has to be known out-of-band before `dial()` can pin it, so
/// an operator would typically run this once over a serial or physical
/// channel right after first boot to learn the server key.
///
/// Default path is `/etc/oxwrt/key.ed25519`; a different path can be
/// supplied as a single positional argument.
fn run_print_server_key(args: Vec<String>) -> ExitCode {
    let path = args
        .into_iter()
        .next()
        .unwrap_or_else(|| "/etc/oxwrt/key.ed25519".to_string());
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("oxwrtctl: read {path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    if bytes.len() != 32 {
        eprintln!(
            "oxwrtctl: {path}: expected 32-byte Ed25519 seed, got {} bytes",
            bytes.len()
        );
        return ExitCode::FAILURE;
    }
    let seed: [u8; 32] = bytes.as_slice().try_into().unwrap();
    let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
    let verifying = signing.verifying_key();
    println!("{}", hex::encode(verifying.to_bytes()));
    ExitCode::SUCCESS
}

fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    // Read RUST_LOG; default to info for our own crate and warn elsewhere
    // so e.g. rtnetlink's internal debug chatter doesn't drown the real
    // output. Written to stderr so stdout stays clean for subcommands
    // like --version that pipe values.
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("oxwrtctl=info,warn"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .try_init();
}

#[cfg(target_os = "linux")]
fn run_smoke(args: Vec<String>) -> ExitCode {
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("smoke: failed to build tokio runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    rt.block_on(smoke_async(args))
}

#[cfg(target_os = "linux")]
async fn smoke_async(args: Vec<String>) -> ExitCode {
    use std::path::PathBuf;
    use std::time::{Duration, Instant};

    let mut it = args.into_iter();
    let Some(rootfs) = it.next() else {
        eprintln!("--smoke: missing <rootfs>");
        return ExitCode::from(2);
    };
    let entrypoint: Vec<String> = it.collect();
    if entrypoint.is_empty() {
        eprintln!("--smoke: missing <entrypoint>");
        return ExitCode::from(2);
    }

    // Allow the smoke harness to exercise SecurityProfile.seccomp_allow and
    // the cap retain list via env vars so the CLI surface stays minimal.
    // Comma-separated names, e.g.
    //   OXWRT_SMOKE_SECCOMP_ALLOW=unshare,bpf
    //   OXWRT_SMOKE_CAPS=SYS_ADMIN,NET_ADMIN
    // Setting OXWRT_SMOKE_CAPS replaces the entire retain list, including
    // the four-cap default, so include SETPCAP if you still want it dropped
    // last instead of last-of-many.
    let mut security = config::SecurityProfile::default();
    if let Ok(allow) = std::env::var("OXWRT_SMOKE_SECCOMP_ALLOW") {
        security.seccomp_allow = allow
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
    }
    if let Ok(caps) = std::env::var("OXWRT_SMOKE_CAPS") {
        security.caps = caps
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
    }
    if std::env::var("OXWRT_SMOKE_USERNS").is_ok() {
        security.user_namespace = true;
    }

    let spec = config::Service {
        name: "smoke".to_string(),
        rootfs: PathBuf::from(&rootfs),
        entrypoint,
        env: Default::default(),
        // Smoke mode shares the host netns so the guest can actually bind
        // and be reachable without the supervisor having to set up a veth
        // pair. Real services use NetMode::Isolated.
        net_mode: config::NetMode::Host,
        veth: None,
        memory_max: None,
        cpu_max: None,
        pids_max: None,
        binds: vec![],
        depends_on: vec![],
        security,
    };
    eprintln!(
        "smoke: rootfs={} entrypoint={:?} net_mode={:?}",
        rootfs, spec.entrypoint, spec.net_mode
    );

    let logd = logd::Logd::new();
    let mut sup = container::Supervised::new(spec);

    if let Err(e) = container::spawn(&mut sup, &logd) {
        eprintln!("smoke: spawn failed: {e}");
        return ExitCode::FAILURE;
    }
    eprintln!("smoke: spawn ok, pid={:?}, state={:?}", sup.pid(), sup.state);

    let deadline = Instant::now() + Duration::from_secs(30);
    let exit_code = loop {
        match container::reap(&mut sup) {
            Ok(Some(status)) => {
                eprintln!(
                    "smoke: child exited: code={:?} success={}",
                    status.code(),
                    status.success()
                );
                break if status.success() {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::FAILURE
                };
            }
            Ok(None) => {
                if Instant::now() > deadline {
                    eprintln!("smoke: 30s timeout waiting for child");
                    let _ = container::stop(&mut sup);
                    break ExitCode::FAILURE;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(e) => {
                eprintln!("smoke: reap error: {e}");
                break ExitCode::FAILURE;
            }
        }
    };

    // Give drain tasks a moment to finish reading from the now-closed pipes,
    // then dump whatever we captured so the smoke output shows real child
    // stdout/stderr going through the full logd path.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let captured = logd.tail("smoke", 200);
    eprintln!("smoke: captured {} log line(s)", captured.len());
    for line in &captured {
        eprintln!("smoke:   | {}", line.line);
    }

    exit_code
}

#[cfg(not(target_os = "linux"))]
fn run_smoke(_args: Vec<String>) -> ExitCode {
    eprintln!("oxwrtctl: --smoke is only supported on Linux");
    ExitCode::FAILURE
}

#[cfg(target_os = "linux")]
fn run_init() -> ExitCode {
    match init::run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("oxwrtctl: init failed: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn run_init() -> ExitCode {
    eprintln!("oxwrtctl: --init is only supported on Linux");
    ExitCode::FAILURE
}

fn run_client(args: Vec<String>) -> ExitCode {
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("oxwrtctl: failed to build tokio runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    match rt.block_on(control::client::run(args)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("oxwrtctl: client failed: {e}");
            ExitCode::FAILURE
        }
    }
}

// -------- --smoke-ns --------

#[cfg(target_os = "linux")]
fn run_smoke_ns(args: Vec<String>) -> ExitCode {
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("smoke-ns: failed to build tokio runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    rt.block_on(smoke_ns_async(args))
}

#[cfg(target_os = "linux")]
async fn smoke_ns_async(args: Vec<String>) -> ExitCode {
    use std::net::Ipv4Addr;
    use std::path::PathBuf;
    use std::time::{Duration, Instant};

    let mut it = args.into_iter();
    let Some(rootfs) = it.next() else {
        eprintln!("--smoke-ns: missing <rootfs>");
        return ExitCode::from(2);
    };
    let Some(host_ip) = it.next().and_then(|s| s.parse::<Ipv4Addr>().ok()) else {
        eprintln!("--smoke-ns: missing/invalid <host_ip>");
        return ExitCode::from(2);
    };
    let Some(peer_ip) = it.next().and_then(|s| s.parse::<Ipv4Addr>().ok()) else {
        eprintln!("--smoke-ns: missing/invalid <peer_ip>");
        return ExitCode::from(2);
    };
    let entrypoint: Vec<String> = it.collect();
    if entrypoint.is_empty() {
        eprintln!("--smoke-ns: missing <entrypoint>");
        return ExitCode::from(2);
    }

    let svc_name = "smokens".to_string();
    let prefix: u8 = 30;

    eprintln!(
        "smoke-ns: rootfs={} host_ip={} peer_ip={} entrypoint={:?}",
        rootfs, host_ip, peer_ip, entrypoint
    );

    let net = match net::Net::new() {
        Ok(n) => n,
        Err(e) => {
            eprintln!("smoke-ns: Net::new failed: {e}");
            return ExitCode::FAILURE;
        }
    };
    let (host_name, peer_name) = match net.setup_host_veth(&svc_name, host_ip, prefix).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("smoke-ns: setup_host_veth failed: {e}");
            return ExitCode::FAILURE;
        }
    };
    eprintln!(
        "smoke-ns: host veth up: {}={}/{} peer={}",
        host_name, host_ip, prefix, peer_name
    );

    if let Err(e) = net::enable_ipv4_forwarding() {
        eprintln!("smoke-ns: enable_ipv4_forwarding: {e}");
        return ExitCode::FAILURE;
    }
    eprintln!("smoke-ns: ip_forward=1");

    let spec = config::Service {
        name: svc_name.clone(),
        rootfs: PathBuf::from(&rootfs),
        entrypoint,
        env: Default::default(),
        net_mode: config::NetMode::Isolated,
        veth: Some(config::VethConfig {
            host_ip,
            peer_ip,
            prefix,
        }),
        memory_max: None,
        cpu_max: None,
        pids_max: None,
        binds: vec![],
        depends_on: vec![],
        security: Default::default(),
    };

    let logd = logd::Logd::new();
    let mut sup = container::Supervised::new(spec);
    // `container::spawn` itself fires the `--attach-netns` helper for
    // Isolated services now; the orchestrator only has to do the host-side
    // prep above and wait on the service below.
    if let Err(e) = container::spawn(&mut sup, &logd) {
        eprintln!("smoke-ns: spawn failed: {e}");
        return ExitCode::FAILURE;
    }
    eprintln!("smoke-ns: spawn ok, pid={:?}", sup.pid());

    // Wait for the supervised service as the existing smoke does.
    let deadline = Instant::now() + Duration::from_secs(30);
    let exit_code = loop {
        match container::reap(&mut sup) {
            Ok(Some(status)) => {
                eprintln!(
                    "smoke-ns: child exited: code={:?} success={}",
                    status.code(),
                    status.success()
                );
                break if status.success() {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::FAILURE
                };
            }
            Ok(None) => {
                if Instant::now() > deadline {
                    eprintln!("smoke-ns: 30s timeout");
                    let _ = container::stop(&mut sup);
                    break ExitCode::FAILURE;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(e) => {
                eprintln!("smoke-ns: reap error: {e}");
                break ExitCode::FAILURE;
            }
        }
    };

    tokio::time::sleep(Duration::from_millis(100)).await;
    let captured = logd.tail(&svc_name, 500);
    eprintln!("smoke-ns: captured {} log line(s)", captured.len());
    for line in &captured {
        eprintln!("smoke-ns:   | {}", line.line);
    }

    exit_code
}

#[cfg(not(target_os = "linux"))]
fn run_smoke_ns(_args: Vec<String>) -> ExitCode {
    eprintln!("oxwrtctl: --smoke-ns is only supported on Linux");
    ExitCode::FAILURE
}

// -------- --attach-netns --------

#[cfg(target_os = "linux")]
fn run_attach_netns(args: Vec<String>) -> ExitCode {
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("attach-netns: tokio runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    rt.block_on(attach_netns_async(args))
}

#[cfg(target_os = "linux")]
async fn attach_netns_async(args: Vec<String>) -> ExitCode {
    use std::net::{IpAddr, Ipv4Addr};
    use std::os::fd::{AsFd, AsRawFd};

    use rtnetlink::{LinkUnspec, RouteMessageBuilder, new_connection};

    let mut it = args.into_iter();
    let Some(pid) = it.next().and_then(|s| s.parse::<u32>().ok()) else {
        eprintln!("--attach-netns: missing/invalid <pid>");
        return ExitCode::from(2);
    };
    let Some(peer_name) = it.next() else {
        eprintln!("--attach-netns: missing <peer_name>");
        return ExitCode::from(2);
    };
    let Some(peer_ip) = it.next().and_then(|s| s.parse::<Ipv4Addr>().ok()) else {
        eprintln!("--attach-netns: missing/invalid <peer_ip>");
        return ExitCode::from(2);
    };
    let Some(prefix) = it.next().and_then(|s| s.parse::<u8>().ok()) else {
        eprintln!("--attach-netns: missing/invalid <prefix>");
        return ExitCode::from(2);
    };
    let Some(gateway_ip) = it.next().and_then(|s| s.parse::<Ipv4Addr>().ok()) else {
        eprintln!("--attach-netns: missing/invalid <gateway_ip>");
        return ExitCode::from(2);
    };

    // Open the child's netns file in the host netns so we can (a) move the
    // peer into it and (b) setns ourselves into it afterwards.
    let ns_path = format!("/proc/{pid}/ns/net");
    let ns_file = match std::fs::File::open(&ns_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("attach-netns: open {ns_path}: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Step 1: in the host netns, find the peer veth and move it into the
    // child's netns via its fd. This connection and its worker task live on
    // the current-thread runtime; we drop them before setns so the next
    // rtnetlink connection below is scoped to the child netns.
    {
        let (connection, handle, _) = match new_connection() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("attach-netns: new_connection (host): {e}");
                return ExitCode::FAILURE;
            }
        };
        let conn_task = tokio::spawn(connection);

        let peer_idx = match link_index(&handle, &peer_name).await {
            Ok(i) => i,
            Err(e) => {
                eprintln!("attach-netns: link_index {peer_name}: {e}");
                return ExitCode::FAILURE;
            }
        };
        if let Err(e) = handle
            .link()
            .set(
                LinkUnspec::new_with_index(peer_idx)
                    .setns_by_fd(ns_file.as_fd().as_raw_fd())
                    .build(),
            )
            .execute()
            .await
        {
            eprintln!("attach-netns: setns_by_fd {peer_name}: {e}");
            return ExitCode::FAILURE;
        }
        drop(handle);
        conn_task.abort();
    }

    // Step 2: move this thread into the child's netns.
    if let Err(e) = rustix::thread::move_into_link_name_space(
        ns_file.as_fd(),
        Some(rustix::thread::LinkNameSpaceType::Network),
    ) {
        eprintln!("attach-netns: setns: {e}");
        return ExitCode::FAILURE;
    }

    // Step 3: in the child netns, open a fresh rtnetlink connection and
    // bring up `lo` and the peer end.
    let (connection, handle, _) = match new_connection() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("attach-netns: new_connection (child ns): {e}");
            return ExitCode::FAILURE;
        }
    };
    tokio::spawn(connection);

    let lo_idx = match link_index(&handle, "lo").await {
        Ok(i) => i,
        Err(e) => {
            eprintln!("attach-netns: child lo index: {e}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(e) = handle
        .link()
        .set(LinkUnspec::new_with_index(lo_idx).up().build())
        .execute()
        .await
    {
        eprintln!("attach-netns: bring up lo: {e}");
        return ExitCode::FAILURE;
    }

    let peer_idx = match link_index(&handle, &peer_name).await {
        Ok(i) => i,
        Err(e) => {
            eprintln!("attach-netns: child peer index: {e}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(e) = handle
        .address()
        .add(peer_idx, IpAddr::V4(peer_ip), prefix)
        .execute()
        .await
    {
        eprintln!("attach-netns: address add on peer: {e}");
        return ExitCode::FAILURE;
    }
    if let Err(e) = handle
        .link()
        .set(LinkUnspec::new_with_index(peer_idx).up().build())
        .execute()
        .await
    {
        eprintln!("attach-netns: bring up peer: {e}");
        return ExitCode::FAILURE;
    }

    // Default route inside the child netns via the gateway (host veth end).
    let route = RouteMessageBuilder::<Ipv4Addr>::new()
        .destination_prefix(Ipv4Addr::UNSPECIFIED, 0)
        .gateway(gateway_ip)
        .build();
    if let Err(e) = handle.route().add(route).execute().await {
        eprintln!("attach-netns: default route add: {e}");
        return ExitCode::FAILURE;
    }

    eprintln!(
        "attach-netns: ok pid={pid} peer={peer_name} ip={peer_ip}/{prefix} gw={gateway_ip}"
    );
    ExitCode::SUCCESS
}

#[cfg(target_os = "linux")]
async fn link_index(
    handle: &rtnetlink::Handle,
    name: &str,
) -> Result<u32, rtnetlink::Error> {
    use futures_util::stream::TryStreamExt;
    let mut stream = handle
        .link()
        .get()
        .match_name(name.to_string())
        .execute();
    match stream.try_next().await? {
        Some(msg) => Ok(msg.header.index),
        None => Err(rtnetlink::Error::NamespaceError(format!(
            "link {name} not found"
        ))),
    }
}

#[cfg(not(target_os = "linux"))]
fn run_attach_netns(_args: Vec<String>) -> ExitCode {
    eprintln!("oxwrtctl: --attach-netns is only supported on Linux");
    ExitCode::FAILURE
}
