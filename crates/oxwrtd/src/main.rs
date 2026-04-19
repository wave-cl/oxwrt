// config + rpc moved to oxwrt-api. container / net / wan_dhcp / wifi /
// sysupgrade / logd moved to oxwrt-linux. All re-exported here as if
// they were local modules so every existing `crate::config::X`,
// `crate::container::Y`, etc. call site keeps resolving — avoids
// churning thousands of imports across init.rs + control/server.rs.
pub use oxwrt_api::{config, rpc};
#[cfg(target_os = "linux")]
pub use oxwrt_linux::{
    blocklists, container, corerad, logd, net, sqm, static_routes, sysupgrade, wan_dhcp,
    wan_dhcp6, wifi, wireguard,
};
mod control;

#[cfg(target_os = "linux")]
mod ddns;
#[cfg(target_os = "linux")]
mod init;
#[cfg(target_os = "linux")]
mod metrics;

use std::process::ExitCode;

fn main() -> ExitCode {
    let is_pid1 = std::process::id() == 1;
    // Run BEFORE init_tracing so that any subsequent eprintln hits
    // the console. When the kernel execs /sbin/init directly, stdio
    // may be closed or pointed at /dev/null — procd-init does this
    // normally in early_console(); stock OpenWrt gives us nothing
    // when we replace procd-init.
    // init module is linux-only; the console hand-off + panic hook
    // only matter when we're actually pid 1 on the device. On non-
    // linux hosts there's nothing to do.
    #[cfg(target_os = "linux")]
    if is_pid1 {
        init::console::early_console();
        init::console::install_panic_hook();
    }
    init_tracing();
    let mut args = std::env::args().skip(1);
    let mode = args.next();

    match mode.as_deref() {
        Some("--init") => run_init(),
        Some("--control-only") => run_control_only(),
        Some("--services-only") => run_services_only(),
        Some("--client") => run_client(args.collect()),
        Some("--smoke") => run_smoke(args.collect()),
        Some("--smoke-ns") => run_smoke_ns(args.collect()),
        Some("--attach-netns") => run_attach_netns(args.collect()),
        Some("--print-server-key") => run_print_server_key(args.collect()),
        Some("--version") => {
            println!("oxwrtd {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Some("--help") => {
            print_usage();
            ExitCode::SUCCESS
        }
        // No args + PID 1: the kernel invoked /sbin/init (our symlink)
        // or procd-init execve'd /sbin/procd (us). Either way, run init.
        _ if is_pid1 => run_init(),
        // No args + not PID 1: almost always OpenWrt's /sbin/init (or
        // one of the preinit shell scripts) forking /sbin/procd during
        // preinit. Real procd has a preinit protocol (/tmp/.preinit
        // marker, env var signals) we don't implement — the shell
        // /etc/preinit does the equivalent work before our real pid-1
        // invocation, so silently exiting here is correct.
        //
        // Two earlier attempts tried to distinguish "init invoked us"
        // from "operator typed `oxwrtd`" via (argv[0] basename ==
        // "procd"), (ppid == 1), and (!stderr.is_terminal()). None
        // caught every case. Simpler to unconditionally no-op on no
        // args and require an explicit --help/-h for the usage print.
        // Operators who type `oxwrtd` bare get a silent exit; they
        // figure it out from `oxwrtd --help`.
        _ => ExitCode::SUCCESS,
    }
}

fn print_usage() {
    eprintln!(
        "usage: oxwrtd --init\n\
                oxwrtd --control-only\n\
                oxwrtd --services-only\n\
                oxwrtd --client <remote> <cmd> [args...]\n\
                oxwrtd --smoke <rootfs> <entrypoint> [args...]\n\
                oxwrtd --smoke-ns <rootfs> <host_ip> <peer_ip> <entrypoint> [args...]\n\
                oxwrtd --attach-netns <pid> <peer_name> <peer_ip> <prefix> <gateway_ip>\n\
                oxwrtd --print-server-key [path]\n\
                oxwrtd --version\n\
                oxwrtd --help"
    );
}

// run_print_server_key moved to oxwrtctl-cli as
// `oxwrtctl_cli::print_server_key` and is called from both `oxwrtd
// --print-server-key` and `oxctl --print-server-key`.
fn run_print_server_key(args: Vec<String>) -> ExitCode {
    oxwrtctl_cli::print_server_key(args)
}

fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    // Read RUST_LOG; default to info for our own crate and warn elsewhere
    // so e.g. rtnetlink's internal debug chatter doesn't drown the real
    // output. Written to stderr so stdout stays clean for subcommands
    // like --version that pipe values.
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("oxwrtd=info,warn"));
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
    eprintln!(
        "smoke: spawn ok, pid={:?}, state={:?}",
        sup.pid(),
        sup.state
    );

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
    eprintln!("oxwrtd: --smoke is only supported on Linux");
    ExitCode::FAILURE
}

#[cfg(target_os = "linux")]
fn run_init() -> ExitCode {
    match init::run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("oxwrtd: init failed: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn run_init() -> ExitCode {
    eprintln!("oxwrtd: --init is only supported on Linux");
    ExitCode::FAILURE
}

#[cfg(target_os = "linux")]
fn run_control_only() -> ExitCode {
    match init::run_control_only() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("oxwrtd: control-only failed: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn run_control_only() -> ExitCode {
    eprintln!("oxwrtd: --control-only is only supported on Linux");
    ExitCode::FAILURE
}

#[cfg(target_os = "linux")]
fn run_services_only() -> ExitCode {
    match init::run_services_only() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("oxwrtd: services-only failed: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn run_services_only() -> ExitCode {
    eprintln!("oxwrtd: --services-only is only supported on Linux");
    ExitCode::FAILURE
}

fn run_client(args: Vec<String>) -> ExitCode {
    // Delegated to the oxwrtctl-cli crate so the daemon and the
    // standalone `oxctl` binary share one implementation. Prints
    // its own error on failure.
    oxwrtctl_cli::run_client_sync(args)
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
    eprintln!("oxwrtd: --smoke-ns is only supported on Linux");
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

    eprintln!("attach-netns: ok pid={pid} peer={peer_name} ip={peer_ip}/{prefix} gw={gateway_ip}");
    ExitCode::SUCCESS
}

#[cfg(target_os = "linux")]
async fn link_index(handle: &rtnetlink::Handle, name: &str) -> Result<u32, rtnetlink::Error> {
    use futures_util::stream::TryStreamExt;
    let mut stream = handle.link().get().match_name(name.to_string()).execute();
    match stream.try_next().await? {
        Some(msg) => Ok(msg.header.index),
        None => Err(rtnetlink::Error::NamespaceError(format!(
            "link {name} not found"
        ))),
    }
}

#[cfg(not(target_os = "linux"))]
fn run_attach_netns(_args: Vec<String>) -> ExitCode {
    eprintln!("oxwrtd: --attach-netns is only supported on Linux");
    ExitCode::FAILURE
}

// early_console + install_panic_hook moved to init/console.rs during
// step 6 of the workspace refactor. Invoked above in `main()`.
