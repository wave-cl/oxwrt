pub mod client;
#[cfg(target_os = "linux")]
pub mod server;

use std::io;
#[cfg(target_os = "linux")]
use std::sync::{Arc, Mutex, RwLock};

#[cfg(target_os = "linux")]
use crate::config::Config;
#[cfg(target_os = "linux")]
use crate::container::Supervisor;
#[cfg(target_os = "linux")]
use crate::logd::Logd;
#[cfg(target_os = "linux")]
use crate::wan_dhcp::DhcpLease;

/// Shared WAN lease state. `None` until the boot-time DHCP `acquire`
/// succeeds, then mutated in place by `spawn_renewal_loop` on every
/// renewal. `handle_diag("dhcp")` reads it for the diag RPC. Wrapped
/// in an `Arc<RwLock<...>>` so the renewal loop and `ControlState` can
/// hold independent clones — the renewal loop is spawned BEFORE
/// `ControlState::new` runs, so it can't share via the `ControlState`
/// `Arc` itself.
#[cfg(target_os = "linux")]
pub type SharedLease = Arc<RwLock<Option<DhcpLease>>>;

/// State shared between the init main loop and sQUIC control-plane tasks.
///
/// `config` is behind an `RwLock<Arc<Config>>`: readers clone the inner
/// `Arc` (cheap), holders of the write lock can swap it atomically during
/// `Reload`. `supervisor` is behind a `std::sync::Mutex` because all
/// critical sections are purely synchronous. `logd` is `Clone` (it's
/// `Arc` inside) so it needs no outer lock.
///
/// `firewall_dump` is the human-readable rendering of the rules that
/// `net::install_firewall` last installed, captured at boot from
/// `net::format_firewall_dump(&cfg)` and read by the `Diag::firewall`
/// RPC. It's a `RwLock<Vec<String>>` rather than a snapshot field so a
/// future reload that reinstalls the firewall can refresh it.
#[cfg(target_os = "linux")]
pub struct ControlState {
    pub config: RwLock<Arc<Config>>,
    pub supervisor: Mutex<Supervisor>,
    pub logd: Logd,
    pub firewall_dump: RwLock<Vec<String>>,
    pub wan_lease: SharedLease,
    /// `Instant` captured at `ControlState::new`. The `Status` RPC
    /// returns `supervisor_uptime_secs = boot_time.elapsed().as_secs()`
    /// so operators get a "how long has this router been up?" answer
    /// without a separate RPC. Not the PID-1 fork time — there's a
    /// few hundred ms of early mounts / netlink setup before this
    /// fires — but close enough for operational use.
    pub boot_time: std::time::Instant,
}

#[cfg(target_os = "linux")]
impl ControlState {
    pub fn new(
        config: Config,
        supervisor: Supervisor,
        logd: Logd,
        firewall_dump: Vec<String>,
        wan_lease: SharedLease,
    ) -> Arc<Self> {
        Arc::new(Self {
            config: RwLock::new(Arc::new(config)),
            supervisor: Mutex::new(supervisor),
            logd,
            firewall_dump: RwLock::new(firewall_dump),
            wan_lease,
            boot_time: std::time::Instant::now(),
        })
    }

    pub fn config_snapshot(&self) -> Arc<Config> {
        self.config.read().unwrap().clone()
    }
}

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::rpc::{CrudAction, Request, Response};

const MAX_FRAME: u32 = 1 << 20;

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("frame too large: {0} bytes")]
    TooLarge(u32),
    #[error("encode: {0}")]
    Encode(String),
    #[error("decode: {0}")]
    Decode(String),
}

pub async fn write_frame<W, T>(w: &mut W, msg: &T) -> Result<(), FrameError>
where
    W: AsyncWriteExt + Unpin,
    T: serde::Serialize,
{
    let body =
        rmp_serde::to_vec_named(msg).map_err(|e| FrameError::Encode(e.to_string()))?;
    let len = u32::try_from(body.len())
        .map_err(|_| FrameError::TooLarge(u32::MAX))?;
    if len > MAX_FRAME {
        return Err(FrameError::TooLarge(len));
    }
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(&body).await?;
    Ok(())
}

pub async fn read_frame<R, T>(r: &mut R) -> Result<T, FrameError>
where
    R: AsyncReadExt + Unpin,
    T: serde::de::DeserializeOwned,
{
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME {
        return Err(FrameError::TooLarge(len));
    }
    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body).await?;
    rmp_serde::from_slice(&body).map_err(|e| FrameError::Decode(e.to_string()))
}

pub fn parse_request(cmd: &str, args: &[String]) -> Result<Request, String> {
    match cmd {
        "get" => {
            let key = args.first().ok_or("get: missing key")?.clone();
            Ok(Request::Get { key })
        }
        "set" => {
            let key = args.first().ok_or("set: missing key")?.clone();
            let value = args.get(1).ok_or("set: missing value")?.clone();
            Ok(Request::Set { key, value })
        }
        "reload" => Ok(Request::Reload),
        "status" => Ok(Request::Status),
        "logs" => {
            let service = args.first().ok_or("logs: missing service")?.clone();
            let follow = args.iter().any(|a| a == "--follow" || a == "-f");
            Ok(Request::Logs { service, follow })
        }
        "restart" => {
            let service = args.first().ok_or("restart: missing service")?.clone();
            Ok(Request::Restart { service })
        }
        "reset" => {
            // The CLI requires an explicit `--confirm` flag so a typo can't
            // wipe the operator's config. The server enforces the same
            // invariant on the wire.
            let confirm = args.iter().any(|a| a == "--confirm");
            if !confirm {
                return Err(
                    "reset: refusing to reset without --confirm (this wipes /etc/oxwrt.toml)"
                        .to_string(),
                );
            }
            Ok(Request::Reset { confirm: true })
        }
        "diag" => {
            let name = args.first().ok_or(
                "diag: missing op (try `links`, `routes`)",
            )?;
            let rest = if args.len() > 1 { args[1..].to_vec() } else { Vec::new() };
            Ok(Request::Diag {
                name: name.clone(),
                args: rest,
            })
        }
        "update" => {
            // `oxwrtctl --client <remote> update <firmware.bin>`
            // The path is used by the client to read the file and compute
            // SHA-256. The Request carries size + hash; the file bytes
            // are streamed separately on the sQUIC bi-stream.
            let path = args
                .first()
                .ok_or("update: missing firmware image path")?;
            let meta = std::fs::metadata(path)
                .map_err(|e| format!("update: {path}: {e}"))?;
            let size = meta.len();
            // Compute SHA-256 of the image file.
            let sha256 = {
                use sha2::{Sha256, Digest};
                let mut file = std::fs::File::open(path)
                    .map_err(|e| format!("update: open {path}: {e}"))?;
                let mut hasher = Sha256::new();
                std::io::copy(&mut file, &mut hasher)
                    .map_err(|e| format!("update: hash {path}: {e}"))?;
                hex::encode(hasher.finalize())
            };
            Ok(Request::FwUpdate { size, sha256 })
        }
        "apply" => {
            let confirm = args.iter().any(|a| a == "--confirm");
            if !confirm {
                return Err(
                    "apply: refusing to flash without --confirm (this reboots the router)"
                        .to_string(),
                );
            }
            // --clean = discard all settings (sysupgrade -n).
            // Default (no --clean) = keep /etc/oxwrt.toml + keys.
            let keep_settings = !args.iter().any(|a| a == "--clean");
            Ok(Request::FwApply { confirm: true, keep_settings })
        }
        "network" | "zone" | "rule" | "wifi" | "radio" => {
            let action = match args.first().map(|s| s.as_str()) {
                Some("list") => CrudAction::List,
                Some("get") => {
                    let name = args.get(1).ok_or(format!("{cmd} get: missing name"))?;
                    CrudAction::Get { name: name.clone() }
                }
                Some("add") => {
                    let json = args.get(1).ok_or(format!("{cmd} add: missing JSON"))?;
                    CrudAction::Add { json: json.clone() }
                }
                Some("update") => {
                    let name = args.get(1).ok_or(format!("{cmd} update: missing name"))?;
                    let json = args.get(2).ok_or(format!("{cmd} update: missing JSON"))?;
                    CrudAction::Update { name: name.clone(), json: json.clone() }
                }
                Some("remove") => {
                    let name = args.get(1).ok_or(format!("{cmd} remove: missing name"))?;
                    CrudAction::Remove { name: name.clone() }
                }
                _ => return Err(format!("{cmd}: missing action (list|get|add|update|remove)")),
            };
            Ok(Request::Collection { collection: cmd.to_string(), action })
        }
        _ => Err(format!("unknown command: {cmd}")),
    }
}

/// The minimal default config a freshly-reset router boots with.
/// Matches the GL.iNet shipped defaults (LAN 192.168.8.1/24) so a user
/// who doesn't know what address they're at can plug in and reach the
/// router on the obvious one. Preserves the in-memory `[control]` block
/// (listen addrs + authorized keys path) so the operator never loses
/// the management path across a reset — without that preservation, a
/// reset over the control plane would immediately drop its only
/// management path.
///
/// This lives in `control.rs` (which builds on macOS) rather than
/// `control/server.rs` (Linux-only) so the round-trip test below
/// runs in `cargo check` on the host. The reset handler in
/// `control/server.rs` calls it via `crate::control::default_config_text`.
pub fn default_config_text(control: &crate::config::Control) -> String {
    let listen_lines = control
        .listen
        .iter()
        .map(|s| format!("  {:?}", s))
        .collect::<Vec<_>>()
        .join(",\n");
    let authorized_keys = control.authorized_keys.display();
    format!(
        r#"# oxwrt.toml — written by `oxwrtctl reset`. Edit freely.
hostname = "oxwrt"

[[networks]]
name = "wan"
type = "wan"
iface = "eth0"
mode = "dhcp"

[[networks]]
name = "lan"
type = "lan"
bridge = "br-lan"
members = ["eth1", "eth2"]
address = "192.168.8.1"
prefix = 24

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
name = "lan-internet"
src = "lan"
dest = "wan"
action = "accept"

[control]
listen = [
{listen_lines}
]
authorized_keys = "{authorized_keys}"
"#,
    )
}

pub fn format_response(resp: &Response) -> String {
    match resp {
        Response::Ok => "ok".to_string(),
        Response::Value { value } => value.clone(),
        Response::Status {
            services,
            supervisor_uptime_secs,
            wan,
            firewall_rules,
        } => {
            let mut out = String::new();
            out.push_str(&format!(
                "supervisor uptime: {}s\nfirewall rules:    {}\n",
                supervisor_uptime_secs, firewall_rules
            ));
            match wan {
                Some(w) => {
                    out.push_str(&format!(
                        "wan:               {}/{} via {} (lease {}s)\n",
                        w.address,
                        w.prefix,
                        w.gateway.as_deref().unwrap_or("none"),
                        w.lease_seconds
                    ));
                }
                None => {
                    out.push_str("wan:               (no dhcp lease)\n");
                }
            }
            if services.is_empty() {
                out.push_str("services:          (none)\n");
            } else {
                out.push_str("services:\n");
                for s in services {
                    out.push_str(&format!(
                        "  {:<16} {:?} pid={:?} restarts={} uptime={}s\n",
                        s.name, s.state, s.pid, s.restarts, s.uptime_secs
                    ));
                }
            }
            out
        }
        Response::LogLine { line } => line.clone(),
        Response::FwProgress { bytes_received } => {
            format!("upload: {bytes_received} bytes received")
        }
        Response::Err { message } => format!("error: {message}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, Control};
    use crate::rpc::CrudAction;
    use std::path::PathBuf;

    /// `default_config_text` must produce TOML that round-trips into a
    /// valid `Config`, and the preserved `[control]` block must come
    /// through verbatim — that's the load-bearing invariant of the
    /// reset path (operator can't lock themselves out).
    #[test]
    fn default_config_text_roundtrips_and_preserves_control() {
        let control = Control {
            listen: vec!["192.168.8.1:51820".to_string(), "[::1]:51820".to_string()],
            authorized_keys: PathBuf::from("/etc/oxwrt/authorized_keys"),
        };
        let text = default_config_text(&control);
        let cfg: Config = toml::from_str(&text).expect("default config must parse");
        assert_eq!(cfg.control.listen, control.listen);
        assert_eq!(cfg.control.authorized_keys, control.authorized_keys);
        assert_eq!(cfg.lan().unwrap().iface(), "br-lan");
        assert!(cfg.services.is_empty());
        assert_eq!(cfg.networks.len(), 2); // wan + lan
    }

    /// Listen string must be quoted exactly once — this guards against
    /// accidentally double-quoting via `format!("\"{s}\"")`.
    #[test]
    fn default_config_text_quotes_listen_strings_once() {
        let control = Control {
            listen: vec!["10.0.0.1:51820".to_string()],
            authorized_keys: PathBuf::from("/etc/oxwrt/keys"),
        };
        let text = default_config_text(&control);
        let n = text.matches("\"10.0.0.1:51820\"").count();
        assert_eq!(n, 1, "listen string not quoted exactly once: {text}");
    }

    /// The CLI parser must refuse `reset` without `--confirm`. This is
    /// the first-line defense against a typo wiping the operator's
    /// config; the wire-level invariant is enforced server-side too.
    #[test]
    fn reset_requires_confirm_flag() {
        let err = parse_request("reset", &[]).unwrap_err();
        assert!(err.contains("--confirm"), "unexpected error: {err}");
        let req = parse_request("reset", &["--confirm".to_string()]).unwrap();
        match req {
            Request::Reset { confirm } => assert!(confirm),
            _ => panic!("expected Reset, got {req:?}"),
        }
    }

    /// Arg builders for the curated diag binaries validate operator
    /// input and produce a closed argv that can't be injected.
    #[test]
    #[cfg(target_os = "linux")]
    fn diag_binary_arg_builders() {
        use crate::control::server::{build_ping_args, build_traceroute_args, build_drill_args, build_ss_args};

        // ping: valid
        let argv = build_ping_args(&["1.2.3.4".into(), "5".into()]).unwrap();
        assert!(argv.contains(&"5".to_string())); // count
        assert!(argv.contains(&"1.2.3.4".to_string()));

        // ping: invalid target
        assert!(build_ping_args(&["not-an-ip".into()]).is_err());

        // ping: count out of range
        assert!(build_ping_args(&["1.1.1.1".into(), "99".into()]).is_err());

        // traceroute: valid
        let argv = build_traceroute_args(&["8.8.8.8".into()]).unwrap();
        assert!(argv.contains(&"8.8.8.8".to_string()));

        // traceroute: bad hops
        assert!(build_traceroute_args(&["1.1.1.1".into(), "50".into()]).is_err());

        // drill: valid name
        let argv = build_drill_args(&["example.com".into()]).unwrap();
        assert!(argv.contains(&"example.com".to_string()));

        // drill: name + server + type
        let argv = build_drill_args(&["example.com".into(), "@1.1.1.1".into(), "MX".into()]).unwrap();
        assert!(argv.contains(&"@1.1.1.1".to_string()));
        assert!(argv.contains(&"MX".to_string()));

        // drill: rejects flag injection
        assert!(build_drill_args(&["-x".into()]).is_err());

        // ss: defaults
        let argv = build_ss_args(&[]).unwrap();
        assert_eq!(argv, vec!["-tunlp"]);

        // ss: allowed flag
        let argv = build_ss_args(&["-tl".into()]).unwrap();
        assert_eq!(argv, vec!["-tl"]);

        // ss: rejects unknown flag
        assert!(build_ss_args(&["-Z".into()]).is_err());
    }

    /// `diag` requires a sub-op name; bare `diag` is rejected. Extra
    /// args go into `Request::Diag.args` so future ops with parameters
    /// can pick them up without a parser change.
    #[test]
    fn diag_parses_op_and_args() {
        let err = parse_request("diag", &[]).unwrap_err();
        assert!(err.contains("missing op"), "unexpected error: {err}");

        let req = parse_request("diag", &["links".to_string()]).unwrap();
        match req {
            Request::Diag { name, args } => {
                assert_eq!(name, "links");
                assert!(args.is_empty());
            }
            _ => panic!("expected Diag, got {req:?}"),
        }

        let req = parse_request(
            "diag",
            &[
                "ping".to_string(),
                "1.1.1.1".to_string(),
                "3".to_string(),
            ],
        )
        .unwrap();
        match req {
            Request::Diag { name, args } => {
                assert_eq!(name, "ping");
                assert_eq!(args, vec!["1.1.1.1".to_string(), "3".to_string()]);
            }
            _ => panic!("expected Diag, got {req:?}"),
        }
    }

    /// `apply` requires `--confirm` (same safety gate as `reset`).
    #[test]
    fn apply_requires_confirm_flag() {
        let err = parse_request("apply", &[]).unwrap_err();
        assert!(err.contains("--confirm"), "unexpected error: {err}");

        let req = parse_request("apply", &["--confirm".to_string()]).unwrap();
        match req {
            Request::FwApply {
                confirm,
                keep_settings,
            } => {
                assert!(confirm);
                assert!(keep_settings, "default should keep settings");
            }
            _ => panic!("expected FwApply, got {req:?}"),
        }
    }

    /// `apply --confirm --clean` sets keep_settings = false.
    #[test]
    fn apply_clean_flag() {
        let req = parse_request(
            "apply",
            &["--confirm".to_string(), "--clean".to_string()],
        )
        .unwrap();
        match req {
            Request::FwApply {
                confirm,
                keep_settings,
            } => {
                assert!(confirm);
                assert!(!keep_settings, "--clean should set keep_settings=false");
            }
            _ => panic!("expected FwApply, got {req:?}"),
        }
    }

    /// `update` requires a file path. We can't test with a real file in
    /// a unit test easily, but we can verify missing-path rejection.
    #[test]
    fn update_requires_path() {
        let err = parse_request("update", &[]).unwrap_err();
        assert!(
            err.contains("missing firmware image path"),
            "unexpected error: {err}"
        );
    }

    /// `update` with a nonexistent file returns a clear error.
    #[test]
    fn update_rejects_nonexistent_file() {
        let err = parse_request(
            "update",
            &["/tmp/does-not-exist-oxwrt-test.bin".to_string()],
        )
        .unwrap_err();
        assert!(
            err.contains("No such file") || err.contains("not found") || err.contains("os error"),
            "unexpected error: {err}"
        );
    }

    /// `update` with a real (temp) file produces FwUpdate with correct
    /// size and a valid hex SHA-256 hash.
    #[test]
    fn update_computes_sha256() {
        let tmp = std::env::temp_dir().join("oxwrt-test-fw.bin");
        let payload = b"oxwrt test payload";
        std::fs::write(&tmp, payload).unwrap();

        let req = parse_request("update", &[tmp.to_str().unwrap().to_string()]).unwrap();
        match req {
            Request::FwUpdate { size, sha256 } => {
                assert_eq!(size, payload.len() as u64);
                assert_eq!(sha256.len(), 64, "sha256 should be 64 hex chars");
                assert!(
                    sha256.chars().all(|c| c.is_ascii_hexdigit()),
                    "sha256 should be hex: {sha256}"
                );
            }
            _ => panic!("expected FwUpdate, got {req:?}"),
        }

        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn collection_crud_parse() {
        // list
        let req = parse_request("rule", &["list".to_string()]).unwrap();
        match req {
            Request::Collection { collection, action } => {
                assert_eq!(collection, "rule");
                assert!(matches!(action, CrudAction::List));
            }
            _ => panic!("expected Collection"),
        }

        // add
        let req = parse_request(
            "network",
            &[
                "add".to_string(),
                r#"{"name":"test","type":"simple","iface":"eth5","address":"10.0.0.1","prefix":24}"#.to_string(),
            ],
        )
        .unwrap();
        match req {
            Request::Collection { action: CrudAction::Add { json }, .. } => {
                assert!(json.contains("test"));
            }
            _ => panic!("expected Collection Add"),
        }

        // get
        let req = parse_request("wifi", &["get".to_string(), "MySSID".to_string()]).unwrap();
        match req {
            Request::Collection { collection, action: CrudAction::Get { name } } => {
                assert_eq!(collection, "wifi");
                assert_eq!(name, "MySSID");
            }
            _ => panic!("expected Collection Get"),
        }

        // update
        let req = parse_request(
            "radio",
            &["update".to_string(), "phy0".to_string(), r#"{"channel":44}"#.to_string()],
        )
        .unwrap();
        match req {
            Request::Collection { collection, action: CrudAction::Update { name, json } } => {
                assert_eq!(collection, "radio");
                assert_eq!(name, "phy0");
                assert!(json.contains("44"));
            }
            _ => panic!("expected Collection Update"),
        }

        // remove
        let req = parse_request("zone", &["remove".to_string(), "guest".to_string()]).unwrap();
        match req {
            Request::Collection { action: CrudAction::Remove { name }, .. } => {
                assert_eq!(name, "guest");
            }
            _ => panic!("expected Collection Remove"),
        }

        // missing action
        assert!(parse_request("rule", &[]).is_err());
    }
}
