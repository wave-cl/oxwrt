//! oxwrt-proto — sQUIC frame codec + RPC parse/format.
//!
//! The cross-platform transport layer shared by the daemon (accepts
//! frames over sQUIC streams) and the CLI (dials + sends one frame,
//! receives one). Pure codec + a bit of parse: no daemon state, no
//! tokio runtime management, nothing Linux-specific.
//!
//! ## Framing
//!
//! Every RPC is a length-prefixed msgpack frame:
//!
//! ```text
//! [ u32 len (big-endian) ][ rmp-serde body ]
//! ```
//!
//! The 1 MiB cap ([`MAX_FRAME`]) is enforced on both encode and decode;
//! a misbehaving peer can't force unbounded allocation.
//!
//! ## Split history
//!
//! Moved out of `oxwrtd/src/control.rs` during the workspace split
//! (step 3 of the plan). The daemon-specific pieces — `ControlState`,
//! `SharedLease`, `pub mod {client,server,validate}` — stay there.

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use oxwrt_api::config::Control;
use oxwrt_api::rpc::{CrudAction, Request, Response};

const MAX_FRAME: u32 = 1 << 20;

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
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
    let body = rmp_serde::to_vec_named(msg).map_err(|e| FrameError::Encode(e.to_string()))?;
    let len = u32::try_from(body.len()).map_err(|_| FrameError::TooLarge(u32::MAX))?;
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
            let name = args
                .first()
                .ok_or("diag: missing op (try `links`, `routes`)")?;
            let rest = if args.len() > 1 {
                args[1..].to_vec()
            } else {
                Vec::new()
            };
            Ok(Request::Diag {
                name: name.clone(),
                args: rest,
            })
        }
        "update" => {
            // `oxwrtd --client <remote> update <firmware.bin>`
            // The path is used by the client to read the file and compute
            // SHA-256. The Request carries size + hash; the file bytes
            // are streamed separately on the sQUIC bi-stream.
            let path = args.first().ok_or("update: missing firmware image path")?;
            let meta = std::fs::metadata(path).map_err(|e| format!("update: {path}: {e}"))?;
            let size = meta.len();
            // Compute SHA-256 of the image file.
            let sha256 = {
                use sha2::{Digest, Sha256};
                let mut file =
                    std::fs::File::open(path).map_err(|e| format!("update: open {path}: {e}"))?;
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
            Ok(Request::FwApply {
                confirm: true,
                keep_settings,
            })
        }
        "network" | "zone" | "rule" | "wifi" | "radio" | "service" | "port-forward" | "wg-peer"
        | "ddns" => {
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
                    CrudAction::Update {
                        name: name.clone(),
                        json: json.clone(),
                    }
                }
                Some("remove") => {
                    let name = args.get(1).ok_or(format!("{cmd} remove: missing name"))?;
                    CrudAction::Remove { name: name.clone() }
                }
                _ => {
                    return Err(format!(
                        "{cmd}: missing action (list|get|add|update|remove)"
                    ));
                }
            };
            Ok(Request::Collection {
                collection: cmd.to_string(),
                action,
            })
        }
        "config-dump" => Ok(Request::ConfigDump),
        "backup" => Ok(Request::Backup),
        "reboot" => {
            // Require --confirm so a typo can't take down the router
            // mid-session. Same safety gate as `reset` and `apply`.
            let confirm = args.iter().any(|a| a == "--confirm");
            if !confirm {
                return Err(
                    "reboot: refusing to reboot without --confirm (this restarts the device)"
                        .to_string(),
                );
            }
            Ok(Request::Reboot { confirm: true })
        }
        "restore" => {
            let path = args.first().ok_or("restore: missing <backup-file>")?;
            let confirm = args.iter().any(|a| a == "--confirm");
            let bytes = std::fs::read(path).map_err(|e| format!("restore: read {path}: {e}"))?;
            use base64::Engine as _;
            let data_b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
            Ok(Request::Restore { data_b64, confirm })
        }
        "config-push" => {
            let path = args.first().ok_or("config-push: missing TOML file path")?;
            let toml = std::fs::read_to_string(path)
                .map_err(|e| format!("config-push: read {path}: {e}"))?;
            Ok(Request::ConfigPush { toml })
        }
        "wg-enroll" => {
            // Positional: name allowed_ips endpoint_host [--dns IP]
            let name = args.first().ok_or("wg-enroll: missing <name>")?.clone();
            let allowed_ips = args
                .get(1)
                .ok_or("wg-enroll: missing <allowed_ips>")?
                .clone();
            let endpoint_host = args
                .get(2)
                .ok_or("wg-enroll: missing <endpoint_host>")?
                .clone();
            // --dns IP is optional; scan remaining args.
            let mut dns = None;
            let mut i = 3;
            while i < args.len() {
                if args[i] == "--dns" {
                    dns = args.get(i + 1).cloned();
                    i += 2;
                } else {
                    return Err(format!("wg-enroll: unknown arg {:?}", args[i]));
                }
            }
            Ok(Request::WgEnroll {
                name,
                allowed_ips,
                endpoint_host,
                dns,
            })
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
/// The reset handler in `oxwrtd::control::server::reset` calls this
/// via `oxwrt_proto::default_config_text`.
pub fn default_config_text(control: &Control) -> String {
    let listen_lines = control
        .listen
        .iter()
        .map(|s| format!("  {:?}", s))
        .collect::<Vec<_>>()
        .join(",\n");
    let authorized_keys = control.authorized_keys.display();
    format!(
        r#"# oxwrt.toml — written by `oxwrtd reset`. Edit freely.
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

/// Human-readable byte formatter for Status output. Scales to
/// KB/MB/GB/TB with 1 decimal; stays in bytes below 1 KiB so tiny
/// counters don't show as "0.0 KB". Kept terse — the Status
/// display has limited width.
fn human_bytes(b: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    if b < 1024 {
        return format!("{b} B");
    }
    let mut v = b as f64;
    let mut u = 0usize;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    format!("{v:.1} {}", UNITS[u])
}

pub fn format_response(resp: &Response) -> String {
    match resp {
        Response::Ok => "ok".to_string(),
        Response::Value { value } => value.clone(),
        Response::Status {
            services,
            supervisor_uptime_secs,
            wan,
            active_wan,
            firewall_rules,
            aps,
            wg,
        } => {
            let mut out = String::new();
            out.push_str(&format!(
                "supervisor uptime: {}s\nfirewall rules:    {}\n",
                supervisor_uptime_secs, firewall_rules
            ));
            match wan {
                Some(w) => {
                    let active = active_wan
                        .as_deref()
                        .map(|n| format!(" [active={n}]"))
                        .unwrap_or_default();
                    out.push_str(&format!(
                        "wan:               {}/{} via {} (lease {}s){}\n",
                        w.address,
                        w.prefix,
                        w.gateway.as_deref().unwrap_or("none"),
                        w.lease_seconds,
                        active,
                    ));
                }
                None => {
                    out.push_str("wan:               (no dhcp lease)\n");
                }
            }
            if !aps.is_empty() {
                out.push_str("access points:\n");
                for ap in aps {
                    // Short format: operstate + iface + band/channel
                    // alongside SSID. Caller can still pull the full
                    // record via `oxctl ... diag links` if needed.
                    out.push_str(&format!(
                        "  {:<16} {:<4} iface={:<10} radio={} {}{}\n",
                        ap.ssid,
                        ap.operstate,
                        ap.iface,
                        ap.radio_phy,
                        ap.band,
                        if ap.channel > 0 {
                            format!(" ch{}", ap.channel)
                        } else {
                            String::new()
                        },
                    ));
                }
            }
            if !wg.is_empty() {
                out.push_str("wireguard:\n");
                for iface in wg {
                    out.push_str(&format!(
                        "  {:<10} :{} ({} peers)\n",
                        iface.iface,
                        iface.listen_port,
                        iface.peers.len()
                    ));
                    for peer in &iface.peers {
                        // Render handshake age as human text. Three
                        // buckets: live (<5 min), stale (<30 days),
                        // never. "never" includes config-only peers
                        // that haven't dialed in yet.
                        let hs = match peer.last_handshake_secs_ago {
                            None => "never".to_string(),
                            Some(s) if s < 300 => format!("{}s ago", s),
                            Some(s) if s < 3600 => format!("{}m ago", s / 60),
                            Some(s) if s < 86400 => format!("{}h ago", s / 3600),
                            Some(s) => format!("{}d ago", s / 86400),
                        };
                        let endpoint = if peer.endpoint.is_empty() {
                            "(none)".to_string()
                        } else {
                            peer.endpoint.clone()
                        };
                        out.push_str(&format!(
                            "    {:<16} hs={:<10} rx={} tx={} ep={}\n",
                            peer.name,
                            hs,
                            human_bytes(peer.rx_bytes),
                            human_bytes(peer.tx_bytes),
                            endpoint
                        ));
                    }
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
                    // Indented last-log line if the server sent one —
                    // makes crash causes visible at a glance instead
                    // of forcing an `oxwrtd logs <service>` follow-up.
                    if let Some(line) = &s.last_log {
                        if !line.is_empty() {
                            out.push_str(&format!("    ↳ {}\n", line.trim_end()));
                        }
                    }
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
    use oxwrt_api::config::{Config, Control};
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

    /// Same `--confirm` gate on `reboot` — accidental reboot mid-
    /// session would drop all WG tunnels + re-trigger WAN DHCP.
    #[test]
    fn reboot_requires_confirm_flag() {
        let err = parse_request("reboot", &[]).unwrap_err();
        assert!(err.contains("--confirm"), "unexpected error: {err}");
        let req = parse_request("reboot", &["--confirm".to_string()]).unwrap();
        match req {
            Request::Reboot { confirm } => assert!(confirm),
            _ => panic!("expected Reboot, got {req:?}"),
        }
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
            &["ping".to_string(), "1.1.1.1".to_string(), "3".to_string()],
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
        let req =
            parse_request("apply", &["--confirm".to_string(), "--clean".to_string()]).unwrap();
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
            Request::Collection {
                action: CrudAction::Add { json },
                ..
            } => {
                assert!(json.contains("test"));
            }
            _ => panic!("expected Collection Add"),
        }

        // get
        let req = parse_request("wifi", &["get".to_string(), "MySSID".to_string()]).unwrap();
        match req {
            Request::Collection {
                collection,
                action: CrudAction::Get { name },
            } => {
                assert_eq!(collection, "wifi");
                assert_eq!(name, "MySSID");
            }
            _ => panic!("expected Collection Get"),
        }

        // update
        let req = parse_request(
            "radio",
            &[
                "update".to_string(),
                "phy0".to_string(),
                r#"{"channel":44}"#.to_string(),
            ],
        )
        .unwrap();
        match req {
            Request::Collection {
                collection,
                action: CrudAction::Update { name, json },
            } => {
                assert_eq!(collection, "radio");
                assert_eq!(name, "phy0");
                assert!(json.contains("44"));
            }
            _ => panic!("expected Collection Update"),
        }

        // remove
        let req = parse_request("zone", &["remove".to_string(), "guest".to_string()]).unwrap();
        match req {
            Request::Collection {
                action: CrudAction::Remove { name },
                ..
            } => {
                assert_eq!(name, "guest");
            }
            _ => panic!("expected Collection Remove"),
        }

        // missing action
        assert!(parse_request("rule", &[]).is_err());
    }
}
