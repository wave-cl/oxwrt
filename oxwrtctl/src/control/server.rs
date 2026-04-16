use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;

use ed25519_dalek::SigningKey;

use crate::container;
use crate::control::{ControlState, FrameError, read_frame, write_frame};
use crate::rpc::{Request, Response, ServiceStatus};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("squic: {0}")]
    Squic(#[from] squic::Error),
    #[error("frame: {0}")]
    Frame(#[from] FrameError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub struct Server {
    pub signing_key: SigningKey,
    pub authorized_keys: Vec<[u8; 32]>,
    pub state: Arc<ControlState>,
}

impl Server {
    pub fn load(
        key_path: &Path,
        authorized_keys_path: &Path,
        state: Arc<ControlState>,
    ) -> Result<Self, Error> {
        let signing_key = load_or_create_signing_key(key_path)?;
        let authorized_keys = load_authorized_keys(authorized_keys_path)?;
        Ok(Self {
            signing_key,
            authorized_keys,
            state,
        })
    }

    pub async fn listen(self: Arc<Self>, addrs: &[SocketAddr]) -> Result<(), Error> {
        let mut joins = Vec::new();
        for addr in addrs {
            let this = self.clone();
            let addr = *addr;
            joins.push(tokio::spawn(async move { this.listen_on(addr).await }));
        }
        for j in joins {
            let _ = j.await;
        }
        Ok(())
    }

    async fn listen_on(self: Arc<Self>, addr: SocketAddr) -> Result<(), Error> {
        let mut config = squic::Config::default();
        if !self.authorized_keys.is_empty() {
            config.allowed_keys = Some(self.authorized_keys.clone());
        }
        let listener = squic::listen(addr, &self.signing_key, config).await?;
        tracing::info!(%addr, "control plane listening");

        loop {
            let incoming = match listener.accept().await {
                Some(i) => i,
                None => break,
            };
            let this = self.clone();
            tokio::spawn(async move {
                if let Err(e) = this.handle_incoming(incoming).await {
                    tracing::warn!(error = %e, "control: connection error");
                }
            });
        }
        Ok(())
    }

    async fn handle_incoming(self: Arc<Self>, incoming: quinn::Incoming) -> Result<(), Error> {
        let conn = incoming.await.map_err(|e| Error::Squic(squic::Error::from(e)))?;
        loop {
            let (mut send, mut recv) = match conn.accept_bi().await {
                Ok(s) => s,
                Err(quinn::ConnectionError::ApplicationClosed(_))
                | Err(quinn::ConnectionError::ConnectionClosed(_)) => return Ok(()),
                Err(e) => return Err(Error::Squic(squic::Error::from(e))),
            };
            let request: Request = read_frame(&mut recv).await?;

            // Streaming logs take a different path — they hold the bi
            // stream open and push LogLine frames as the logd broadcast
            // channel produces them, until the client closes or the
            // connection drops.
            if let Request::Logs {
                service,
                follow: true,
            } = &request
            {
                stream_follow_logs(&self.state, &mut send, service).await?;
                send.finish().ok();
                continue;
            }

            // Diag also takes an async detour because the in-process
            // implementations call rtnetlink (and eventually
            // rustables / hickory-resolver), which all need a tokio
            // runtime context. The sync `handle()` dispatcher can't
            // call them. The detour returns a single Value response.
            if let Request::Diag { name, args } = &request {
                let resp = handle_diag(&self.state, name, args).await;
                write_frame(&mut send, &resp).await?;
                send.finish().ok();
                continue;
            }

            // Reload takes the async detour too — the network-state
            // reconciliation calls rtnetlink, which needs a tokio
            // runtime context. The sync `handle()` dispatcher can't.
            if let Request::Reload = &request {
                let resp = handle_reload_async(&self.state).await;
                write_frame(&mut send, &resp).await?;
                send.finish().ok();
                continue;
            }

            // Reset delegates to Reload at the tail, so it's also async.
            if let Request::Reset { confirm } = &request {
                let resp = handle_reset(&self.state, *confirm).await;
                write_frame(&mut send, &resp).await?;
                send.finish().ok();
                continue;
            }

            // Firmware update: streaming upload on the same bi-stream.
            // The client sends the metadata frame (already read above),
            // then streams raw image bytes. We read, hash, and stage.
            if let Request::FwUpdate { size, sha256 } = &request {
                let resp = handle_fw_update(&mut send, &mut recv, *size, sha256).await;
                write_frame(&mut send, &resp).await?;
                send.finish().ok();
                continue;
            }

            // Firmware apply: trigger sysupgrade + reboot.
            if let Request::FwApply { confirm, keep_settings } = &request {
                let resp = handle_fw_apply(*confirm, *keep_settings);
                write_frame(&mut send, &resp).await?;
                send.finish().ok();
                // If apply succeeded, the router is about to reboot.
                // The connection will drop — that's expected.
                continue;
            }

            let responses = handle(&self.state, request);
            for response in &responses {
                write_frame(&mut send, response).await?;
            }
            send.finish().ok();
        }
    }
}

async fn stream_follow_logs(
    state: &ControlState,
    send: &mut quinn::SendStream,
    service: &str,
) -> Result<(), Error> {
    // First replay the last-N buffered lines so the client sees recent
    // context, then subscribe to the live channel for anything new.
    for entry in state.logd.tail(service, LOG_TAIL_LIMIT) {
        let resp = Response::LogLine { line: entry.line };
        write_frame(send, &resp).await?;
    }
    let mut subscription = state.logd.subscribe();
    loop {
        match subscription.recv().await {
            Ok(entry) if entry.service == service => {
                let resp = Response::LogLine { line: entry.line };
                if write_frame(send, &resp).await.is_err() {
                    break;
                }
            }
            Ok(_) => continue,
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                // Client fell behind; send a marker and keep going.
                let resp = Response::LogLine {
                    line: "[…lagged, some lines dropped…]".to_string(),
                };
                if write_frame(send, &resp).await.is_err() {
                    break;
                }
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
        }
    }
    Ok(())
}

fn handle(state: &ControlState, request: Request) -> Vec<Response> {
    match request {
        Request::Get { key } => vec![handle_get(state, &key)],
        Request::Set { key, value } => vec![handle_set(state, &key, &value)],
        Request::Reload => vec![Response::Err {
            // Caught upstream in handle_incoming via the async detour;
            // reaching this arm is a routing bug.
            message: "BUG: Reload should be handled async upstream".to_string(),
        }],
        Request::Status => {
            let services = collect_status(state);
            let supervisor_uptime_secs = state.boot_time.elapsed().as_secs();
            let wan = state.wan_lease.read().unwrap().as_ref().map(|l| {
                crate::rpc::WanSummary {
                    address: l.address.to_string(),
                    prefix: l.prefix,
                    gateway: l.gateway.map(|g| g.to_string()),
                    lease_seconds: l.lease_seconds,
                }
            });
            let firewall_rules = state.firewall_dump.read().unwrap().len();
            vec![Response::Status {
                services,
                supervisor_uptime_secs,
                wan,
                firewall_rules,
            }]
        }
        Request::Logs { service, follow } => handle_logs(state, &service, follow),
        Request::Restart { service } => vec![handle_restart(state, &service)],
        Request::Reset { .. } => vec![Response::Err {
            // Caught upstream in handle_incoming via the async detour;
            // reaching this arm is a routing bug.
            message: "BUG: Reset should be handled async upstream".to_string(),
        }],
        Request::Diag { .. } => vec![Response::Err {
            message: "BUG: Diag should be handled async upstream".to_string(),
        }],
        Request::FwUpdate { .. } => vec![Response::Err {
            message: "BUG: FwUpdate should be handled async upstream".to_string(),
        }],
        Request::FwApply { .. } => vec![Response::Err {
            message: "BUG: FwApply should be handled async upstream".to_string(),
        }],
    }
}

fn handle_set(state: &ControlState, key: &str, value: &str) -> Response {
    use crate::config::{self, Wan};
    use std::net::Ipv4Addr;
    use std::path::Path;

    // Phase 1: validate the value parses into the right type and clone
    // the in-memory Config with the mutation applied. Any parse error
    // here rejects the request before we touch the disk.
    let cfg_arc = state.config_snapshot();
    let mut new_cfg = (*cfg_arc).clone();

    match key {
        "hostname" => {
            if value.is_empty() {
                return Response::Err {
                    message: "hostname must not be empty".to_string(),
                };
            }
            new_cfg.hostname = value.to_string();
        }
        "timezone" => {
            new_cfg.timezone = if value.is_empty() {
                None
            } else {
                Some(value.to_string())
            };
        }
        "lan.address" => match value.parse::<Ipv4Addr>() {
            Ok(a) => new_cfg.lan.address = a,
            Err(e) => {
                return Response::Err {
                    message: format!("invalid ipv4 address: {e}"),
                };
            }
        },
        "lan.prefix" => match value.parse::<u8>() {
            Ok(p) if p <= 32 => new_cfg.lan.prefix = p,
            _ => {
                return Response::Err {
                    message: "lan.prefix must be 0..=32".to_string(),
                };
            }
        },
        "lan.bridge" => {
            if value.is_empty() || value.len() >= 16 {
                return Response::Err {
                    message: "lan.bridge must be 1..15 chars".to_string(),
                };
            }
            new_cfg.lan.bridge = value.to_string();
        }
        "wan.mode" => {
            // Switching WAN mode replaces the entire Wan variant.
            // The iface is carried over from the current config.
            let iface = match &new_cfg.wan {
                Wan::Dhcp { iface }
                | Wan::Static { iface, .. }
                | Wan::Pppoe { iface, .. } => iface.clone(),
            };
            match value {
                "dhcp" => {
                    new_cfg.wan = Wan::Dhcp { iface };
                }
                "static" => {
                    // Default to a placeholder address — operator must
                    // follow up with `set wan.address/prefix/gateway`
                    // before `reload` to get a working static config.
                    new_cfg.wan = Wan::Static {
                        iface,
                        address: Ipv4Addr::new(0, 0, 0, 0),
                        prefix: 24,
                        gateway: Ipv4Addr::new(0, 0, 0, 0),
                        dns: vec![],
                    };
                }
                "pppoe" => {
                    new_cfg.wan = Wan::Pppoe {
                        iface,
                        username: String::new(),
                        password: String::new(),
                    };
                }
                _ => {
                    return Response::Err {
                        message: format!(
                            "unknown wan.mode: {value:?}. Valid: dhcp, static, pppoe"
                        ),
                    };
                }
            }
        }
        "wan.iface" => match &mut new_cfg.wan {
            Wan::Dhcp { iface } | Wan::Static { iface, .. } | Wan::Pppoe { iface, .. } => {
                *iface = value.to_string();
            }
        },
        "wan.address" => match (value.parse::<Ipv4Addr>(), &mut new_cfg.wan) {
            (Ok(a), Wan::Static { address, .. }) => {
                *address = a;
            }
            (Ok(_), _) => {
                return Response::Err {
                    message: "wan.address only valid when wan.mode = \"static\"".to_string(),
                };
            }
            (Err(e), _) => {
                return Response::Err {
                    message: format!("invalid ipv4 address: {e}"),
                };
            }
        },
        "wan.prefix" => match (value.parse::<u8>(), &mut new_cfg.wan) {
            (Ok(p), Wan::Static { prefix, .. }) if p <= 32 => {
                *prefix = p;
            }
            (Ok(_), Wan::Static { .. }) => {
                return Response::Err {
                    message: "wan.prefix must be 0..=32".to_string(),
                };
            }
            (Ok(_), _) => {
                return Response::Err {
                    message: "wan.prefix only valid when wan.mode = \"static\"".to_string(),
                };
            }
            (Err(_), _) => {
                return Response::Err {
                    message: "wan.prefix must be 0..=32".to_string(),
                };
            }
        },
        "wan.gateway" => match (value.parse::<Ipv4Addr>(), &mut new_cfg.wan) {
            (Ok(a), Wan::Static { gateway, .. }) => {
                *gateway = a;
            }
            (Ok(_), _) => {
                return Response::Err {
                    message: "wan.gateway only valid when wan.mode = \"static\"".to_string(),
                };
            }
            (Err(e), _) => {
                return Response::Err {
                    message: format!("invalid ipv4 address: {e}"),
                };
            }
        },
        "wan.username" => match &mut new_cfg.wan {
            Wan::Pppoe { username, .. } => *username = value.to_string(),
            _ => {
                return Response::Err {
                    message: "wan.username only valid when wan.mode = \"pppoe\"".to_string(),
                };
            }
        },
        "wan.password" => match &mut new_cfg.wan {
            Wan::Pppoe { password, .. } => *password = value.to_string(),
            _ => {
                return Response::Err {
                    message: "wan.password only valid when wan.mode = \"pppoe\"".to_string(),
                };
            }
        },
        "wan.dns" => {
            // Comma-separated list of IP addresses, e.g. "1.1.1.1,9.9.9.9".
            // Only valid in static mode (DHCP mode gets DNS from the lease).
            let Wan::Static { dns, .. } = &mut new_cfg.wan else {
                return Response::Err {
                    message: "wan.dns only valid when wan.mode = \"static\"".to_string(),
                };
            };
            let mut addrs = Vec::new();
            for part in value.split(',') {
                let trimmed = part.trim();
                if trimmed.is_empty() {
                    continue;
                }
                match trimmed.parse::<std::net::IpAddr>() {
                    Ok(a) => addrs.push(a),
                    Err(e) => {
                        return Response::Err {
                            message: format!("invalid IP address {trimmed:?}: {e}"),
                        };
                    }
                }
            }
            *dns = addrs;
        }
        "lan.allow_wan" => match value {
            "true" | "1" | "yes" => new_cfg.lan.allow_wan = true,
            "false" | "0" | "no" => new_cfg.lan.allow_wan = false,
            _ => {
                return Response::Err {
                    message: "lan.allow_wan must be true/false".to_string(),
                };
            }
        },
        _ => {
            return Response::Err {
                message: format!(
                    "key '{key}' is not writable. Writable keys: \
                     hostname, timezone, lan.bridge, lan.address, \
                     lan.prefix, lan.allow_wan, wan.mode, wan.iface, \
                     wan.address, wan.prefix, wan.gateway, wan.dns"
                ),
            };
        }
    }

    // Phase 2: surgically patch the on-disk TOML via `toml_edit` so we
    // preserve the operator's comments and formatting. This is more
    // work than `toml::to_string(&new_cfg)` but it's the right thing
    // for a file that humans edit by hand.
    let path = Path::new(config::DEFAULT_PATH);
    let original = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            return Response::Err {
                message: format!("read {path:?}: {e}"),
            };
        }
    };
    let mut doc = match original.parse::<toml_edit::DocumentMut>() {
        Ok(d) => d,
        Err(e) => {
            return Response::Err {
                message: format!("parse {path:?}: {e}"),
            };
        }
    };
    if let Err(msg) = apply_set_to_toml(&mut doc, key, value) {
        return Response::Err { message: msg };
    }

    // Phase 3: atomic write tmp + rename. Write-failure leaves the
    // original file intact; rename-failure cleans up the tmp file.
    let tmp_path = match path.parent() {
        Some(parent) => parent.join(".oxwrt.toml.tmp"),
        None => {
            return Response::Err {
                message: format!("config path has no parent: {path:?}"),
            };
        }
    };
    if let Err(e) = std::fs::write(&tmp_path, doc.to_string()) {
        return Response::Err {
            message: format!("write {tmp_path:?}: {e}"),
        };
    }
    if let Err(e) = std::fs::rename(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Response::Err {
            message: format!("rename: {e}"),
        };
    }

    // Phase 4: publish the new in-memory config so subsequent Get/Status
    // see the update. Services are NOT restarted — operator follows up
    // with Reload to apply.
    {
        let Ok(mut cfg_lock) = state.config.write() else {
            return Response::Err {
                message: "config lock poisoned".to_string(),
            };
        };
        *cfg_lock = std::sync::Arc::new(new_cfg);
    }

    tracing::info!(key, value, "config key updated (pending reload)");
    Response::Value {
        value: format!("{key} = {value} (persisted; run `reload` to apply)"),
    }
}

/// Navigate the `toml_edit` document to the right field and replace its
/// value, preserving comments and formatting. Returns a human-readable
/// error message on unknown keys or unexpected document shapes.
fn apply_set_to_toml(doc: &mut toml_edit::DocumentMut, key: &str, value: &str) -> Result<(), String> {
    use toml_edit::{Item, value as tv};

    match key {
        "hostname" => {
            doc["hostname"] = tv(value);
        }
        "timezone" => {
            if value.is_empty() {
                // Removing rather than writing an empty string, so the
                // field stays `Option<String> = None` after reload.
                if let Some(tbl) = doc.as_table_mut().get_mut("timezone") {
                    *tbl = Item::None;
                }
            } else {
                doc["timezone"] = tv(value);
            }
        }
        "lan.bridge" => {
            let lan = doc
                .get_mut("lan")
                .and_then(|i| i.as_table_mut())
                .ok_or_else(|| "on-disk config has no [lan] table".to_string())?;
            lan["bridge"] = tv(value);
        }
        "lan.address" => {
            let lan = doc
                .get_mut("lan")
                .and_then(|i| i.as_table_mut())
                .ok_or_else(|| "on-disk config has no [lan] table".to_string())?;
            lan["address"] = tv(value);
        }
        "lan.prefix" => {
            // Already validated as 0..=32 above, safe to unwrap.
            let n: i64 = value.parse::<u8>().unwrap() as i64;
            let lan = doc
                .get_mut("lan")
                .and_then(|i| i.as_table_mut())
                .ok_or_else(|| "on-disk config has no [lan] table".to_string())?;
            lan["prefix"] = tv(n);
        }
        "wan.mode" => {
            let wan = doc
                .get_mut("wan")
                .and_then(|i| i.as_table_mut())
                .ok_or_else(|| "on-disk config has no [wan] table".to_string())?;
            // Preserve iface, rewrite the rest of the table for the new mode.
            let iface = wan
                .get("iface")
                .and_then(|v| v.as_str())
                .unwrap_or("eth0")
                .to_string();
            wan.clear();
            wan.insert("mode", tv(value));
            wan.insert("iface", tv(&iface));
            match value {
                "static" => {
                    wan.insert("address", tv("0.0.0.0"));
                    wan.insert("prefix", tv(24i64));
                    wan.insert("gateway", tv("0.0.0.0"));
                    let arr = toml_edit::Array::new();
                    wan.insert("dns", Item::Value(toml_edit::Value::Array(arr)));
                }
                "pppoe" => {
                    wan.insert("username", tv(""));
                    wan.insert("password", tv(""));
                }
                _ => {} // dhcp — mode + iface is sufficient
            }
        }
        "wan.iface" => {
            let wan = doc
                .get_mut("wan")
                .and_then(|i| i.as_table_mut())
                .ok_or_else(|| "on-disk config has no [wan] table".to_string())?;
            wan["iface"] = tv(value);
        }
        "wan.address" | "wan.gateway" => {
            let wan = doc
                .get_mut("wan")
                .and_then(|i| i.as_table_mut())
                .ok_or_else(|| "on-disk config has no [wan] table".to_string())?;
            let field = key.strip_prefix("wan.").unwrap();
            wan[field] = tv(value);
        }
        "wan.prefix" => {
            // Already validated as 0..=32 above, safe to unwrap.
            let n: i64 = value.parse::<u8>().unwrap() as i64;
            let wan = doc
                .get_mut("wan")
                .and_then(|i| i.as_table_mut())
                .ok_or_else(|| "on-disk config has no [wan] table".to_string())?;
            wan["prefix"] = tv(n);
        }
        "wan.username" | "wan.password" => {
            let wan = doc
                .get_mut("wan")
                .and_then(|i| i.as_table_mut())
                .ok_or_else(|| "on-disk config has no [wan] table".to_string())?;
            let field = key.strip_prefix("wan.").unwrap();
            wan[field] = tv(value);
        }
        "wan.dns" => {
            let wan = doc
                .get_mut("wan")
                .and_then(|i| i.as_table_mut())
                .ok_or_else(|| "on-disk config has no [wan] table".to_string())?;
            let mut arr = toml_edit::Array::new();
            for part in value.split(',') {
                let trimmed = part.trim();
                if !trimmed.is_empty() {
                    arr.push(trimmed);
                }
            }
            wan["dns"] = Item::Value(toml_edit::Value::Array(arr));
        }
        "lan.allow_wan" => {
            let lan = doc
                .get_mut("lan")
                .and_then(|i| i.as_table_mut())
                .ok_or_else(|| "on-disk config has no [lan] table".to_string())?;
            let b = matches!(value, "true" | "1" | "yes");
            lan["allow_wan"] = tv(b);
        }
        _ => return Err(format!("BUG: unexpected key in apply_set_to_toml: {key}")),
    }
    Ok(())
}

/// Factory reset: overwrite `/etc/oxwrt.toml` with a stock minimal
/// config, preserving the operator's `[control]` block (listen addrs +
/// authorized keys path) so the management plane stays reachable. Then
/// runs the normal reload path so the supervisor sees the new (empty)
/// service list and the in-memory config is republished.
///
/// `confirm == false` is rejected with an error — the wire-level
/// invariant matches the CLI's `--confirm` requirement, so a buggy
/// custom client can't accidentally wipe the operator's config either.
async fn handle_reset(state: &ControlState, confirm: bool) -> Response {
    use crate::config;
    use std::path::Path;

    if !confirm {
        return Response::Err {
            message: "reset: refusing to reset without confirm=true".to_string(),
        };
    }

    // Snapshot the current control block so it survives the reset.
    // Without this the new config would have empty `listen` and the
    // operator would lose the management path the moment the reload
    // tears down the old listener.
    let cfg_arc = state.config_snapshot();
    let preserved_control = cfg_arc.control.clone();
    let default_text = crate::control::default_config_text(&preserved_control);

    // Sanity: the text we just generated must round-trip into a Config
    // before we touch the disk. If this fails it's a bug in
    // `default_config_text` — better to catch it here than to leave the
    // operator with an unparseable file on disk.
    if let Err(e) = toml::from_str::<config::Config>(&default_text) {
        tracing::error!(error = %e, "BUG: default_config_text produced invalid TOML");
        return Response::Err {
            message: format!("reset: refusing to write invalid default config: {e}"),
        };
    }

    // Atomic write: tmp + rename. Same pattern as handle_set.
    let path = Path::new(config::DEFAULT_PATH);
    let tmp_path = match path.parent() {
        Some(parent) => parent.join(".oxwrt.toml.tmp"),
        None => {
            return Response::Err {
                message: format!("reset: config path has no parent: {path:?}"),
            };
        }
    };
    if let Err(e) = std::fs::write(&tmp_path, &default_text) {
        return Response::Err {
            message: format!("reset: write {tmp_path:?}: {e}"),
        };
    }
    if let Err(e) = std::fs::rename(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Response::Err {
            message: format!("reset: rename: {e}"),
        };
    }

    tracing::warn!(path = %path.display(), "factory reset: config wiped to defaults");

    // Reuse the existing reload path — it re-reads from disk, reconciles
    // network state, reinstalls the firewall, swaps the supervisor, and
    // republishes the in-memory config snapshot. If reload fails, the
    // on-disk default config is still in place and a future Reload will
    // pick it up; we report the underlying error.
    handle_reload_async(state).await
}

/// In-process diagnostic dispatcher. Each op opens its own short-lived
/// rtnetlink connection (cheap; the operator hits this rarely), runs
/// the dump, formats it as human-readable text, and returns a single
/// Value response. No subprocesses, no shell, no extra binaries — the
/// appliance model survives.
async fn handle_diag(state: &ControlState, name: &str, args: &[String]) -> Response {
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
        other => Response::Err {
            message: format!(
                "diag: unknown op {other:?} (supported: links, routes, addresses, firewall, dhcp, \
                 ping, traceroute, dig)"
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
        expose: Vec::new(),
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

/// Async reload handler. Five-phase pipeline:
///
/// 1. **Parse** the on-disk config. Bad TOML → error, nothing changes.
/// 2. **Reconcile netlink address state** for any `lan.address` or
///    `lan.prefix` change. Uses a short-lived rtnetlink connection to
///    delete the old IPv4 address from the bridge interface and add
///    the new one. Bridge name changes, WAN mode changes, and
///    veth/DNAT reconciliation are still deferred — they're far
///    rarer than an IP change and require significantly more
///    bookkeeping. Reconcile failure returns an error; the config +
///    firewall are NOT updated, so the operator can correct and
///    retry.
/// 3. **Reinstall the firewall**. `rustables` sends the Add/Del/Add
///    batch atomically, so either the old ruleset stays in place or
///    the new one fully replaces it.
/// 4. **Rebuild the supervisor** from the new service list.
/// 5. **Publish** the new config, firewall dump, and (implicitly)
///    supervisor atomically.
/// Exposed for use by the SIGHUP handler in `init.rs` — reloads the
/// config from disk, reconciles network state, reinstalls the firewall,
/// and rebuilds the supervisor, exactly as the sQUIC `Reload` RPC does.
pub async fn handle_reload_async(state: &ControlState) -> Response {
    use crate::config::Config;
    use crate::container::Supervisor;
    use std::path::Path;

    // Phase 1: parse.
    let path = Path::new(crate::config::DEFAULT_PATH);
    let new_cfg = match Config::load(path) {
        Ok(c) => c,
        Err(e) => {
            return Response::Err {
                message: format!("reload: {e}"),
            };
        }
    };

    // Phase 2: reconcile netlink address state. We compare against the
    // KERNEL's current state, not the in-memory `state.config` —
    // because `Set` already updated the in-memory config and any two
    // snapshots of it are guaranteed equal at this point. The kernel
    // is the source of truth for "what's actually on the bridge."
    //
    // Bridge rename is still refused — creating the new bridge and
    // moving ports is substantially more work than an address swap.
    let old_cfg = state.config_snapshot();
    if old_cfg.lan.bridge != new_cfg.lan.bridge {
        return Response::Err {
            message: format!(
                "reload: lan.bridge changed from {:?} to {:?}; bridge rename is not \
                 supported over reload, reboot required",
                old_cfg.lan.bridge, new_cfg.lan.bridge
            ),
        };
    }
    if let Err(e) = reconcile_iface_address(
        &new_cfg.lan.bridge,
        new_cfg.lan.address,
        new_cfg.lan.prefix,
        "lan",
    )
    .await
    {
        return Response::Err {
            message: format!("reload: lan address reconcile failed: {e}"),
        };
    }

    // WAN static mode: same reconcile against the WAN iface. DHCP mode
    // is handled by the renewal loop (which runs DISCOVER → REQUEST →
    // ACK and applies the lease independently of reload). Pppoe has
    // its own setup path and isn't reconciled here.
    if let crate::config::Wan::Static {
        iface,
        address,
        prefix,
        ..
    } = &new_cfg.wan
    {
        if let Err(e) =
            reconcile_iface_address(iface, *address, *prefix, "wan").await
        {
            return Response::Err {
                message: format!("reload: wan static address reconcile failed: {e}"),
            };
        }
    }

    // Hostname change: apply via sethostname(2) so the live kernel
    // agrees with the new config. No-op if the hostname didn't change
    // (sethostname is idempotent and cheap). Failure is logged but not
    // fatal — a hostname mismatch is a UX quirk, not a router outage.
    if let Err(e) = rustix::system::sethostname(new_cfg.hostname.as_bytes()) {
        tracing::warn!(
            error = %e,
            hostname = %new_cfg.hostname,
            "reload: sethostname failed"
        );
    }

    // Phase 3: reinstall firewall.
    if let Err(e) = crate::net::install_firewall(&new_cfg) {
        return Response::Err {
            message: format!("reload: firewall install failed: {e}"),
        };
    }
    let new_firewall_dump = crate::net::format_firewall_dump(&new_cfg);

    // Phase 4: rebuild supervisor.
    {
        let Ok(mut sup) = state.supervisor.lock() else {
            return Response::Err {
                message: "reload: supervisor mutex poisoned".to_string(),
            };
        };
        sup.shutdown();
        *sup = Supervisor::from_config(&new_cfg.services);
    }

    // Phase 5: publish new state.
    {
        let Ok(mut cfg) = state.config.write() else {
            return Response::Err {
                message: "reload: config lock poisoned".to_string(),
            };
        };
        *cfg = std::sync::Arc::new(new_cfg);
    }
    {
        let Ok(mut dump) = state.firewall_dump.write() else {
            return Response::Err {
                message: "reload: firewall_dump lock poisoned".to_string(),
            };
        };
        *dump = new_firewall_dump;
    }

    tracing::info!("config reloaded, firewall reinstalled, supervisor rebuilt");
    Response::Ok
}

/// Bring the IPv4 addresses on `iface` into agreement with
/// `new_ip/new_prefix`. Compares the KERNEL's current state (not any
/// in-memory Config) because `Set` already updated the config before
/// `reload` ran — the kernel is the only source of truth for "what's
/// actually on the iface right now." Used for both the LAN bridge and
/// the WAN iface (in static mode); previously this was LAN-specific.
///
/// Algorithm:
/// 1. Dump all IPv4 addresses on `iface`.
/// 2. If the desired `new_ip/new_prefix` is already there, done.
/// 3. Otherwise, delete every other IPv4 address on the iface (we
///    assume the supervisor owns the addressing — there's no expected
///    "extra" IP an operator would have added out of band, since the
///    appliance has no shell).
/// 4. Add the new address.
///
/// Tolerates ENOENT / File exists on individual operations — the
/// kernel state may have shifted slightly between our get and our
/// del/add, which is fine as long as the final state is what we
/// wanted.
async fn reconcile_iface_address(
    iface: &str,
    new_ip: std::net::Ipv4Addr,
    new_prefix: u8,
    role: &str, // "lan" or "wan", for log tagging
) -> Result<(), String> {
    use futures_util::stream::TryStreamExt;
    use rtnetlink::packet_route::{address::AddressAttribute, AddressFamily};

    let (connection, handle, _messages) =
        rtnetlink::new_connection().map_err(|e| e.to_string())?;
    let conn_task = tokio::spawn(connection);

    // Resolve iface → index.
    let idx = {
        let mut stream = handle
            .link()
            .get()
            .match_name(iface.to_string())
            .execute();
        let msg = stream
            .try_next()
            .await
            .map_err(|e| format!("link get {iface}: {e}"))?
            .ok_or_else(|| format!("link {iface} not found"))?;
        msg.header.index
    };

    // Dump IPv4 addresses on the iface. Collect (is_desired, msg) so
    // we can act on them after the stream closes (calling another
    // rtnetlink op while a dump stream is open would deadlock the
    // handle).
    let mut desired_present = false;
    let mut to_delete: Vec<rtnetlink::packet_route::address::AddressMessage> = Vec::new();
    let mut addrs = handle.address().get().execute();
    while let Some(msg) = addrs
        .try_next()
        .await
        .map_err(|e| format!("address get: {e}"))?
    {
        if msg.header.index != idx {
            continue;
        }
        if msg.header.family != AddressFamily::Inet {
            continue;
        }
        let mut this_ip: Option<std::net::Ipv4Addr> = None;
        for attr in &msg.attributes {
            if let AddressAttribute::Address(std::net::IpAddr::V4(a)) = attr {
                this_ip = Some(*a);
                break;
            }
        }
        let Some(ip) = this_ip else {
            continue;
        };
        if ip == new_ip && msg.header.prefix_len == new_prefix {
            desired_present = true;
        } else {
            to_delete.push(msg);
        }
    }

    for msg in to_delete {
        let ip_str = format_v4_from_attrs(&msg.attributes);
        let prefix = msg.header.prefix_len;
        if let Err(e) = handle.address().del(msg).execute().await {
            conn_task.abort();
            return Err(format!("del {ip_str}/{prefix}: {e}"));
        }
        tracing::info!(
            role,
            iface,
            deleted = %ip_str,
            prefix,
            "reconcile: removed stale address"
        );
    }

    if !desired_present {
        match handle
            .address()
            .add(idx, std::net::IpAddr::V4(new_ip), new_prefix)
            .execute()
            .await
        {
            Ok(()) => {
                tracing::info!(role, iface, %new_ip, new_prefix, "reconcile: added address");
            }
            Err(e) => {
                let msg = e.to_string();
                if !msg.contains("File exists") {
                    conn_task.abort();
                    return Err(format!("add {new_ip}/{new_prefix}: {e}"));
                }
                // Race: something added it between our dump and our add.
                // Treat as success.
            }
        }
    }

    conn_task.abort();
    Ok(())
}

fn format_v4_from_attrs(
    attrs: &[rtnetlink::packet_route::address::AddressAttribute],
) -> String {
    use rtnetlink::packet_route::address::AddressAttribute;
    for attr in attrs {
        if let AddressAttribute::Address(std::net::IpAddr::V4(a)) = attr {
            return a.to_string();
        }
    }
    "?".to_string()
}

const LOG_TAIL_LIMIT: usize = 200;

fn handle_logs(state: &ControlState, service: &str, follow: bool) -> Vec<Response> {
    // `follow = true` is special-cased upstream in `handle_incoming` so the
    // bi stream can stay open. This path only services non-follow logs.
    let _ = follow;
    let mut out: Vec<Response> = state
        .logd
        .tail(service, LOG_TAIL_LIMIT)
        .into_iter()
        .map(|l| Response::LogLine { line: l.line })
        .collect();
    out.push(Response::Ok);
    out
}

// ── Firmware update ──────────────────────────────────────────────────

/// Staging path for the uploaded firmware image. Lives on tmpfs so it
/// survives the write but not a reboot (which is fine — we apply it
/// immediately after staging, or the operator re-uploads next boot).
const FW_STAGING_PATH: &str = "/tmp/fw_update.bin";
const FW_STAGING_TMP: &str = "/tmp/fw_update.bin.tmp";
/// Max firmware image size: 64 MiB. Sane upper bound for an OpenWrt
/// sysupgrade image (typical: 10-30 MiB). Rejects obviously-wrong sizes
/// before any I/O.
const FW_MAX_SIZE: u64 = 64 * 1024 * 1024;
/// Chunk size for reading the raw byte stream. 64 KiB balances syscall
/// overhead against memory usage.
const FW_CHUNK_SIZE: usize = 64 * 1024;
/// Send a progress frame every N bytes received.
const FW_PROGRESS_INTERVAL: u64 = 1024 * 1024; // 1 MiB

/// Receive a firmware image over the sQUIC bi-stream, hash it, stage it.
///
/// Protocol: the client has already sent the `FwUpdate { size, sha256 }`
/// metadata frame (already read by the dispatch loop). Next, the client
/// writes `size` raw bytes directly on the same stream (no framing),
/// then calls `send.finish()`. We read, hash with SHA-256, write to a
/// temp file, verify the hash, and rename to the staging path.
///
/// Progress frames (`FwProgress { bytes_received }`) are sent back on
/// the send side periodically so the client can display a progress bar.
async fn handle_fw_update(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    size: u64,
    expected_sha256: &str,
) -> Response {
    use sha2::{Sha256, Digest};

    if size == 0 || size > FW_MAX_SIZE {
        return Response::Err {
            message: format!(
                "fw_update: size {size} out of range (1..{FW_MAX_SIZE})"
            ),
        };
    }

    // Validate the expected hash is a valid hex string.
    if expected_sha256.len() != 64
        || !expected_sha256.chars().all(|c| c.is_ascii_hexdigit())
    {
        return Response::Err {
            message: "fw_update: sha256 must be 64 hex chars".to_string(),
        };
    }

    // Open temp file for writing.
    let mut file = match tokio::fs::File::create(FW_STAGING_TMP).await {
        Ok(f) => f,
        Err(e) => {
            return Response::Err {
                message: format!("fw_update: create staging tmp: {e}"),
            };
        }
    };

    let mut hasher = Sha256::new();
    let mut received: u64 = 0;
    let mut buf = vec![0u8; FW_CHUNK_SIZE];
    let mut last_progress: u64 = 0;

    // Read raw bytes from the stream (no framing).
    while received < size {
        let want = std::cmp::min(FW_CHUNK_SIZE as u64, size - received) as usize;
        let n = match recv.read(&mut buf[..want]).await {
            Ok(Some(n)) if n > 0 => n,
            Ok(_) => {
                // Stream closed before we got all bytes.
                let _ = tokio::fs::remove_file(FW_STAGING_TMP).await;
                return Response::Err {
                    message: format!(
                        "fw_update: stream closed after {received}/{size} bytes"
                    ),
                };
            }
            Err(e) => {
                let _ = tokio::fs::remove_file(FW_STAGING_TMP).await;
                return Response::Err {
                    message: format!("fw_update: read error: {e}"),
                };
            }
        };

        hasher.update(&buf[..n]);
        if let Err(e) = tokio::io::AsyncWriteExt::write_all(&mut file, &buf[..n]).await {
            let _ = tokio::fs::remove_file(FW_STAGING_TMP).await;
            return Response::Err {
                message: format!("fw_update: write error: {e}"),
            };
        }

        received += n as u64;

        // Send progress every FW_PROGRESS_INTERVAL bytes.
        if received - last_progress >= FW_PROGRESS_INTERVAL || received == size {
            let progress = Response::FwProgress {
                bytes_received: received,
            };
            // Best-effort: if the progress frame fails to send, continue
            // — the upload itself is more important than the progress bar.
            let _ = write_frame(send, &progress).await;
            last_progress = received;
        }
    }

    // Flush and close the file.
    if let Err(e) = tokio::io::AsyncWriteExt::flush(&mut file).await {
        let _ = tokio::fs::remove_file(FW_STAGING_TMP).await;
        return Response::Err {
            message: format!("fw_update: flush: {e}"),
        };
    }
    drop(file);

    // Verify the hash.
    let computed = hex::encode(hasher.finalize());
    if computed != expected_sha256 {
        let _ = tokio::fs::remove_file(FW_STAGING_TMP).await;
        return Response::Err {
            message: format!(
                "fw_update: SHA-256 mismatch: expected {expected_sha256}, got {computed}"
            ),
        };
    }

    // Atomic rename to the staging path.
    if let Err(e) = tokio::fs::rename(FW_STAGING_TMP, FW_STAGING_PATH).await {
        let _ = tokio::fs::remove_file(FW_STAGING_TMP).await;
        return Response::Err {
            message: format!("fw_update: rename to staging: {e}"),
        };
    }

    tracing::info!(
        size,
        sha256 = %expected_sha256,
        "firmware image staged at {FW_STAGING_PATH}"
    );
    Response::Ok
}

/// Apply the staged firmware image. Triggers `sysupgrade -n` (or the
/// platform-appropriate flash command) and reboots. The sQUIC
/// connection drops on reboot — the client detects this as success.
///
/// `confirm` must be true (same safety gate as Reset). Rejects if no
/// staged image exists.
fn handle_fw_apply(confirm: bool, keep_settings: bool) -> Response {
    if !confirm {
        return Response::Err {
            message: "fw_apply: pass --confirm to proceed".to_string(),
        };
    }

    let meta = match std::fs::metadata(FW_STAGING_PATH) {
        Ok(m) => m,
        Err(e) => {
            return Response::Err {
                message: format!(
                    "fw_apply: no staged image at {FW_STAGING_PATH}: {e}"
                ),
            };
        }
    };

    tracing::warn!(
        size = meta.len(),
        keep_settings,
        "fw_apply: applying firmware and rebooting"
    );

    // sysupgrade flags:
    //   (no -n) = keep /etc/sysupgrade.conf files (default: keep settings)
    //   -n      = do NOT keep settings (clean flash)
    let mut args = Vec::new();
    if !keep_settings {
        args.push("-n");
    }
    args.push(FW_STAGING_PATH);

    match std::process::Command::new("sysupgrade")
        .args(&args)
        .spawn()
    {
        Ok(_) => Response::Ok,
        Err(e) => Response::Err {
            message: format!("fw_apply: sysupgrade spawn: {e}"),
        },
    }
}

fn handle_get(state: &ControlState, key: &str) -> Response {
    use crate::config::Wan;
    let cfg = state.config_snapshot();
    let value = match key {
        "hostname" => Some(cfg.hostname.clone()),
        "timezone" => cfg.timezone.clone(),
        "lan.bridge" => Some(cfg.lan.bridge.clone()),
        "lan.address" => Some(format!("{}/{}", cfg.lan.address, cfg.lan.prefix)),
        "wan.mode" => Some(
            match &cfg.wan {
                Wan::Dhcp { .. } => "dhcp",
                Wan::Static { .. } => "static",
                Wan::Pppoe { .. } => "pppoe",
            }
            .to_string(),
        ),
        "wan.iface" => Some(
            match &cfg.wan {
                Wan::Dhcp { iface }
                | Wan::Static { iface, .. }
                | Wan::Pppoe { iface, .. } => iface.clone(),
            },
        ),
        "wan.address" => match &cfg.wan {
            Wan::Static { address, prefix, .. } => Some(format!("{address}/{prefix}")),
            _ => Some("(not static)".to_string()),
        },
        "wan.gateway" => match &cfg.wan {
            Wan::Static { gateway, .. } => Some(gateway.to_string()),
            _ => Some("(not static)".to_string()),
        },
        "wan.dns" => match &cfg.wan {
            Wan::Static { dns, .. } => Some(
                dns.iter()
                    .map(|a| a.to_string())
                    .collect::<Vec<_>>()
                    .join(","),
            ),
            _ => Some("(not static)".to_string()),
        },
        "lan.allow_wan" => Some(cfg.lan.allow_wan.to_string()),
        "lan.allow_control_plane" => Some(cfg.lan.allow_control_plane.to_string()),
        "lan.members" => Some(cfg.lan.members.join(",")),
        "services" => Some(
            cfg.services
                .iter()
                .map(|s| s.name.clone())
                .collect::<Vec<_>>()
                .join(","),
        ),
        _ => None,
    };
    match value {
        Some(v) => Response::Value { value: v },
        None => Response::Err {
            message: format!("unknown key: {key}"),
        },
    }
}

fn handle_restart(state: &ControlState, name: &str) -> Response {
    let Ok(mut sup) = state.supervisor.lock() else {
        return Response::Err {
            message: "supervisor mutex poisoned".to_string(),
        };
    };
    let Some(target) = sup.services.iter_mut().find(|s| s.spec.name == name) else {
        return Response::Err {
            message: format!("unknown service: {name}"),
        };
    };
    if let Err(e) = container::stop(target) {
        return Response::Err {
            message: format!("stop {name}: {e}"),
        };
    }
    // Reset backoff so the next tick restarts the service immediately.
    target.backoff = std::time::Duration::from_millis(100);
    target.next_restart = Some(std::time::Instant::now());
    Response::Ok
}

fn collect_status(state: &ControlState) -> Vec<ServiceStatus> {
    let Ok(sup) = state.supervisor.lock() else {
        return vec![];
    };
    let now = SystemTime::now();
    let _ = now; // uptime is measured from Instant, not SystemTime
    sup.services
        .iter()
        .map(|s| ServiceStatus {
            name: s.spec.name.clone(),
            pid: s.pid(),
            state: s.state,
            restarts: s.restarts,
            uptime_secs: s.uptime().as_secs(),
        })
        .collect()
}

fn load_or_create_signing_key(path: &Path) -> Result<SigningKey, Error> {
    if let Ok(bytes) = std::fs::read(path) {
        if bytes.len() == 32 {
            let arr: [u8; 32] = bytes.as_slice().try_into().unwrap();
            return Ok(SigningKey::from_bytes(&arr));
        }
    }
    let key = SigningKey::generate(&mut rand_core::OsRng);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, key.to_bytes())?;
    Ok(key)
}

fn load_authorized_keys(path: &Path) -> Result<Vec<[u8; 32]>, Error> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => return Err(Error::Io(e)),
    };
    let mut keys = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Ok(bytes) = hex::decode(line) {
            if let Ok(arr) = <[u8; 32]>::try_from(bytes.as_slice()) {
                keys.push(arr);
            }
        }
    }
    Ok(keys)
}

