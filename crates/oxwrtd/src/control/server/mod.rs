use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;

use ed25519_dalek::SigningKey;

use crate::container;
use crate::control::{ControlState, FrameError, read_frame, write_frame};
use crate::rpc::{CrudAction, Request, Response, ServiceStatus};

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
        // Log the derived public key at startup so operators can
        // discover it off a UART console after a fresh flash —
        // /etc/oxwrt/ is regenerated on every full sysupgrade and the
        // client needs this value as SQUIC_SERVER_KEY. Without this
        // log, the only way to get the key is to read
        // /etc/oxwrt/key.ed25519 over a shell (impossible if oxwrtd
        // replaces dropbear) or via the --print-server-key mode
        // (impossible if oxwrtd is pid 1).
        let verifying = signing_key.verifying_key();
        tracing::info!(
            server_pubkey = %hex::encode(verifying.to_bytes()),
            "control: server signing keypair loaded"
        );
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

            // Collection CRUD: synchronous handler, single response.
            if let Request::Collection { collection, action } = &request {
                let resp = handle_collection(&self.state, collection, action);
                write_frame(&mut send, &resp).await?;
                send.finish().ok();
                continue;
            }

            // Config dump/push: full config as TOML.
            if let Request::ConfigDump = &request {
                let resp = handle_config_dump(&self.state);
                write_frame(&mut send, &resp).await?;
                send.finish().ok();
                continue;
            }
            if let Request::ConfigPush { toml } = &request {
                let resp = handle_config_push(&self.state, toml);
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

            // WireGuard enroll: server-generated client keypair + a
            // rendered [Interface]+[Peer] .conf text for the operator
            // to hand off. Handled here (not in sync dispatch) because
            // it shells out to `wg genkey` / `wg pubkey`.
            if let Request::WgEnroll {
                name,
                allowed_ips,
                endpoint_host,
                dns,
            } = &request
            {
                let resp = handle_wg_enroll(
                    &self.state,
                    name,
                    allowed_ips,
                    endpoint_host,
                    dns.as_deref(),
                );
                write_frame(&mut send, &resp).await?;
                send.finish().ok();
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

// Submodules split out of this file during step 7 of the
// workspace refactor. See each file's header for scope.
mod crud;
mod diag;
mod logs;
mod reload;
mod reset;
mod set;
mod sysupgrade;

// Re-exports for call sites that used to hit these via
// crate::control::server::build_ping_args etc. (only the
// diag-binary-arg-builders test needs them).
pub use diag::{build_drill_args, build_ping_args, build_ss_args, build_traceroute_args};
pub use reload::handle_reload_async;

// Submodule-local handlers used by handle_incoming + sync handle()
// dispatch. The originals were all `fn` at the top level; these
// imports bring the names back into scope so call sites don't change.
use crud::{
    handle_crud_ddns, handle_crud_network, handle_crud_port_forward, handle_crud_radio,
    handle_crud_rule, handle_crud_service, handle_crud_wg_peer, handle_crud_wifi,
    handle_crud_zone, handle_wg_enroll,
};
use diag::handle_diag;
use logs::{handle_logs, stream_follow_logs};
use reset::handle_reset;
use set::handle_set;
use sysupgrade::{handle_fw_apply, handle_fw_update};

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
            let aps = collect_ap_status(&state.config_snapshot());
            vec![Response::Status {
                services,
                supervisor_uptime_secs,
                wan,
                firewall_rules,
                aps,
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
        Request::Collection { .. } => vec![Response::Err {
            message: "BUG: Collection should be handled upstream".to_string(),
        }],
        Request::ConfigDump => vec![Response::Err {
            message: "BUG: ConfigDump should be handled upstream".to_string(),
        }],
        Request::WgEnroll { .. } => vec![Response::Err {
            message: "BUG: WgEnroll should be handled async upstream".to_string(),
        }],
        Request::ConfigPush { .. } => vec![Response::Err {
            message: "BUG: ConfigPush should be handled upstream".to_string(),
        }],
    }
}


fn handle_get(state: &ControlState, key: &str) -> Response {
    use crate::config::{Network, WanConfig};
    let cfg = state.config_snapshot();
    let value = match key {
        "hostname" => Some(cfg.hostname.clone()),
        "timezone" => cfg.timezone.clone(),
        "lan.bridge" => cfg.lan().map(|n| n.iface().to_string()),
        "lan.address" => cfg.lan().map(|n| {
            if let Network::Lan { address, prefix, .. } = n {
                format!("{address}/{prefix}")
            } else {
                unreachable!()
            }
        }),
        // lan.prefix and wan.prefix are also settable (as integers);
        // exposing them separately means operators can script against
        // the prefix without parsing the combined "address/prefix" form.
        "lan.prefix" => cfg.lan().map(|n| {
            if let Network::Lan { prefix, .. } = n {
                prefix.to_string()
            } else {
                unreachable!()
            }
        }),
        "wan.mode" => cfg.primary_wan().map(|n| {
            if let Network::Wan { wan, .. } = n {
                match wan {
                    WanConfig::Dhcp => "dhcp",
                    WanConfig::Static { .. } => "static",
                    WanConfig::Pppoe { .. } => "pppoe",
                }
                .to_string()
            } else {
                unreachable!()
            }
        }),
        "wan.iface" => cfg.primary_wan().map(|n| n.iface().to_string()),
        "wan.address" => cfg.primary_wan().map(|n| {
            if let Network::Wan { wan: WanConfig::Static { address, prefix, .. }, .. } = n {
                format!("{address}/{prefix}")
            } else {
                "(not static)".to_string()
            }
        }),
        "wan.prefix" => cfg.primary_wan().map(|n| {
            if let Network::Wan { wan: WanConfig::Static { prefix, .. }, .. } = n {
                prefix.to_string()
            } else {
                "(not static)".to_string()
            }
        }),
        // wan.username is operator config (ISP account), not a secret —
        // exposed symmetrically with the Set that writes it. wan.password
        // is deliberately NOT exposed: it's settable but never readable,
        // matching the convention of write-only credential fields.
        "wan.username" => cfg.primary_wan().map(|n| {
            if let Network::Wan { wan: WanConfig::Pppoe { username, .. }, .. } = n {
                username.clone()
            } else {
                "(not pppoe)".to_string()
            }
        }),
        "wan.gateway" => cfg.primary_wan().map(|n| {
            if let Network::Wan { wan: WanConfig::Static { gateway, .. }, .. } = n {
                gateway.to_string()
            } else {
                "(not static)".to_string()
            }
        }),
        "wan.dns" => cfg.primary_wan().map(|n| {
            if let Network::Wan { wan: WanConfig::Static { dns, .. }, .. } = n {
                dns.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(",")
            } else {
                "(not static)".to_string()
            }
        }),
        "lan.members" => cfg.lan().map(|n| {
            if let Network::Lan { members, .. } = n {
                members.join(",")
            } else {
                unreachable!()
            }
        }),
        "services" => Some(
            cfg.services
                .iter()
                .map(|s| s.name.clone())
                .collect::<Vec<_>>()
                .join(","),
        ),
        // Control-plane fields. `listen` is safe to expose — it's the
        // same info `ss -lnu` would show to anyone on the LAN. The
        // `authorized_keys` *path* is also safe (just a filesystem
        // location); we deliberately don't expose the pubkey *contents*
        // because that's unnecessary and an attacker who hasn't already
        // compromised the control plane shouldn't care, while one who
        // has can cat the file directly.
        "control.listen" => Some(cfg.control.listen.join(",")),
        "control.authorized_keys" => {
            Some(cfg.control.authorized_keys.to_string_lossy().into_owned())
        }
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

/// Byte cap on the `last_log` field per ServiceStatus. 240 chars fits
/// on two terminal lines of an 80-col display without wrapping into
/// something unreadable — long enough to carry a one-line panic
/// message or an "Error: <reason>" from a Rust binary's stderr, short
/// enough that a `status` response with 10 crashed services doesn't
/// dwarf the useful fields above it.
const LAST_LOG_CLIP: usize = 240;

fn collect_status(state: &ControlState) -> Vec<ServiceStatus> {
    let Ok(sup) = state.supervisor.lock() else {
        return vec![];
    };
    let now = SystemTime::now();
    let _ = now; // uptime is measured from Instant, not SystemTime
    sup.services
        .iter()
        .map(|s| {
            // Pull the most recent log line for this service, if any.
            // logd holds a bounded ring so this is O(ring_cap); cheap
            // enough to do every time `status` is called.
            let last_log = state
                .logd
                .tail(&s.spec.name, 1)
                .into_iter()
                .next()
                .map(|l| {
                    let mut line = l.line;
                    if line.len() > LAST_LOG_CLIP {
                        line.truncate(LAST_LOG_CLIP);
                        line.push_str("…");
                    }
                    line
                });
            ServiceStatus {
                name: s.spec.name.clone(),
                pid: s.pid(),
                state: s.state,
                restarts: s.restarts,
                uptime_secs: s.uptime().as_secs(),
                last_log,
            }
        })
        .collect()
}

/// For each `[[wifi]]` entry, produce an `ApStatus` record by:
///   1. deriving the expected iface name from the convention used by
///      `netdev::create_wifi_ap_interfaces` (`{phy}-ap0`),
///   2. looking up the matching `[[radios]]` entry for band + channel,
///   3. reading `/sys/class/net/<iface>/operstate` for live state.
///
/// Sysfs is the right source here — a single file-read per AP, no
/// rtnetlink round-trip, no async required. On non-Linux the file is
/// absent and operstate reports "unknown", which is the right signal
/// for "can't tell you".
pub(crate) fn collect_ap_status(cfg: &crate::config::Config) -> Vec<crate::rpc::ApStatus> {
    cfg.wifi
        .iter()
        .map(|w| {
            let iface = format!("{}-ap0", w.radio);
            let (band, channel) = cfg
                .radios
                .iter()
                .find(|r| r.phy == w.radio)
                .map(|r| (r.band.clone(), r.channel))
                .unwrap_or_else(|| (String::new(), 0));
            let operstate = std::fs::read_to_string(format!(
                "/sys/class/net/{iface}/operstate"
            ))
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "unknown".to_string());
            crate::rpc::ApStatus {
                ssid: w.ssid.clone(),
                iface,
                radio_phy: w.radio.clone(),
                band,
                channel,
                operstate,
            }
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

// ── Collection CRUD ─────────────────────────────────────────────────

fn handle_collection(state: &ControlState, collection: &str, action: &CrudAction) -> Response {
    match collection {
        "network" => handle_crud_network(state, action),
        "zone" => handle_crud_zone(state, action),
        "rule" => handle_crud_rule(state, action),
        "wifi" => handle_crud_wifi(state, action),
        "radio" => handle_crud_radio(state, action),
        "service" => handle_crud_service(state, action),
        "port-forward" => handle_crud_port_forward(state, action),
        "wg-peer" => handle_crud_wg_peer(state, action),
        "ddns" => handle_crud_ddns(state, action),
        _ => Response::Err {
            message: format!("unknown collection: {collection}"),
        },
    }
}

// CRUD validation helpers + json_merge live in crate::control::validate
// so they can be unit-tested without cross-compiling the rest of this
// (linux-only) module. Re-imported here at call sites.
use crate::control::validate::{
    check_rule_zone_refs, check_wifi_refs, check_zone_network_refs, dependents_on_network,
    dependents_on_radio, dependents_on_zone, json_merge,
};

/// Dump the entire running config as TOML.
/// Write config text to disk. Tries atomic tmp+rename first; falls back
/// to direct overwrite if rename returns EBUSY (bind-mounted files in
/// Docker / containers can't be renamed over).
fn atomic_write_config(text: &str) -> Result<(), String> {
    let path = std::path::Path::new(crate::config::DEFAULT_PATH);
    let tmp_path = path.with_extension("toml.tmp");
    if let Err(e) = std::fs::write(&tmp_path, text) {
        // tmp write failed — try direct overwrite as last resort
        return std::fs::write(path, text)
            .map_err(|e2| format!("write config: tmp failed ({e}), direct failed ({e2})"));
    }
    match std::fs::rename(&tmp_path, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp_path);
            // EBUSY on bind-mounted files — fall back to direct overwrite.
            // Less atomic but the only option on bind mounts.
            tracing::debug!(error = %e, "rename failed, falling back to direct write");
            std::fs::write(path, text)
                .map_err(|e2| format!("write config: rename ({e}), direct ({e2})"))
        }
    }
}

fn handle_config_dump(state: &ControlState) -> Response {
    let cfg = state.config_snapshot();
    match toml::to_string_pretty(&*cfg) {
        Ok(text) => Response::Value { value: text },
        Err(e) => Response::Err {
            message: format!("serialize config: {e}"),
        },
    }
}

/// Replace the entire config with the provided TOML. Validates that it
/// parses as a valid Config before persisting.
fn handle_config_push(state: &ControlState, toml_text: &str) -> Response {
    let new_cfg: crate::config::Config = match toml::from_str(toml_text) {
        Ok(c) => c,
        Err(e) => {
            return Response::Err {
                message: format!("invalid config: {e}"),
            };
        }
    };
    persist_and_swap(state, new_cfg, "config pushed (pending reload)")
}

// (CRUD cross-reference helpers live in crate::control::validate;
// imported at the top of the CRUD helper section above.)

/// Serialize config to TOML, atomic-write to disk, swap the in-memory Arc.
fn persist_and_swap(
    state: &ControlState,
    new_cfg: crate::config::Config,
    desc: &str,
) -> Response {
    let toml_text = match toml::to_string_pretty(&new_cfg) {
        Ok(t) => t,
        Err(e) => {
            return Response::Err {
                message: format!("serialize config: {e}"),
            };
        }
    };
    if let Err(e) = atomic_write_config(&toml_text) {
        return Response::Err { message: e };
    }
    if let Ok(mut cfg_lock) = state.config.write() {
        *cfg_lock = std::sync::Arc::new(new_cfg);
    }
    tracing::info!("{desc} (pending reload)");
    Response::Ok
}
