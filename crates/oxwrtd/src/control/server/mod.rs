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
    /// Per-listener concurrent-connection cap. Shared across all
    /// listeners (loopback + LAN bind both draw from this pool).
    /// A `try_acquire_owned` on each incoming either returns a
    /// permit (dropped when the connection task finishes) or
    /// fails immediately — in which case we close the incoming
    /// without handshake.
    pub connection_slots: Arc<tokio::sync::Semaphore>,
}

impl Server {
    pub fn load(
        key_path: &Path,
        control: &crate::config::Control,
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
        let authorized_keys = load_merged_authorized_keys(control)?;
        let slots = control.max_connections.max(1) as usize;
        let connection_slots = Arc::new(tokio::sync::Semaphore::new(slots));
        tracing::debug!(
            max_connections = slots,
            "control: sQUIC concurrent-connection cap"
        );
        Ok(Self {
            signing_key,
            authorized_keys,
            state,
            connection_slots,
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
            // Gate on the connection-slot semaphore. try_acquire
            // succeeds-or-fails immediately; no await. If the
            // pool is drained, close the incoming without a
            // handshake — the operator will retry, a WAN scan
            // gets a clean reject, and tasks already in flight
            // aren't starved by a fresh flood.
            let permit = match self.connection_slots.clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    tracing::warn!(
                        cap = self.connection_slots.available_permits() as i32
                            + self.connection_slots.available_permits() as i32,
                        "control: connection-cap reached; refusing new peer"
                    );
                    drop(incoming);
                    continue;
                }
            };
            let this = self.clone();
            tokio::spawn(async move {
                // Hold the permit for the lifetime of this task —
                // dropped on return (success OR error path) via
                // RAII, releasing the slot for the next peer.
                let _permit = permit;
                if let Err(e) = this.handle_incoming(incoming).await {
                    // Client disconnects-without-close (the CLI exits
                    // as soon as its single RPC finishes) show up here
                    // as "quinn connection: timed out" from the idle
                    // timer. That's normal operation, not actionable —
                    // downgrade to debug so every oxctl call doesn't
                    // spam a warn into dmesg. Real handler bugs
                    // (frame parse, rpc dispatch failure) produce
                    // different error text and still need visibility
                    // — for those we raise to warn explicitly.
                    let s = e.to_string();
                    if s.contains("timed out") || s.contains("connection closed") {
                        tracing::debug!(error = %e, "control: peer idle-closed connection");
                    } else {
                        tracing::warn!(error = %e, "control: connection error");
                    }
                }
            });
        }
        Ok(())
    }

    async fn handle_incoming(self: Arc<Self>, incoming: quinn::Incoming) -> Result<(), Error> {
        let conn = incoming
            .await
            .map_err(|e| Error::Squic(squic::Error::from(e)))?;
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
            if let Request::ReloadDryRun = &request {
                let resp = handle_reload_dry_run();
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
            if let Request::VpnKeyUpload {
                name,
                private_key_b64,
            } = &request
            {
                let resp = handle_vpn_key_upload(name, private_key_b64);
                write_frame(&mut send, &resp).await?;
                send.finish().ok();
                continue;
            }

            // Firmware apply: trigger sysupgrade + reboot.
            if let Request::FwApply {
                confirm,
                keep_settings,
            } = &request
            {
                let resp = handle_fw_apply(*confirm, *keep_settings);
                write_frame(&mut send, &resp).await?;
                send.finish().ok();
                // If apply succeeded, the router is about to reboot.
                // The connection will drop — that's expected.
                continue;
            }

            // Graceful reboot: save seed + shut down services + sync
            // + reboot(2). The connection drops on successful reboot
            // — client interprets that as "reboot in progress."
            if let Request::Reboot { confirm } = &request {
                let resp = handle_reboot(&self.state, *confirm).await;
                write_frame(&mut send, &resp).await?;
                send.finish().ok();
                continue;
            }

            // Backup: stream /etc/oxwrt/ + /etc/oxwrt.toml as a
            // base64-encoded tar.gz.
            if let Request::Backup = &request {
                let resp = backup::handle_backup();
                write_frame(&mut send, &resp).await?;
                send.finish().ok();
                continue;
            }
            // Restore: extract + swap, then reload to apply.
            if let Request::Restore { data_b64, confirm } = &request {
                let resp = backup::handle_restore(&self.state, data_b64, *confirm).await;
                write_frame(&mut send, &resp).await?;
                send.finish().ok();
                continue;
            }
            // Rollback: revert to the last-good snapshot + reload.
            if let Request::Rollback { confirm, to } = &request {
                let resp = rollback::handle_rollback(&self.state, *confirm, *to).await;
                write_frame(&mut send, &resp).await?;
                send.finish().ok();
                continue;
            }
            // Rollback-list: read-only enumeration of the ring.
            if let Request::RollbackList = &request {
                let resp = rollback::handle_rollback_list();
                write_frame(&mut send, &resp).await?;
                send.finish().ok();
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
pub mod backup;
mod crud;
mod diag;
mod logs;
mod reboot;
mod reload;
mod reset;
pub mod rollback;
mod set;
mod sysupgrade;

// Re-exports for call sites that used to hit these via
// crate::control::server::build_ping_args etc. Only the
// diag-binary-arg-builders test in control.rs still consumes
// them, so scope the re-export to `cfg(test)` — keeps clippy's
// dead-code detector happy in non-test builds without losing
// test coverage.
#[cfg(test)]
pub(crate) use diag::{build_drill_args, build_ping_args, build_ss_args, build_traceroute_args};
pub use reload::{handle_reload_async, handle_reload_dry_run};

// Submodule-local handlers used by handle_incoming + sync handle()
// dispatch. The originals were all `fn` at the top level; these
// imports bring the names back into scope so call sites don't change.
use crud::{
    handle_crud_ddns, handle_crud_network, handle_crud_port_forward, handle_crud_radio,
    handle_crud_rule, handle_crud_service, handle_crud_wg_peer, handle_crud_wifi, handle_crud_zone,
    handle_wg_enroll,
};
use diag::handle_diag;
use logs::{handle_logs, stream_follow_logs};
use reboot::handle_reboot;
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
            let wan = state
                .wan_lease
                .read()
                .unwrap()
                .as_ref()
                .map(|l| crate::rpc::WanSummary {
                    address: l.address.to_string(),
                    prefix: l.prefix,
                    gateway: l.gateway.map(|g| g.to_string()),
                    lease_seconds: l.lease_seconds,
                });
            let firewall_rules = state.firewall_dump.read().unwrap().len();
            let aps = collect_ap_status(&state.config_snapshot());
            let wg = collect_wg_status(&state.config_snapshot());
            let active_wan: Option<String> = state
                .active_wan
                .lock()
                .ok()
                .and_then(|g| (*g).clone());
            // Per-WAN breakdown — one entry per declared WAN,
            // regardless of active-ness. Cheap: reads 3 locks,
            // clones the small HashMaps inside, releases.
            let wans: Vec<crate::rpc::WanEntry> = crate::wan_failover::snapshot_all(
                &state.config_snapshot(),
                &state.wan_leases,
                &state.wan_health,
                &state.active_wan,
            )
            .into_iter()
            .map(|s| crate::rpc::WanEntry {
                name: s.name,
                iface: s.iface,
                priority: s.priority,
                healthy: s.healthy,
                active: s.active,
                address: s.address.map(|a| a.to_string()),
                gateway: s.gateway.map(|g| g.to_string()),
            })
            .collect();
            // Per-VPN snapshot. Same pattern as wans above —
            // read-only clone of the shared state. Empty on a
            // non-VPN router (no vpn_client declared).
            let active_vpn: Option<String> = state
                .active_vpn
                .lock()
                .ok()
                .and_then(|g| (*g).clone());
            let vpns: Vec<crate::rpc::VpnEntry> =
                crate::vpn_failover::snapshot_all(
                    &state.config_snapshot(),
                    &state.vpn_bringup,
                    &state.vpn_health,
                    &state.active_vpn,
                )
                .into_iter()
                .map(|s| crate::rpc::VpnEntry {
                    name: s.name,
                    iface: s.iface,
                    priority: s.priority,
                    healthy: s.healthy,
                    active: s.active,
                    endpoint: s.endpoint,
                    probe_target: s.probe_target.to_string(),
                })
                .collect();
            vec![Response::Status {
                services,
                supervisor_uptime_secs,
                wan,
                active_wan,
                wans,
                firewall_rules,
                aps,
                wg,
                active_vpn,
                vpns,
            }]
        }
        Request::Logs { service, follow } => handle_logs(state, &service, follow),
        Request::Restart { service } => vec![handle_restart(state, &service)],
        Request::Reboot { .. } => vec![Response::Err {
            message: "BUG: Reboot should be handled async upstream".to_string(),
        }],
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
        Request::Backup => vec![Response::Err {
            message: "BUG: Backup should be handled async upstream".to_string(),
        }],
        Request::Restore { .. } => vec![Response::Err {
            message: "BUG: Restore should be handled async upstream".to_string(),
        }],
        Request::Rollback { .. } => vec![Response::Err {
            message: "BUG: Rollback should be handled async upstream".to_string(),
        }],
        Request::RollbackList => vec![Response::Err {
            message: "BUG: RollbackList should be handled upstream".to_string(),
        }],
        Request::ReloadDryRun => vec![Response::Err {
            message: "BUG: ReloadDryRun should be handled upstream".to_string(),
        }],
        Request::ConfigPush { .. } => vec![Response::Err {
            message: "BUG: ConfigPush should be handled upstream".to_string(),
        }],
        Request::VpnKeyUpload { .. } => vec![Response::Err {
            message: "BUG: VpnKeyUpload should be handled upstream".to_string(),
        }],
    }
}

/// Write a vpn_client profile's private key to
/// /etc/oxwrt/vpn/<name>.key with 0600 perms. Path-traversal
/// defense: `name` must be \[a-zA-Z0-9_-\]+ (same charset as
/// wg_peer names). Key content is NOT validated beyond
/// not-empty; `wg setconf` will reject a malformed key on the
/// next bring-up, which is a clean failure mode. Atomic via
/// tmp+rename under the same directory.
fn handle_vpn_key_upload(name: &str, private_key_b64: &str) -> Response {
    use std::io::Write as _;
    use std::path::Path;
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Response::Err {
            message: format!(
                "vpn-key-upload: invalid name {:?} (alphanum + _ - only)",
                name
            ),
        };
    }
    if private_key_b64.trim().is_empty() {
        return Response::Err {
            message: "vpn-key-upload: empty private key".to_string(),
        };
    }
    let dir = "/etc/oxwrt/vpn";
    if let Err(e) = std::fs::create_dir_all(dir) {
        return Response::Err {
            message: format!("vpn-key-upload: mkdir {dir}: {e}"),
        };
    }
    let path_str = format!("{dir}/{name}.key");
    let tmp_str = format!("{dir}/{name}.key.tmp");
    let path = Path::new(&path_str);
    let tmp = Path::new(&tmp_str);
    let res = (|| -> std::io::Result<()> {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(tmp)?;
        f.write_all(private_key_b64.trim().as_bytes())?;
        f.write_all(b"\n")?;
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        f.sync_all()?;
        std::fs::rename(tmp, path)?;
        Ok(())
    })();
    match res {
        Ok(()) => {
            tracing::info!(path = %path_str, "vpn_client: private key uploaded");
            Response::Ok
        }
        Err(e) => Response::Err {
            message: format!("vpn-key-upload: write {path_str}: {e}"),
        },
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
            if let Network::Lan {
                address, prefix, ..
            } = n
            {
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
                    WanConfig::Dhcp { .. } => "dhcp",
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
            if let Network::Wan {
                wan: WanConfig::Static {
                    address, prefix, ..
                },
                ..
            } = n
            {
                format!("{address}/{prefix}")
            } else {
                "(not static)".to_string()
            }
        }),
        "wan.prefix" => cfg.primary_wan().map(|n| {
            if let Network::Wan {
                wan: WanConfig::Static { prefix, .. },
                ..
            } = n
            {
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
            if let Network::Wan {
                wan: WanConfig::Pppoe { username, .. },
                ..
            } = n
            {
                username.clone()
            } else {
                "(not pppoe)".to_string()
            }
        }),
        "wan.gateway" => cfg.primary_wan().map(|n| {
            if let Network::Wan {
                wan: WanConfig::Static { gateway, .. },
                ..
            } = n
            {
                gateway.to_string()
            } else {
                "(not static)".to_string()
            }
        }),
        "wan.dns" => cfg.primary_wan().map(|n| {
            if let Network::Wan {
                wan: WanConfig::Static { dns, .. },
                ..
            } = n
            {
                dns.iter()
                    .map(|a| a.to_string())
                    .collect::<Vec<_>>()
                    .join(",")
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

pub(crate) fn collect_status(state: &ControlState) -> Vec<ServiceStatus> {
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
                        line.push('…');
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
            let operstate = std::fs::read_to_string(format!("/sys/class/net/{iface}/operstate"))
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

/// For each `[[wireguard]]` entry, shell out to `wg show <iface>
/// dump` to pull live peer state. Parse the tab-separated output
/// and correlate pubkey back to the peer name from cfg.
///
/// Output format (hard-coded in wireguard-tools' wg(8)):
///   line 1: <priv> <pub> <listen_port> <fwmark>
///   lines 2..: <peer_pub> <psk> <endpoint> <allowed_ips>
///              <last_handshake_unix> <rx> <tx> <persistent_keepalive>
/// Empty fields render as "(none)" or "0". Handshake unix timestamp
/// of 0 means "never".
///
/// Error paths: missing `wg` binary, iface doesn't exist, or wg
/// isn't available are all logged debug + produce an empty entry
/// (the iface still shows up in Status as declared, just with no
/// peers) — a missing binary shouldn't fail the whole Status RPC.
pub(crate) fn collect_wg_status(cfg: &crate::config::Config) -> Vec<crate::rpc::WgIfaceStatus> {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let mut out = Vec::with_capacity(cfg.wireguard.len());
    for wg in &cfg.wireguard {
        let iface = wg.iface.as_deref().unwrap_or(&wg.name).to_string();
        let result = Command::new("wg").args(["show", &iface, "dump"]).output();
        let output = match result {
            Ok(o) if o.status.success() => o,
            Ok(o) => {
                tracing::debug!(
                    iface,
                    stderr = %String::from_utf8_lossy(&o.stderr).trim(),
                    "wg show dump non-zero exit"
                );
                out.push(crate::rpc::WgIfaceStatus {
                    iface,
                    listen_port: wg.listen_port,
                    peers: Vec::new(),
                });
                continue;
            }
            Err(e) => {
                tracing::debug!(iface, error = %e, "wg show dump spawn failed");
                out.push(crate::rpc::WgIfaceStatus {
                    iface,
                    listen_port: wg.listen_port,
                    peers: Vec::new(),
                });
                continue;
            }
        };
        let text = String::from_utf8_lossy(&output.stdout);
        let mut lines = text.lines();

        // Interface line (skip — we already have listen_port from cfg).
        let _ = lines.next();

        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let mut peers = Vec::new();
        for line in lines {
            let f: Vec<&str> = line.split('\t').collect();
            if f.len() < 7 {
                continue;
            }
            let pubkey = f[0].to_string();
            let endpoint = if f[2] == "(none)" {
                String::new()
            } else {
                f[2].to_string()
            };
            let last_handshake_unix: u64 = f[4].parse().unwrap_or(0);
            let last_handshake_secs_ago = if last_handshake_unix == 0 {
                None
            } else {
                Some(now_unix.saturating_sub(last_handshake_unix))
            };
            let rx_bytes: u64 = f[5].parse().unwrap_or(0);
            let tx_bytes: u64 = f[6].parse().unwrap_or(0);
            // Match back to the operator-supplied name via pubkey.
            // Unknown pubkeys (shouldn't happen unless someone poked
            // `wg` directly) render with name = "(unknown)" so they
            // still show up in status.
            let name = wg
                .peers
                .iter()
                .find(|p| p.pubkey == pubkey)
                .map(|p| p.name.clone())
                .unwrap_or_else(|| "(unknown)".to_string());
            peers.push(crate::rpc::WgPeerStatus {
                name,
                pubkey,
                endpoint,
                last_handshake_secs_ago,
                rx_bytes,
                tx_bytes,
            });
        }
        out.push(crate::rpc::WgIfaceStatus {
            iface,
            listen_port: wg.listen_port,
            peers,
        });
    }
    out
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

/// Merge the legacy file-backed ACL (at `control.authorized_keys`)
/// with the inline `[[control.clients]]` entries. Deduplicates by
/// raw 32-byte key so listing the same key in both sources doesn't
/// inflate the allowed_keys Vec.
///
/// Inline entries whose `key` doesn't parse as 64 hex chars are
/// logged at `warn` and skipped — the daemon should boot even with
/// a malformed ACL entry, because the legacy file path may still
/// admit the operator.
fn load_merged_authorized_keys(
    control: &crate::config::Control,
) -> Result<Vec<[u8; 32]>, Error> {
    use std::collections::BTreeSet;
    let mut seen: BTreeSet<[u8; 32]> = BTreeSet::new();
    let mut out: Vec<[u8; 32]> = Vec::new();
    for key in load_authorized_keys(&control.authorized_keys)? {
        if seen.insert(key) {
            out.push(key);
        }
    }
    for client in &control.clients {
        let Ok(bytes) = hex::decode(&client.key) else {
            tracing::warn!(
                name = %client.name,
                key = %client.key,
                "control.clients: skipping entry with non-hex key"
            );
            continue;
        };
        let Ok(arr) = <[u8; 32]>::try_from(bytes.as_slice()) else {
            tracing::warn!(
                name = %client.name,
                key_len = bytes.len(),
                "control.clients: skipping entry whose decoded key isn't 32 bytes"
            );
            continue;
        };
        if seen.insert(arr) {
            out.push(arr);
        }
    }
    tracing::info!(
        file_path = %control.authorized_keys.display(),
        inline_count = control.clients.len(),
        total_unique = out.len(),
        "control: authorized-key ACL loaded"
    );
    Ok(out)
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
/// Write config text to disk, splitting secrets out into
/// `oxwrt.secrets.toml` alongside the public `oxwrt.toml`.
///
/// Both files use the same tmp+fsync+rename pattern as
/// `urandom_seed::save` (empirically the only shape that persists
/// across reboots on MT7986 f2fs+overlay). The secrets file is
/// written mode 0600 so `cat` by a non-root user fails.
///
/// `text` is the merged (public + secret) TOML as a single string,
/// as produced today by `toml::to_string_pretty(&cfg)` or by
/// operator-authored `toml_edit` edits. We re-parse it here to
/// split — cheaper than threading DocumentMut through every
/// caller, and keeps the split logic confined to one function.
fn atomic_write_config(text: &str) -> Result<(), String> {
    use oxwrt_api::secrets::split_document;
    let path = std::path::Path::new(crate::config::DEFAULT_PATH);
    let secrets_path = path.with_file_name("oxwrt.secrets.toml");
    let mut doc: toml_edit::DocumentMut = text
        .parse()
        .map_err(|e| format!("re-parse config for secrets split: {e}"))?;
    let secret_doc = split_document(&mut doc);
    let public_text = doc.to_string();
    let secret_text = secret_doc.to_string();
    atomic_write_file(path, &public_text, 0o644)?;
    atomic_write_file(&secrets_path, &secret_text, 0o600)?;
    Ok(())
}

/// tmp+fsync+rename atomic write, with post-rename chmod to `mode`
/// (because create(true) respects umask rather than mode).
fn atomic_write_file(
    path: &std::path::Path,
    text: &str,
    mode: u32,
) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let tmp_path = path.with_extension(match path.extension().and_then(|e| e.to_str()) {
        Some(ext) => format!("{ext}.tmp"),
        None => "tmp".to_string(),
    });
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp_path)
            .map_err(|e| format!("open tmp {}: {e}", tmp_path.display()))?;
        f.write_all(text.as_bytes())
            .map_err(|e| format!("write tmp: {e}"))?;
        f.sync_all().map_err(|e| format!("fsync tmp: {e}"))?;
    }
    // Set mode pre-rename so there's no window where the file
    // exists at its final path with default perms.
    let _ = std::fs::set_permissions(
        &tmp_path,
        std::fs::Permissions::from_mode(mode),
    );
    std::fs::rename(&tmp_path, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp_path);
        format!("rename {} → {}: {e}", tmp_path.display(), path.display())
    })?;
    if let Some(parent) = path.parent() {
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
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
fn persist_and_swap(state: &ControlState, new_cfg: crate::config::Config, desc: &str) -> Response {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AuthorizedClient, Control};

    fn control_with(clients: Vec<AuthorizedClient>, file_path: &str) -> Control {
        Control {
            listen: vec![],
            authorized_keys: std::path::PathBuf::from(file_path),
            clients,
        }
    }

    #[test]
    fn load_merged_uses_inline_when_file_missing() {
        let ctrl = control_with(
            vec![AuthorizedClient {
                name: "laptop".into(),
                key: "a".repeat(64),
            }],
            "/nonexistent/authorized_keys",
        );
        let keys = load_merged_authorized_keys(&ctrl).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0][0], 0xaa);
    }

    #[test]
    fn load_merged_skips_malformed_inline() {
        let ctrl = control_with(
            vec![
                AuthorizedClient {
                    name: "good".into(),
                    key: "b".repeat(64),
                },
                AuthorizedClient {
                    name: "bad-hex".into(),
                    key: "zzz".into(),
                },
                AuthorizedClient {
                    name: "bad-len".into(),
                    key: "ab".into(),
                },
            ],
            "/nonexistent",
        );
        let keys = load_merged_authorized_keys(&ctrl).unwrap();
        assert_eq!(keys.len(), 1, "only the well-formed entry survives");
    }

    #[test]
    fn load_merged_dedupes_file_and_inline() {
        // Write a temp file with one hex key, then set the same key
        // inline under a different label — merged list must have 1.
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("authorized_keys");
        let key = "c".repeat(64);
        std::fs::write(&path, format!("{key}\n")).unwrap();
        let ctrl = Control {
            listen: vec![],
            authorized_keys: path.clone(),
            clients: vec![AuthorizedClient {
                name: "same-key-new-label".into(),
                key: key.clone(),
            }],
        };
        let keys = load_merged_authorized_keys(&ctrl).unwrap();
        assert_eq!(keys.len(), 1);
    }

    #[test]
    fn load_merged_file_plus_inline() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("authorized_keys");
        let file_key = "1".repeat(64);
        std::fs::write(&path, format!("# comment\n{file_key}\n\n")).unwrap();
        let inline_key = "2".repeat(64);
        let ctrl = Control {
            listen: vec![],
            authorized_keys: path,
            clients: vec![AuthorizedClient {
                name: "inline-only".into(),
                key: inline_key,
            }],
        };
        let keys = load_merged_authorized_keys(&ctrl).unwrap();
        assert_eq!(keys.len(), 2);
    }
}
