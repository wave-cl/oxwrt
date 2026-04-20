//! Reload: re-parse config, reconcile netlink addrs + firewall +
//! supervisor + wifi conf. Split out in step 7.
//!
//! Service-respawn-on-spec-change: reload walks the new config
//! through `Supervisor::reconcile()` (container.rs:1134), which
//! compares each service's old spec to the new one and, on any
//! change (security profile, entrypoint, binds, env, ...), stops
//! the running child and marks the slot Stopped so the next
//! supervisor tick respawns it with the new spec. This means a
//! `[services.security]` edit takes effect on reload — no
//! explicit `oxctl restart <service>` needed. Confirmed by the
//! `reconcile_replaces_changed_spec` test in container.rs. The
//! `oxctl restart <service>` RPC exists for the rare case where
//! an operator wants to force a respawn without touching config
//! (e.g. to pick up a rotated upstream cert that's read once at
//! service startup).

use super::*;

/// Validate the on-disk config without any reconcile side
/// effects. Runs every cross-section / per-item check that
/// `handle_reload_inner` + the CRUD handlers would run before
/// touching live state. Returns the FIRST violation — a future
/// improvement is to collect all of them.
pub fn handle_reload_dry_run() -> Response {
    use crate::config::Config;
    use std::path::Path;

    let path = Path::new(crate::config::DEFAULT_PATH);
    let cfg = match Config::load(path) {
        Ok(c) => c,
        Err(e) => {
            return Response::Err {
                message: format!("reload-dry-run: parse: {e}"),
            };
        }
    };

    if let Err(e) = crate::control::validate::check_vlan_consistency(&cfg) {
        return Response::Err {
            message: format!("reload-dry-run: {e}"),
        };
    }
    for zone in &cfg.firewall.zones {
        if let Err(e) = crate::control::validate::check_zone_network_refs(zone, &cfg) {
            return Response::Err {
                message: format!("reload-dry-run: {e}"),
            };
        }
    }
    for rule in &cfg.firewall.rules {
        if let Err(e) = crate::control::validate::check_rule_zone_refs(rule, &cfg) {
            return Response::Err {
                message: format!("reload-dry-run: {e}"),
            };
        }
    }
    for pf in &cfg.port_forwards {
        if let Err(e) = crate::control::validate::check_port_forward(pf, &cfg) {
            return Response::Err {
                message: format!("reload-dry-run: {e}"),
            };
        }
    }
    for wifi in &cfg.wifi {
        if let Err(e) = crate::control::validate::check_wifi_refs(wifi, &cfg) {
            return Response::Err {
                message: format!("reload-dry-run: {e}"),
            };
        }
    }
    for svc in &cfg.services {
        if let Err(e) = crate::control::validate::check_service(svc, &cfg) {
            return Response::Err {
                message: format!("reload-dry-run: {e}"),
            };
        }
    }

    tracing::info!(
        networks = cfg.networks.len(),
        zones = cfg.firewall.zones.len(),
        rules = cfg.firewall.rules.len(),
        wifi = cfg.wifi.len(),
        services = cfg.services.len(),
        "reload-dry-run: all validators passed"
    );
    Response::Ok
}

pub async fn handle_reload_async(state: &std::sync::Arc<ControlState>) -> Response {
    let start = std::time::Instant::now();
    let first = handle_reload_inner(state).await;
    let duration = start.elapsed();
    let success = matches!(first, Response::Ok);
    crate::metrics_state::record_reload(success, duration);

    if success {
        return first;
    }

    // Reload failed. Attempt a one-shot auto-restore: if a
    // last-good snapshot exists AND it differs from what's live
    // on disk right now, copy the snapshot back and re-run
    // reconcile. Single level — if the recovery reload also
    // fails, we STOP and surface a combined error. Better to
    // admit "we're stuck, fix by hand" than recurse into an ever-
    // older snapshot that might itself be broken.
    //
    // Skipped when live == snapshot (nothing to revert to), or
    // no snapshot exists (fresh install that's never been
    // successfully reloaded — there's no earlier known-good).
    use super::rollback;
    let path = std::path::Path::new(crate::config::DEFAULT_PATH);
    let Response::Err { message: orig } = &first else {
        return first;
    };
    if !rollback::has_snapshot(path) {
        tracing::error!(
            error = %orig,
            "reload failed; no last-good snapshot to auto-restore from"
        );
        return first;
    }
    if rollback::live_matches_snapshot(path) {
        tracing::error!(
            error = %orig,
            "reload failed and live config already matches the last-good snapshot — \
             operator intervention needed (the snapshot itself is broken)"
        );
        return first;
    }

    tracing::warn!(
        orig_error = %orig,
        "reload failed; auto-restoring last-good snapshot + retrying"
    );
    if let Err(e) = rollback::restore_snapshot(path) {
        tracing::error!(error = %e, orig_error = %orig, "auto-restore: copy failed");
        return Response::Err {
            message: format!(
                "reload failed: {orig}\nauto-restore also failed while copying snapshot: {e}"
            ),
        };
    }

    let recovery = handle_reload_inner(state).await;
    crate::metrics_state::record_reload(false, start.elapsed());
    match recovery {
        Response::Ok => {
            tracing::warn!(
                orig_error = %orig,
                "auto-restore succeeded; device is back on the last-good config"
            );
            Response::Err {
                message: format!(
                    "reload failed; auto-restored to last-good snapshot.\n\
                     original error: {orig}"
                ),
            }
        }
        Response::Err { message: recov_msg } => {
            tracing::error!(
                orig_error = %orig,
                recov_error = %recov_msg,
                "auto-restore: snapshot reload also failed — device in undefined state"
            );
            Response::Err {
                message: format!(
                    "reload failed: {orig}\n\
                     auto-restore reload ALSO failed: {recov_msg}\n\
                     operator intervention needed"
                ),
            }
        }
        other => other,
    }
}

async fn handle_reload_inner(state: &std::sync::Arc<ControlState>) -> Response {
    use crate::config::Config;
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

    // Phase 1a: cross-section validation. These checks span multiple
    // sections (vlan fields on Simple, etc.) so they don't fit the
    // per-item check_*_refs pattern. Reject early before touching
    // live state.
    if let Err(e) = crate::control::validate::check_vlan_consistency(&new_cfg) {
        return Response::Err {
            message: format!("reload: {e}"),
        };
    }
    for svc in &new_cfg.services {
        if let Err(e) = crate::control::validate::check_service(svc, &new_cfg) {
            return Response::Err {
                message: format!("reload: {e}"),
            };
        }
    }

    // Control-only mode short-circuit: re-parse + swap the in-memory
    // config but skip every reconcile phase (netlink, sethostname,
    // firewall, supervisor). This preserves the ability to hand-edit
    // /etc/oxwrt.toml and have `reload` validate + publish the result
    // for subsequent Get/CRUD reads, without violating the
    // --control-only contract of "don't touch live network state."
    if state.control_only {
        let Ok(mut cfg) = state.config.write() else {
            return Response::Err {
                message: "reload: config lock poisoned".to_string(),
            };
        };
        *cfg = std::sync::Arc::new(new_cfg);
        tracing::info!("control-only reload: config re-parsed and swapped (no reconcile)");
        return Response::Ok;
    }

    // Phase 2: reconcile netlink address state. We compare against the
    // KERNEL's current state, not the in-memory `state.config` —
    // because `Set` already updated the in-memory config and any two
    // snapshots of it are guaranteed equal at this point. The kernel
    // is the source of truth for "what's actually on the bridge."
    //
    // Bridge rename is still refused — creating the new bridge and
    // moving ports is substantially more work than an address swap.
    let old_cfg = state.config_snapshot();
    let old_lan_iface = old_cfg.lan().map(|n| n.iface().to_string());
    let new_lan_iface = new_cfg.lan().map(|n| n.iface().to_string());
    if old_lan_iface != new_lan_iface {
        return Response::Err {
            message: format!(
                "reload: lan bridge changed from {:?} to {:?}; bridge rename is not \
                 supported over reload, reboot required",
                old_lan_iface, new_lan_iface
            ),
        };
    }
    if let Some(crate::config::Network::Lan {
        bridge,
        address,
        prefix,
        ..
    }) = new_cfg.lan()
    {
        if let Err(e) = reconcile_iface_address(bridge, *address, *prefix, "lan").await {
            return Response::Err {
                message: format!("reload: lan address reconcile failed: {e}"),
            };
        }
    }

    // WAN static mode: same reconcile against the WAN iface. DHCP mode
    // is handled by the renewal loop (which runs DISCOVER → REQUEST →
    // ACK and applies the lease independently of reload). Pppoe has
    // its own setup path and isn't reconciled here.
    //
    // Iterate ALL static WANs (not just primary_wan), because multi-
    // WAN configs can declare static secondaries that need the same
    // address reconcile. Also publish each into wan_leases as a
    // synthesized lease so the failover coordinator sees them —
    // mirrors the init::run() boot-time path.
    for w in new_cfg.networks.iter() {
        if let crate::config::Network::Wan {
            name,
            iface,
            wan:
                crate::config::WanConfig::Static {
                    address,
                    prefix,
                    gateway,
                    dns,
                },
            ..
        } = w
        {
            if let Err(e) = reconcile_iface_address(iface, *address, *prefix, name).await {
                return Response::Err {
                    message: format!("reload: static wan {} address reconcile failed: {e}", name),
                };
            }
            // Synthesize lease for the coordinator. Matches init::run.
            let v4_dns: Vec<std::net::Ipv4Addr> = dns
                .iter()
                .filter_map(|ip| match ip {
                    std::net::IpAddr::V4(v) => Some(*v),
                    _ => None,
                })
                .collect();
            let synth = oxwrt_linux::wan_dhcp::DhcpLease {
                address: *address,
                prefix: *prefix,
                gateway: Some(*gateway),
                dns: v4_dns,
                lease_seconds: u32::MAX,
                server: std::net::Ipv4Addr::UNSPECIFIED,
            };
            if let Ok(mut leases) = state.wan_leases.write() {
                leases.insert(name.clone(), Some(synth));
            }
        }
    }

    // Respawn ICMP probes against the new config. spawn_probes
    // captures `probe_target` at spawn time, so an operator editing
    // probe_target via CRUD + reload wouldn't otherwise take effect
    // until next reboot. Abort the old handles, clear stale health
    // entries, spawn new tasks. Cheap: probes don't hold meaningful
    // state beyond the hysteresis counters, which are fine to reset.
    {
        let mut handles_guard = state.probe_handles.lock().unwrap();
        for h in handles_guard.drain(..) {
            h.abort();
        }
        // Clear stale health so removed-WAN entries don't linger
        // (pick_active does unwrap_or(true) on missing entries,
        // which is the right default for freshly-spawned probes
        // before they've reported).
        if let Ok(mut health) = state.wan_health.write() {
            health.clear();
        }
        let new_handles =
            oxwrt_linux::wan_failover::spawn_probes(&new_cfg, state.wan_health.clone());
        handles_guard.extend(new_handles);
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

    // Phase 2b: re-run net.bring_up for Simple VLAN networks. The
    // core LAN/WAN address reconcile above keeps wired ifaces in
    // sync, but newly-added Simple networks with `vlan` set need
    // their sub-iface created via rtnetlink. bring_up is idempotent
    // — existing ifaces are skipped by its link_index check — so
    // calling it here doesn't disturb the already-configured world.
    // Scoped to a new rtnetlink connection because the caller
    // doesn't have a Handle in scope.
    {
        match crate::net::Net::new() {
            Ok(net) => {
                if let Err(e) = net.bring_up(&new_cfg).await {
                    tracing::warn!(error = %e, "reload: net.bring_up had errors");
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "reload: Net::new failed; skipping bring_up");
            }
        }
    }

    // Phase 3: reinstall firewall.
    if let Err(e) = crate::net::install_firewall(&new_cfg) {
        return Response::Err {
            message: format!("reload: firewall install failed: {e}"),
        };
    }
    let new_firewall_dump = crate::net::format_firewall_dump(&new_cfg);

    // Phase 3a: re-apply wireguard config. Picks up new/removed
    // [[wireguard]] entries and peer-list updates made via CRUD
    // since the last install — without this, `oxctl wg-peer add …`
    // + `reload` would persist the peer in oxwrt.toml but never
    // push it to the running wg iface, so the tunnel stays silently
    // broken until the next reboot.
    if let Err(e) = crate::wireguard::setup_wireguard(&new_cfg) {
        tracing::error!(error = %e, "reload: wireguard reapply failed");
        // Non-fatal: the rest of the reload continues so a bad wg
        // config doesn't knock the router offline.
    }

    // Phase 3a.1: reapply outbound VPN client tunnels. Same
    // rationale as wireguard above — CRUD-level profile edits
    // must propagate to the kernel iface without a reboot. The
    // bring-up is idempotent (existing iface skipped at link-add,
    // config always re-rendered + re-pushed).
    if let Err(e) = crate::vpn_client::setup_all(&new_cfg) {
        tracing::error!(error = %e, "reload: vpn_client reapply failed");
    }
    // Seed bringup state for any newly-declared profiles (removed
    // ones linger in the map — harmless because pick_active iterates
    // cfg.vpn_client, not the map).
    oxwrt_linux::vpn_failover::mark_bringup(&state.vpn_bringup, &new_cfg, true);

    // Phase 3a.3: respawn VPN coordinator + probes. Abort the old
    // set first; the coordinator and probes all capture an
    // Arc<Config> at spawn time, so a live probe_target or
    // priority edit wouldn't otherwise take effect until reboot.
    //
    // Abort happens inside a sync block (no awaits); the
    // async-requiring cleanup_stale_endpoint_exemptions call
    // lives OUTSIDE that block because std::sync::Mutex guards
    // are !Send and can't cross await points.
    {
        let mut probe_handles = state.vpn_probe_handles.lock().unwrap();
        for h in probe_handles.drain(..) {
            h.abort();
        }
        if let Some(coord) = state.vpn_coordinator_handle.lock().unwrap().take() {
            coord.abort();
        }
        // Clear stale health so removed-profile entries don't
        // linger with a stale `false`.
        if let Ok(mut h) = state.vpn_health.write() {
            h.clear();
        }
    }
    // Cleanup stale proto-155 /32s AFTER the old coordinator is
    // aborted but BEFORE the new one spawns. If the new
    // coordinator runs first, its initial tick installs a fresh
    // /32 which a subsequent cleanup would wipe, leaving the
    // coordinator's prev_endpoint_key tracking a kernel route
    // that no longer exists — re-install would be skipped for
    // the rest of the coordinator's life (the bug this commit
    // addresses).
    if !new_cfg.vpn_client.is_empty() {
        let (connection, nl_handle, _messages) = match rtnetlink::new_connection() {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(error = %e, "reload: exemption-cleanup rtnetlink failed");
                return Response::Err {
                    message: format!("reload: cleanup rtnetlink: {e}"),
                };
            }
        };
        let conn_task = tokio::spawn(connection);
        if let Err(e) =
            oxwrt_linux::vpn_routing::cleanup_stale_endpoint_exemptions(&nl_handle).await
        {
            tracing::warn!(error = %e, "reload: exemption cleanup failed");
        }
        conn_task.abort();
    }
    // Actual spawn of new coordinator + probes. All-sync inside
    // the lock scope — no awaits — so MutexGuards are safe.
    {
        let mut probe_handles = state.vpn_probe_handles.lock().unwrap();
        if !new_cfg.vpn_client.is_empty() {
            let (connection, nl_handle, _messages) = match rtnetlink::new_connection() {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!(error = %e, "reload: vpn_failover rtnetlink failed");
                    return Response::Err {
                        message: format!("reload: vpn_failover rtnetlink: {e}"),
                    };
                }
            };
            // The worker needs to outlive this reload (it's a
            // long-running coordinator). Detach by letting the
            // tokio runtime own it — no .abort() on it; the
            // old one's already aborted above. When the next
            // reload fires, a fresh connection replaces this.
            tokio::spawn(connection);
            let new_probes =
                oxwrt_linux::vpn_failover::spawn_probes(&new_cfg, state.vpn_health.clone());
            probe_handles.extend(new_probes);
            let coord = oxwrt_linux::vpn_failover::spawn(
                std::sync::Arc::new(new_cfg.clone()),
                state.vpn_bringup.clone(),
                state.vpn_health.clone(),
                state.active_vpn.clone(),
                state.wan_leases.clone(),
                state.active_wan.clone(),
                nl_handle,
            );
            *state.vpn_coordinator_handle.lock().unwrap() = Some(coord);
            tracing::info!(
                profiles = new_cfg.vpn_client.len(),
                "reload: vpn_failover respawned"
            );
        }
    }

    // Phase 3a.2: policy-routing scaffolding for via_vpn zones.
    // Same idempotent add pattern as at boot — EEXIST tolerated.
    // Reload is the only moment a via_vpn=true flag can appear
    // mid-run, so this re-add picks it up. Stale rules from a
    // flag-off aren't cleaned (documented limitation).
    if !new_cfg.vpn_client.is_empty() || new_cfg.firewall.zones.iter().any(|z| z.via_vpn) {
        use oxwrt_linux::net::zone_ifaces;
        let (connection, handle, _messages) = match rtnetlink::new_connection() {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(error = %e, "reload: vpn_routing rtnetlink failed");
                return Response::Err {
                    message: format!("reload: vpn_routing rtnetlink: {e}"),
                };
            }
        };
        let conn_task = tokio::spawn(connection);
        let via_vpn_ifaces: Vec<String> = new_cfg
            .firewall
            .zones
            .iter()
            .filter(|z| z.via_vpn)
            .flat_map(|z| zone_ifaces(&new_cfg, &z.name))
            .collect();
        if let Err(e) =
            oxwrt_linux::vpn_routing::install_policy_rules(&handle, &via_vpn_ifaces).await
        {
            tracing::error!(error = %e, "reload: vpn_routing policy rules failed");
        }
        if let Err(e) = oxwrt_linux::vpn_routing::install_table_51_blackhole(&handle).await {
            tracing::error!(error = %e, "reload: vpn_routing blackhole failed");
        }
        // Stale-exemption cleanup moved into the respawn block
        // above — it HAS to run before the new coordinator's
        // first tick or the coordinator's install gets wiped by
        // the cleanup immediately after (see the reorder commit
        // that moved this).
        // v6 parallel — gated on any profile declaring address_v6.
        if new_cfg.vpn_client.iter().any(|v| v.address_v6.is_some()) {
            if let Err(e) =
                oxwrt_linux::vpn_routing::install_policy_rules_v6(&handle, &via_vpn_ifaces).await
            {
                tracing::error!(error = %e, "reload: v6 iif rules failed");
            }
            if let Err(e) = oxwrt_linux::vpn_routing::install_table_51_blackhole_v6(&handle).await {
                tracing::error!(error = %e, "reload: v6 blackhole failed");
            }
        }
        let bypass: Vec<String> = new_cfg
            .vpn_client
            .iter()
            .flat_map(|v| v.bypass_destinations.iter().cloned())
            .collect();
        if let Err(e) = oxwrt_linux::vpn_routing::install_bypass_rules(&handle, &bypass).await {
            tracing::error!(error = %e, "reload: vpn_routing bypass install failed");
        }
        let bypass_v6: Vec<String> = new_cfg
            .vpn_client
            .iter()
            .flat_map(|v| v.bypass_destinations_v6.iter().cloned())
            .collect();
        if let Err(e) = oxwrt_linux::vpn_routing::install_bypass_rules_v6(&handle, &bypass_v6).await
        {
            tracing::error!(error = %e, "reload: v6 bypass install failed");
        }
        // Per-zone WAN routing rules. Reload picks up
        // additions / removals of `wan` flags on firewall zones.
        // The per-WAN table defaults themselves are updated by
        // the DHCP lease-apply paths (not retriggered here) —
        // acceptable because the table's default route stays
        // valid across reload.
        if new_cfg.firewall.zones.iter().any(|z| z.wan.is_some()) {
            if let Err(e) =
                oxwrt_linux::wan_routing::install_zone_wan_rules(&handle, &new_cfg).await
            {
                tracing::error!(error = %e, "reload: zone WAN rules failed");
            }
        }
        conn_task.abort();
        // MSS clamp on WAN. Same gate as boot — no point if no
        // vpn_client profile is declared.
        if let Some(wan) = new_cfg.primary_wan() {
            if let Err(e) = oxwrt_linux::vpn_routing::install_mss_clamp(wan.iface()) {
                tracing::warn!(error = %e, "reload: MSS clamp install failed");
            }
        }
    }

    // Regenerate corerad config from new_cfg.networks' ipv6_*
    // fields. The corerad service picks it up on its next restart;
    // supervisor::from_config below replays the service list so this
    // is where the reload actually takes effect.
    if let Err(e) = crate::corerad::write_config(&new_cfg) {
        tracing::error!(error = %e, "reload: corerad config write failed");
    }

    // Regenerate miniupnpd config from new_cfg.upnp. Same lifecycle
    // as corerad — the service (when present) picks up the new
    // config on its next supervisor-driven restart.
    if let Err(e) = crate::miniupnpd::write_config(&new_cfg) {
        tracing::error!(error = %e, "reload: miniupnpd config write failed");
    }

    // Regenerate hickory-dns config from new_cfg.dns (absent → no-op
    // so legacy installs keep working). Picks up upstream/listen
    // changes on the service's next restart.
    if let Err(e) = crate::hickory::write_config(&new_cfg) {
        tracing::error!(error = %e, "reload: hickory config write failed");
    }

    if let Err(e) = crate::coredhcp::write_config(&new_cfg) {
        tracing::error!(error = %e, "reload: coredhcp config write failed");
    }

    if let Err(e) = crate::ntpd::write_config(&new_cfg) {
        tracing::error!(error = %e, "reload: ntpd config write failed");
    }

    // Reapply SQM — picks up bandwidth/extra_args changes; removes
    // stale qdiscs when sqm goes from Some → None.
    if let Err(e) = crate::sqm::setup_sqm(&new_cfg) {
        tracing::error!(error = %e, "reload: sqm reapply failed");
    }

    // Blocklists reconcile: re-fetch + rewrite the oxwrt-blocklist
    // table with the new list. Uses the same `install` path as boot
    // — the `delete table ; add table` idiom makes it idempotent.
    if let Err(e) = crate::blocklists::install(&new_cfg).await {
        tracing::error!(error = %e, "reload: blocklists install failed");
    }

    // Reconcile static routes: del routes that disappeared from
    // new_cfg, add the ones that appeared. Unchanged routes are left
    // alone so a config change that doesn't touch `[[routes]]`
    // produces zero kernel route-table churn.
    {
        let (connection, handle, _messages) = match rtnetlink::new_connection() {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(error = %e, "reload: static_routes rtnetlink failed");
                return Response::Err {
                    message: format!("reload: static_routes rtnetlink: {e}"),
                };
            }
        };
        let conn_task = tokio::spawn(connection);
        if let Err(e) = crate::static_routes::reload(&new_cfg, &handle).await {
            tracing::error!(error = %e, "reload: static_routes reload failed");
            // Non-fatal: logged and skipped. Same policy as sqm —
            // a bad route shouldn't block the rest of reload.
        }
        conn_task.abort();
    }

    // Phase 3b: regenerate per-phy hostapd.conf files at
    // /etc/oxwrt/hostapd/. Must run BEFORE phase 4 (supervisor rebuild)
    // so when the new hostapd-5g / hostapd-2g services come up they
    // read the freshly-generated config rather than stale content from
    // the previous boot. Failure is logged, not fatal — the services
    // might start with an old config or fail to start entirely, but we
    // don't want to block the rest of reload on it.
    if let Err(e) = crate::wifi::write_all(&new_cfg) {
        tracing::error!(error = %e, "reload: wifi::write_all failed");
    }

    // Phase 4: reconcile supervisor. Unlike the previous
    // shutdown()+from_config() pattern this leaves unchanged
    // services running — hostapd doesn't blip wifi clients on a
    // reload that only touched a route or a firewall rule. Spec
    // changes still trigger a stop+respawn, so `oxctl wifi update`
    // + reload still takes effect.
    {
        let Ok(mut sup) = state.supervisor.lock() else {
            return Response::Err {
                message: "reload: supervisor mutex poisoned".to_string(),
            };
        };
        sup.reconcile(&new_cfg.services);
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

    // Phase 6: reconcile the metrics HTTP listener. apply() is
    // idempotent: starts a listener if [metrics] was just added,
    // stops one if it was just removed, rebinds on addr change.
    // Before this was wired into reload, toggling [metrics]
    // required a full reboot for the listener to start — caught
    // during the metrics live-verify.
    crate::metrics::apply(state);

    // Snapshot: the live config just successfully reconciled, so
    // it's now the last-known-good. Overwrites any previous
    // snapshot. Non-fatal; see rollback::take_snapshot for the
    // error-handling rationale.
    super::rollback::take_snapshot(std::path::Path::new(crate::config::DEFAULT_PATH));

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
    use rtnetlink::packet_route::{AddressFamily, address::AddressAttribute};

    let (connection, handle, _messages) = rtnetlink::new_connection().map_err(|e| e.to_string())?;
    let conn_task = tokio::spawn(connection);

    // Resolve iface → index.
    let idx = {
        let mut stream = handle.link().get().match_name(iface.to_string()).execute();
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

fn format_v4_from_attrs(attrs: &[rtnetlink::packet_route::address::AddressAttribute]) -> String {
    use rtnetlink::packet_route::address::AddressAttribute;
    for attr in attrs {
        if let AddressAttribute::Address(std::net::IpAddr::V4(a)) = attr {
            return a.to_string();
        }
    }
    "?".to_string()
}
