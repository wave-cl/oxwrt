//! Client-side WireGuard — outbound tunnels to commercial VPN
//! providers (Mullvad, Proton, etc.).
//!
//! Distinct from `wireguard.rs`, which is the server side
//! (roadwarrior peers connect IN). Client tunnels own their
//! own netdev (e.g. wgvpn0), have exactly one upstream peer,
//! and hardcode AllowedIPs=0.0.0.0/0 so every packet that the
//! policy-router sends this way can exit.
//!
//! Address assignment is done HERE (not via `[[networks]]`) —
//! vpn_client ifaces aren't user-managed networks, they shouldn't
//! show up in bridge membership or firewall zone wiring, and the
//! tunnel-interior address is trivially determined from the
//! provider config. Keeping the setup self-contained avoids
//! coupling that every caller would have to maintain.
//!
//! Kill-switch, DNS redirection, and routing-table installs are
//! owned by siblings `vpn_routing.rs` and `net::install_firewall`.
//! This module ONLY handles the iface lifecycle + key material +
//! `wg setconf`.

use std::path::Path;
use std::process::{Command, Stdio};

use oxwrt_api::config::{Config, VpnClient};

use crate::net::Error;
use crate::wireguard::{apply_wg_config, link_up};

/// Bring up every declared `[[vpn_client]]` profile. Idempotent
/// in the same shape as `wireguard::setup_wireguard` — reload
/// just rewrites the config and re-calls wg setconf; the kernel
/// iface is preserved if it already exists.
///
/// Never returns Err — failures are logged per profile and skipped
/// so one bad profile can't block boot. The coordinator layer
/// handles "this profile doesn't actually work" via probes.
pub fn setup_all(cfg: &Config) -> Result<(), Error> {
    for v in &cfg.vpn_client {
        if let Err(e) = bring_up_one(v) {
            tracing::error!(profile = %v.name, iface = %v.iface, error = %e, "vpn_client bring-up failed");
        }
    }
    Ok(())
}

/// Core bring-up for a single profile. Five steps matching the
/// server-side flow, plus MTU + address assignment:
///   1. Load / generate the client private key.
///   2. Create the iface if missing.
///   3. Render single-peer config + `wg setconf`.
///   4. Set MTU and assign tunnel-interior address.
///   5. Bring link up.
fn bring_up_one(v: &VpnClient) -> Result<(), Error> {
    let iface = &v.iface;

    // 1. Private key. Same generation/loading pattern as
    //    wireguard::bring_up_one — shell to `wg genkey` if the
    //    file is missing, else trust whatever's on disk. 0600.
    let key_path = Path::new(&v.key_path);
    if !key_path.exists() {
        if let Some(parent) = key_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::Firewall(format!("vpn_client: mkdir {parent:?}: {e}")))?;
        }
        let out = Command::new("wg")
            .arg("genkey")
            .output()
            .map_err(|e| Error::Firewall(format!("vpn_client: wg genkey: {e}")))?;
        if !out.status.success() {
            return Err(Error::Firewall(format!(
                "vpn_client: wg genkey failed: {}",
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        std::fs::write(key_path, &out.stdout)
            .map_err(|e| Error::Firewall(format!("vpn_client: write {key_path:?}: {e}")))?;
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::PermissionsExt;
            let perm = std::fs::Permissions::from_mode(0o600);
            if let Err(e) = std::fs::set_permissions(key_path, perm) {
                tracing::warn!(path = %v.key_path, error = %e, "vpn_client key chmod 0600 failed");
            }
        }
        tracing::info!(profile = %v.name, path = %v.key_path, "generated vpn_client key");
    }
    let private_key = std::fs::read_to_string(key_path)
        .map_err(|e| Error::Firewall(format!("vpn_client: read {key_path:?}: {e}")))?
        .trim()
        .to_string();

    // 2. Create iface if missing.
    let present = Command::new("ip")
        .args(["link", "show", iface])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !present {
        let st = Command::new("ip")
            .args(["link", "add", "dev", iface, "type", "wireguard"])
            .status()
            .map_err(|e| Error::Firewall(format!("ip link add {iface}: {e}")))?;
        if !st.success() {
            return Err(Error::Firewall(format!(
                "ip link add {iface} type wireguard: exit {st:?}"
            )));
        }
        tracing::info!(profile = %v.name, iface, "vpn_client link created");
    }

    // 3. Render + apply config.
    let conf_text = render_with_psk(v, &private_key)?;
    apply_wg_config(iface, &conf_text)?;
    tracing::info!(profile = %v.name, iface, "vpn_client config applied");

    // 4. Set MTU. Done BEFORE link up so the kernel doesn't
    //    advertise/negotiate with the wrong size briefly.
    let st = Command::new("ip")
        .args(["link", "set", "dev", iface, "mtu", &v.mtu.to_string()])
        .status()
        .map_err(|e| Error::Firewall(format!("ip link set mtu: {e}")))?;
    if !st.success() {
        tracing::warn!(profile = %v.name, iface, mtu = v.mtu, "vpn_client MTU set failed (continuing)");
    }

    // 4b. Assign tunnel-interior address. `ip addr replace` is
    //     idempotent — no need to check presence first.
    let st = Command::new("ip")
        .args(["addr", "replace", &v.address, "dev", iface])
        .status()
        .map_err(|e| Error::Firewall(format!("ip addr replace: {e}")))?;
    if !st.success() {
        return Err(Error::Firewall(format!(
            "ip addr replace {} dev {iface}: exit {st:?}",
            v.address
        )));
    }

    // 5. Link up.
    link_up(iface)?;
    Ok(())
}

/// Renderer shim that reads the PresharedKey file (if any) and
/// inlines it into the INI. Kept out of `VpnClient::render_config`
/// so that function stays pure (no disk I/O) and unit-testable.
fn render_with_psk(v: &VpnClient, private_key: &str) -> Result<String, Error> {
    let mut text = v.render_config(private_key);
    if let Some(psk_path) = &v.preshared_key_path {
        let psk = std::fs::read_to_string(psk_path)
            .map_err(|e| Error::Firewall(format!("vpn_client: read psk {psk_path}: {e}")))?
            .trim()
            .to_string();
        // Insert PresharedKey right after the Endpoint line so wg
        // setconf sees it within the [Peer] block. Simpler than
        // re-rendering: replace the marker comment that
        // render_config emits when preshared_key_path is Some.
        let marker = format!("# PresharedKey from {}", psk_path);
        text = text.replace(&marker, &format!("PresharedKey = {}", psk));
    }
    Ok(text)
}
