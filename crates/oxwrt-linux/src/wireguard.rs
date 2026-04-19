//! WireGuard iface bring-up — for each `[[wireguard]]` entry in
//! Config we ensure the iface exists, load/generate the server
//! private key, push the full [Interface] + [[Peer]] config via
//! `wg setconf`, and bring the link up.
//!
//! External-binary pattern: uses `ip` + `wg` from wireguard-tools
//! via `std::process::Command`. That's the same pattern as
//! `netdev::create_wifi_ap_interfaces` (which calls `iw`) — netlink
//! support for the WireGuard generic-netlink family isn't in any of
//! our current netlink crates (rtnetlink 0.20 has no link-kind
//! helper for wireguard, and pulling in a standalone wg-uapi crate
//! adds real dep surface for a one-shot config push). `wg` is a
//! tiny musl binary, already packaged by OpenWrt as
//! `wireguard-tools`, and the image grows by ~200 KB.
//!
//! Address assignment to wg0 is NOT done here — the operator
//! declares a matching `[[networks]] type="simple" iface="wg0"
//! address=...` entry and the existing `Net::setup_lan` /
//! `setup_wan` pipeline (or equivalent for simple) picks it up.
//! Keeping topology declarative in `[[networks]]` means wg0 lands
//! in `diag links` / `diag routes` output the same as any other
//! netdev.

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};

use oxwrt_api::config::{Config, Wireguard};

use crate::net::Error;

/// Bring up every declared `[[wireguard]]` iface on boot. Idempotent:
/// skips link-create when the iface already exists (e.g. after SIGHUP
/// reload), always refreshes the peer set via `wg setconf` so removed
/// peers disappear the next install cycle.
pub fn setup_wireguard(cfg: &Config) -> Result<(), Error> {
    for wg in &cfg.wireguard {
        if let Err(e) = bring_up_one(wg) {
            tracing::error!(wg = %wg.name, error = %e, "wireguard bring-up failed");
            // Keep going with other interfaces rather than aborting the
            // whole boot — a single misconfigured wg entry shouldn't
            // take the router offline.
        }
    }
    Ok(())
}

fn bring_up_one(wg: &Wireguard) -> Result<(), Error> {
    let iface = wg.iface.as_deref().unwrap_or(&wg.name);

    // 1. Ensure the private key file exists. If missing, generate via
    //    `wg genkey`. If present, trust whatever format the file holds
    //    (`wg setconf` accepts base64; raw 32 bytes works if hex-
    //    encoded externally — not our concern).
    let key_path = Path::new(&wg.key_path);
    if !key_path.exists() {
        if let Some(parent) = key_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::Firewall(format!("wg: mkdir {parent:?}: {e}")))?;
        }
        let out = Command::new("wg")
            .arg("genkey")
            .output()
            .map_err(|e| Error::Firewall(format!("wg genkey: {e}")))?;
        if !out.status.success() {
            return Err(Error::Firewall(format!(
                "wg genkey failed: {}",
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        std::fs::write(key_path, &out.stdout)
            .map_err(|e| Error::Firewall(format!("wg: write {key_path:?}: {e}")))?;
        // 0600 — the key is as sensitive as the sQUIC signing seed.
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::PermissionsExt;
            let perm = std::fs::Permissions::from_mode(0o600);
            if let Err(e) = std::fs::set_permissions(key_path, perm) {
                tracing::warn!(path = %wg.key_path, error = %e, "wg key chmod 0600 failed");
            }
        }
        tracing::info!(path = %wg.key_path, "generated wg server key");
    }
    let private_key = std::fs::read_to_string(key_path)
        .map_err(|e| Error::Firewall(format!("wg: read {key_path:?}: {e}")))?
        .trim()
        .to_string();

    // 2. Create the iface if missing. `ip link add` is idempotent-ish
    //    (returns "RTNETLINK answers: File exists" non-zero); check
    //    presence first to keep logs clean.
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
        tracing::info!(iface, "wireguard link created");
    }

    // 3. Render full wg config (Interface + Peers) and apply.
    let conf_text = wg.render_config(&private_key);
    apply_wg_config(iface, &conf_text)?;
    tracing::info!(iface, peers = wg.peers.len(), "wireguard config applied");

    // 4. Bring the link up. Address assignment happens via the
    //    matching [[networks]] type="simple" entry elsewhere.
    link_up(iface)?;
    Ok(())
}

/// Write the rendered wg-quick INI to /var/run/wireguard/<iface>.conf
/// and push it into the kernel via `wg setconf`. Shared between
/// the server-side `[[wireguard]]` setup and the client-side
/// `[[vpn_client]]` setup — both produce an INI with an [Interface]
/// + one-or-more [Peer] blocks.
///
/// The file goes through write-to-tmp + atomic rename + 0600 so a
/// concurrent `wg show` can't see a half-written file and the
/// private key on disk doesn't widen its readership between the
/// write and the chmod.
pub(crate) fn apply_wg_config(iface: &str, conf_text: &str) -> Result<(), Error> {
    let conf_dir = Path::new("/var/run/wireguard");
    std::fs::create_dir_all(conf_dir)
        .map_err(|e| Error::Firewall(format!("mkdir {conf_dir:?}: {e}")))?;
    let conf_path = conf_dir.join(format!("{iface}.conf"));
    let tmp_path = conf_dir.join(format!("{iface}.conf.tmp"));
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp_path)
            .map_err(|e| Error::Firewall(format!("open {tmp_path:?}: {e}")))?;
        f.write_all(conf_text.as_bytes())
            .map_err(|e| Error::Firewall(format!("write {tmp_path:?}: {e}")))?;
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = f.set_permissions(std::fs::Permissions::from_mode(0o600));
        }
    }
    std::fs::rename(&tmp_path, &conf_path)
        .map_err(|e| Error::Firewall(format!("rename {tmp_path:?} → {conf_path:?}: {e}")))?;
    let st = Command::new("wg")
        .args(["setconf", iface])
        .arg(&conf_path)
        .status()
        .map_err(|e| Error::Firewall(format!("wg setconf {iface}: {e}")))?;
    if !st.success() {
        return Err(Error::Firewall(format!("wg setconf {iface}: exit {st:?}")));
    }
    Ok(())
}

/// `ip link set <iface> up` — thin helper so the client-side
/// bring-up can do the same final step without duplicating the
/// command-builder pattern.
pub(crate) fn link_up(iface: &str) -> Result<(), Error> {
    let st = Command::new("ip")
        .args(["link", "set", iface, "up"])
        .status()
        .map_err(|e| Error::Firewall(format!("ip link set {iface} up: {e}")))?;
    if !st.success() {
        return Err(Error::Firewall(format!(
            "ip link set {iface} up: exit {st:?}"
        )));
    }
    Ok(())
}
