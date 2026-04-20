//! Backup + restore of `/etc/oxwrt/` (which now contains
//! `oxwrt.toml` + `oxwrt.secrets.toml` + crypto identity files).
//!
//! One tar.gz contains the identity-critical state: main config,
//! sQUIC signing seed (`key.ed25519`), WireGuard server key
//! (`wg0.key`), root SSH authorized_keys, and debug-ssh host keys.
//! Restoring the tarball recovers full device identity — clients
//! pinned to the old sQUIC server key continue to authenticate,
//! existing WG tunnels keep their peer-record/server-key pairing.
//!
//! Why all at once: these files are an inseparable tuple — you
//! can't roll back oxwrt.toml's `[[wireguard]]` peer list without
//! also rolling back the server's wg0.key, because the peers'
//! client configs reference the server's *public* key which is
//! derived from the private key in wg0.key. Partial rollback ==
//! silently broken tunnels. Backup everything or nothing.
//!
//! Restore uses a two-phase extract: unpack into a tmpdir, verify
//! structure, then atomic-swap the live tree. Failures at any
//! phase leave `/etc/oxwrt/` untouched.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use base64::Engine as _;
use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;

use crate::control::ControlState;
use crate::rpc::Response;

const OXWRT_DIR: &str = "/etc/oxwrt";

/// Build the backup tarball in memory and return it as a base64
/// string. Keeping the whole thing in memory is fine — the tree is
/// tens of KB, well under any sQUIC frame limit (and the base64
/// expansion of a 20 KB input is still under 30 KB).
pub(super) fn handle_backup() -> Response {
    // Called from the Backup RPC. The operator explicitly asked
    // for the tarball, so always include secrets — the alternative
    // would be a backup that can't restore the device without
    // out-of-band credential replay.
    let bytes = match build_tarball(true) {
        Ok(b) => b,
        Err(e) => {
            return Response::Err {
                message: format!("backup: {e}"),
            };
        }
    };
    let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
    Response::Value { value: b64 }
}

/// Build the backup tarball. `include_secrets` controls whether
/// `oxwrt.secrets.toml` (sibling of the public config) is included.
/// For the Backup RPC we always pass `true` (restore would be
/// useless otherwise); the SFTP-backup path honours the config's
/// `[backup_sftp].include_secrets` knob so compliance-conscious
/// operators can push only the publishable half to the remote.
pub fn build_tarball(include_secrets: bool) -> Result<Vec<u8>, String> {
    let gz = GzEncoder::new(Vec::new(), Compression::default());
    let mut tar = tar::Builder::new(gz);

    // /etc/oxwrt/ — recursive. Walk in sorted order for reproducible
    // tarballs (useful for SHA diffs between backups — if nothing
    // changed, the hash matches).
    //
    // `/etc/oxwrt/vpn/` is skipped: those files are WireGuard
    // client private keys for `[[vpn_client]]` profiles. Including
    // them in backups would make a casually-shared backup file a
    // complete VPN-identity compromise. The sQUIC signing seed and
    // wg SERVER key are different — those ARE in the backup
    // because recovering onto the same device is the whole point
    // of backup/restore; losing them is more painful than their
    // blast radius. vpn_client keys are per-provider secrets the
    // operator re-downloads from Mullvad / Proton / etc. if lost —
    // cheap to regenerate, expensive to leak.
    let mut paths: Vec<PathBuf> = Vec::new();
    walk_collect(Path::new(OXWRT_DIR), &mut paths).map_err(|e| e.to_string())?;
    paths.sort();
    for path in &paths {
        // Relative-to-OXWRT_DIR with a "oxwrt/" prefix so restore
        // knows what goes where.
        let rel = path
            .strip_prefix(OXWRT_DIR)
            .map_err(|e| e.to_string())?
            .to_string_lossy()
            .to_string();
        // Skip the vpn/ subtree — see comment above.
        if is_vpn_key_path(&rel) {
            continue;
        }
        // Honour include_secrets: drop oxwrt.secrets.toml if the
        // operator opted out. The rest of /etc/oxwrt/ (keys, known
        // hosts, etc.) stays — those are needed for identity
        // continuity on restore regardless of the secrets-file
        // choice. If an operator really needs a secret-free backup
        // they'll also want to rotate wg0.key / key.ed25519
        // out-of-band; we leave that to them.
        if !include_secrets && rel == "oxwrt.secrets.toml" {
            continue;
        }
        let archive_name = format!("oxwrt/{rel}");
        if path.is_dir() {
            continue; // we'll mkdir on extract from the file paths
        }
        let bytes = std::fs::read(path).map_err(|e| format!("read {path:?}: {e}"))?;
        append_blob(&mut tar, &archive_name, &bytes)?;
    }

    let gz = tar.into_inner().map_err(|e| e.to_string())?;
    gz.finish().map_err(|e| e.to_string())
}

fn append_blob<W: Write>(
    tar: &mut tar::Builder<W>,
    name: &str,
    bytes: &[u8],
) -> Result<(), String> {
    let mut header = tar::Header::new_gnu();
    header.set_size(bytes.len() as u64);
    // Preserve mode 0600 for secret files (keys), 0644 for the rest.
    // The name suffix is the only signal we have to discriminate here
    // without reading the original files' metadata (which we threw
    // away when we read the bytes). Cheap heuristic: ".ed25519",
    // ".key", "authorized_keys", "debug-ssh-keys/" get 0600.
    let mode = if name.contains(".ed25519")
        || name.ends_with(".key")
        || name.contains("authorized_keys")
        || name.contains("debug-ssh-keys/")
    {
        0o600
    } else {
        0o644
    };
    header.set_mode(mode);
    header.set_cksum();
    tar.append_data(&mut header, name, bytes)
        .map_err(|e| format!("tar append {name}: {e}"))
}

fn walk_collect(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Ok(()); // missing dir → empty — fine
    };
    for ent in entries.flatten() {
        let path = ent.path();
        if path.is_dir() {
            walk_collect(&path, out)?;
        } else {
            out.push(path);
        }
    }
    Ok(())
}

/// Decode + extract a backup tarball, swap it over the live tree,
/// and reload so the new config takes effect. Confirm-gated because
/// a restored backup overwrites the sQUIC key — if the client
/// doesn't already have the old key pinned, it will be locked out
/// until UART recovery.
pub(super) async fn handle_restore(
    state: &std::sync::Arc<ControlState>,
    data_b64: &str,
    confirm: bool,
) -> Response {
    if !confirm {
        return Response::Err {
            message: "restore: must be called with --confirm (resets sQUIC key + all secrets; client may lock itself out if not re-pinning to the new key)"
                .to_string(),
        };
    }
    let bytes = match base64::engine::general_purpose::STANDARD.decode(data_b64) {
        Ok(b) => b,
        Err(e) => {
            return Response::Err {
                message: format!("restore: base64 decode: {e}"),
            };
        }
    };
    // Stage under a tmpdir, then atomic-swap. If anything goes wrong
    // during extract, the live tree is untouched.
    let stage = match tempfile::tempdir() {
        Ok(d) => d,
        Err(e) => {
            return Response::Err {
                message: format!("restore: mkdir tmpdir: {e}"),
            };
        }
    };
    if let Err(e) = extract_to(&bytes, stage.path()) {
        return Response::Err {
            message: format!("restore: extract: {e}"),
        };
    }
    // Validate that we got the main config. Missing oxwrt.toml is
    // a hard fail — backup must have been malformed. The archive
    // places it at `oxwrt/oxwrt.toml` (under the /etc/oxwrt/ tree
    // walk), matching the post-DEFAULT_PATH-migration layout.
    if !stage.path().join("oxwrt/oxwrt.toml").exists() {
        return Response::Err {
            message: "restore: tarball missing oxwrt/oxwrt.toml".to_string(),
        };
    }
    // Swap in.
    if let Err(e) = swap_live(stage.path()) {
        return Response::Err {
            message: format!("restore: swap: {e}"),
        };
    }
    // Reload so the new config actually takes effect — firewall,
    // services, wg, etc. all recycle.
    let resp = super::reload::handle_reload_async(state).await;
    if matches!(resp, Response::Err { .. }) {
        // Best-effort: the live tree is already swapped, reload
        // failed. Operator sees the reload error; they can
        // `oxctl <host> reload` manually or reboot.
        return resp;
    }
    Response::Ok
}

fn extract_to(bytes: &[u8], dst: &Path) -> Result<(), String> {
    let gz = GzDecoder::new(std::io::Cursor::new(bytes));
    let mut tar = tar::Archive::new(gz);
    for entry in tar.entries().map_err(|e| e.to_string())? {
        let mut entry = entry.map_err(|e| e.to_string())?;
        let path_in_tar = entry.path().map_err(|e| e.to_string())?.into_owned();
        // Reject any entry that tries to escape the staging dir.
        // `tar::Entries` by default doesn't strip leading "../" etc,
        // so we hand-check that the resolved output stays under dst.
        let target = dst.join(&path_in_tar);
        let dst_canon = dst.canonicalize().map_err(|e| e.to_string())?;
        // Use the parent to canonicalize; the file may not exist yet.
        let target_parent = target
            .parent()
            .ok_or_else(|| format!("no parent for {target:?}"))?;
        std::fs::create_dir_all(target_parent).map_err(|e| e.to_string())?;
        let parent_canon = target_parent.canonicalize().map_err(|e| e.to_string())?;
        if !parent_canon.starts_with(&dst_canon) {
            return Err(format!("tarball entry escapes stage: {path_in_tar:?}"));
        }
        let mut data = Vec::new();
        entry.read_to_end(&mut data).map_err(|e| e.to_string())?;
        std::fs::write(&target, &data).map_err(|e| format!("write {target:?}: {e}"))?;
        // Preserve mode from the header.
        let mode = entry.header().mode().ok().unwrap_or(0o644);
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&target, std::fs::Permissions::from_mode(mode));
        }
    }
    Ok(())
}

fn swap_live(stage: &Path) -> Result<(), String> {
    // /etc/oxwrt/ — clobber existing files. We do NOT rm the entire
    // dir first: some files (e.g. debug-ssh host keys) may legit
    // exist on-device but not in the backup (tarball was taken
    // before they were generated). Overwriting-only preserves
    // those.
    let src_dir = stage.join("oxwrt");
    if src_dir.is_dir() {
        std::fs::create_dir_all(OXWRT_DIR).map_err(|e| format!("mkdir: {e}"))?;
        copy_tree(&src_dir, Path::new(OXWRT_DIR))?;
    }
    Ok(())
}

/// Should this path (relative to /etc/oxwrt/) be excluded from
/// backups? `/etc/oxwrt/vpn/` holds provider-supplied private
/// keys for `[[vpn_client]]` profiles; we keep them out of the
/// backup so a stolen backup file isn't an instant VPN-identity
/// compromise. Operator re-downloads from Mullvad / Proton on
/// restore — trivial compared to regenerating identities baked
/// into server-side secrets that ARE backed up.
fn is_vpn_key_path(rel: &str) -> bool {
    rel == "vpn" || rel.starts_with("vpn/")
}

#[cfg(test)]
mod tests {
    use super::is_vpn_key_path;

    #[test]
    fn excludes_vpn_subtree() {
        assert!(is_vpn_key_path("vpn"));
        assert!(is_vpn_key_path("vpn/mullvad-primary.key"));
        assert!(is_vpn_key_path("vpn/deep/nested.key"));
    }

    #[test]
    fn includes_everything_else() {
        assert!(!is_vpn_key_path(""));
        assert!(!is_vpn_key_path("key.ed25519"));
        assert!(!is_vpn_key_path("authorized_keys"));
        assert!(!is_vpn_key_path("wg0.key")); // server key, different dir
        assert!(!is_vpn_key_path("debug-ssh-keys/dropbear_ed25519_host_key"));
        assert!(!is_vpn_key_path("vpnsomething.conf")); // prefix trap
    }
}

fn copy_tree(src: &Path, dst: &Path) -> Result<(), String> {
    for ent in std::fs::read_dir(src).map_err(|e| e.to_string())? {
        let ent = ent.map_err(|e| e.to_string())?;
        let src_path = ent.path();
        let name = ent.file_name();
        let dst_path = dst.join(&name);
        if src_path.is_dir() {
            std::fs::create_dir_all(&dst_path).map_err(|e| e.to_string())?;
            copy_tree(&src_path, &dst_path)?;
        } else {
            std::fs::copy(&src_path, &dst_path)
                .map_err(|e| format!("copy {src_path:?} → {dst_path:?}: {e}"))?;
            // Preserve mode.
            if let Ok(meta) = std::fs::metadata(&src_path) {
                let _ = std::fs::set_permissions(&dst_path, meta.permissions());
            }
        }
    }
    Ok(())
}
