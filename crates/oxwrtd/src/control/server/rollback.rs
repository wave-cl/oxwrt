//! Last-known-good config snapshot + rollback handler.
//!
//! After every fully-successful reload, oxwrtd snapshots the live
//! pair (`/etc/oxwrt/oxwrt.toml` + `/etc/oxwrt/oxwrt.secrets.toml`)
//! to sibling `.last-good.toml` + `.last-good.secrets.toml` files.
//! The snapshot represents "a config that was reconciled + applied
//! successfully at least once on this device" — a useful rollback
//! target when a subsequent edit breaks routing, firewall, or
//! services.
//!
//! Rollback path: `oxctl <host> rollback --confirm` (or the
//! corresponding RPC) copies the snapshot back over the live pair
//! and triggers a reload. Failure there is loud — a rollback that
//! itself can't reconcile means the snapshot is also broken, which
//! needs UART recovery. We don't try to roll back a rollback.
//!
//! Snapshots are NOT taken at `config-push` or `set` time —
//! mutations there mark the on-disk state as *pending* reconcile,
//! not known-good. If the operator pushes then reloads and the
//! reload succeeds, the snapshot captures that combined state;
//! if the reload fails, the snapshot still points at the
//! pre-push config (which is what they'd want to revert to).

use std::path::{Path, PathBuf};

use crate::control::ControlState;
use crate::rpc::Response;

/// Basename of the public config, relative to its parent dir.
/// Matches `config::DEFAULT_PATH`'s basename — kept here as a
/// literal so the snapshot path logic isn't coupled to a specific
/// dir layout.
const PUBLIC_BASENAME: &str = "oxwrt.toml";
const SECRETS_BASENAME: &str = "oxwrt.secrets.toml";
const PUBLIC_SNAPSHOT_BASENAME: &str = "oxwrt.toml.last-good";
const SECRETS_SNAPSHOT_BASENAME: &str = "oxwrt.secrets.toml.last-good";

/// Returns the snapshot paths for a given live public-config path.
/// Just splits the dir — no I/O.
fn snapshot_paths(public_path: &Path) -> (PathBuf, PathBuf, PathBuf) {
    let dir = public_path
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("/etc/oxwrt"));
    (
        dir.join(PUBLIC_SNAPSHOT_BASENAME),
        dir.join(SECRETS_BASENAME),
        dir.join(SECRETS_SNAPSHOT_BASENAME),
    )
}

/// Copy the live public (+ secrets, if present) to their
/// `.last-good` siblings. Called from the reload success path.
///
/// Non-fatal: a snapshot write failure logs at warn and returns
/// `Ok(())` — the reload succeeded and we don't want a snapshot
/// issue to undo that. Next successful reload will retry.
pub fn take_snapshot(public_path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let (public_snap, secrets_live, secrets_snap) = snapshot_paths(public_path);

    if let Err(e) = std::fs::copy(public_path, &public_snap) {
        tracing::warn!(
            error = %e,
            from = %public_path.display(),
            to = %public_snap.display(),
            "rollback: snapshot of public config failed"
        );
        return;
    }
    // Match the mode of the live file (0644 expected) on the copy.
    if let Ok(meta) = std::fs::metadata(public_path) {
        let _ = std::fs::set_permissions(&public_snap, meta.permissions());
    }

    // Secrets snapshot is conditional on the live file existing —
    // fresh installs may not have a secrets overlay.
    if secrets_live.exists() {
        if let Err(e) = std::fs::copy(&secrets_live, &secrets_snap) {
            tracing::warn!(
                error = %e,
                from = %secrets_live.display(),
                to = %secrets_snap.display(),
                "rollback: snapshot of secrets overlay failed"
            );
            return;
        }
        // Secrets snapshot must stay 0600.
        let _ = std::fs::set_permissions(
            &secrets_snap,
            std::fs::Permissions::from_mode(0o600),
        );
    } else if secrets_snap.exists() {
        // Live secrets file disappeared between last snapshot and
        // now (operator deleted it). Clean up the stale snapshot
        // so a rollback doesn't resurrect credentials.
        let _ = std::fs::remove_file(&secrets_snap);
    }
    tracing::debug!(
        snap = %public_snap.display(),
        "rollback: last-good snapshot updated"
    );
}

/// Does a last-good snapshot exist?
pub fn has_snapshot(public_path: &Path) -> bool {
    let (public_snap, _, _) = snapshot_paths(public_path);
    public_snap.exists()
}

/// Copy the `.last-good` snapshot back over the live pair.
/// Returns Err(msg) if the snapshot is missing or the copy
/// failed — caller turns that into a Response::Err.
pub fn restore_snapshot(public_path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let (public_snap, secrets_live, secrets_snap) = snapshot_paths(public_path);
    if !public_snap.exists() {
        return Err(format!(
            "no last-good snapshot at {}; nothing to roll back to",
            public_snap.display()
        ));
    }
    std::fs::copy(&public_snap, public_path).map_err(|e| {
        format!(
            "copy {} → {}: {e}",
            public_snap.display(),
            public_path.display()
        )
    })?;
    // Secrets: if the snapshot has one, restore; else remove the
    // live file (the snapshot predates a secrets overlay being
    // created).
    if secrets_snap.exists() {
        std::fs::copy(&secrets_snap, &secrets_live).map_err(|e| {
            format!(
                "copy {} → {}: {e}",
                secrets_snap.display(),
                secrets_live.display()
            )
        })?;
        let _ = std::fs::set_permissions(
            &secrets_live,
            std::fs::Permissions::from_mode(0o600),
        );
    } else if secrets_live.exists() {
        let _ = std::fs::remove_file(&secrets_live);
    }
    Ok(())
}

/// RPC handler for `Rollback`. Runs on the async RPC dispatch
/// path so it can call `handle_reload_async` — rolling back without
/// reloading would leave the kernel in a state that doesn't match
/// the restored config.
pub async fn handle_rollback(
    state: &std::sync::Arc<ControlState>,
    confirm: bool,
) -> Response {
    if !confirm {
        return Response::Err {
            message: "rollback: must be called with --confirm \
                      (reverts to last-good snapshot and reloads; \
                      current config is discarded)"
                .to_string(),
        };
    }
    let path = Path::new(crate::config::DEFAULT_PATH);
    if let Err(e) = restore_snapshot(path) {
        return Response::Err {
            message: format!("rollback: {e}"),
        };
    }
    tracing::warn!(
        "rollback: restored last-good snapshot; triggering reload"
    );
    super::reload::handle_reload_async(state).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_paths_match_siblings() {
        let (p, sl, ss) = snapshot_paths(Path::new("/etc/oxwrt/oxwrt.toml"));
        assert_eq!(p, Path::new("/etc/oxwrt/oxwrt.toml.last-good"));
        assert_eq!(sl, Path::new("/etc/oxwrt/oxwrt.secrets.toml"));
        assert_eq!(ss, Path::new("/etc/oxwrt/oxwrt.secrets.toml.last-good"));
    }

    #[test]
    fn take_and_restore_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let public = tmp.path().join("oxwrt.toml");
        let secrets = tmp.path().join("oxwrt.secrets.toml");
        std::fs::write(&public, "hostname = \"snap\"\n").unwrap();
        std::fs::write(&secrets, "[[wifi]]\nssid = \"s\"\npassphrase = \"p\"\n")
            .unwrap();
        assert!(!has_snapshot(&public));
        take_snapshot(&public);
        assert!(has_snapshot(&public));
        // Mutate both live files.
        std::fs::write(&public, "hostname = \"broken\"\n").unwrap();
        std::fs::write(&secrets, "[[wifi]]\nssid = \"s\"\npassphrase = \"oops\"\n")
            .unwrap();
        // Rollback restores the snapshot contents.
        restore_snapshot(&public).unwrap();
        assert!(std::fs::read_to_string(&public).unwrap().contains("snap"));
        assert!(std::fs::read_to_string(&secrets).unwrap().contains("\"p\""));
    }

    #[test]
    fn restore_without_snapshot_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let public = tmp.path().join("oxwrt.toml");
        std::fs::write(&public, "hostname = \"x\"").unwrap();
        let err = restore_snapshot(&public).unwrap_err();
        assert!(err.contains("no last-good snapshot"));
    }

    #[test]
    fn snapshot_without_secrets_overlay_is_ok() {
        let tmp = tempfile::tempdir().unwrap();
        let public = tmp.path().join("oxwrt.toml");
        std::fs::write(&public, "hostname = \"nosec\"\n").unwrap();
        take_snapshot(&public);
        assert!(has_snapshot(&public));
        // Restore: public is back; secrets file absent on both sides.
        std::fs::write(&public, "hostname = \"changed\"").unwrap();
        restore_snapshot(&public).unwrap();
        assert!(std::fs::read_to_string(&public).unwrap().contains("nosec"));
        assert!(!tmp.path().join("oxwrt.secrets.toml").exists());
    }

    #[test]
    fn restore_clears_live_secrets_when_snapshot_has_none() {
        // Scenario: snapshot taken before an operator added a
        // secrets file. Rolling back should REMOVE the live
        // secrets file — leaving it in place would resurrect
        // credentials the operator meant to stop shipping.
        let tmp = tempfile::tempdir().unwrap();
        let public = tmp.path().join("oxwrt.toml");
        let secrets = tmp.path().join("oxwrt.secrets.toml");
        std::fs::write(&public, "hostname = \"old\"\n").unwrap();
        take_snapshot(&public); // snapshot has no secrets
        std::fs::write(&public, "hostname = \"new\"\n").unwrap();
        std::fs::write(&secrets, "[[wifi]]\nssid = \"s\"\npassphrase = \"x\"\n")
            .unwrap();
        restore_snapshot(&public).unwrap();
        assert!(!secrets.exists());
    }
}
