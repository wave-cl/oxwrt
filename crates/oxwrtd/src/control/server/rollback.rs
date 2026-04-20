//! Last-known-good config snapshot ring + rollback handlers.
//!
//! After every fully-successful reload, oxwrtd snapshots the live
//! pair (`/etc/oxwrt/oxwrt.toml` + `/etc/oxwrt/oxwrt.secrets.toml`)
//! into a rotating ring of `.last-good-<N>` files:
//!
//!   oxwrt.toml.last-good-0   ← most recent successful reload
//!   oxwrt.toml.last-good-1   ← one before that
//!   ...
//!   oxwrt.toml.last-good-{RING_SIZE-1}   ← oldest retained
//!
//! Each snapshot has a matching `oxwrt.secrets.toml.last-good-<N>`
//! sibling (mode 0600) when a secrets overlay is present.
//!
//! Rollback path: `oxctl <host> rollback --confirm` reverts to
//! index 0. `--to <N>` picks an older snapshot — useful when the
//! most recent known-good is the one that broke (e.g. the operator
//! reloaded, the config applied, then a downstream state change
//! exposed a latent bug).
//!
//! Auto-restore on a failed reload (see `reload.rs`) only targets
//! index 0; climbing deeper is a conscious operator decision.
//!
//! Migration: if a legacy single-file `.last-good` snapshot exists
//! (pre-ring), `take_snapshot` treats it as the ring's index 0 and
//! shifts it along with the new one. After one successful reload
//! post-upgrade, the legacy naming is gone.
//!
//! Snapshots are NOT taken at `config-push` or `set` time —
//! mutations there mark the on-disk state as *pending* reconcile,
//! not known-good.

use std::path::{Path, PathBuf};

use crate::control::ControlState;
use crate::rpc::Response;

const SECRETS_BASENAME: &str = "oxwrt.secrets.toml";

/// Legacy single-file snapshot basenames — looked up during
/// migration only. Post-ring these are renamed to -0.
const LEGACY_PUBLIC_SNAPSHOT: &str = "oxwrt.toml.last-good";
const LEGACY_SECRETS_SNAPSHOT: &str = "oxwrt.secrets.toml.last-good";

/// How many snapshots to retain. 5 covers "this reload plus the
/// last four known-good" — deep enough to survive an afternoon of
/// iterative tweaks, shallow enough that the filesystem doesn't
/// accumulate ancient configs. If an operator asks for tuning,
/// promote to a `Control` field.
pub const RING_SIZE: usize = 5;

fn public_snap_path(dir: &Path, idx: usize) -> PathBuf {
    dir.join(format!("oxwrt.toml.last-good-{idx}"))
}

fn secrets_snap_path(dir: &Path, idx: usize) -> PathBuf {
    dir.join(format!("oxwrt.secrets.toml.last-good-{idx}"))
}

fn live_secrets_path(public_path: &Path) -> PathBuf {
    let dir = public_path
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("/etc/oxwrt"));
    dir.join(SECRETS_BASENAME)
}

fn snapshot_dir(public_path: &Path) -> PathBuf {
    public_path
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("/etc/oxwrt"))
}

/// One-shot: if legacy unindexed `.last-good` files exist, rename
/// them to ring index 0. Called from `take_snapshot` before the
/// rotation, so the legacy snapshot is promoted into the ring on
/// the first post-upgrade reload.
fn migrate_legacy_snapshot(dir: &Path) {
    let legacy_pub = dir.join(LEGACY_PUBLIC_SNAPSHOT);
    let legacy_sec = dir.join(LEGACY_SECRETS_SNAPSHOT);
    let ring_pub_0 = public_snap_path(dir, 0);
    let ring_sec_0 = secrets_snap_path(dir, 0);
    if legacy_pub.exists() && !ring_pub_0.exists() {
        if let Err(e) = std::fs::rename(&legacy_pub, &ring_pub_0) {
            tracing::warn!(
                error = %e,
                from = %legacy_pub.display(),
                to = %ring_pub_0.display(),
                "rollback: migrate legacy public snapshot failed"
            );
        }
    }
    if legacy_sec.exists() && !ring_sec_0.exists() {
        if let Err(e) = std::fs::rename(&legacy_sec, &ring_sec_0) {
            tracing::warn!(
                error = %e,
                from = %legacy_sec.display(),
                to = %ring_sec_0.display(),
                "rollback: migrate legacy secrets snapshot failed"
            );
        }
    }
}

/// Rotate the ring + copy the live pair to index 0. Called from
/// the reload success path.
///
/// Rotation is lazy: we only rename slots that actually exist. The
/// highest index (RING_SIZE-1) is deleted if present. Errors in
/// rotation are warn-logged and non-fatal — the reload succeeded
/// and we don't want a snapshot issue to undo that. Next successful
/// reload retries.
pub fn take_snapshot(public_path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let dir = snapshot_dir(public_path);

    migrate_legacy_snapshot(&dir);

    // Drop the oldest slot first, then shift each existing slot up
    // by one index. Top-down so we don't clobber as we go.
    let oldest = RING_SIZE - 1;
    let _ = std::fs::remove_file(public_snap_path(&dir, oldest));
    let _ = std::fs::remove_file(secrets_snap_path(&dir, oldest));
    for i in (0..oldest).rev() {
        let from_pub = public_snap_path(&dir, i);
        let to_pub = public_snap_path(&dir, i + 1);
        if from_pub.exists() {
            let _ = std::fs::rename(&from_pub, &to_pub);
        }
        let from_sec = secrets_snap_path(&dir, i);
        let to_sec = secrets_snap_path(&dir, i + 1);
        if from_sec.exists() {
            let _ = std::fs::rename(&from_sec, &to_sec);
        }
    }

    // Copy the live pair into slot 0.
    let pub_snap = public_snap_path(&dir, 0);
    let sec_live = live_secrets_path(public_path);
    let sec_snap = secrets_snap_path(&dir, 0);

    if let Err(e) = std::fs::copy(public_path, &pub_snap) {
        tracing::warn!(
            error = %e,
            from = %public_path.display(),
            to = %pub_snap.display(),
            "rollback: snapshot of public config failed"
        );
        return;
    }
    if let Ok(meta) = std::fs::metadata(public_path) {
        let _ = std::fs::set_permissions(&pub_snap, meta.permissions());
    }

    if sec_live.exists() {
        if let Err(e) = std::fs::copy(&sec_live, &sec_snap) {
            tracing::warn!(
                error = %e,
                from = %sec_live.display(),
                to = %sec_snap.display(),
                "rollback: snapshot of secrets overlay failed"
            );
            return;
        }
        let _ = std::fs::set_permissions(&sec_snap, std::fs::Permissions::from_mode(0o600));
    } else if sec_snap.exists() {
        // Live secrets disappeared between last snapshot and now
        // (operator deleted it). Clean up the stale slot-0 secrets
        // so a rollback doesn't resurrect credentials.
        let _ = std::fs::remove_file(&sec_snap);
    }
    tracing::debug!(
        snap = %pub_snap.display(),
        "rollback: snapshot written to slot 0"
    );
}

/// Does any ring slot hold a snapshot?
pub fn has_snapshot(public_path: &Path) -> bool {
    let dir = snapshot_dir(public_path);
    // Cheap check: index 0 is where the most recent snapshot lives,
    // and `take_snapshot` always writes there. If it's absent then
    // nothing's been snapshotted on this device yet.
    public_snap_path(&dir, 0).exists()
}

/// Byte-compare the live public + secrets against slot 0. Used by
/// the auto-restore gate — if they match, restoring would be a
/// no-op and we skip the loop.
pub fn live_matches_snapshot(public_path: &Path) -> bool {
    let dir = snapshot_dir(public_path);
    let pub_snap = public_snap_path(&dir, 0);
    let sec_live = live_secrets_path(public_path);
    let sec_snap = secrets_snap_path(&dir, 0);
    let live_pub = std::fs::read(public_path).unwrap_or_default();
    let snap_pub = std::fs::read(&pub_snap).unwrap_or_default();
    if live_pub != snap_pub {
        return false;
    }
    let live_sec = std::fs::read(&sec_live).ok();
    let snap_sec = std::fs::read(&sec_snap).ok();
    live_sec == snap_sec
}

/// Restore a specific ring slot over the live pair. Index 0 is
/// the default / auto-restore target; >0 lets the operator rewind
/// further via `oxctl rollback --to <N>`.
pub fn restore_snapshot_index(public_path: &Path, idx: usize) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    if idx >= RING_SIZE {
        return Err(format!(
            "rollback: index {idx} out of range (ring size is {RING_SIZE})"
        ));
    }
    let dir = snapshot_dir(public_path);
    let pub_snap = public_snap_path(&dir, idx);
    let sec_live = live_secrets_path(public_path);
    let sec_snap = secrets_snap_path(&dir, idx);

    if !pub_snap.exists() {
        return Err(format!(
            "no snapshot at index {idx} ({})",
            pub_snap.display()
        ));
    }
    std::fs::copy(&pub_snap, public_path).map_err(|e| {
        format!(
            "copy {} → {}: {e}",
            pub_snap.display(),
            public_path.display()
        )
    })?;

    // Secrets: mirror `take_snapshot`'s "remove live if snapshot
    // has none" rule. Otherwise a rollback-to-older-than-secrets
    // would leave stale credentials around.
    if sec_snap.exists() {
        std::fs::copy(&sec_snap, &sec_live)
            .map_err(|e| format!("copy {} → {}: {e}", sec_snap.display(), sec_live.display()))?;
        let _ = std::fs::set_permissions(&sec_live, std::fs::Permissions::from_mode(0o600));
    } else if sec_live.exists() {
        let _ = std::fs::remove_file(&sec_live);
    }
    Ok(())
}

/// Convenience wrapper for the common "restore slot 0" path. Used
/// by the auto-restore loop in `handle_reload_async` and by the
/// default `oxctl rollback` call.
pub fn restore_snapshot(public_path: &Path) -> Result<(), String> {
    restore_snapshot_index(public_path, 0)
}

/// Info about one snapshot slot for `list_snapshots`.
#[derive(Debug, Clone)]
pub struct SnapshotInfo {
    pub index: usize,
    /// Unix-timestamp seconds of the slot's mtime.
    pub mtime_secs: Option<u64>,
    /// Byte size of the public file in the slot.
    pub size_bytes: u64,
    /// `Config.hostname` extracted from the public file; None on
    /// any read / parse error (so `list` still reports existence).
    pub hostname: Option<String>,
}

/// Enumerate every occupied slot in the ring + its summary.
/// Returns an empty Vec if no slot is occupied.
pub fn list_snapshots(public_path: &Path) -> Vec<SnapshotInfo> {
    let dir = snapshot_dir(public_path);
    let mut out = Vec::new();
    for idx in 0..RING_SIZE {
        let p = public_snap_path(&dir, idx);
        let Ok(meta) = std::fs::metadata(&p) else {
            continue;
        };
        let mtime_secs = meta.modified().ok().and_then(|t| {
            t.duration_since(std::time::UNIX_EPOCH)
                .ok()
                .map(|d| d.as_secs())
        });
        let hostname = std::fs::read_to_string(&p).ok().and_then(|s| {
            s.lines()
                .map(|l| l.trim())
                .find(|l| l.starts_with("hostname"))
                .and_then(|l| l.split('=').nth(1))
                .map(|v| v.trim().trim_matches('"').to_string())
        });
        out.push(SnapshotInfo {
            index: idx,
            mtime_secs,
            size_bytes: meta.len(),
            hostname,
        });
    }
    out
}

/// RPC handler for `Rollback`. Runs on the async RPC dispatch
/// path so it can call `handle_reload_async` — rolling back without
/// reloading would leave the kernel in a state that doesn't match
/// the restored config.
pub async fn handle_rollback(
    state: &std::sync::Arc<ControlState>,
    confirm: bool,
    to_index: Option<u32>,
) -> Response {
    if !confirm {
        return Response::Err {
            message: "rollback: must be called with --confirm \
                      (reverts to a snapshot and reloads; \
                      current config is discarded)"
                .to_string(),
        };
    }
    let idx = to_index.unwrap_or(0) as usize;
    let path = Path::new(crate::config::DEFAULT_PATH);
    if let Err(e) = restore_snapshot_index(path, idx) {
        return Response::Err {
            message: format!("rollback: {e}"),
        };
    }
    tracing::warn!(
        index = idx,
        "rollback: restored snapshot; triggering reload"
    );
    super::reload::handle_reload_async(state).await
}

/// RPC handler for `RollbackList`. Pure read — safe without a
/// confirm gate. Renders the list as one line per slot so
/// `oxctl rollback-list` can echo the response directly.
pub fn handle_rollback_list() -> Response {
    let path = Path::new(crate::config::DEFAULT_PATH);
    let snaps = list_snapshots(path);
    if snaps.is_empty() {
        return Response::Value {
            value: "no snapshots".to_string(),
        };
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut s = String::new();
    s.push_str("index  age         size   hostname\n");
    for snap in &snaps {
        let age_s = snap.mtime_secs.map(|m| now.saturating_sub(m)).unwrap_or(0);
        let age = format_age(age_s);
        s.push_str(&format!(
            "{:5}  {:10}  {:5}  {}\n",
            snap.index,
            age,
            snap.size_bytes,
            snap.hostname.as_deref().unwrap_or("?")
        ));
    }
    Response::Value { value: s }
}

fn format_age(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else if secs < 86400 {
        format!("{}h{:02}m", secs / 3600, (secs % 3600) / 60)
    } else {
        format!("{}d{:02}h", secs / 86400, (secs % 86400) / 3600)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_snapshot_populates_slot_0() {
        let tmp = tempfile::tempdir().unwrap();
        let public = tmp.path().join("oxwrt.toml");
        std::fs::write(&public, "hostname = \"a\"\n").unwrap();
        assert!(!has_snapshot(&public));
        take_snapshot(&public);
        assert!(has_snapshot(&public));
        let dir = snapshot_dir(&public);
        assert!(public_snap_path(&dir, 0).exists());
        assert!(!public_snap_path(&dir, 1).exists());
    }

    #[test]
    fn rotation_shifts_older_slots_down_the_ring() {
        let tmp = tempfile::tempdir().unwrap();
        let public = tmp.path().join("oxwrt.toml");
        // Three successful reloads → three distinct snapshots.
        for (i, h) in ["a", "b", "c"].iter().enumerate() {
            std::fs::write(&public, format!("hostname = \"{h}\"\n")).unwrap();
            take_snapshot(&public);
            // After iteration i, slot 0 is the latest write, slot
            // j (for j <= i) holds hostname from iteration i-j.
            let dir = snapshot_dir(&public);
            for j in 0..=i {
                let p = public_snap_path(&dir, j);
                let c = std::fs::read_to_string(&p).unwrap();
                let expected = ["a", "b", "c"][i - j];
                assert!(
                    c.contains(&format!("\"{expected}\"")),
                    "slot {j} after iter {i}: expected {expected}, got {c:?}"
                );
            }
        }
    }

    #[test]
    fn ring_drops_oldest_once_full() {
        let tmp = tempfile::tempdir().unwrap();
        let public = tmp.path().join("oxwrt.toml");
        // Take RING_SIZE+2 snapshots; verify only the most recent
        // RING_SIZE survive.
        for i in 0..(RING_SIZE + 2) {
            std::fs::write(&public, format!("hostname = \"h{i}\"\n")).unwrap();
            take_snapshot(&public);
        }
        let dir = snapshot_dir(&public);
        for j in 0..RING_SIZE {
            let p = public_snap_path(&dir, j);
            let c = std::fs::read_to_string(&p).unwrap();
            let expected = (RING_SIZE + 2 - 1) - j; // newest in slot 0
            assert!(
                c.contains(&format!("\"h{expected}\"")),
                "slot {j}: expected h{expected}, got {c:?}"
            );
        }
        // No slot beyond RING_SIZE-1 should exist.
        assert!(!public_snap_path(&dir, RING_SIZE).exists());
    }

    #[test]
    fn restore_index_0_is_the_default() {
        let tmp = tempfile::tempdir().unwrap();
        let public = tmp.path().join("oxwrt.toml");
        std::fs::write(&public, "hostname = \"snap\"\n").unwrap();
        take_snapshot(&public);
        std::fs::write(&public, "hostname = \"broken\"\n").unwrap();
        restore_snapshot(&public).unwrap();
        assert!(std::fs::read_to_string(&public).unwrap().contains("snap"));
    }

    #[test]
    fn restore_nonzero_index_picks_older_slot() {
        let tmp = tempfile::tempdir().unwrap();
        let public = tmp.path().join("oxwrt.toml");
        for h in ["old", "middle", "new"] {
            std::fs::write(&public, format!("hostname = \"{h}\"\n")).unwrap();
            take_snapshot(&public);
        }
        // Slot 0 = new, slot 1 = middle, slot 2 = old.
        restore_snapshot_index(&public, 2).unwrap();
        assert!(std::fs::read_to_string(&public).unwrap().contains("old"));
    }

    #[test]
    fn restore_out_of_range_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let public = tmp.path().join("oxwrt.toml");
        std::fs::write(&public, "hostname = \"x\"").unwrap();
        take_snapshot(&public);
        let err = restore_snapshot_index(&public, RING_SIZE).unwrap_err();
        assert!(err.contains("out of range"));
    }

    #[test]
    fn restore_missing_slot_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let public = tmp.path().join("oxwrt.toml");
        std::fs::write(&public, "hostname = \"x\"").unwrap();
        take_snapshot(&public);
        // Only slot 0 was populated; asking for slot 2 is a miss.
        let err = restore_snapshot_index(&public, 2).unwrap_err();
        assert!(err.contains("no snapshot at index 2"));
    }

    #[test]
    fn legacy_single_file_snapshot_migrates_on_next_take() {
        // Operator upgraded from the single-file shape. The
        // legacy files exist but no ring slots do. First
        // take_snapshot should preserve the legacy contents as
        // slot 1 (after the rotation shifts the migrated slot 0
        // to slot 1 and writes the new snapshot to slot 0).
        let tmp = tempfile::tempdir().unwrap();
        let public = tmp.path().join("oxwrt.toml");
        let legacy_pub = tmp.path().join(LEGACY_PUBLIC_SNAPSHOT);
        std::fs::write(&legacy_pub, "hostname = \"pre-upgrade\"\n").unwrap();
        std::fs::write(&public, "hostname = \"post-upgrade\"\n").unwrap();
        take_snapshot(&public);
        let dir = snapshot_dir(&public);
        // Slot 0 = the just-snapshotted live config
        let slot0 = std::fs::read_to_string(public_snap_path(&dir, 0)).unwrap();
        assert!(slot0.contains("post-upgrade"));
        // Slot 1 = the migrated legacy snapshot
        let slot1 = std::fs::read_to_string(public_snap_path(&dir, 1)).unwrap();
        assert!(slot1.contains("pre-upgrade"));
        // Legacy file is gone.
        assert!(!legacy_pub.exists());
    }

    #[test]
    fn list_snapshots_returns_one_entry_per_slot() {
        let tmp = tempfile::tempdir().unwrap();
        let public = tmp.path().join("oxwrt.toml");
        assert!(list_snapshots(&public).is_empty());
        for h in ["a", "b", "c"] {
            std::fs::write(&public, format!("hostname = \"{h}\"\n")).unwrap();
            take_snapshot(&public);
        }
        let snaps = list_snapshots(&public);
        assert_eq!(snaps.len(), 3);
        assert_eq!(snaps[0].index, 0);
        assert_eq!(snaps[0].hostname.as_deref(), Some("c"));
        assert_eq!(snaps[2].hostname.as_deref(), Some("a"));
        assert!(snaps[0].size_bytes > 0);
    }

    #[test]
    fn restore_clears_live_secrets_when_snapshot_has_none() {
        let tmp = tempfile::tempdir().unwrap();
        let public = tmp.path().join("oxwrt.toml");
        let secrets = tmp.path().join("oxwrt.secrets.toml");
        std::fs::write(&public, "hostname = \"old\"\n").unwrap();
        take_snapshot(&public); // no secrets at snapshot time
        std::fs::write(&public, "hostname = \"new\"\n").unwrap();
        std::fs::write(&secrets, "[[wifi]]\nssid = \"s\"\npassphrase = \"x\"\n").unwrap();
        restore_snapshot(&public).unwrap();
        assert!(!secrets.exists());
    }

    #[test]
    fn live_matches_slot_0() {
        let tmp = tempfile::tempdir().unwrap();
        let public = tmp.path().join("oxwrt.toml");
        std::fs::write(&public, "hostname = \"x\"\n").unwrap();
        take_snapshot(&public);
        assert!(live_matches_snapshot(&public));
        std::fs::write(&public, "hostname = \"y\"\n").unwrap();
        assert!(!live_matches_snapshot(&public));
    }

    #[test]
    fn format_age_variants() {
        assert_eq!(format_age(3), "3s");
        assert_eq!(format_age(120), "2m");
        assert_eq!(format_age(3_700), "1h01m");
        assert_eq!(format_age(90_000), "1d01h");
    }
}
