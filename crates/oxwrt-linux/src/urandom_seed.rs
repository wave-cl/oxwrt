//! Persistent urandom seed — preserve kernel entropy pool state
//! across reboots so early-boot cryptographic operations
//! (hostapd SAE nonce, sQUIC ed25519 random, DHCP xid) draw from
//! a warm CRNG instead of an unseeded one.
//!
//! # Problem
//!
//! The kernel's CRNG takes a few seconds after boot to reach
//! "full entropy" on embedded devices — there's no on-die RNG
//! on MT7986 that the kernel trusts at level 256. Meanwhile
//! oxwrtd fires its first crypto operations within ~100 ms of
//! pid 1. Without a persisted seed the first random draws come
//! from a CRNG that's still accumulating jitter/interrupt
//! entropy. Symptom: dmesg shows
//! "urandom-seed: Seed file not found (/etc/urandom.seed)" on
//! first boot after a clean flash.
//!
//! # Design
//!
//! Two halves. The LOAD half already lives in
//! `/lib/preinit/81_urandom_seed` (shipped via the imagebuilder
//! overlay): reads /etc/urandom.seed and cats it into
//! /dev/urandom at preinit. This module is the SAVE half.
//!
//! Save strategy: a tokio task dumps 512 random bytes to
//! /etc/urandom.seed atomically (write temp + rename) on boot
//! + every `SAVE_INTERVAL` (30 min). Periodic saves guarantee
//! that unexpected power-cycles cost at most 30 min of freshness
//! — operators yanking the plug is the common case on a
//! residential router and we can't hook graceful shutdown for
//! that.
//!
//! /etc/urandom.seed is preserved across sysupgrade via
//! sysupgrade.conf's default keep list; that's why we use that
//! path rather than /etc/oxwrt/urandom.seed (where we'd have to
//! add it to the keep list manually).
//!
//! # First-boot bootstrap
//!
//! First boot has no seed file → the stock preinit logs "Seed
//! file not found" and skips. Our first save (30 s after
//! oxwrtd spawn) creates one for the next boot. That's fine:
//! on a truly fresh device there's no prior-boot secret to
//! protect, and 30 s of runtime collects enough jitter
//! entropy that the save value is genuinely unpredictable.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

// Path lives under /etc/oxwrt/ so it's preserved across
// sysupgrade — our shipped /etc/sysupgrade.conf already keeps
// /etc/oxwrt/ as a single entry, avoiding a separate config
// file add for this one path. The matching preinit loader
// (/lib/preinit/81_urandom_seed) is updated in lockstep.
const SEED_PATH: &str = "/etc/oxwrt/urandom.seed";
const SEED_SIZE: usize = 512;
const SAVE_INTERVAL: Duration = Duration::from_secs(30 * 60); // 30 min
const INITIAL_DELAY: Duration = Duration::from_secs(30);

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Atomically save `SEED_SIZE` bytes from /dev/urandom to
/// `SEED_PATH`. Write goes to `<path>.tmp` first, then rename —
/// so a crash/power-cycle mid-save leaves the previous seed
/// intact rather than a truncated file.
pub fn save() -> Result<(), Error> {
    save_to(Path::new(SEED_PATH))
}

fn save_to(path: &Path) -> Result<(), Error> {
    // Read random bytes from /dev/urandom. std::fs::read works
    // here because urandom always returns the requested length
    // (no short reads at this size).
    let mut seed = vec![0u8; SEED_SIZE];
    {
        use std::io::Read;
        let mut f = std::fs::File::open("/dev/urandom")?;
        f.read_exact(&mut seed)?;
    }

    // Write to <path>.tmp with mode 0600 so an observer on the
    // filesystem can't read the seed (which would compromise
    // downstream entropy draws). The rename below is atomic on
    // the same filesystem.
    let tmp_path: PathBuf = match path.file_name() {
        Some(name) => {
            let mut p = path.to_path_buf();
            p.set_file_name(format!("{}.tmp", name.to_string_lossy()));
            p
        }
        None => {
            return Err(Error::Io(std::io::Error::other(
                "seed path has no filename",
            )));
        }
    };

    // Ensure the parent dir exists — on a fresh flash with a
    // sparse overlay, /etc may be present but unusual paths
    // under /etc/oxwrt might not be. Also ensure owner-only
    // access on the directory isn't needed — /etc is world-read
    // on OpenWrt by convention.
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp_path)?;
        f.write_all(&seed)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp_path, path)?;

    // fsync the parent directory so the rename's metadata entry
    // is on-disk before we return. Without this, a crash/reboot
    // between rename() and the next periodic fs checkpoint can
    // leave the directory entry pointing at nothing — observed
    // on Flint 2's f2fs+overlay where sync(2) from the reboot
    // handler wasn't enough to commit the rename.
    if let Some(parent) = path.parent() {
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }

    tracing::debug!(path = %path.display(), bytes = SEED_SIZE, "urandom seed saved");
    Ok(())
}

/// Spawn the periodic saver. Returns the JoinHandle so the
/// caller can abort on shutdown if it wants (we don't today —
/// the task is cheap and surviving past process exit is OK).
///
/// Timeline:
///   t+30s            first save (bootstraps /etc/urandom.seed
///                    on a clean-flash system where preinit
///                    logged "Seed file not found")
///   t+30s+30min      second save
///   t+30s+60min      third save
///   ...
pub fn spawn_saver() -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        tokio::time::sleep(INITIAL_DELAY).await;
        loop {
            match save() {
                Ok(()) => tracing::info!(
                    path = SEED_PATH,
                    interval_s = SAVE_INTERVAL.as_secs(),
                    "urandom seed: saved"
                ),
                Err(e) => tracing::warn!(error = %e, "urandom seed: save failed"),
            }
            tokio::time::sleep(SAVE_INTERVAL).await;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn save_writes_expected_size_and_is_readable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("seed");
        save_to(&path).unwrap();

        let mut buf = Vec::new();
        std::fs::File::open(&path)
            .unwrap()
            .read_to_end(&mut buf)
            .unwrap();
        assert_eq!(buf.len(), SEED_SIZE);

        // Two consecutive saves must differ — proves we're
        // reading fresh bytes from /dev/urandom each time, not
        // caching a stale seed.
        let first = buf.clone();
        save_to(&path).unwrap();
        let mut second = Vec::new();
        std::fs::File::open(&path)
            .unwrap()
            .read_to_end(&mut second)
            .unwrap();
        assert_ne!(first, second, "two saves must produce different seeds");
    }

    #[test]
    fn save_creates_parent_dir() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("subdir").join("seed");
        save_to(&path).unwrap();
        assert!(path.exists(), "create_dir_all must materialize parents");
    }

    #[test]
    fn save_is_atomic_replaces_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("seed");
        // Seed the path with a known marker — the save must
        // replace it entirely, not append/mix.
        std::fs::write(&path, b"OLD").unwrap();
        save_to(&path).unwrap();
        let content = std::fs::read(&path).unwrap();
        assert_eq!(content.len(), SEED_SIZE);
        assert_ne!(&content[..3], b"OLD", "old content must be replaced");
        // Temp file must not linger after a successful rename.
        let tmp = dir.path().join("seed.tmp");
        assert!(!tmp.exists(), "tmp file must be renamed away");
    }

    #[test]
    fn save_file_mode_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("seed");
        save_to(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "seed readable by anyone would defeat the point"
        );
    }
}
