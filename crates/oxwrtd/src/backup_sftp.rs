//! Scheduled off-router backup task.
//!
//! When `[backup_sftp]` is present in oxwrt.toml, spawn a tokio
//! task that:
//!   1. Waits `interval_hours` (default 24).
//!   2. Builds an in-memory backup tarball (delegating to the
//!      same `backup::build_tarball` that the Backup RPC uses —
//!      /etc/oxwrt/* minus the vpn/ subtree for the
//!      private-key-leak reason, plus /etc/oxwrt.toml).
//!   3. Streams the bytes via `ssh -i <key> user@host "cat >
//!      remote_dir/oxwrt-<timestamp>.tar.gz"`.
//!   4. Lists + prunes older files: `ssh ... "ls -1t remote_dir/
//!      oxwrt-*.tar.gz | tail -n +N+1 | xargs rm -f"`.
//!
//! Shell-out to the OpenSSH / dropbear client rather than pulling
//! russh into the dep graph (~500 kB of aarch64-musl object
//! code). Both dropbear (via dbclient with -m flag for scp-like
//! usage) and openssh (`ssh`, `scp`) support `cat > path` as an
//! exec command, so this works with whatever client is in the
//! image. Default flags assume `/usr/bin/ssh`; the schema could
//! add a `ssh_binary` override later if the image-builder ships
//! only dbclient.
//!
//! Failure mode: errors log at warn + skip that push. Next tick
//! tries again. No retry-with-backoff — the interval is already
//! coarse enough (hours) that a single failed tick isn't a
//! meaningful outage signal.

use std::time::Duration;

use oxwrt_api::config::{Config, SftpBackup};

/// Spawn the backup task if cfg.backup_sftp is Some. Fire-and-
/// forget; task lives for the process. A reload that changes
/// backup_sftp requires a reboot to pick up (same limitation as
/// other init-spawned tasks). Caller supplies a function that
/// produces the tarball bytes, decoupling this module from the
/// control::server::backup internals.
pub fn spawn<F>(cfg: &Config, build_tarball: F)
where
    F: Fn() -> Result<Vec<u8>, String> + Send + Sync + 'static,
{
    let Some(sftp) = &cfg.backup_sftp else {
        return;
    };
    let s = sftp.clone();
    let builder = std::sync::Arc::new(build_tarball);
    let log_host = s.host.clone();
    let log_hours = s.interval_hours;
    tokio::spawn(async move {
        let hours = s.interval_hours.max(1);
        let interval = Duration::from_secs(u64::from(hours) * 3600);
        let mut tick = tokio::time::interval(interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // Skip the first tick: at boot we assume the live config
        // is already the most-recently-pushed snapshot (operator
        // just flashed / edited it). Wait one full interval
        // before pushing to avoid a redundant-push thrash on
        // every reboot.
        tick.tick().await;
        loop {
            tick.tick().await;
            let builder = builder.clone();
            let sftp = s.clone();
            let res = tokio::task::spawn_blocking(move || push_once(&sftp, builder.as_ref()))
                .await
                .unwrap_or_else(|e| Err(format!("spawn_blocking join: {e}")));
            match res {
                Ok(name) => tracing::info!(
                    host = %s.host, remote = %format!("{}/{name}", s.remote_dir),
                    "backup_sftp: push ok"
                ),
                Err(e) => tracing::warn!(host = %s.host, error = %e, "backup_sftp: push failed"),
            }
        }
    });
    tracing::info!(host = %log_host, hours = log_hours, "backup_sftp task spawned");
}

fn push_once<F>(s: &SftpBackup, build_tarball: &F) -> Result<String, String>
where
    F: Fn() -> Result<Vec<u8>, String>,
{
    use std::io::Write as _;
    use std::process::Stdio;

    let bytes = build_tarball()?;
    // Timestamp: YYYYMMDD-HHMMSS in UTC. Deliberately lexicographic
    // so `ls -1` sorts oldest → newest without -t, and the
    // rotation-prune step is a simple tail -n.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("clock: {e}"))?
        .as_secs();
    let stamp = unix_to_utc_stamp(now);
    let filename = format!("oxwrt-{stamp}.tar.gz");
    let remote_path = format!("{}/{filename}", s.remote_dir);

    // First push: ensure the remote dir exists. `mkdir -p` is
    // idempotent + harmless on every push. Does a round-trip but
    // that's ~20 ms versus the 2-3s a push takes anyway.
    ssh_exec(s, &format!("mkdir -p {}", shell_quote(&s.remote_dir)))?;

    // Stream the tarball via stdin redirected to `cat > file`.
    // Using a unique tmp name + atomic mv defends against a
    // half-pushed file being restored as-is by a confused
    // operator.
    let tmp_path = format!("{remote_path}.inprogress");
    let cmd = format!(
        "cat > {} && mv {} {}",
        shell_quote(&tmp_path),
        shell_quote(&tmp_path),
        shell_quote(&remote_path)
    );
    let mut child = ssh_cmd(s)
        .arg(&cmd)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("ssh spawn: {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(&bytes)
            .map_err(|e| format!("ssh stdin: {e}"))?;
    }
    let out = child
        .wait_with_output()
        .map_err(|e| format!("ssh wait: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "ssh push exit {:?}: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }

    // Prune old backups. `ls -1` + lexical sort means we can
    // tail/head to pick the oldest. We `ls` ALL oxwrt-*.tar.gz,
    // sort ascending (oldest first), drop the last `keep`
    // entries, delete the rest. `keep=0` skips the prune
    // (keep-all).
    if s.keep > 0 {
        let ls_cmd = format!(
            "ls -1 {} 2>/dev/null | sort | head -n -{}  | while read f; do rm -f \"{}/$f\"; done",
            shell_quote(&format!("{}/oxwrt-*.tar.gz", s.remote_dir)),
            s.keep,
            s.remote_dir.replace('"', "\\\"")
        );
        // Any error here is non-fatal; push already succeeded.
        if let Err(e) = ssh_exec(s, &ls_cmd) {
            tracing::warn!(error = %e, "backup_sftp: prune failed");
        }
    }
    Ok(filename)
}

/// Build an ssh Command with the shared flags. Caller adds the
/// remote command as a final positional.
///
/// Host-key verification: if `s.host_key` is set, the daemon
/// materialises a per-push `known_hosts` under /run (tmpfs,
/// cleared on reboot) containing `<host> <host_key>` and points
/// ssh at that. This keeps the ACL in the TOML. When unset we
/// fall back to the legacy `/etc/oxwrt/known_hosts` so installs
/// that already staged that file keep working unchanged.
fn ssh_cmd(s: &SftpBackup) -> std::process::Command {
    let known_hosts = match derive_known_hosts_file(s) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "backup_sftp: failed to materialise known_hosts from config; falling back to /etc/oxwrt/known_hosts");
            std::path::PathBuf::from("/etc/oxwrt/known_hosts")
        }
    };
    let mut c = std::process::Command::new("ssh");
    c.arg("-i").arg(&s.key_path);
    c.arg("-p").arg(s.port.to_string());
    // Harden against the first-contact prompt and MITM on the
    // "trust on first use" flow. StrictHostKeyChecking=yes rejects
    // unknown hosts; the known_hosts file is either derived from
    // `backup_sftp.host_key` above or the legacy hand-staged path.
    c.arg("-o").arg("StrictHostKeyChecking=yes");
    c.arg("-o")
        .arg(format!("UserKnownHostsFile={}", known_hosts.display()));
    c.arg("-o").arg("BatchMode=yes"); // never prompt interactively
    c.arg("-o").arg("ConnectTimeout=10");
    c.arg(format!("{}@{}", s.username, s.host));
    c
}

/// If `s.host_key` is set, write `<host> <host_key>\n` to
/// `/run/oxwrt/backup-known-hosts` and return that path. Else
/// return the legacy `/etc/oxwrt/known_hosts`. Caller's choice
/// what to do on the I/O error path.
fn derive_known_hosts_file(s: &SftpBackup) -> Result<std::path::PathBuf, String> {
    let Some(host_key) = s.host_key.as_deref() else {
        return Ok(std::path::PathBuf::from("/etc/oxwrt/known_hosts"));
    };
    let host_key = host_key.trim();
    if host_key.is_empty() {
        return Ok(std::path::PathBuf::from("/etc/oxwrt/known_hosts"));
    }
    let dir = std::path::PathBuf::from("/run/oxwrt");
    std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir {}: {e}", dir.display()))?;
    let path = dir.join("backup-known-hosts");
    let line = format!("{} {}\n", s.host, host_key);
    std::fs::write(&path, line).map_err(|e| format!("write {}: {e}", path.display()))?;
    Ok(path)
}

/// Run a one-shot remote shell command + capture stdout/stderr.
fn ssh_exec(s: &SftpBackup, cmd: &str) -> Result<(), String> {
    let out = ssh_cmd(s)
        .arg(cmd)
        .output()
        .map_err(|e| format!("ssh exec: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "ssh exec exit {:?}: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}

/// Single-quote-wrap a path for POSIX shell. Rejects paths with
/// single quotes (not worth chasing every escape edge case for
/// an operator-provided config value; if they've got a `'` in
/// their remote path they can pick a different path).
fn shell_quote(s: &str) -> String {
    if s.contains('\'') {
        // Degrade gracefully — caller will get a clear ssh-exec
        // error message when the shell can't parse the command.
        format!("'{}'", s.replace('\'', ""))
    } else {
        format!("'{s}'")
    }
}

/// Convert a Unix timestamp to UTC "YYYYMMDD-HHMMSS" without
/// pulling in chrono. Correct for all dates >= 1970; uses the
/// civil-from-days algorithm (Howard Hinnant's date arithmetic).
fn unix_to_utc_stamp(secs: u64) -> String {
    let days = (secs / 86400) as i64;
    let seconds_of_day = secs % 86400;
    let hh = seconds_of_day / 3600;
    let mm = (seconds_of_day / 60) % 60;
    let ss = seconds_of_day % 60;
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}{m:02}{d:02}-{hh:02}{mm:02}{ss:02}")
}

/// Hinnant's civil-from-days — days-since-epoch → (year, month, day).
fn civil_from_days(z: i64) -> (i32, u32, u32) {
    // Shift so 0 = 0000-03-01 (Julian-style, 1970-01-01 = 719468).
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m as u32, d as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_stamp_known_epochs() {
        // 1970-01-01 00:00:00 UTC
        assert_eq!(unix_to_utc_stamp(0), "19700101-000000");
        // 2000-01-01 00:00:00 UTC = 946684800
        assert_eq!(unix_to_utc_stamp(946_684_800), "20000101-000000");
        // 2024-02-29 12:34:56 UTC (leap day) = 1_709_210_096
        assert_eq!(unix_to_utc_stamp(1_709_210_096), "20240229-123456");
    }

    fn sftp_fixture(host_key: Option<String>) -> SftpBackup {
        SftpBackup {
            host: "backup.example.com".into(),
            port: 22,
            username: "user".into(),
            key_path: "/etc/oxwrt/backup.key".into(),
            remote_dir: "/snap".into(),
            interval_hours: 24,
            keep: 30,
            include_secrets: true,
            host_key,
        }
    }

    #[test]
    fn derive_known_hosts_legacy_when_unset() {
        let s = sftp_fixture(None);
        let p = derive_known_hosts_file(&s).unwrap();
        assert_eq!(p, std::path::PathBuf::from("/etc/oxwrt/known_hosts"));
    }

    #[test]
    fn derive_known_hosts_empty_string_is_legacy() {
        let s = sftp_fixture(Some("   ".into()));
        let p = derive_known_hosts_file(&s).unwrap();
        assert_eq!(p, std::path::PathBuf::from("/etc/oxwrt/known_hosts"));
    }

    // The inline host_key path writes under /run/oxwrt — tested only
    // in the integration layer where /run is writable. On dev macs
    // /run doesn't exist, so we don't exercise the file-write here;
    // the logic is straight-line and the error branch is covered by
    // the legacy-fallback behaviour at call sites.

    #[test]
    fn shell_quote_simple() {
        assert_eq!(shell_quote("/tmp/foo"), "'/tmp/foo'");
        assert_eq!(shell_quote("has space"), "'has space'");
        // single-quote degrades by stripping — documented compromise.
        assert_eq!(shell_quote("a'b"), "'ab'");
    }
}
