//! IP blocklist manager — fetches CIDR lists from HTTP URLs and
//! installs them as nftables named sets in a dedicated
//! `oxwrt-blocklist` table, with drop rules on INPUT. Equivalent to
//! OpenWrt's `banip` package for the common use case ("just drop
//! everything on the firehol_level1 list").
//!
//! # Design
//!
//! Two layers:
//! 1. **Table**: a separate `inet oxwrt-blocklist` table hook-prio-
//!    before the main `oxwrt` table's INPUT (priority -10 vs 0), so
//!    matches short-circuit without touching the main ruleset.
//!    Keeping it in its own table means `net::install_firewall` is
//!    untouched and a blocklist reload doesn't clobber main rules.
//! 2. **Sets**: one `ipv4_addr/cidr` named set per blocklist, kept
//!    up to date by a per-list tokio task.
//!
//! # Fail-open on fetch failure
//!
//! Cold boot before WAN is up, or a CDN outage, would otherwise
//! block boot indefinitely or drop clients on an empty set. We log
//! warn and install an empty set — security posture is slightly
//! worse until the first successful fetch, but the alternative is
//! "no internet at all" which is strictly worse for operators.
//!
//! # Refresh cadence
//!
//! Per-list `refresh_seconds` (default 24h). Default is deliberately
//! slow because public lists update on the hour at most and most
//! operators don't want to re-download firehol 900 times a minute.
//! The task respects the new interval on reload — it spawns a fresh
//! task per list each boot, and old tasks are abandoned when the
//! per-list JoinHandle goes out of scope.

use std::collections::HashSet;
use std::io::Write;
use std::net::Ipv4Addr;
use std::process::{Command, Stdio};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use oxwrt_api::config::{Blocklist, Config};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("http: {0}")]
    Http(String),
    #[error("nft: {0}")]
    Nft(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Install the full blocklist table at boot. Synchronous best-effort
/// fetch of each list with a short timeout — failures log warn and
/// install an empty set for that list. Called once from init::run
/// before the refresher task spawns, so the first install doesn't
/// race with a background update.
pub async fn install(cfg: &Config) -> Result<(), Error> {
    if cfg.blocklists.is_empty() {
        // Nothing to install, and no table to flush — if a previous
        // boot had blocklists and they were removed via reload, the
        // reload handler is responsible for dropping the table.
        return Ok(());
    }

    let client = reqwest::Client::builder()
        .user_agent(concat!("oxwrtd/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| Error::Http(e.to_string()))?;

    let mut entries: Vec<(String, Vec<(Ipv4Addr, u8)>)> = Vec::new();
    for bl in &cfg.blocklists {
        match fetch_and_parse(&client, bl).await {
            Ok(cidrs) => {
                tracing::info!(
                    name = %bl.name, url = %bl.url, count = cidrs.len(),
                    "blocklist: fetched"
                );
                crate::metrics_state::record_blocklist_fetch(
                    &bl.name,
                    "ok",
                    Some(cidrs.len()),
                );
                entries.push((bl.name.clone(), cidrs));
            }
            Err(e) => {
                tracing::warn!(
                    name = %bl.name, url = %bl.url, error = %e,
                    "blocklist: fetch failed, installing empty set"
                );
                crate::metrics_state::record_blocklist_fetch(&bl.name, "http_error", Some(0));
                entries.push((bl.name.clone(), Vec::new()));
            }
        }
    }

    apply_nft(&cfg.blocklists, &entries)
}

/// Spawn one refresher task per blocklist. Each task sleeps for
/// `refresh_seconds`, fetches its URL, and updates just its own
/// set via `nft flush set … ; add element …` — so a slow list
/// doesn't hold up a fast one.
pub fn spawn_refreshers(cfg: Arc<Config>) -> Vec<tokio::task::JoinHandle<()>> {
    if cfg.blocklists.is_empty() {
        return Vec::new();
    }
    let client = match reqwest::Client::builder()
        .user_agent(concat!("oxwrtd/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "blocklist: client build failed; refresh disabled");
            return Vec::new();
        }
    };

    let mut handles = Vec::with_capacity(cfg.blocklists.len());
    for bl in &cfg.blocklists {
        let bl = bl.clone();
        let client = client.clone();
        handles.push(tokio::spawn(async move {
            let interval = Duration::from_secs(bl.refresh_seconds.max(60));
            loop {
                tokio::time::sleep(interval).await;
                match fetch_and_parse(&client, &bl).await {
                    Ok(cidrs) => {
                        let count = cidrs.len();
                        if let Err(e) = update_set(&bl.name, &cidrs) {
                            tracing::warn!(name = %bl.name, error = %e, "blocklist: set update failed");
                            // nft apply failed: treat like a parse
                            // error for metrics — we didn't end up
                            // with fresh entries installed.
                            crate::metrics_state::record_blocklist_fetch(
                                &bl.name,
                                "parse_error",
                                None,
                            );
                        } else {
                            tracing::info!(name = %bl.name, count, "blocklist: refreshed");
                            crate::metrics_state::record_blocklist_fetch(
                                &bl.name,
                                "ok",
                                Some(count),
                            );
                        }
                    }
                    Err(e) => {
                        tracing::warn!(name = %bl.name, error = %e, "blocklist: refresh fetch failed");
                        crate::metrics_state::record_blocklist_fetch(
                            &bl.name,
                            "http_error",
                            None,
                        );
                    }
                }
            }
        }));
    }
    handles
}

async fn fetch_and_parse(
    client: &reqwest::Client,
    bl: &Blocklist,
) -> Result<Vec<(Ipv4Addr, u8)>, Error> {
    let resp = client
        .get(&bl.url)
        .send()
        .await
        .map_err(|e| Error::Http(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(Error::Http(format!("status {}", resp.status())));
    }
    let body = resp
        .text()
        .await
        .map_err(|e| Error::Http(e.to_string()))?;
    Ok(parse_cidr_list(&body))
}

/// Parse a plaintext CIDR list (one per line, `#` comments, inline
/// `;` comments, blank lines ignored). Bare IPs without /prefix are
/// treated as /32. Silently skips invalid lines — we don't want a
/// single bad entry in a 900-line list to leave us with no
/// blocklist at all; the count tracing above lets operators notice
/// if parsing broke.
fn parse_cidr_list(body: &str) -> Vec<(Ipv4Addr, u8)> {
    let mut out: Vec<(Ipv4Addr, u8)> = Vec::new();
    let mut seen: HashSet<(Ipv4Addr, u8)> = HashSet::new();
    for line in body.lines() {
        // Strip comments and trim.
        let cleaned = line.split('#').next().unwrap_or("").trim();
        let cleaned = cleaned.split(';').next().unwrap_or("").trim();
        if cleaned.is_empty() {
            continue;
        }
        // Take the first token — some list formats append extra
        // columns separated by whitespace.
        let token = cleaned.split_whitespace().next().unwrap_or("");
        if token.is_empty() {
            continue;
        }
        let (addr_str, prefix) = match token.split_once('/') {
            Some((a, p)) => {
                let Ok(p) = p.parse::<u8>() else {
                    continue;
                };
                if p > 32 {
                    continue;
                }
                (a, p)
            }
            None => (token, 32),
        };
        let Ok(addr) = Ipv4Addr::from_str(addr_str) else {
            continue;
        };
        // Normalise the network address (zero the host bits) so we
        // don't install "1.2.3.4/16" and "1.2.0.0/16" as two
        // different entries.
        let mask: u32 = if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        };
        let net = Ipv4Addr::from(u32::from(addr) & mask);
        if seen.insert((net, prefix)) {
            out.push((net, prefix));
        }
    }
    out
}

/// Full nft -f install: create the table + chain + one set per
/// blocklist + one drop rule per set. Idempotent — the `delete
/// table … ; add table …` idiom at the top wipes any prior install
/// so reloads converge cleanly.
fn apply_nft(
    blocklists: &[Blocklist],
    entries: &[(String, Vec<(Ipv4Addr, u8)>)],
) -> Result<(), Error> {
    run_nft_script(&build_install_script(blocklists, entries))
}

/// Pure script builder — extracted from `apply_nft` so unit tests
/// can pin the exact nft syntax without invoking the nft binary.
/// A regression in the priority, hook, set flags, or rule ordering
/// would break silently in production (drops not firing, main
/// table clobbered). This function being pure means those changes
/// are caught at `cargo test` time.
pub(crate) fn build_install_script(
    blocklists: &[Blocklist],
    entries: &[(String, Vec<(Ipv4Addr, u8)>)],
) -> String {
    let mut script = String::with_capacity(4096);
    script.push_str("table inet oxwrt-blocklist { }\n");
    script.push_str("delete table inet oxwrt-blocklist\n");
    script.push_str("table inet oxwrt-blocklist {\n");

    for (bl, (_, cidrs)) in blocklists.iter().zip(entries.iter()) {
        script.push_str(&format!(
            "  set {} {{ type ipv4_addr; flags interval;",
            nft_ident(&bl.name)
        ));
        if !cidrs.is_empty() {
            script.push_str(" elements = { ");
            let mut first = true;
            for (addr, prefix) in cidrs {
                if !first {
                    script.push_str(", ");
                }
                script.push_str(&format!("{addr}/{prefix}"));
                first = false;
            }
            script.push_str(" }");
        }
        script.push_str(" }\n");
    }

    // Chain hooked at priority -10 so it runs before the main
    // `oxwrt` filter table's INPUT (priority 0). ip saddr @set drop
    // for each configured blocklist.
    script.push_str(
        "  chain input {\n    type filter hook input priority -10; policy accept;\n",
    );
    for bl in blocklists {
        script.push_str(&format!(
            "    ip saddr @{} drop\n",
            nft_ident(&bl.name)
        ));
    }
    script.push_str("  }\n");
    script.push_str("}\n");
    script
}

/// Narrow atomic update for a single set: flush then add elements.
/// Used by the refresher task — no other set or rule is touched, so
/// a slow refresh on one list doesn't jitter rule evaluation on
/// another.
fn update_set(name: &str, cidrs: &[(Ipv4Addr, u8)]) -> Result<(), Error> {
    run_nft_script(&build_update_script(name, cidrs))
}

/// Pure builder for the narrow per-set update. Same rationale as
/// `build_install_script` — tested at the string level.
pub(crate) fn build_update_script(name: &str, cidrs: &[(Ipv4Addr, u8)]) -> String {
    let mut script = String::with_capacity(256 + cidrs.len() * 20);
    script.push_str(&format!(
        "flush set inet oxwrt-blocklist {}\n",
        nft_ident(name)
    ));
    if !cidrs.is_empty() {
        script.push_str(&format!(
            "add element inet oxwrt-blocklist {} {{ ",
            nft_ident(name)
        ));
        let mut first = true;
        for (addr, prefix) in cidrs {
            if !first {
                script.push_str(", ");
            }
            script.push_str(&format!("{addr}/{prefix}"));
            first = false;
        }
        script.push_str(" }\n");
    }
    script
}

fn run_nft_script(script: &str) -> Result<(), Error> {
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    {
        let stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| Error::Nft("stdin not captured".into()))?;
        stdin.write_all(script.as_bytes())?;
    }
    let out = child.wait_with_output()?;
    if !out.status.success() {
        return Err(Error::Nft(format!(
            "nft exit {:?}: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

/// Conservative nft identifier sanitiser. nft set names must match
/// `[A-Za-z_][A-Za-z0-9_]*`; we replace anything else with `_`. The
/// config field already constrains to something sensible in
/// practice but this protects against surprises (Unicode, hyphens).
fn nft_ident(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for (i, c) in s.chars().enumerate() {
        let ok = if i == 0 {
            c.is_ascii_alphabetic() || c == '_'
        } else {
            c.is_ascii_alphanumeric() || c == '_'
        };
        out.push(if ok { c } else { '_' });
    }
    if out.is_empty() {
        "bl".to_string()
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_skips_comments_and_blanks() {
        let body = "\
            # firehol_level1\n\
            \n\
            1.2.3.0/24\n\
            ; also blocked\n\
            5.6.7.8\n\
            not-an-ip\n\
            1.2.3.0/24\n\
            ";
        let out = parse_cidr_list(body);
        assert_eq!(
            out,
            vec![
                (Ipv4Addr::new(1, 2, 3, 0), 24),
                (Ipv4Addr::new(5, 6, 7, 8), 32),
            ],
            "dup + invalid lines should collapse"
        );
    }

    #[test]
    fn parse_normalises_host_bits() {
        let body = "1.2.3.4/16\n";
        let out = parse_cidr_list(body);
        assert_eq!(out, vec![(Ipv4Addr::new(1, 2, 0, 0), 16)]);
    }

    #[test]
    fn parse_rejects_oversize_prefix() {
        let body = "1.2.3.4/99\n";
        assert!(parse_cidr_list(body).is_empty());
    }

    #[test]
    fn nft_ident_sanitises() {
        assert_eq!(nft_ident("firehol_level1"), "firehol_level1");
        assert_eq!(nft_ident("my-list"), "my_list");
        assert_eq!(nft_ident("1badstart"), "_badstart");
        assert_eq!(nft_ident(""), "bl");
    }

    #[test]
    fn default_refresh_is_daily() {
        let toml = r#"
name = "fh"
url = "http://example.com/list.txt"
"#;
        let bl: Blocklist = toml::from_str(toml).unwrap();
        assert_eq!(bl.refresh_seconds, 86400);
        assert!(bl.zones.is_empty());
    }

    // ── Pure script-builder tests: lock down the exact nft syntax ──

    fn sample_bl(name: &str) -> Blocklist {
        Blocklist {
            name: name.into(),
            url: "http://example.com/list.txt".into(),
            refresh_seconds: 86400,
            zones: vec![],
        }
    }

    /// The install script MUST start with `delete table ; add table`
    /// (the atomic-swap idiom). A change to emit `flush table` or
    /// plain `add` would leave stale rules around across reloads.
    #[test]
    fn install_script_uses_delete_then_add() {
        let bl = vec![sample_bl("fh")];
        let entries = vec![(
            "fh".to_string(),
            vec![(Ipv4Addr::new(1, 2, 3, 0), 24)],
        )];
        let s = build_install_script(&bl, &entries);
        assert!(s.contains("table inet oxwrt-blocklist { }\n"));
        assert!(s.contains("delete table inet oxwrt-blocklist\n"));
        assert!(
            s.find("delete table").unwrap() < s.find("chain input").unwrap(),
            "delete must precede the chain definition"
        );
    }

    /// Priority -10 + hook input. If either drifts, matches no
    /// longer short-circuit before the main oxwrt table — security
    /// regression.
    #[test]
    fn install_script_hook_priority_is_minus_10() {
        let bl = vec![sample_bl("fh")];
        let entries = vec![("fh".to_string(), vec![])];
        let s = build_install_script(&bl, &entries);
        assert!(s.contains("type filter hook input priority -10; policy accept;"));
    }

    /// `flags interval` is required on the set because we insert
    /// CIDRs (ranges) rather than individual IPs. Without it the
    /// nft parser rejects the `elements = { 1.2.3.0/24 }` syntax.
    #[test]
    fn install_script_set_uses_interval_flags() {
        let bl = vec![sample_bl("fh")];
        let entries = vec![(
            "fh".to_string(),
            vec![(Ipv4Addr::new(1, 2, 3, 0), 24)],
        )];
        let s = build_install_script(&bl, &entries);
        assert!(s.contains("flags interval"));
        assert!(s.contains("1.2.3.0/24"));
    }

    /// One drop rule per blocklist, each saddr-matched to its own
    /// named set via @ident. Tests that multiple blocklists don't
    /// silently collapse to one rule (previous bug: emitted one rule
    /// per iteration of the wrong loop).
    #[test]
    fn install_script_emits_one_drop_rule_per_list() {
        let bls = vec![sample_bl("a"), sample_bl("b"), sample_bl("c")];
        let entries = vec![
            ("a".to_string(), vec![]),
            ("b".to_string(), vec![]),
            ("c".to_string(), vec![]),
        ];
        let s = build_install_script(&bls, &entries);
        assert_eq!(
            s.matches("ip saddr @").count(),
            3,
            "expected 3 drop rules, script:\n{s}"
        );
        assert!(s.contains("ip saddr @a drop"));
        assert!(s.contains("ip saddr @b drop"));
        assert!(s.contains("ip saddr @c drop"));
    }

    /// Empty set still produces a valid `set foo { type … flags … }`
    /// block (no `elements = {}`, which nft rejects as empty).
    #[test]
    fn install_script_empty_set_omits_elements_clause() {
        let bl = vec![sample_bl("fh")];
        let entries = vec![("fh".to_string(), vec![])];
        let s = build_install_script(&bl, &entries);
        assert!(s.contains("set fh { type ipv4_addr; flags interval; }"));
        assert!(!s.contains("elements = {"), "empty elements clause: {s}");
    }

    /// Zero blocklists: script still emits a valid empty table +
    /// chain. We don't currently call the installer with empty
    /// input (install() short-circuits), but defensive — the pure
    /// function shouldn't panic or emit malformed nft.
    #[test]
    fn install_script_with_no_lists_is_valid() {
        let s = build_install_script(&[], &[]);
        assert!(s.contains("table inet oxwrt-blocklist {"));
        assert!(s.contains("chain input"));
        assert_eq!(s.matches("ip saddr @").count(), 0);
    }

    // --- update_set ---

    #[test]
    fn update_script_flushes_then_adds() {
        let s = build_update_script("fh", &[(Ipv4Addr::new(1, 2, 3, 0), 24)]);
        assert!(s.starts_with("flush set inet oxwrt-blocklist fh"));
        assert!(s.contains("add element inet oxwrt-blocklist fh"));
        assert!(s.contains("1.2.3.0/24"));
    }

    /// Empty cidr list — flush only, no add. Prevents the nft
    /// parser error "no elements in set" on a refresh that yields
    /// zero entries.
    #[test]
    fn update_script_empty_cidrs_is_flush_only() {
        let s = build_update_script("fh", &[]);
        assert!(s.contains("flush set"));
        assert!(!s.contains("add element"), "{s}");
    }

    /// Sanitised ident flows through to both flush + add to prevent
    /// nft syntax error on a name with punctuation in it. (The
    /// schema doesn't strictly bar punctuation today — operators
    /// may set `name = "foo-bar"` and the code must not break.)
    #[test]
    fn update_script_sanitises_ident() {
        let s = build_update_script("foo-bar", &[(Ipv4Addr::new(1, 1, 1, 1), 32)]);
        assert!(s.contains("foo_bar"));
        assert!(!s.contains("foo-bar"));
    }

    // --- parser edge cases ---

    /// A list mixing tabs + trailing whitespace + windows line
    /// endings — real public lists often mix these. Parser must
    /// survive and yield the expected CIDRs.
    #[test]
    fn parse_tolerates_mixed_whitespace_and_crlf() {
        let body = "1.2.3.0/24\r\n\t5.6.7.8  \r\n   \r\n9.9.9.0/28\n";
        let out = parse_cidr_list(body);
        assert_eq!(
            out,
            vec![
                (Ipv4Addr::new(1, 2, 3, 0), 24),
                (Ipv4Addr::new(5, 6, 7, 8), 32),
                (Ipv4Addr::new(9, 9, 9, 0), 28),
            ]
        );
    }

    /// Prefix 0 (the whole internet) is a legal CIDR even if
    /// operators shouldn't use it — don't reject silently, don't
    /// panic on the zero-shift.
    #[test]
    fn parse_prefix_zero_yields_zero_network() {
        let out = parse_cidr_list("8.8.8.8/0\n");
        assert_eq!(out, vec![(Ipv4Addr::new(0, 0, 0, 0), 0)]);
    }

    /// Dup detection is prefix-aware: 1.2.3.0/24 and 1.2.3.0/25 are
    /// different networks and both must survive.
    #[test]
    fn parse_keeps_different_prefixes_with_same_network() {
        let out = parse_cidr_list("1.2.3.0/24\n1.2.3.0/25\n");
        assert_eq!(
            out,
            vec![
                (Ipv4Addr::new(1, 2, 3, 0), 24),
                (Ipv4Addr::new(1, 2, 3, 0), 25),
            ]
        );
    }
}
