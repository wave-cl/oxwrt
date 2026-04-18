//! Dynamic-DNS updater. A background task polls the shared WAN
//! lease, and every time the address changes (or on first run for
//! each entry) it calls the configured provider's update API.
//!
//! Kept as a `#[cfg(target_os = "linux")]` module on the daemon side
//! because it sits next to the SharedLease (which lives in
//! oxwrt-linux) and is only meaningful on-device. The provider
//! selection + request-body building are pure functions and could
//! move to oxwrt-api later if an off-target consumer ever wants
//! them — no consumer today.
//!
//! Polling interval: 5 minutes. DHCP renewal typically runs twice
//! the lease time, and most residential ISPs give multi-day leases;
//! hourly polls would be wasteful. Providers' rate limits are much
//! higher than this so we're nowhere near throttled.

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use oxwrt_api::config::Ddns;

use crate::control::SharedLease;

/// Spawn the DDNS updater task. Returns the JoinHandle in case the
/// caller wants to abort on shutdown. Safe to call with an empty
/// `entries` Vec — the task immediately returns.
pub fn spawn(entries: Vec<Ddns>, lease: SharedLease) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if entries.is_empty() {
            return;
        }
        // Per-entry memory of the last-pushed IP so we only fire the
        // update call when it's actually changed. Otherwise we'd
        // spam the provider on every poll with an unchanged address.
        let last_pushed: Arc<Mutex<Vec<Option<Ipv4Addr>>>> =
            Arc::new(Mutex::new(vec![None; entries.len()]));

        let client = match build_client() {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(error = %e, "ddns: http client init failed; disabling");
                return;
            }
        };

        let mut tick = tokio::time::interval(Duration::from_secs(300));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            let Some(current_ip) = lease.read().ok().and_then(|l| l.as_ref().map(|x| x.address))
            else {
                continue; // no WAN lease yet
            };
            for (idx, entry) in entries.iter().enumerate() {
                let prev = last_pushed
                    .lock()
                    .ok()
                    .and_then(|g| g.get(idx).copied().flatten());
                if prev == Some(current_ip) {
                    continue;
                }
                match push(&client, entry, current_ip).await {
                    Ok(()) => {
                        tracing::info!(
                            name = entry.name(),
                            ip = %current_ip,
                            "ddns push ok"
                        );
                        if let Ok(mut g) = last_pushed.lock() {
                            if let Some(slot) = g.get_mut(idx) {
                                *slot = Some(current_ip);
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            name = entry.name(),
                            ip = %current_ip,
                            error = %e,
                            "ddns push failed; will retry on next tick"
                        );
                    }
                }
            }
        }
    })
}

fn build_client() -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .user_agent(concat!("oxwrtd/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(15))
        .build()
}

async fn push(
    client: &reqwest::Client,
    entry: &Ddns,
    ip: Ipv4Addr,
) -> Result<(), String> {
    match entry {
        Ddns::Duckdns { domain, token, .. } => {
            let url = format!(
                "https://www.duckdns.org/update?domains={}&token={}&ip={}",
                urlencode(domain),
                urlencode(token),
                ip
            );
            let resp = client
                .get(&url)
                .send()
                .await
                .map_err(|e| format!("duckdns send: {e}"))?;
            let status = resp.status();
            let body = resp
                .text()
                .await
                .map_err(|e| format!("duckdns body: {e}"))?;
            // DuckDNS returns "OK" or "KO" in the body regardless of HTTP
            // status — we have to pattern-match the string, not just
            // status.is_success().
            if body.trim() == "OK" {
                Ok(())
            } else {
                Err(format!("duckdns: status={status} body={body:?}"))
            }
        }
        Ddns::Cloudflare {
            zone_id,
            record_id,
            domain,
            api_token,
            ttl,
            ..
        } => {
            let url = format!(
                "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}"
            );
            // Cloudflare PUT body: full record state. `proxied` left as
            // default (unset in body) — whatever the record was already
            // configured with on the dashboard side stays.
            let body = serde_json::json!({
                "type": "A",
                "name": domain,
                "content": ip.to_string(),
                "ttl": ttl,
            });
            let resp = client
                .put(&url)
                .bearer_auth(api_token)
                .json(&body)
                .send()
                .await
                .map_err(|e| format!("cloudflare send: {e}"))?;
            if !resp.status().is_success() {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                return Err(format!("cloudflare: status={status} body={body}"));
            }
            Ok(())
        }
    }
}

/// Minimal percent-encoder: treats alphanum + `-_.~` as safe, escapes
/// everything else. Avoids pulling in `urlencoding` for a one-call
/// use. The DDNS providers we target don't care about unicode
/// normalization — the values are typically ASCII tokens + FQDNs.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        let ok = b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~');
        if ok {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urlencode_basic() {
        assert_eq!(urlencode("abc123.-_~"), "abc123.-_~");
        assert_eq!(urlencode("a b"), "a%20b");
        assert_eq!(urlencode("x/y?z"), "x%2Fy%3Fz");
    }

    #[test]
    fn ddns_duckdns_serde() {
        let toml_text = r#"
provider = "duckdns"
name = "home"
domain = "myrouter"
token = "uuid-token"
"#;
        let d: Ddns = toml::from_str(toml_text).unwrap();
        match d {
            Ddns::Duckdns { name, domain, token } => {
                assert_eq!(name, "home");
                assert_eq!(domain, "myrouter");
                assert_eq!(token, "uuid-token");
            }
            _ => panic!("expected Duckdns variant"),
        }
    }

    #[test]
    fn ddns_cloudflare_serde_default_ttl() {
        let toml_text = r#"
provider = "cloudflare"
name = "cf"
zone_id = "zzz"
record_id = "rrr"
domain = "vpn.example.com"
api_token = "tok"
"#;
        let d: Ddns = toml::from_str(toml_text).unwrap();
        match d {
            Ddns::Cloudflare { name, ttl, .. } => {
                assert_eq!(name, "cf");
                assert_eq!(ttl, 60, "default TTL");
            }
            _ => panic!("expected Cloudflare variant"),
        }
    }
}
