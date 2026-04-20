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

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use oxwrt_api::config::Ddns;

use crate::control::{ControlState, SharedLease};

/// Spawn the DDNS updater task. Returns the JoinHandle in case the
/// caller wants to abort on shutdown. Safe to call when `cfg.ddns`
/// is empty — the task still runs a tick loop (cheap) and picks up
/// any entries added via CRUD + reload, instead of requiring a
/// reboot to start ddns for the first time.
pub fn spawn(state: Arc<ControlState>, lease: SharedLease) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let client = match build_client() {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(error = %e, "ddns: http client init failed; disabling");
                return;
            }
        };

        // Per-entry memory of the last-pushed IP, keyed by the
        // entry's `name` (CRUD-stable). Persisting the state across
        // CRUD updates keeps us from re-pushing after an unrelated
        // cfg reload: the name stays the same, the last-pushed IP
        // stays mapped, no needless provider hit.
        let mut last_pushed: HashMap<String, Ipv4Addr> = HashMap::new();

        let mut tick = tokio::time::interval(Duration::from_secs(300));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            let cfg = state.config_snapshot();
            if cfg.ddns.is_empty() {
                continue;
            }
            let Some(current_ip) = lease
                .read()
                .ok()
                .and_then(|l| l.as_ref().map(|x| x.address))
            else {
                continue;
            };
            for entry in &cfg.ddns {
                if last_pushed.get(entry.name()) == Some(&current_ip) {
                    continue;
                }
                match push(&client, entry, current_ip).await {
                    Ok(()) => {
                        tracing::info!(name = entry.name(), ip = %current_ip, "ddns push ok");
                        last_pushed.insert(entry.name().to_string(), current_ip);
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
            // Forget entries that are no longer in the config — stops
            // the HashMap from growing across many CRUD add/remove
            // churns. O(n log n) but n is tiny.
            last_pushed.retain(|name, _| cfg.ddns.iter().any(|d| d.name() == name));
        }
    })
}

fn build_client() -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .user_agent(concat!("oxwrtd/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(15))
        .build()
}

async fn push(client: &reqwest::Client, entry: &Ddns, ip: Ipv4Addr) -> Result<(), String> {
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
        Ddns::Namecheap {
            host,
            domain,
            password,
            ..
        } => {
            // Namecheap Dynamic DNS endpoint. Response is XML
            // with an <ErrCount> element; anything non-zero
            // means auth/host mismatch. HTTP status is usually
            // 200 even on error.
            let url = format!(
                "https://dynamicdns.park-your-domain.com/update?host={}&domain={}&password={}&ip={}",
                urlencode(host),
                urlencode(domain),
                urlencode(password),
                ip
            );
            let resp = client
                .get(&url)
                .send()
                .await
                .map_err(|e| format!("namecheap send: {e}"))?;
            let body = resp
                .text()
                .await
                .map_err(|e| format!("namecheap body: {e}"))?;
            // Parse-light: trust the ErrCount>0 signal. A proper
            // XML parser would be over-engineering; the response
            // always contains either "<ErrCount>0</ErrCount>" on
            // success or "<ErrCount>N</ErrCount>" (N>0) + Errors
            // block on failure.
            if body.contains("<ErrCount>0</ErrCount>") {
                Ok(())
            } else {
                Err(format!("namecheap: body={body:?}"))
            }
        }
        Ddns::Dynv6 {
            hostname, token, ..
        } => {
            // dynv6's HTTP API. Response body is literally "addresses
            // updated" on success or an error message on failure —
            // no structured format. Match against the known-good
            // substring.
            let url = format!(
                "https://ipv4.dynv6.com/api/update?hostname={}&ipv4={}&token={}",
                urlencode(hostname),
                ip,
                urlencode(token)
            );
            let resp = client
                .get(&url)
                .send()
                .await
                .map_err(|e| format!("dynv6 send: {e}"))?;
            let status = resp.status();
            let body = resp
                .text()
                .await
                .map_err(|e| format!("dynv6 body: {e}"))?;
            // "addresses updated" is the success body. "addresses
            // already set to …" is ALSO success — a no-op update
            // when we push the same IP twice in a row. Both match
            // the substring "address" so we pattern on that +
            // HTTP 200.
            if status.is_success() && body.to_lowercase().contains("address") {
                Ok(())
            } else {
                Err(format!("dynv6: status={status} body={body:?}"))
            }
        }
        Ddns::HurricaneElectric { hostname, key, .. } => {
            // HE.net's dyn.dns.he.net speaks the classic DynDNS2
            // protocol: Basic auth (hostname as username, DDNS
            // key as password), GET /nic/update?hostname=&myip=.
            // Response codes are "good <ip>" on change and
            // "nochg <ip>" on duplicate — both success.
            let url = format!(
                "https://dyn.dns.he.net/nic/update?hostname={}&myip={}",
                urlencode(hostname),
                ip
            );
            let resp = client
                .get(&url)
                .basic_auth(hostname, Some(key))
                .send()
                .await
                .map_err(|e| format!("he.net send: {e}"))?;
            let status = resp.status();
            let body = resp
                .text()
                .await
                .map_err(|e| format!("he.net body: {e}"))?;
            let trimmed = body.trim();
            if status.is_success()
                && (trimmed.starts_with("good ") || trimmed.starts_with("nochg "))
            {
                Ok(())
            } else {
                Err(format!("he.net: status={status} body={body:?}"))
            }
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
            Ddns::Duckdns {
                name,
                domain,
                token,
            } => {
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

    #[test]
    fn ddns_namecheap_serde() {
        let toml_text = r#"
provider = "namecheap"
name = "home"
host = "router"
domain = "example.com"
password = "per-host-ddns-key"
"#;
        let d: Ddns = toml::from_str(toml_text).unwrap();
        match d {
            Ddns::Namecheap { host, domain, .. } => {
                assert_eq!(host, "router");
                assert_eq!(domain, "example.com");
            }
            _ => panic!("expected Namecheap variant"),
        }
    }

    #[test]
    fn ddns_dynv6_serde() {
        let toml_text = r#"
provider = "dynv6"
name = "home"
hostname = "myrouter.dynv6.net"
token = "zone-token"
"#;
        let d: Ddns = toml::from_str(toml_text).unwrap();
        assert!(matches!(d, Ddns::Dynv6 { .. }));
    }

    #[test]
    fn ddns_he_net_serde() {
        let toml_text = r#"
provider = "he"
name = "home"
hostname = "router.example.com"
key = "ddns-key"
"#;
        let d: Ddns = toml::from_str(toml_text).unwrap();
        assert!(matches!(d, Ddns::HurricaneElectric { .. }));
    }
}
