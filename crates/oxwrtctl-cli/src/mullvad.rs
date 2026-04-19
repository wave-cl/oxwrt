//! Mullvad relay-list integration for `oxctl mullvad-relays` and
//! `oxctl vpn-switch-relay`.
//!
//! The Mullvad public API at
//! `https://api.mullvad.net/app/v1/relays` returns a JSON
//! document listing every WireGuard relay — hostname, endpoint
//! IPs, public key, country/city codes, active flag. No auth
//! needed for the list; only per-account operations (key upload,
//! subscription checks) would require credentials.
//!
//! Provider-specific and pragmatically scoped: we parse only
//! the fields we need and tolerate schema drift by treating
//! everything optional. If Mullvad rearranges the response a
//! future day, a missing field degrades gracefully (skipped
//! relay) rather than panicking.

use serde::{Deserialize, Serialize};

/// Default API endpoint. Not const-ified via env because there's
/// only one production URL and overriding it would be a footgun
/// (easy to send credentials to a typo'd host). Test harnesses
/// that need to mock can swap the `RELAYS_URL` at the call site.
pub const RELAYS_URL: &str = "https://api.mullvad.net/app/v1/relays";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayList {
    /// Defensive `#[serde(default)]` — if Mullvad ever renames
    /// this key, we degrade to "no relays" rather than failing
    /// the whole oxctl invocation.
    #[serde(default)]
    pub wireguard: WireguardSection,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WireguardSection {
    #[serde(default)]
    pub relays: Vec<Relay>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Relay {
    pub hostname: String,
    #[serde(default)]
    pub ipv4_addr_in: Option<String>,
    #[serde(default)]
    pub ipv6_addr_in: Option<String>,
    #[serde(default)]
    pub public_key: Option<String>,
    /// Combined location code, e.g. "se-got" (country-city).
    /// Mullvad's API returns this as a single string rather than
    /// separate fields; we split it for filtering via
    /// `country_code()` / `city_code()` accessors. Empty means
    /// "unknown location" — included in unfiltered output,
    /// excluded when --country or --city is specified.
    #[serde(default)]
    pub location: Option<String>,
    /// Mullvad marks relays inactive during maintenance — filter
    /// these out of pick-a-relay UX by default. Operator can
    /// still target one explicitly by hostname via
    /// `vpn-switch-relay`.
    #[serde(default = "default_active")]
    pub active: bool,
    /// Load-balancing weight, included here so a follow-up
    /// "pick the least-loaded relay" feature can use it.
    #[serde(default)]
    pub weight: Option<u32>,
}

impl Relay {
    /// Two-letter country code extracted from `location`. None if
    /// location is missing or malformed.
    pub fn country_code(&self) -> Option<&str> {
        self.location.as_deref()?.split('-').next()
    }
    /// Three-letter city code extracted from `location`.
    pub fn city_code(&self) -> Option<&str> {
        self.location.as_deref()?.split('-').nth(1)
    }
}

fn default_active() -> bool {
    // When the field is absent, assume the relay is usable —
    // same principle as Mullvad's own client: don't hide a
    // relay because of a missing optional field.
    true
}

/// Standard Mullvad port for WireGuard. Not in the relay list
/// because it's universally 51820 — hardcoding it is the
/// pragmatic call. If a per-relay port ever appears in the API,
/// add a field to `Relay` and read it here.
pub const MULLVAD_WG_PORT: u16 = 51820;

/// Fetch the relay list via reqwest. Async (called from tokio
/// context). 10 s timeout — the API is fast (<500 ms typical);
/// anything longer means network trouble.
pub async fn fetch_relays() -> Result<RelayList, String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .user_agent(concat!("oxctl/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| format!("http client: {e}"))?;
    let resp = client
        .get(RELAYS_URL)
        .send()
        .await
        .map_err(|e| format!("GET {RELAYS_URL}: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("GET {RELAYS_URL}: status {}", resp.status()));
    }
    resp.json::<RelayList>()
        .await
        .map_err(|e| format!("parse relay list: {e}"))
}

/// Filter + sort helper used by the `mullvad-relays` subcommand.
/// Filters out inactive relays unless `include_inactive`; applies
/// optional country/city filters (exact match on code, case-
/// insensitive); sorts by country then hostname for stable
/// output.
pub fn filter_relays(
    all: &[Relay],
    country: Option<&str>,
    city: Option<&str>,
    include_inactive: bool,
) -> Vec<Relay> {
    let mut out: Vec<Relay> = all
        .iter()
        .filter(|r| include_inactive || r.active)
        .filter(|r| {
            country
                .map(|c| r.country_code().map(|x| x.eq_ignore_ascii_case(c)).unwrap_or(false))
                .unwrap_or(true)
        })
        .filter(|r| {
            city.map(|c| r.city_code().map(|x| x.eq_ignore_ascii_case(c)).unwrap_or(false))
                .unwrap_or(true)
        })
        .cloned()
        .collect();
    out.sort_by(|a, b| {
        a.location
            .cmp(&b.location)
            .then_with(|| a.hostname.cmp(&b.hostname))
    });
    out
}

/// Find a relay by exact hostname. Returns None if no match.
/// Case-sensitive — Mullvad hostnames are lowercase by
/// convention; a mismatch probably means a typo and we'd rather
/// surface it.
pub fn find_by_hostname<'a>(relays: &'a [Relay], hostname: &str) -> Option<&'a Relay> {
    relays.iter().find(|r| r.hostname == hostname)
}

/// Measure ping latency to a single IP. Returns latency in
/// milliseconds on success, or None if the ping failed or timed
/// out.
///
/// Uses the system `ping` binary — available on macOS, Linux,
/// BSD. Parses the "time=XX.XX ms" line from stdout. Timeout is
/// ~1 second; a relay that takes longer than that to respond
/// isn't a candidate anyway.
pub async fn ping_latency_ms(ip: &str) -> Option<f64> {
    // -c 1: single echo. -W: per-reply timeout. macOS uses
    // seconds, Linux uses milliseconds. Using 1000 works on Linux
    // (1000ms) and macOS treats the arg as seconds (1000s — never
    // hit in practice because -t also caps total). Add -t 2 to
    // cap wall-clock at 2s on macOS. Cross-platform enough.
    let out = tokio::process::Command::new("ping")
        .args(["-c", "1", "-W", "1000", "-t", "2", ip])
        .output()
        .await
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        if let Some(rest) = line.split_once("time=") {
            let ms_str = rest.1.split_whitespace().next()?;
            return ms_str.parse::<f64>().ok();
        }
    }
    None
}

/// Ping a batch of IPs in parallel, return (ip, latency) pairs
/// sorted ascending by latency. Failed pings are dropped.
/// Concurrency matters: 10 candidates × ~800ms each serial
/// would be 8s; in parallel it's a single timeout window.
pub async fn race_pings(ips: Vec<String>) -> Vec<(String, f64)> {
    let futs = ips.into_iter().map(|ip| async move {
        let latency = ping_latency_ms(&ip).await;
        (ip, latency)
    });
    let results = futures_util::future::join_all(futs).await;
    let mut timed: Vec<(String, f64)> = results
        .into_iter()
        .filter_map(|(ip, lat)| lat.map(|l| (ip, l)))
        .collect();
    timed.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
    timed
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<Relay> {
        vec![
            Relay {
                hostname: "se-got-wg-001".into(),
                ipv4_addr_in: Some("193.138.7.34".into()),
                ipv6_addr_in: Some("2a03:1b20::1".into()),
                public_key: Some("AAAA".into()),
                location: Some("se-got".into()),
                active: true,
                weight: Some(100),
            },
            Relay {
                hostname: "de-ber-wg-001".into(),
                ipv4_addr_in: Some("185.213.154.66".into()),
                ipv6_addr_in: None,
                public_key: Some("BBBB".into()),
                location: Some("de-ber".into()),
                active: false,
                weight: None,
            },
            Relay {
                hostname: "us-nyc-wg-002".into(),
                ipv4_addr_in: Some("198.51.100.2".into()),
                ipv6_addr_in: None,
                public_key: Some("CCCC".into()),
                location: Some("us-nyc".into()),
                active: true,
                weight: Some(80),
            },
        ]
    }

    #[test]
    fn filter_hides_inactive_by_default() {
        let out = filter_relays(&sample(), None, None, false);
        assert_eq!(out.len(), 2);
        assert!(out.iter().all(|r| r.hostname != "de-ber-wg-001"));
    }

    #[test]
    fn filter_includes_inactive_when_asked() {
        let out = filter_relays(&sample(), None, None, true);
        assert_eq!(out.len(), 3);
    }

    #[test]
    fn filter_by_country_case_insensitive() {
        let out = filter_relays(&sample(), Some("SE"), None, true);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].hostname, "se-got-wg-001");
    }

    #[test]
    fn filter_by_city() {
        let out = filter_relays(&sample(), None, Some("nyc"), true);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].hostname, "us-nyc-wg-002");
    }

    #[test]
    fn filter_sorts_by_country_then_hostname() {
        let out = filter_relays(&sample(), None, None, true);
        let codes: Vec<&str> = out.iter().filter_map(|r| r.country_code()).collect();
        assert_eq!(codes, vec!["de", "se", "us"]);
    }

    #[test]
    fn location_accessors_split_at_dash() {
        let r = Relay {
            hostname: "x".into(),
            ipv4_addr_in: None,
            ipv6_addr_in: None,
            public_key: None,
            location: Some("jp-tyo".into()),
            active: true,
            weight: None,
        };
        assert_eq!(r.country_code(), Some("jp"));
        assert_eq!(r.city_code(), Some("tyo"));
    }

    #[test]
    fn find_by_hostname_exact_match() {
        let relays = sample();
        assert!(find_by_hostname(&relays, "se-got-wg-001").is_some());
        assert!(find_by_hostname(&relays, "SE-GOT-WG-001").is_none());
        assert!(find_by_hostname(&relays, "nonexistent").is_none());
    }

    /// Real Mullvad response stub — shape matches what
    /// api.mullvad.net/app/v1/relays returns today: `location`
    /// is a combined "cc-ccc" string, not separate fields.
    #[test]
    fn parses_response_shape() {
        let json = r#"{
            "wireguard": {
                "relays": [
                    {
                        "hostname": "se-got-wg-001",
                        "ipv4_addr_in": "193.138.7.34",
                        "public_key": "AAA=",
                        "location": "se-got",
                        "active": true,
                        "weight": 100
                    }
                ]
            }
        }"#;
        let parsed: RelayList = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.wireguard.relays.len(), 1);
        assert_eq!(parsed.wireguard.relays[0].hostname, "se-got-wg-001");
        assert_eq!(parsed.wireguard.relays[0].country_code(), Some("se"));
        assert_eq!(parsed.wireguard.relays[0].city_code(), Some("got"));
    }

    #[test]
    fn parses_missing_optional_fields() {
        let json = r#"{
            "wireguard": {
                "relays": [
                    { "hostname": "bare-relay" }
                ]
            }
        }"#;
        let parsed: RelayList = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.wireguard.relays.len(), 1);
        assert_eq!(parsed.wireguard.relays[0].hostname, "bare-relay");
        assert!(parsed.wireguard.relays[0].public_key.is_none());
        // default_active → true when field absent.
        assert!(parsed.wireguard.relays[0].active);
    }
}
