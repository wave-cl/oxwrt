//! Shared counters/gauges for the `/metrics` endpoint, populated
//! from in-process observation points (DHCP acquire, reload
//! handler, blocklist refresher) and read by `metrics::render`.
//!
//! # Why one Mutex<MetricsState> instead of per-metric atomics
//!
//! Prometheus counters with label cardinality (e.g.
//! `oxwrt_dhcp_acquires_total{iface="eth1",result="ok"}`) don't
//! map cleanly onto raw AtomicU64s — we'd need a dynamic table
//! of label-set → counter. A single Mutex<HashMap> keeps the
//! lock critical section short (all updates are O(1) HashMap
//! upserts) without per-metric registry plumbing.
//!
//! Contention is nil: instrumented events fire at human time-
//! scales (once per reload, once per DHCP acquire per minutes,
//! once per blocklist refresh per hour). The /metrics scraper
//! itself is the dominant reader and holds the lock for ~µs.
//!
//! # Why not a full Prometheus client library
//!
//! Adding a transitive dep for ~12 metrics we hand-format in
//! metrics::render is overkill — the render() function is ~80
//! LOC and our test surface is string-level anyway.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Global shared state. Write sites call the `record_*` helpers;
/// the metrics renderer locks once, copies what it needs, unlocks,
/// and formats.
pub static METRICS: LazyLock<Mutex<MetricsState>> =
    LazyLock::new(|| Mutex::new(MetricsState::default()));

#[derive(Debug, Default)]
pub struct MetricsState {
    // ── reload ───────────────────────────────────────────────────
    /// Count of reload RPCs that returned Response::Ok.
    pub reloads_ok_total: u64,
    /// Count of reload RPCs that returned Response::Err.
    pub reloads_err_total: u64,
    /// Wall-clock duration of the most recent reload (ok or err),
    /// in milliseconds. Gauge — replaced on each call.
    pub reload_last_duration_ms: u64,

    // ── WAN DHCP ─────────────────────────────────────────────────
    /// Counter keyed on (iface, result) where result ∈ {"ok",
    /// "timeout", "error"}. "ok" means DISCOVER → OFFER → REQUEST
    /// → ACK completed; "timeout" = acquire deadline elapsed
    /// waiting for any DHCP reply; "error" = any other path
    /// (socket, encode, missing option, rtnetlink failure).
    pub dhcp_acquires: HashMap<(String, &'static str), u64>,
    /// Most recent successful acquire latency per iface, in
    /// milliseconds. Gauge — replaced on each "ok" acquire. No
    /// entry until the first success.
    pub dhcp_last_latency_ms: HashMap<String, u64>,

    // ── Blocklists ───────────────────────────────────────────────
    /// Number of CIDR entries currently installed in each
    /// blocklist's nftables set. Gauge — updated on install +
    /// on each refresh. Zero counts an installed-but-empty set
    /// (e.g. URL fetch failed, fail-open path took it).
    pub blocklist_entries: HashMap<String, u64>,
    /// Fetch counter keyed on (name, result) where result ∈
    /// {"ok", "http_error", "parse_error"}. "ok" includes an
    /// empty body that parsed to 0 entries — the HTTP request
    /// itself succeeded. "http_error" covers DNS, TCP, TLS, and
    /// non-2xx statuses.
    pub blocklist_fetches: HashMap<(String, &'static str), u64>,
    /// Unix timestamp (seconds) of the most recent successful
    /// fetch per blocklist. Lets operators alert on "stale list".
    pub blocklist_last_fetch_unix: HashMap<String, u64>,
}

pub fn record_reload(success: bool, duration: Duration) {
    let mut m = METRICS.lock().unwrap();
    if success {
        m.reloads_ok_total += 1;
    } else {
        m.reloads_err_total += 1;
    }
    m.reload_last_duration_ms = duration.as_millis() as u64;
}

pub fn record_dhcp_acquire(iface: &str, result: &'static str, latency: Option<Duration>) {
    let mut m = METRICS.lock().unwrap();
    let key = (iface.to_string(), result);
    *m.dhcp_acquires.entry(key).or_insert(0) += 1;
    if let Some(d) = latency {
        if result == "ok" {
            m.dhcp_last_latency_ms
                .insert(iface.to_string(), d.as_millis() as u64);
        }
    }
}

pub fn record_blocklist_fetch(name: &str, result: &'static str, entries: Option<usize>) {
    let mut m = METRICS.lock().unwrap();
    let key = (name.to_string(), result);
    *m.blocklist_fetches.entry(key).or_insert(0) += 1;
    if let Some(n) = entries {
        m.blocklist_entries.insert(name.to_string(), n as u64);
    }
    if result == "ok" {
        let unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        m.blocklist_last_fetch_unix
            .insert(name.to_string(), unix);
    }
}

/// Cheap snapshot for the renderer. Clones the inner maps so the
/// formatter doesn't hold the Mutex across its ~200 allocating
/// writeln! calls — brief hiccups for write sites during a scrape
/// would be worse than the memcpy we do here.
pub fn snapshot() -> MetricsState {
    let m = METRICS.lock().unwrap();
    MetricsState {
        reloads_ok_total: m.reloads_ok_total,
        reloads_err_total: m.reloads_err_total,
        reload_last_duration_ms: m.reload_last_duration_ms,
        dhcp_acquires: m.dhcp_acquires.clone(),
        dhcp_last_latency_ms: m.dhcp_last_latency_ms.clone(),
        blocklist_entries: m.blocklist_entries.clone(),
        blocklist_fetches: m.blocklist_fetches.clone(),
        blocklist_last_fetch_unix: m.blocklist_last_fetch_unix.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two OK acquires on the same iface bump the counter to 2;
    /// the latest latency gauge reflects the second call.
    #[test]
    fn dhcp_acquire_counter_and_latency_gauge() {
        // Clear global state from any prior test.
        {
            let mut m = METRICS.lock().unwrap();
            *m = MetricsState::default();
        }
        record_dhcp_acquire("eth1", "ok", Some(Duration::from_millis(1234)));
        record_dhcp_acquire("eth1", "ok", Some(Duration::from_millis(5678)));
        let s = snapshot();
        assert_eq!(s.dhcp_acquires[&("eth1".to_string(), "ok")], 2);
        assert_eq!(s.dhcp_last_latency_ms["eth1"], 5678);
    }

    /// Timeout acquires don't overwrite the success-latency gauge.
    #[test]
    fn dhcp_timeout_keeps_last_ok_latency() {
        {
            let mut m = METRICS.lock().unwrap();
            *m = MetricsState::default();
        }
        record_dhcp_acquire("eth1", "ok", Some(Duration::from_millis(100)));
        record_dhcp_acquire("eth1", "timeout", None);
        let s = snapshot();
        assert_eq!(s.dhcp_last_latency_ms["eth1"], 100);
        assert_eq!(
            s.dhcp_acquires[&("eth1".to_string(), "timeout")],
            1,
            "timeout counted separately"
        );
    }

    #[test]
    fn reload_success_and_failure_tracked() {
        {
            let mut m = METRICS.lock().unwrap();
            *m = MetricsState::default();
        }
        record_reload(true, Duration::from_millis(50));
        record_reload(false, Duration::from_millis(120));
        record_reload(true, Duration::from_millis(30));
        let s = snapshot();
        assert_eq!(s.reloads_ok_total, 2);
        assert_eq!(s.reloads_err_total, 1);
        assert_eq!(s.reload_last_duration_ms, 30);
    }

    #[test]
    fn blocklist_fetch_ok_updates_entries_and_timestamp() {
        {
            let mut m = METRICS.lock().unwrap();
            *m = MetricsState::default();
        }
        record_blocklist_fetch("fh", "ok", Some(912));
        let s = snapshot();
        assert_eq!(s.blocklist_entries["fh"], 912);
        assert!(s.blocklist_last_fetch_unix["fh"] > 0);
        assert_eq!(s.blocklist_fetches[&("fh".to_string(), "ok")], 1);
    }

    #[test]
    fn blocklist_http_error_doesnt_update_timestamp() {
        {
            let mut m = METRICS.lock().unwrap();
            *m = MetricsState::default();
        }
        record_blocklist_fetch("fh", "http_error", None);
        let s = snapshot();
        assert!(
            !s.blocklist_last_fetch_unix.contains_key("fh"),
            "stale-list alerting must only reset on success"
        );
        assert_eq!(s.blocklist_fetches[&("fh".to_string(), "http_error")], 1);
    }
}
