# Grafana dashboard for oxwrt

One-click visualization of every metric oxwrt exports on
`/metrics`. Suitable for a home Grafana + Prometheus setup
scraping a single router, or a Prometheus per-instance label
multiplexing across many.

## Prerequisites

1. **oxwrt's metrics endpoint enabled.** In `/etc/oxwrt/oxwrt.toml`:
   ```toml
   [metrics]
   listen = "192.168.50.1:9100"
   ```
   No auth — bind to the LAN IP and rely on firewall zone rules to
   keep it off WAN. The Control-plane sQUIC port is a separate
   concern.

2. **Prometheus scraping the endpoint.** Example scrape config:
   ```yaml
   scrape_configs:
     - job_name: oxwrt
       scrape_interval: 30s
       static_configs:
         - targets: ['192.168.50.1:9100']
           labels:
             role: router
             site: home
   ```

3. **Grafana with a Prometheus datasource.** Any version from
   10.0 onwards; the dashboard's `schemaVersion` is 39.

## Import

1. Grafana left sidebar → **Dashboards** → **Import**.
2. **Upload JSON file** → select `oxwrt-dashboard.json`.
3. Pick the Prometheus datasource when prompted — the dashboard
   uses `${DS_PROMETHEUS}` as a variable so it doesn't hardcode a
   UID.
4. **Import**.

## Layout

Rows, top to bottom:

| Row | Panels |
|---|---|
| **Supervisor** | Uptime, reload rate (ok vs error), last-reload duration, firewall rule count |
| **Services** | Per-service state (points per state), restart rate |
| **WAN** | DHCP lease remaining, acquire attempts / rate, last acquire latency |
| **Wi-Fi** | Per-AP up gauge (ssid + iface + band legend) |
| **Blocklists** | Entry count, staleness (time since last fetch) |
| **WireGuard server** | Peer handshake age, rx / tx rate |
| **VPN client** | Active profile gauge, healthy gauge (per profile) |

The `$instance` template variable multi-selects across any
instances labeled in Prometheus — useful if you're running a
fleet. Single-router setups can leave it as "All".

## Metrics covered

All families from the `metrics` section of `config/oxwrt.toml`'s
top-of-file index:

- `oxwrt_supervisor_uptime_seconds`
- `oxwrt_service_state`, `oxwrt_service_restarts_total`,
  `oxwrt_service_uptime_seconds`
- `oxwrt_ap_up{ssid,iface,phy,band}`
- `oxwrt_wan_lease_seconds`, `oxwrt_wan_dhcp_acquires_total`,
  `oxwrt_wan_dhcp_last_acquire_seconds`
- `oxwrt_reloads_total`, `oxwrt_reload_last_duration_seconds`
- `oxwrt_firewall_rules`
- `oxwrt_blocklist_entries`, `oxwrt_blocklist_fetches_total`,
  `oxwrt_blocklist_last_fetch_timestamp`
- `oxwrt_wg_peer_last_handshake_seconds`,
  `oxwrt_wg_peer_rx_bytes_total`, `oxwrt_wg_peer_tx_bytes_total`
- `oxwrt_vpn_active{profile,iface}`,
  `oxwrt_vpn_healthy{profile,iface}`

If you add custom scrapes / recording rules on top, extend the
panels — the dashboard UID is stable (`oxwrt-overview`) so
updates via import preserve operator-customized panels around
ours.

## Troubleshooting

- **"Data source does not exist"** → edit each panel's datasource
  field, or re-import and select the right datasource on the
  prompt. The JSON uses a variable ref (`${DS_PROMETHEUS}`) that
  Grafana binds at import time.
- **Panels say "No data"** → check Prometheus actually scrapes
  oxwrt: `curl http://<router>:9100/metrics | grep oxwrt_`.
  Also confirm the `$instance` selector matches — set to "All"
  during setup.
- **Service-state panel looks flat at 1** → that's the expected
  baseline; Running = 1. Crashed services drop to 0 or negative.
- **`oxwrt_vpn_*` panels empty** → no `[[vpn_client]]` profile
  declared in oxwrt.toml. Add one and reload.
