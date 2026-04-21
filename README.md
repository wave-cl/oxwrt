# oxwrt

Router firmware for the **GL-MT6000 (Flint 2)**, written as a Rust
PID-1 replacement for OpenWrt's procd stack. One daemon (`oxwrtd`)
owns every userspace responsibility on the router — early mounts,
kernel-module loading, overlay setup, netdev configuration,
firewall, DHCP, DNS, NTP, WireGuard, service supervision, and the
operator control plane.

Everything the device does is described by one pair of TOML files:

- `/etc/oxwrt/oxwrt.toml` (publishable) — networks, firewall zones
  + rules, WiFi, services, DDNS, port forwards, VPN, etc.
- `/etc/oxwrt/oxwrt.secrets.toml` (mode 0600) — Wi-Fi passphrases,
  DDNS tokens, WG peer PSKs, PPPoE passwords.

An operator mutates state by editing TOML (or pushing via RPC),
running `oxctl <host> reload`, and watching the daemon reconcile.
Failed reconciles auto-revert to the last-known-good snapshot.

## Who's it for

Homelab-scale operators who want:
- a **single config pair** that fully describes the device (backups
  are a tarball; restore is one RPC)
- **containerized services** with real isolation (caps-drop, seccomp,
  landlock, per-service namespaces) rather than whatever-process-
  under-root
- a **control plane** over sQUIC with ed25519-pinned clients
  instead of SSH + uci-cli
- **failover + rollback** that doesn't require hand-editing files
  over UART after a bad push

Not for: people who want a web UI today (deferred; see roadmap),
operators on every OpenWrt target (Flint 2 only for now), or
environments that need SELinux / dm-verity / TPM-sealed secrets
(on the roadmap; see `SECURITY.md`).

## Architecture at a glance

```
                         ┌──────────────────────────────────┐
                         │  oxwrtd (PID 1)                  │
                         │  ┌────────────────────────────┐  │
                         │  │ supervisor + reconcile     │  │
                         │  └──┬─────────────────────────┘  │
                         │     │ spawns containers          │
                         │     │ (clone3 + seccomp +        │
                         │     │  landlock + caps)          │
                         │     ▼                            │
                         │  hostapd-5g   hickory-dns        │
                         │  hostapd-2g   coredhcp           │
                         │  ntpd-rs      corerad            │
                         │  miniupnpd    (vpn containers)   │
                         └──┬───────────────────────────────┘
                            │
                 ┌──────────┴──────────┐
                 │ sQUIC control plane │  ← oxctl <host> ...
                 └─────────────────────┘
                            │
                 ┌──────────┴──────────┐
                 │  /etc/oxwrt/*.toml  │  ← edit + reload
                 └─────────────────────┘
```

Crates:

| Crate | Role |
|-------|------|
| `oxwrt-api` | Pure data types: TOML schema, RPC enums. No syscalls, builds on macOS + Linux + CI. |
| `oxwrt-linux` | Linux-only: netlink, nftables (rustables), cgroup v2, seccomp, landlock, clone3, DHCPv4/v6 clients, VPN routing. |
| `oxwrt-proto` | sQUIC framing + CLI parsing. Shared between client and server. |
| `oxwrtd` | The PID-1 daemon binary. |
| `oxwrtctl-cli` | The `oxctl` operator CLI. Library + binary — on-device `oxwrtd --client` reuses the same code. |

## Quick start (already-flashed device)

```sh
# On your laptop, after pointing at the router's LAN IP and
# exporting the server pubkey (printed at first boot, see below):
export SQUIC_SERVER_KEY=a1b2c3…  # 64 hex chars
oxctl 192.168.50.1:51820 status
oxctl 192.168.50.1:51820 get hostname
oxctl 192.168.50.1:51820 wifi list

# Live-updating status (Ctrl-C to quit):
oxctl 192.168.50.1:51820 watch
oxctl 192.168.50.1:51820 watch --interval 2 diag links
```

Every mutation is TOML. Typical flow:

```sh
# 1. Edit locally
$EDITOR oxwrt.toml

# 2. Validate without side effects
oxctl 192.168.50.1:51820 config-push oxwrt.toml
oxctl 192.168.50.1:51820 reload --dry-run

# 3. Commit
oxctl 192.168.50.1:51820 reload
# — if reconcile fails, the daemon auto-restores the last-good
#   snapshot and reloads against that. You see the original error
#   in the response.

# 4. If you want to back out anyway:
oxctl 192.168.50.1:51820 rollback --confirm
oxctl 192.168.50.1:51820 rollback-list     # see the ring
oxctl 192.168.50.1:51820 rollback --confirm --to 2   # deeper rewind
```

## First-flash workflow

1. **Build the image** (image-builder + overlay). The project's
   openwrt-packages/imagebuilder-overlay/ contains the preinit
   hooks, sQUIC seed provisioning, and Cargo-built binaries. See
   `scripts/qemu-integration-test.sh` for the end-to-end flow
   that CI exercises against a real aarch64 VM — it's also the
   best reference for the flash-free boot path.

2. **Generate a starter config on the laptop:**

   ```sh
   oxctl wizard --out /tmp/oxwrt.toml
   ```
   The wizard prompts for hostname, LAN CIDR, WAN mode, SSIDs,
   etc., and emits a split public + secrets pair. Copy both to
   `/etc/oxwrt/` on the router.

3. **Discover the server pubkey** (printed to UART at first boot):

   ```sh
   # On the router (over UART):
   oxctl --print-server-key
   ```

4. **Authorize your client** by adding `[[control.clients]]`
   entries to `oxwrt.toml`:

   ```toml
   [[control.clients]]
   name = "laptop"
   key = "…64 hex chars…"
   ```

5. **Reload.** Every subsequent change is the 4-step `$EDITOR`
   → `config-push` → `reload --dry-run` → `reload` flow above.

## Building

```sh
# Native (macOS or Linux) — runs all the non-Linux-gated tests:
cargo test --workspace

# Cross to aarch64-musl for the router:
cargo zigbuild --release --target aarch64-unknown-linux-musl -p oxwrtd
cargo zigbuild --release --target aarch64-unknown-linux-musl -p oxwrtctl-cli
```

Prerequisites: Rust stable, `cargo-zigbuild`, `zig 0.14`. On
macOS developers additionally need GNU `ar` (Homebrew's
`binutils` package) — cargo-zigbuild uses it for the linker step.

CI runs fmt, clippy `-D warnings`, `cargo test --workspace`, and
a full QEMU boot+RPC suite against every PR. See
`.github/workflows/ci.yml`.

## Key documents

- [`config/oxwrt.toml`](config/oxwrt.toml) — the cookbook.
  Annotated example of every section.
- [`config/oxwrt.secrets.toml.example`](config/oxwrt.secrets.toml.example) —
  the secrets-overlay shape. Copy to
  `provisioning/oxwrt.secrets.toml` on the build host to bake it
  into every image at mode 0600 (same pattern as
  `provisioning/key.ed25519`); `provisioning/` is gitignored so
  the real file never lands in a PR.
- [`SECURITY.md`](SECURITY.md) — threat model, what's protected,
  known gaps (unsigned firmware, no rate limiting, etc.).
- [`CHANGELOG.md`](CHANGELOG.md) — release history (generated by
  `scripts/release.sh`).

## Status

Usable on the Flint 2 for single-router deployments. Everything
listed in `config/oxwrt.toml` is implemented; several items in
`SECURITY.md`'s "Known limitations" (signed firmware updates,
control-plane rate limiting) are tracked TODOs but not yet live.
Version `0.x` — no API stability guarantees across releases;
breaking changes land in minor bumps.

## Roadmap (next likely ~10 commits)

- **Signed firmware updates** — ed25519 release-artifact sigs
  verified before sysupgrade. Biggest outstanding gap per
  SECURITY.md.
- **Control-plane rate limiting** — per-pubkey token bucket.
- **LAN device discovery** — `oxctl diag devices` joining DHCP +
  ARP + mDNS into a single view.
- **Time-based firewall rules** — `schedule` field using nft's
  `meta hour` / `meta day` predicates.
- **Syslog forwarding** — RFC5424 remote tracing events.

## Reporting issues

[`SECURITY.md`](SECURITY.md) has the security-disclosure policy.
Everything else: GitHub Issues. Bug reports that include the
output of `oxctl dump-config` are worth their weight in espresso
— it's the safe-to-paste merged view (every secret leaf is
`<redacted>`).

## License

MIT. See individual `Cargo.toml` files for the authoritative
statement.
