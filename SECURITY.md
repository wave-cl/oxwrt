# Security posture

This document is the threat model + security-properties inventory for
oxwrt. It's written against the code as it stands, not aspirations —
every property below cites a source file + line that enforces it.
When a property gets weakened or removed, update this doc in the same
commit.

## Assets we protect

- **Device identity seeds.** The sQUIC signing seed, the WireGuard
  server key, per-profile VPN client keys. Leakage → an attacker can
  impersonate the router on the control plane or on a site-to-site WG
  tunnel; fleet compromise if one device's seeds get copied into
  another.
- **The operator's control-plane access.** The authorized-clients list
  on the daemon side; the operator's own signing key on the client
  side. Leakage → attacker issues arbitrary RPCs (`reset`, `apply`,
  `wg-peer add`, etc.).
- **Configuration secrets.** Wi-Fi passphrases, DDNS tokens, PPPoE
  passwords, WireGuard peer PSKs. Leakage → local radio access, a
  stolen DNS name, an ISP-session hijack, reduced-secrecy VPN tunnels.
- **LAN-client traffic + DNS.** The router sees every packet the LAN
  generates. A compromise upgrades to full-network MITM.
- **The boot path.** Signed images, atomic sysupgrade, overlay
  integrity. Compromise → persistent code execution with kernel
  privileges.

## Adversaries considered (in scope)

1. **Unauthenticated WAN attacker.** Internet-side scans, DDoS
   traffic, opportunistic exploits against any port the router
   exposes.
2. **Unauthenticated LAN attacker.** A guest who joined the
   untrusted SSID, a compromised IoT device, a drive-by
   malware-infected laptop.
3. **Local non-root.** A container-escape candidate inside one of
   the supervised service containers.
4. **Stolen backup tarball.** `oxctl backup` output ending up on
   someone else's machine (misaddressed email, lost laptop).
5. **Stolen device.** Physical access to a flashed router whose
   backup has never been taken off-box.
6. **Careless pasted config.** An operator sharing their
   `oxwrt.toml` in a support thread without realising what's in it.

### Explicitly out of scope

- **Nation-state-level supply-chain attacks.** We use upstream crate
  dependencies as-is; we don't audit each release of `quinn` or
  `rustables` line-by-line.
- **Hardware/firmware tampering.** BootROM attacks, JTAG pickup,
  cold-boot RAM dumps. No secure boot chain (yet).
- **Side-channel attacks.** Timing, power analysis, spectre-class
  CPU issues.
- **DoS against the data plane.** Saturating the WAN uplink is
  trivially possible; out-of-scope for the firmware to prevent.

## Trust boundaries

```
 WAN ──[1]── firewall ──[2]── router userland ──[3]── containers
                                     │
                                     └──[4]── LAN clients
```

- **[1] WAN edge.** nftables `INPUT` chain: default DROP, accepts
  only `ct state established` + the WAN DHCPv4 unicast OFFER
  predicate (`net.rs:646` — the narrow bypass; see
  `install_firewall`'s WAN-INPUT section).
- **[2] Userland split.** oxwrtd runs as PID 1 with full
  capabilities; everything else runs as a supervised container.
- **[3] Container boundary.** Per-service seccomp + capability
  drop + landlock + mount/pid/net/ipc namespaces. See
  `crates/oxwrt-linux/src/container.rs` — `SECCOMP_DENY_LIST`
  (~20 syscalls: `clone`, `execve`, `ioctl`, `keyctl`, `reboot`,
  module loading, …), `RulesetCreated` (landlock, rootfs + declared
  bind-sources writable only), cap bounding-set drop, optional
  user-namespace mode that maps root→nobody.
- **[4] LAN boundary.** Zone-based nftables forward rules; each
  zone declares its default policy + allowed flows. Guest/IoT
  zones default to `drop` for new forward flows.

## Properties the current implementation upholds

### P1 — public config is publishable

`/etc/oxwrt/oxwrt.toml` contains no secrets after the split
migration (`crates/oxwrt-api/src/secrets.rs`). Every credential
listed in `SECRET_FIELDS` is moved to `oxwrt.secrets.toml`
(mode 0600) or referenced by path. `oxctl dump-config` replaces
each secret leaf with `<redacted>`. → a pasted oxwrt.toml does not
leak Wi-Fi / DDNS / PPPoE / peer-PSK material.

### P2 — cryptographic identity lives outside the config

`key.ed25519` (sQUIC), `wg0.key` (WG server), `vpn/*.key` (VPN
client), `dhcp6-duid` (DHCPv6 identifier) are files under
`/etc/oxwrt/`, referenced by path, never inlined in TOML. The
restore path sanity-checks modes on unpack (`backup.rs:234-240`).
→ a restored backup from a different device doesn't silently
replace your router's identity with theirs.

### P3 — control plane requires ed25519 pubkey pinning

sQUIC's handshake rejects clients whose key isn't in
`control.authorized_keys` (legacy file) ∪ `control.clients`
(inline). Merge + dedupe happens in
`load_merged_authorized_keys` (`control/server/mod.rs:876`).
Confirm gates (`reset`, `reboot`, `apply`, `restore`,
`rollback`) force `confirm = true` on destructive ops.

### P4 — WAN surface defaults to deny-all

`install_firewall` creates the `inet oxwrt` table with INPUT +
FORWARD policy = DROP. Baseline defaults emitted unconditionally
(no operator rule required):

- `ct state established,related accept` on INPUT/FORWARD/OUTPUT
- `ct state invalid drop` on INPUT/FORWARD
- ICMPv6 NDP (`nd-neighbor-*`, `nd-router-*`, `nd-redirect`)
  accept on all chains — IPv6 breaks without it
- ICMPv6 MLD (`mld-listener-*`, `mld2-*`) accept on all chains
- ICMPv6 `packet-too-big` accept on all chains — PMTU-D
- ICMP + ICMPv6 `echo-request` accept on INPUT (router answers
  pings). Operators who want to drop WAN pings add a higher-
  priority `src = "wan"` drop rule ahead.

Operator rules land AFTER the baseline in chain order (nft
first-match-wins), so they can ADD further accepts but can't
accidentally delete the safe-by-default set. Control plane
listens on loopback + LAN, never `0.0.0.0` in the shipped
default or the wizard output.

### P5 — supervised services are sandboxed

Every `[[services]]` entry spawns under: (a) caps-drop to the
declared allowlist, (b) seccomp with the project deny list, (c)
landlock-restricted FS view (rootfs + declared binds only), (d)
fresh mount/uts/ipc/(pid) namespaces. `net_mode = "isolated"`
adds NEWNET. User-namespace mode available per service for
further privilege separation.

### P6 — secrets overlay stays mode 0600

Boot-time guard (`init/run.rs::tighten_secrets_file_mode`) chmods
`oxwrt.secrets.toml` to 0600 on every boot if it isn't already.
Every write path (atomic_write_config, wifi_rotate,
migrate_public_to_split) sets 0o600 on the rename-target. Boot
also sanitises a hand-edit that dropped the mode.

### P7 — failed reload auto-reverts

`handle_reload_async` captures reconcile errors, restores the
last-good snapshot, re-reconciles, and returns a combined error
(`reload.rs`). One-shot, non-recursive — if the restore itself
fails, we stop and surface a "needs UART" message. Combined
with `reload --dry-run`, operators can validate a change
before committing.

### P8 — backup excludes VPN client keys + honors `include_secrets`

Backup tarball deliberately skips `/etc/oxwrt/vpn/` (provider
keys — re-obtainable from Mullvad / Proton, cheap to replace,
dangerous if a stolen backup leaks them). `backup_sftp.include_
secrets` (default true) gates whether `oxwrt.secrets.toml` rides
along to the remote — set false for off-router backups that
compliance requires to be credential-free.

## Known limitations

These are **real gaps** in the current implementation. Each is
tracked as either "intentional v1 scope" or "genuine TODO."

### P9 — firmware updates require a release signature (when baked)

`FwUpdate` verifies `sha256(image)` against a hash the client
sent (`sysupgrade.rs`) AND, when
`/etc/oxwrt/release-pubkey.ed25519` is present on the router,
requires the client to supply an ed25519 signature over the
hash (`handle_fw_update` + `verify_release_signature`). Images
built with a signing key baked in refuse unsigned update pushes;
a compromise of one operator's control-plane pubkey no longer
lets them install arbitrary code — they'd also need the offline
release-signing key.

Clients sign with `oxctl --sign <image>`, keyed off
`$OXWRT_SIGNING_KEY_PATH` (or `$OXWRT_SIGNING_KEY` hex).
Dev-mode images without a baked pubkey fall through to SHA-only
with a warning log, so self-built flows keep working.

### P10 — control plane rate-limits at two layers

sQUIC's accept loop gates on a `tokio::sync::Semaphore` sized to
`cfg.control.max_connections` (default 32). Surplus connections
are refused immediately — a WAN scan can't exhaust the
per-connection task state.

Inside an accepted connection, each RPC pulls a token from a
per-connection bucket (capacity = 2× `max_rpcs_per_sec`, refills
at `max_rpcs_per_sec` tokens/sec; default rate 20). An authenticated
client trying to hammer its held connection gets backpressured —
`acquire` sleeps until a token refills rather than failing the
request, so a legitimate caller sees latency instead of an error.
See `RateBucket` in `control/server/mod.rs`.

Mitigation stack: tight `[[control.clients]]` ACL, short-lived
connections (CLI opens one per RPC), connection cap bounds
concurrent clients, per-connection bucket bounds their
in-connection throughput.

**TODO** (deferred). Per-pubkey (not just per-connection) rate
limit. Requires upstream sQUIC to surface the peer's ed25519
pubkey on the accepted `quinn::Connection`; today the pubkey is
consumed by the MAC-layer whitelist check and not propagated.
Without it, a peer could reconnect to refresh its bucket — but
they'd pay the full handshake cost each time and still sit under
`max_connections`, so the ceiling holds in aggregate.

### Known — DDNS + blocklist fetch trust system CAs

`reqwest::Client::builder()` default verifier, no pinning. A CA
compromise (or a locally-injected root) → man-in-the-middle on
DDNS push / blocklist refresh. Both endpoints have negligible
blast radius (DDNS pushes *from* the router, blocklists are
already public data) — flagged for completeness, not urgent.

### Known — blocklists fail open

If the fetch fails, an empty set is installed with a warning
(`blocklists.rs`). Intentional — otherwise a flaky CDN prevents
boot. An attacker who can DoS a blocklist URL can thereby drop
the filtering. Accepted tradeoff.

### Known — boot path has no attestation

Nothing cryptographically verifies that `/sbin/init` is the
oxwrtd we shipped. Compromising the overlay (via a bug in our
code, or physical access) → persistent root. Hardware-level
secure boot would address this; out of scope v1.

### P11 — PID-namespace isolation opt-in per service

`SecurityProfile.pid_namespace: bool` (default false for v0
compatibility, recommended true for any service retaining
`CAP_KILL` or otherwise exposed to untrusted input). When set,
the spawn routes through the clone3 path with `CLONE_NEWPID`
(NEWUSER only when `user_namespace = true` is also set). The
service is PID 1 inside its own namespace and cannot see or
signal any host process.

Previously, only `user_namespace = true` triggered the clone3
path, and the two flags were coupled. That left services with
`user_namespace = false` (all shipped services today) sharing
the host PID namespace, which matters for any service retaining
`CAP_KILL`: a compromised dropbear with KILL could SIGKILL
oxwrtd (PID 1 on the host) or any sibling. Decoupling
pid_namespace means operators can get process isolation without
paying the rootless-uid mapping overhead.

Verified on-device (2026-04-20 audit):
- Without pid_namespace: shell PID 1202, 108 /proc PIDs visible,
  `kill -0 <sibling-pid>` succeeds against every service.
- With pid_namespace: shell PID 3, 5 /proc PIDs visible,
  `/proc/1/comm = "dropbear"`, every host service PID returns
  "No such process" on `kill -0`.

The debug-ssh example block ships with `pid_namespace = true`
set (alongside the CAP_KILL drop). Any service author adding
a new supervised binary should consider setting it on anything
that handles untrusted input (new SSH surface, new web UI,
new uPNP/SSDP endpoint) — the cost is one extra clone3 syscall
at spawn time.

### Known — host-netns services are MITM-capable if compromised

Four supervised services run in the host netns because their
jobs require raw sockets on real interfaces and can't be run in
an isolated veth:

- `dhcp` (coredhcp) — AF_PACKET raw socket for DHCPv4 frames on br-lan.
- `hostapd-5g` / `hostapd-2g` — 802.11 frame TX/RX via nl80211.
- `corerad` — ICMPv6 RA TX + rtnetlink subscription on br-lan.

Each retains `NET_RAW` + `NET_ADMIN` plus the default
`SETUID / SETGID / SETPCAP / NET_BIND_SERVICE`. `NET_RAW` +
`NET_ADMIN` together are close to unrestricted on the netns:
a compromised service can inject arbitrary Ethernet / Wi-Fi /
ICMPv6 frames, poison ARP, redirect default gateways (via RA),
and DoS the LAN.

Mitigation today: seccomp + landlock + no_new_privs + mount/uts/
ipc namespaces still apply, so a compromise is bounded to
network-layer attacks (no filesystem writes outside declared
binds, no privileged syscalls, no arbitrary execve).
Consequence: **isolate the router's LAN segment from high-value
clients**, or accept that a 0-day in any of these four services
→ LAN-side MITM capability.

Moving these services to isolated netns is blocked by the
hardware requirement (one bridge, one set of Wi-Fi phys, one
rtnetlink namespace that matters), not by design choice. The
`dns` and `ntp` services demonstrate the isolated-netns pattern
where it's feasible.

### Known — firewall feature-set vs OpenWrt fw4

The zone/rule abstraction covers the common deployments but
doesn't match fw4 feature-for-feature. Gaps that remain after
the fw4-parity pass:

- **IPv6 DNAT / port-forwards to v6 targets.** `oxwrt-nat6`
  (MASQUERADE66) is installed when dual-stack zones have
  `masquerade = true`, but `PortForward.internal` still parses
  only IPv4 `ip:port`. Operators exposing a v6 service hand-roll
  via `[[firewall.raw_nft]]` against `ip6 filter` / `ip6
  oxwrt-nat6` until the schema grows a v6 target variant.
- **IPsets.** No `[[firewall.ipsets]]` with `match_set` in
  rules. Country-block / threat-intel workflows need raw_nft
  sets + manual member management.
- **Connection-tracking helpers (SIP ALG, FTP active mode, PPTP
  GRE, RTSP).** Not auto-loaded. Operators who need these load
  the modules manually and express them via raw_nft.
- **`target = "NOTRACK"` / CT zones.** Absent. Rare (high-
  throughput forwarding paths or CGNAT-facing ISP setups).

Everything else from the mainstream fw4 surface landed in the
parity pass: zone `default_output`, rule `src_ip`/`dest_ip`/
`src_mac`/`src_port`/`icmp_type`/`family`/`limit`/`log`/
`enabled`, port-forward `reflection`, IPv6 MASQUERADE66.

### Known — no passphrase strength enforcement

The Wi-Fi passphrase field accepts anything 8+ characters
(RFC2898 floor). No entropy check, no dictionary rejection, no
"insecure password detected" warning. `wifi_rotate` generates
96-bit random passphrases, so operators who enable rotation
sidestep this.

### Known — stolen-device recovery is ad hoc

If a router is stolen, the attacker has the sQUIC server key,
WG server key, Wi-Fi passphrases, every control-plane client
pubkey, every VPN client private key. The operator's only
recovery is: rotate every credential, add the attacker's keys
to a revocation list that doesn't exist yet, re-enrol every
client. No remote-wipe, no per-boot attestation, no TPM-sealed
secrets.

Mitigation today: physically secure the router; take and store
a backup so re-provisioning a replacement is a single
`oxctl restore` instead of a full rebuild.

## Audit helpers (enforced by tests)

- `secrets::tests::split_moves_wifi_passphrase` + siblings:
  assert every SECRET_FIELDS leaf is moved off the public TOML
  on split. Catches a new secret-bearing field being silently
  left inline.
- `rollback::tests::restore_clears_live_secrets_when_snapshot_
  has_none`: guards against a rollback resurrecting credentials
  the operator had deliberately stopped shipping.
- `wan_dhcp::tests::empty_strings_suppress_emission`: zero-
  length DHCP options (hostname, vendor-class-id) aren't emitted
  — some DHCP servers misbehave on them.
- `net::tests::parse_mac_rejects_multicast`: multicast MAC on
  WAN is rejected at parse time (DHCP DISCOVERs would be dropped
  silently otherwise).

## Reporting a vulnerability

This is a personal-hobby-scale project. If you find something
credible, **open a GitHub issue marked `[security]` with as much
context as you can share publicly**, or email the repo owner
directly if coordinated disclosure matters. I'll respond within
a few days — sometimes same-day, never longer than two weeks.

Please don't run active exploitation against hardware you don't
own. I can't pay bounties but I'll credit you in the fix commit
+ release notes if you want.
