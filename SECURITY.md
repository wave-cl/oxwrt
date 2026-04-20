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
FORWARD policy = DROP. The only accepts on WAN are: `ct state
established/related`, `lo`, and (when WAN is DHCP) a narrowly-
predicated bypass for the DISCOVER-cookie response. Control
plane listens on loopback + LAN, never `0.0.0.0` in the shipped
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

### Known — firmware updates are SHA-verified, not signed

`FwUpdate` verifies `sha256(image)` against a hash the client
sent (`sysupgrade.rs`). Any client with control-plane pubkey auth
can trigger an update. There is **no cryptographic signature
verification** on the image itself — a compromise of one operator
pubkey is sufficient to push arbitrary code.

Mitigation for operators: keep `control.clients` lists tight,
rotate keys after any suspected exposure, don't share pubkey
signing-keys across boxes.

**TODO.** Implement ed25519-signed release artifacts + verify
against a build-time embedded pubkey before sysupgrade. Tracked.

### Known — no control-plane rate limiting

sQUIC accepts connections in a naive `loop { accept; spawn }`
(`control/server/mod.rs::listen_on`). An authenticated client can
flood requests; an unauthenticated WAN attacker can burn CPU on
sQUIC handshake failures. Pubkey-pin rejection is cheap enough
that realistic WAN-scan rates don't DoS us, but there's no
explicit guardrail.

**TODO.** Per-pubkey token-bucket rate limit + global
connection-count cap.

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
