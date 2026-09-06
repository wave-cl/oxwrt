# Flashing checklist — GL-MT6000 (Flint 2)

Putting oxwrt onto the router. This is a hands-on task at the hardware. oxwrt is
a **no-shell appliance**: once it is running there is no SSH or LuCI, only
`oxctl` over sQUIC — so keep the U-Boot recovery path (§E) in reach before you
flash.

References: the "First-flash workflow" in [`README.md`](../README.md), the
`Makefile` `image`/`verity` targets, and the known gaps in
[`SECURITY.md`](../SECURITY.md). Steps that follow GL.iNet convention rather than
this repo are marked **[verify against GL.iNet Flint 2 docs]** — hardware revs
differ; confirm before relying on them.

## 0. What you need
- **A Linux build host** for the image itself: the OpenWrt buildroot (`make
  image`) does not run on macOS. The Rust binaries cross-compile anywhere and
  get staged; only the final image assembly needs Linux.
- Toolchain: Rust stable, `cargo-zigbuild`, `zig` (README pins 0.14; newer
  releases work too). On macOS, GNU `ar` from Homebrew `binutils` for the ring
  link step — see the `AR_AARCH64` note in the `Makefile`.
- The GL-MT6000, its PSU, and an Ethernet cable to a LAN port.
- **Strongly recommended: a USB-UART/serial adapter** on the board's console
  header. First boot prints the server pubkey to UART, and the daemon surfaces a
  "needs UART" message on some failure paths (`SECURITY.md`). Flashing a
  shell-less appliance without a console is flying blind.
- `oxctl` on your laptop (`cargo build --release -p oxwrtctl-cli`).

## A. Build the image (Linux host)
1. Cross-build the binaries (Mac or Linux):
   ```sh
   cargo zigbuild --release --target aarch64-unknown-linux-musl -p oxwrtd -p oxwrtctl-cli
   ```
   (macOS: prefix with `AR_aarch64_unknown_linux_musl=<homebrew binutils ar>`.)
2. Stage the service binaries: `make services-stage` (hickory-dns, ntp-daemon,
   coredhcp, corerad, hostapd, upnpd — see the Makefile prerequisites).
3. Bake provisioning secrets (recommended): copy
   [`config/oxwrt.secrets.toml.example`](../config/oxwrt.secrets.toml.example) →
   `provisioning/oxwrt.secrets.toml` and fill it in; optionally add
   `provisioning/key.ed25519` for a fixed server seed instead of first-boot
   auto-generation. `provisioning/` is gitignored.
4. Assemble the image (Linux): `make image`. Output is the standard OpenWrt
   `bin/targets/mediatek/filogic/…-sysupgrade.bin` for the GL-MT6000 profile.
   **[verify the exact target/profile/filename in the build output]**
5. Optional: `make verity` wraps the squashfs in a dm-verity hash tree (root hash
   in the kernel cmdline — block-level tamper detection).
6. **Record `sha256sum` of the sysupgrade image.** Firmware is **unsigned**
   (`SECURITY.md`), so this hash is the only integrity check — carry it to the
   flash step.

## B. Provision config (laptop)
1. `oxctl wizard --out /tmp/oxwrt.toml` — prompts for hostname, LAN CIDR, WAN
   mode, SSIDs; emits a split public + secrets pair.
2. Review both files; they land in `/etc/oxwrt/` on the router (baked via
   `provisioning/` in §A, or copied after first boot).

## C. Flash the device
First flash (from stock GL.iNet firmware) — ordered by safety:
1. **U-Boot web recovery (safest, and the un-brick path).** Power off; hold
   **reset** while powering on until the LED flashes; the router serves a
   recovery page at `http://192.168.1.1`; set your NIC to `192.168.1.2/24`;
   upload the `-sysupgrade.bin`. **[verify reset-hold timing and recovery IP
   against GL.iNet Flint 2 docs]**
2. **GL.iNet stock UI.** LAN to `192.168.8.1`, admin UI → firmware upgrade →
   upload `-sysupgrade.bin`, **uncheck "keep settings"** (you want a clean
   rootfs). **[verify menu path on current GL firmware]**

Subsequent updates (device already on oxwrt): use the daemon's own atomic path,
`oxctl … sysupgrade` (`oxwrt-linux/src/sysupgrade.rs`), which falls back on
failure. There is no LuCI/SSH fallback.

Before flashing: NIC on the right subnet, image hash matches §A.6, UART attached,
and you know how to reach U-Boot recovery (§C.1).

## D. First boot + bring-up
1. Watch UART: the server keypair auto-generates and persists at first boot and
   its pubkey prints to the console (or `oxctl --print-server-key` on the device).
2. Point `oxctl` at the router (default control endpoint per the README quick
   start is `192.168.50.1:51820` — confirm against your config):
   ```sh
   export SQUIC_SERVER_KEY=<64-hex server pubkey>
   oxctl 192.168.50.1:51820 status
   ```
3. Authorize your laptop in `oxwrt.toml`:
   ```toml
   [[control.clients]]
   name = "laptop"
   key  = "…your client pubkey (64 hex)…"
   ```
4. Apply (and every later change): `config-push` → `reload --dry-run` → `reload`.
   On a failed reconcile the daemon auto-restores the last-good snapshot and
   returns the original error.
5. Verify: `oxctl … status`, `… diag links`, `… wifi list`; confirm WAN up and a
   LAN client gets DHCP + internet.

## E. Rollback / recovery
- Config regressions: `oxctl … rollback --confirm` (`rollback-list` shows the
  ring; `--to N` rewinds deeper).
- Bad image / won't boot: return to **U-Boot web recovery** (§C.1) and re-flash a
  known-good image, or restore stock GL.iNet firmware. This is the only recovery
  once the appliance is running (no shell) — which is why the UART + recovery-IP
  prep in §0/§C is non-negotiable.

## Caveats
- Firmware is **unsigned** and control-plane **rate limiting is not yet live**
  (`SECURITY.md` "Known limitations" / roadmap). Treat the LAN control endpoint as
  trusted-network-only until signed updates land.
- oxwrt's control plane is `oxctl`-only over sQUIC; it does not currently expose a
  transport connection cap the way the sqex/sqssh servers do.

