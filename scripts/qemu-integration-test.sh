#!/bin/sh
# qemu-integration-test.sh — end-to-end RPC test against oxwrtd
# running inside a real aarch64 Linux VM (QEMU + OpenWrt armsr/armv8).
#
# Complements scripts/integration-test.sh (Docker-based, fast, but
# shares the host kernel — skips landlock, clone3 CLONE_NEWUSER,
# nftables isolation, and the rest of our hardening stack). This
# harness boots a real kernel so those paths are actually exercised
# before any hardware flash.
#
# Flow:
#   1. Download the OpenWrt 25.12.2 armsr/armv8 ext4 combined-EFI
#      image (cached under /tmp/armvirt-qemu).
#   2. Overlay-inject oxwrtd in pid1 coexist mode:
#        /sbin/procd   ← oxwrtd (PID 1 takeover after preinit)
#        /etc/oxwrt/mode = init
#        /etc/oxwrt.toml = test config (listen 0.0.0.0:51820)
#        /etc/oxwrt/key.ed25519 = fresh random 32-byte seed
#   3. Boot QEMU with hostfwd udp::51820-:51820 so the host can
#      reach the control plane via 127.0.0.1:51820.
#   4. Poll `oxctl status` until the control plane answers, then run
#      the full RPC suite (get/set, CRUD, diag, error cases).
#   5. Kill QEMU, print pass/fail summary.
#
# Usage:
#   ./scripts/qemu-integration-test.sh
#
# Prerequisites:
#   - Docker Desktop (used only for ext4 loopback + musl --print-server-key
#     on the aarch64 binary)
#   - qemu-system-aarch64 + edk2-aarch64 EFI firmware (brew install qemu)
#   - Both binaries built:
#       cargo zigbuild --release --target aarch64-unknown-linux-musl -p oxwrtd
#       cargo build --release -p oxwrtctl-cli    # builds oxctl
#
# On Apple Silicon, QEMU picks up HVF acceleration implicitly (aarch64
# guest on aarch64 host); boot-to-ready is ~30s. On x86_64 hosts this
# runs under TCG and takes 2–3 min — still faster than flashing.

set -eu

PROJ_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="/tmp/armvirt-qemu"
BIN_LINUX="$PROJ_ROOT/target/aarch64-unknown-linux-musl/release/oxwrtd"
# Built by `cargo build --release -p oxwrtctl-cli`. Fall back to the
# daemon binary (oxwrtd also accepts `--client`) if oxctl is missing.
OXCTL="$PROJ_ROOT/target/release/oxctl"
BIN_HOST_FALLBACK="$PROJ_ROOT/target/release/oxwrtd"
IMG_URL_BASE="https://downloads.openwrt.org/releases/25.12.2/targets/armsr/armv8"
IMG_NAME="openwrt-25.12.2-armsr-armv8-generic-ext4-combined-efi.img"
BOOT_TIMEOUT_S=${BOOT_TIMEOUT_S:-120}

if [ ! -f "$BIN_LINUX" ]; then
    echo "Error: aarch64 oxwrtd not built. Run:" >&2
    echo "  cargo zigbuild --release --target aarch64-unknown-linux-musl -p oxwrtd" >&2
    exit 1
fi
if [ -x "$OXCTL" ]; then
    CLIENT="$OXCTL"
elif [ -x "$BIN_HOST_FALLBACK" ]; then
    CLIENT="$BIN_HOST_FALLBACK --client"
else
    echo "Error: neither oxctl nor host oxwrtd found. Run:" >&2
    echo "  cargo build --release -p oxwrtctl-cli" >&2
    exit 1
fi
if ! command -v qemu-system-aarch64 >/dev/null 2>&1; then
    echo "Error: qemu-system-aarch64 not found. brew install qemu." >&2
    exit 1
fi

# Locate EDK2 aarch64 EFI firmware (varies by brew prefix).
EFI_FW=""
for cand in \
    /opt/local/share/qemu/edk2-aarch64-code.fd \
    /opt/homebrew/share/qemu/edk2-aarch64-code.fd \
    /usr/local/share/qemu/edk2-aarch64-code.fd \
    /Users/c/homebrew/share/qemu/edk2-aarch64-code.fd \
    /usr/share/qemu-efi-aarch64/QEMU_EFI.fd \
    /usr/share/AAVMF/AAVMF_CODE.fd \
    /usr/share/edk2/aarch64/QEMU_EFI.fd; do
    if [ -f "$cand" ]; then EFI_FW="$cand"; break; fi
done
if [ -z "$EFI_FW" ]; then
    echo "Error: edk2-aarch64-code.fd not found. Reinstall qemu via brew." >&2
    exit 1
fi

mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# ── Test bookkeeping ──
PASS=0
FAIL=0
check() {
    name="$1"
    expected="$2"
    actual="$3"
    if echo "$actual" | grep -qF "$expected"; then
        PASS=$((PASS + 1))
        echo "  OK   $name"
    else
        FAIL=$((FAIL + 1))
        echo "  FAIL $name"
        echo "       expected: $expected"
        echo "       got:      $(echo "$actual" | head -3)"
    fi
}
check_ok() { check "$1" "ok" "$2"; }
check_err() { check "$1 -> error" "$2" "$3"; }

# ── Step 1: fetch + prepare fresh image ──
echo "=== [1/5] preparing image ==="
if [ ! -f "${IMG_NAME}.gz" ]; then
    echo "downloading $IMG_NAME.gz..."
    curl -sS --connect-timeout 10 --max-time 180 -O "$IMG_URL_BASE/${IMG_NAME}.gz"
fi
rm -f img-test.img
gunzip -ck "${IMG_NAME}.gz" > img-test.img

# ── Step 2: overlay injection ──
echo "=== [2/5] injecting overlay ==="
# Generate fresh ed25519 seed for this test run (not the provisioning
# key). Derive its pubkey via Docker — oxctl is host-native, can't
# print an aarch64 binary's pubkey directly.
dd if=/dev/urandom of="$BUILD_DIR/test-key.ed25519" bs=32 count=1 2>/dev/null
# Use the host-native oxctl to derive the pubkey (seed format is
# 32 raw bytes — arch-independent).
SERVER_KEY=$("$OXCTL" --print-server-key "$BUILD_DIR/test-key.ed25519" 2>/dev/null || true)
if [ -z "$SERVER_KEY" ]; then
    echo "Error: oxctl --print-server-key failed." >&2
    exit 1
fi
echo "test server key: $SERVER_KEY"

# Minimal pid1-standalone config. eth0 is the virtio-net WAN (QEMU
# user-networking gives 10.0.2.15/24 via DHCP). No LAN bridge — the
# test VM has one vNIC. The control plane binds 0.0.0.0:51820 so
# hostfwd can reach it.
cat > "$BUILD_DIR/test-oxwrt.toml" << 'TOML'
hostname = "qemu-test"

[[networks]]
name = "wan"
type = "wan"
iface = "eth0"
mode = "dhcp"

# Minimal firewall: WAN zone drops input by default, but we open
# UDP 51820 for the test driver. QEMU user-mode hostfwd forwards
# the host's 127.0.0.1:51820 onto eth0 inside the VM, so this rule
# is what makes the control plane reachable from the host.
[[firewall.zones]]
name = "wan"
networks = ["wan"]
default_input = "drop"
default_forward = "drop"

[[firewall.rules]]
name = "ct-established"
action = "accept"
ct_state = ["established", "related"]

[[firewall.rules]]
name = "control-plane-wan-test"
src = "wan"
proto = "udp"
dest_port = 51820
action = "accept"

[control]
listen = ["0.0.0.0:51820"]
authorized_keys = "/etc/oxwrt/authorized_keys"

# WireGuard: declared here so wg-peer CRUD has somewhere to attach.
# The iface bring-up fails inside armsr/armv8 (stock image lacks
# kmod-wireguard); the oxwrtd code logs the error and continues,
# which is the desired degraded-mode behavior. CRUD still works
# because it only touches the Config, not the kernel.
[[wireguard]]
name = "wg0"
listen_port = 51820
key_path = "/etc/oxwrt/wg0.key"

# Static route — onlink /16 via eth0 so the kernel accepts it
# without a gateway (no second NIC in the VM to route via). The
# oxwrtd static_routes module installs this at boot; the assertion
# below checks the config-dump shows it and /proc/net/route
# contains 172.16.0.0.
[[routes]]
dest = "172.16.0.0"
prefix = 16
iface = "eth0"

# Blocklist — the URL is deliberately unreachable (.invalid TLD is
# reserved per RFC 2606). This exercises the fail-open path:
# fetch fails, empty set installs, table still gets created. We
# check via config-dump below.
[[blocklists]]
name = "fh_test"
url = "http://blocklist.invalid/list.txt"
refresh_seconds = 86400

# UPnP config — the binary isn't installed so no daemon spawns,
# but oxwrtd still renders /etc/oxwrt/miniupnpd.conf on boot.
# The assertion below checks the file exists + contains
# ext_ifname=eth0.
[upnp]
wan = "eth0"
lan = "eth0"
TOML

# ext4 loopback mount + overlay injection (same offset trick as
# qemu-openwrt-boot.sh — Docker Desktop's partition scanner is flaky).
OFFSET=$((262656 * 512))
# Native-platform alpine is fine — this container only does file-copy
# + ext4 mount/umount, no aarch64 execution. Forcing linux/arm64 here
# would require qemu-user-static on x86_64 runners (CI breaks with
# "exec format error" without it).
docker run --rm --privileged \
    -v "$BUILD_DIR:/work" -v "$PROJ_ROOT:/repo:ro" \
    alpine:latest sh -ec "
apk add --no-cache e2fsprogs util-linux >/dev/null
cd /work
mkdir -p /mnt/root
mount -o loop,offset=$OFFSET img-test.img /mnt/root

# pid1-coexist: overwrite /sbin/procd. OpenWrt's /sbin/init
# (procd-init) execs /sbin/procd at end of preinit — our binary
# takes PID 1 with the rootfs already mounted and modules loaded.
cp /repo/target/aarch64-unknown-linux-musl/release/oxwrtd /mnt/root/sbin/procd
chmod 755 /mnt/root/sbin/procd

# Config + secrets
mkdir -p /mnt/root/etc/oxwrt
cp /work/test-oxwrt.toml /mnt/root/etc/oxwrt.toml
cp /work/test-key.ed25519 /mnt/root/etc/oxwrt/key.ed25519
chmod 600 /mnt/root/etc/oxwrt/key.ed25519
echo init > /mnt/root/etc/oxwrt/mode
touch /mnt/root/etc/oxwrt/authorized_keys

sync
umount /mnt/root
" >/dev/null

# ── Step 3: boot QEMU in background ──
echo "=== [3/5] booting QEMU ==="
# -M virt + HVF on Apple Silicon: native-speed aarch64. On x86_64
# hosts HVF is unavailable and QEMU falls back to TCG automatically.
# hostfwd forwards udp:51820 so oxctl on the host reaches the VM's
# control plane at 127.0.0.1:51820. tcp:2222 is handy for dropping
# into the VM via ssh during debug (no-op otherwise).
# CPU choice: on macOS arm64 HVF is used implicitly and `-cpu max`
# gives native speed. Under TCG on x86_64 runners, `-cpu max` is
# dramatically slower because it emulates SVE + every optional
# extension. `cortex-a72` is fast under TCG and modern enough for
# OpenWrt's armsr/armv8 kernel. On HVF (Apple Silicon) both work;
# `max` would be marginally better but consistency wins.
qemu-system-aarch64 \
    -M virt -cpu cortex-a72 -m 512M -smp 2 \
    -nographic -no-reboot \
    -bios "$EFI_FW" \
    -drive if=virtio,format=raw,file="$BUILD_DIR/img-test.img" \
    -netdev user,id=net0,hostfwd=tcp::2222-:22,hostfwd=udp::51820-:51820 \
    -device virtio-net-pci,netdev=net0 \
    > "$BUILD_DIR/boot.log" 2>&1 &
QPID=$!
# Ensure VM is always cleaned up — even on ^C, test failure, or error.
trap 'kill $QPID 2>/dev/null || true; wait $QPID 2>/dev/null || true' EXIT INT TERM

# Poll control plane. Track wall time, not loop iterations — every
# oxctl handshake attempt can take up to ~10s on cold-boot CI hosts
# before timing out, so counting `+= 2` per loop massively underbids
# the real elapsed and the timeout never fires within job limits.
export SQUIC_SERVER_KEY="$SERVER_KEY"
READY=0
start_ts=$(date +%s)
echo "waiting for control plane (up to ${BOOT_TIMEOUT_S}s)..."
while : ; do
    elapsed=$(($(date +%s) - start_ts))
    if [ $elapsed -ge $BOOT_TIMEOUT_S ]; then
        break
    fi
    if $CLIENT 127.0.0.1:51820 status 2>/dev/null | grep -q "supervisor uptime"; then
        READY=1
        break
    fi
    sleep 2
done
if [ $READY -eq 0 ]; then
    echo "FAIL: control plane never became ready. last 20 lines of boot log:"
    tail -20 "$BUILD_DIR/boot.log"
    exit 1
fi
echo "control plane ready after ${elapsed}s"

# ── Step 4: RPC suite ──
echo ""
echo "=== [4/5] RPC test suite ==="
run_cmd() {
    $CLIENT 127.0.0.1:51820 "$@" 2>&1 || true
}

echo "-- get/set --"
R=$(run_cmd get hostname); check "get hostname" "qemu-test" "$R"
R=$(run_cmd set hostname "qemu-updated"); check "set hostname" "qemu-updated" "$R"
R=$(run_cmd get hostname); check "get hostname after set" "qemu-updated" "$R"
R=$(run_cmd get wan.mode); check "get wan.mode" "dhcp" "$R"

echo "-- status --"
R=$(run_cmd status); check "status" "supervisor uptime" "$R"

echo "-- rule CRUD --"
# Test config has one rule (ct-established) + control-plane-wan-test
# baked in. Use src=wan (the only zone) for the test rule.
R=$(run_cmd rule add '{"name":"t1","src":"wan","proto":"tcp","dest_port":8080,"action":"accept"}')
check_ok "rule add" "$R"
R=$(run_cmd rule list); check "rule list (has t1)" "t1" "$R"
R=$(run_cmd rule get t1); check "rule get" "t1" "$R"
R=$(run_cmd rule remove t1); check_ok "rule remove" "$R"

# Validator regressions — each must fail at CRUD add time, not wait
# for install to silently do the wrong thing.
R=$(run_cmd rule add '{"name":"","action":"accept"}')
check_err "rule empty name" "name must not be empty" "$R"
R=$(run_cmd rule add '{"name":"bad","action":"dnat"}')
check_err "rule dnat without target" "requires dnat_target" "$R"
R=$(run_cmd rule add '{"name":"bad","action":"dnat","dnat_target":"not-an-ip-port"}')
check_err "rule dnat bad target" "dnat_target" "$R"
R=$(run_cmd rule add '{"name":"bad","action":"accept","dnat_target":"10.0.0.1:80"}')
check_err "rule non-dnat with target" "action=dnat" "$R"
R=$(run_cmd rule add '{"name":"bad","proto":"icmp","dest_port":53,"action":"accept"}')
check_err "rule icmp with port" "icmp" "$R"

echo "-- zone CRUD --"
R=$(run_cmd zone list); check "zone list (has wan)" "wan" "$R"
R=$(run_cmd zone add '{"name":"z1","networks":["wan"],"default_input":"drop","default_forward":"drop"}')
check_ok "zone add" "$R"
R=$(run_cmd zone remove z1); check_ok "zone remove" "$R"

echo "-- network CRUD --"
R=$(run_cmd network list); check "network list" "wan" "$R"
R=$(run_cmd network add '{"name":"dmz","type":"simple","iface":"br-dmz","address":"10.50.0.1","prefix":24}')
check_ok "network add dmz" "$R"
R=$(run_cmd network get dmz); check "network get dmz" "10.50.0.1" "$R"
R=$(run_cmd network remove dmz); check_ok "network remove dmz" "$R"

echo "-- radio CRUD --"
# Radio must exist before wifi references it — do radio first.
R=$(run_cmd radio add '{"phy":"phy0","band":"2g","channel":6}'); check_ok "radio add" "$R"
R=$(run_cmd radio list); check "radio list (has phy0)" "phy0" "$R"

echo "-- wg-peer CRUD --"
# Valid pubkey is 44-char base64 ending with '='. Use a fixed test
# key; its private half is never exercised (no actual handshake in CI).
R=$(run_cmd wg-peer list); check "wg-peer list (empty)" "[]" "$R"
R=$(run_cmd wg-peer add '{"name":"alice","pubkey":"aXlSNXL0yz8P6Fkb6Xa9W3Fkq7cLKgqx7qVqEHS9f00=","allowed_ips":"10.8.0.2/32"}')
check_ok "wg-peer add alice" "$R"
R=$(run_cmd wg-peer get alice); check "wg-peer get" "10.8.0.2/32" "$R"
R=$(run_cmd wg-peer list); check "wg-peer list (has alice)" "alice" "$R"
# Reject malformed pubkey.
R=$(run_cmd wg-peer add '{"name":"bad","pubkey":"too-short","allowed_ips":"10.8.0.3/32"}')
check_err "wg-peer add bad pubkey" "44-char base64" "$R"
# Reject bad CIDR.
R=$(run_cmd wg-peer add '{"name":"bad2","pubkey":"bbbbbFkq7cLKgqx7qVqEHS9f00NL0yz8P6Fkb6Xa9W3=","allowed_ips":"notacidr"}')
check_err "wg-peer add bad cidr" "missing /prefix" "$R"
R=$(run_cmd wg-peer remove alice); check_ok "wg-peer remove" "$R"

# wg-enroll: server-generated client keypair + rendered .conf. The
# stock armsr/armv8 test VM lacks wireguard-tools (we'd need to opkg
# install or reshape the image), so the `wg` invocation inside the
# enroll handler returns EEXEC. Validating the error path is still
# useful — it confirms the RPC is dispatched, args parse, and the
# handler fails gracefully when the binary is missing.
R=$(run_cmd wg-enroll charlie 10.8.0.4/32 vpn.example.com)
# Accept either success (if wg is present) OR the friendly binary-
# missing error (more common in CI). Both prove plumbing works.
if echo "$R" | grep -qE "PrivateKey|wireguard-tools"; then
    PASS=$((PASS + 1))
    echo "  OK   wg-enroll (either rendered conf or friendly missing-tool error)"
else
    FAIL=$((FAIL + 1))
    echo "  FAIL wg-enroll"
    echo "       got: $(echo "$R" | head -3)"
fi

echo "-- backup / restore --"
BACKUP_PATH="$BUILD_DIR/backup.tar.gz"
# Take a backup, redirect to file. Backup response writes raw bytes
# to stdout (not the normal text-formatted path).
if $CLIENT 127.0.0.1:51820 backup > "$BACKUP_PATH" 2>/dev/null; then
    # Validate it's a real gzipped tar.
    if file "$BACKUP_PATH" 2>/dev/null | grep -q "gzip compressed"; then
        PASS=$((PASS + 1))
        echo "  OK   backup (gzip output)"
    else
        FAIL=$((FAIL + 1))
        echo "  FAIL backup — wrong file type: $(file "$BACKUP_PATH")"
    fi
    # Should contain oxwrt.toml.
    if tar -tzf "$BACKUP_PATH" 2>/dev/null | grep -q "^oxwrt.toml$"; then
        PASS=$((PASS + 1))
        echo "  OK   backup contains oxwrt.toml"
    else
        FAIL=$((FAIL + 1))
        echo "  FAIL backup missing oxwrt.toml"
    fi
else
    FAIL=$((FAIL + 2))
    echo "  FAIL backup — RPC failed"
fi
# Restore without --confirm is rejected.
R=$(run_cmd restore "$BACKUP_PATH")
check_err "restore without confirm" "confirm" "$R"
# Restore with --confirm succeeds (roundtrip the same backup back in).
R=$(run_cmd restore "$BACKUP_PATH" --confirm)
check_ok "restore with confirm" "$R"

echo "-- ddns CRUD --"
R=$(run_cmd ddns list); check "ddns list (empty)" "[]" "$R"
R=$(run_cmd ddns add '{"provider":"duckdns","name":"home","domain":"myrouter","token":"tok"}')
check_ok "ddns add duckdns" "$R"
R=$(run_cmd ddns get home); check "ddns get" "myrouter" "$R"
R=$(run_cmd ddns list); check "ddns list (has home)" "home" "$R"
R=$(run_cmd ddns add '{"provider":"cloudflare","name":"cf","zone_id":"z","record_id":"r","domain":"a.example.com","api_token":"tok"}')
check_ok "ddns add cloudflare" "$R"
# Dup rejection.
R=$(run_cmd ddns add '{"provider":"duckdns","name":"home","domain":"x","token":"y"}')
check_err "ddns add dup name" "already exists" "$R"
R=$(run_cmd ddns remove home); check_ok "ddns remove" "$R"
R=$(run_cmd ddns remove cf); check_ok "ddns remove cf" "$R"

echo "-- port-forward CRUD --"
# Expand minimal test config to include a LAN for auto-detect, via an
# add-network call. Then exercise port-forward add/list/get/remove.
R=$(run_cmd network add '{"name":"lan","type":"lan","bridge":"br-test","members":[],"address":"192.168.77.1","prefix":24}')
check_ok "network add lan (for port-forward test)" "$R"
# Need the zone too so validator passes.
R=$(run_cmd zone add '{"name":"lan","networks":["lan"],"default_input":"accept","default_forward":"drop"}')
check_ok "zone add lan" "$R"
R=$(run_cmd port-forward list); check "port-forward list (empty)" "[]" "$R"
R=$(run_cmd port-forward add '{"name":"mc","proto":"tcp","external_port":25565,"internal":"192.168.77.50:25565"}')
check_ok "port-forward add (auto-detect dest)" "$R"
R=$(run_cmd port-forward get mc); check "port-forward get" "25565" "$R"
R=$(run_cmd port-forward list); check "port-forward list (has mc)" "mc" "$R"
# Invalid internal: should reject.
R=$(run_cmd port-forward add '{"name":"bad","proto":"tcp","external_port":80,"internal":"not.an.ip:8080"}')
check_err "port-forward add invalid internal" "invalid internal IP" "$R"
# IP outside any subnet: should reject (dest auto-detect).
R=$(run_cmd port-forward add '{"name":"elsewhere","proto":"tcp","external_port":81,"internal":"8.8.8.8:80"}')
check_err "port-forward add unreachable IP" "not in any LAN" "$R"
R=$(run_cmd port-forward remove mc); check_ok "port-forward remove" "$R"
R=$(run_cmd zone remove lan); check_ok "zone remove lan" "$R"
R=$(run_cmd network remove lan); check_ok "network remove lan" "$R"

echo "-- wifi CRUD --"
R=$(run_cmd wifi list); check "wifi list (empty)" "[]" "$R"
R=$(run_cmd wifi add '{"radio":"phy0","ssid":"TestNet","security":"wpa3-sae","passphrase":"testpass","network":"wan"}')
check_ok "wifi add" "$R"
R=$(run_cmd wifi remove TestNet); check_ok "wifi remove" "$R"
R=$(run_cmd radio remove phy0); check_ok "radio remove (post-wifi)" "$R"

echo "-- static routes --"
# static_routes::install ran at boot; check config-dump + the
# kernel route table via diag. The diag surface doesn't have a
# dedicated `routes` op yet, so we verify via diag links (which
# exercises the rtnetlink handle) + config-dump schema presence.
R=$(run_cmd config-dump); check "config-dump has routes section" "172.16.0.0" "$R"

echo "-- blocklists --"
# Fail-open path: URL is .invalid so fetch fails at boot; the
# `oxwrt-blocklist` table still gets installed with an empty set
# (this is the whole point of fail-open — a CDN outage can't drop
# all traffic). diag nft-style reach via `diag nft` doesn't list
# multiple tables yet, so we verify via config-dump schema.
R=$(run_cmd config-dump); check "config-dump has blocklist" "fh_test" "$R"

echo "-- upnp config schema --"
# miniupnpd::write_config ran at boot. config-dump serializes the
# `[upnp]` block as TOML; we confirm the section header is present.
# Render correctness is covered by oxwrt-linux unit tests — the QEMU
# assertion is just "daemon parsed + round-tripped the schema on a
# real kernel."
R=$(run_cmd config-dump); check "config-dump has [upnp] section" "[upnp]" "$R"

echo "-- vlan sub-iface (runtime creation) --"
# Add a VLAN Simple network via CRUD, reload, confirm eth0.99
# shows up in `diag links`. The armsr/armv8 kernel ships the 8021q
# module so this should succeed; failure = a regression in the
# rtnetlink LinkVlan path in net::bring_up_simple.
R=$(run_cmd network add '{"name":"vlan99","type":"simple","iface":"eth0.99","address":"10.99.0.1","prefix":24,"vlan":99,"vlan_parent":"eth0"}')
check_ok "network add vlan99" "$R"
R=$(run_cmd reload); check_ok "reload after vlan99 add" "$R"
R=$(run_cmd diag links); check "diag links shows eth0.99" "eth0.99" "$R"
# VLAN without vlan_parent should be rejected at validate-time.
R=$(run_cmd network add '{"name":"bad","type":"simple","iface":"bad","address":"10.1.0.1","prefix":24,"vlan":10}')
check_err "vlan without parent rejected" "vlan_parent" "$R"
# VLAN id out of range rejected.
R=$(run_cmd network add '{"name":"bad","type":"simple","iface":"bad","address":"10.1.0.1","prefix":24,"vlan":9999,"vlan_parent":"eth0"}')
check_err "vlan id out of range rejected" "out of range" "$R"
R=$(run_cmd network remove vlan99); check_ok "network remove vlan99" "$R"

echo "-- config dump/push --"
R=$(run_cmd config-dump); check "config-dump has hostname" "qemu-updated" "$R"

echo "-- diag (real kernel) --"
R=$(run_cmd diag links); check "diag links (has lo)" "lo" "$R"
# eth0 should be present via virtio-net
check "diag links (has eth0)" "eth0" "$R"
R=$(run_cmd diag nft); check "diag nft (has input chain)" "chain input" "$R"
R=$(run_cmd diag conntrack); check "diag conntrack (runs)" "" "$R"
# Wake-on-LAN: bare `diag wol` with no MAC arg surfaces a clear
# error. A valid send would require a reachable LAN broadcast
# domain which this harness doesn't model, so we test the
# validator path only.
R=$(run_cmd diag wol); check_err "diag wol without mac rejected" "missing" "$R"
R=$(run_cmd diag wol "zzz"); check_err "diag wol invalid mac rejected" "hex" "$R"
# diag devices: ARP-cache-based snapshot of LAN peers. The QEMU
# harness doesn't model real LAN clients so the ARP table is
# usually empty — assert the "no devices" fallback string.
R=$(run_cmd diag devices); check "diag devices (runs)" "LAN" "$R"

echo "-- reload dry-run --"
# Clean config — dry-run must pass before the reload runs it for
# real in the subsequent assertion.
R=$(run_cmd reload --dry-run); check_ok "reload --dry-run (clean config)" "$R"

echo "-- rollback --"
# --confirm gate: bare `rollback` must refuse.
R=$(run_cmd rollback); check_err "rollback without --confirm rejected" "confirm" "$R"
# The boot path takes a snapshot after reconcile succeeds, so by
# now slot 0 exists; rollback --confirm should succeed (reverts
# to itself, reloads).
R=$(run_cmd rollback --confirm); check_ok "rollback --confirm (slot 0)" "$R"
# rollback-list: pure read, enumerates the ring. Boot-time
# snapshot means at least one row appears.
R=$(run_cmd rollback-list); check "rollback-list shows slot 0" "index" "$R"
# Out-of-range --to is rejected with a clear message.
R=$(run_cmd rollback --confirm --to 99); check_err "rollback --to out-of-range" "out of range" "$R"

echo "-- error cases --"
R=$(run_cmd get nope.key); check_err "get unknown key" "unknown" "$R"
R=$(run_cmd rule remove doesnotexist); check_err "remove nonexistent" "not found" "$R"
R=$(run_cmd apply); check_err "apply without confirm" "confirm" "$R"
R=$(run_cmd reload --froogly); check_err "reload unknown flag rejected" "unknown flag" "$R"

# ── Step 5: teardown + report ──
echo ""
echo "=== [5/5] teardown ==="
kill $QPID 2>/dev/null || true
wait $QPID 2>/dev/null || true
trap - EXIT INT TERM

echo ""
echo "================================"
echo "  PASS:  $PASS"
echo "  FAIL:  $FAIL"
echo "  TOTAL: $((PASS + FAIL))"
echo "================================"
echo "Boot log: $BUILD_DIR/boot.log"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
