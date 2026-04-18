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
BOOT_TIMEOUT_S=120

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
    /Users/c/homebrew/share/qemu/edk2-aarch64-code.fd; do
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
TOML

# ext4 loopback mount + overlay injection (same offset trick as
# qemu-openwrt-boot.sh — Docker Desktop's partition scanner is flaky).
OFFSET=$((262656 * 512))
docker run --rm --privileged --platform linux/arm64 \
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
qemu-system-aarch64 \
    -M virt -cpu max -m 512M -smp 2 \
    -nographic -no-reboot \
    -bios "$EFI_FW" \
    -drive if=virtio,format=raw,file="$BUILD_DIR/img-test.img" \
    -netdev user,id=net0,hostfwd=tcp::2222-:22,hostfwd=udp::51820-:51820 \
    -device virtio-net-pci,netdev=net0 \
    > "$BUILD_DIR/boot.log" 2>&1 &
QPID=$!
# Ensure VM is always cleaned up — even on ^C, test failure, or error.
trap 'kill $QPID 2>/dev/null || true; wait $QPID 2>/dev/null || true' EXIT INT TERM

# Poll control plane. Exponential-ish backoff is overkill; a 2s
# poll matches how fast the handshake should succeed once listening.
export SQUIC_SERVER_KEY="$SERVER_KEY"
READY=0
elapsed=0
echo "waiting for control plane (up to ${BOOT_TIMEOUT_S}s)..."
while [ $elapsed -lt $BOOT_TIMEOUT_S ]; do
    if $CLIENT 127.0.0.1:51820 status 2>/dev/null | grep -q "supervisor uptime"; then
        READY=1
        break
    fi
    sleep 2
    elapsed=$((elapsed + 2))
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

echo "-- wifi CRUD --"
R=$(run_cmd wifi list); check "wifi list (empty)" "[]" "$R"
R=$(run_cmd wifi add '{"radio":"phy0","ssid":"TestNet","security":"wpa3-sae","passphrase":"testpass","network":"wan"}')
check_ok "wifi add" "$R"
R=$(run_cmd wifi remove TestNet); check_ok "wifi remove" "$R"
R=$(run_cmd radio remove phy0); check_ok "radio remove (post-wifi)" "$R"

echo "-- config dump/push --"
R=$(run_cmd config-dump); check "config-dump has hostname" "qemu-updated" "$R"

echo "-- diag (real kernel) --"
R=$(run_cmd diag links); check "diag links (has lo)" "lo" "$R"
# eth0 should be present via virtio-net
check "diag links (has eth0)" "eth0" "$R"
R=$(run_cmd diag nft); check "diag nft (has input chain)" "chain input" "$R"
R=$(run_cmd diag conntrack); check "diag conntrack (runs)" "" "$R"

echo "-- error cases --"
R=$(run_cmd get nope.key); check_err "get unknown key" "unknown" "$R"
R=$(run_cmd rule remove doesnotexist); check_err "remove nonexistent" "not found" "$R"
R=$(run_cmd apply); check_err "apply without confirm" "confirm" "$R"

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
