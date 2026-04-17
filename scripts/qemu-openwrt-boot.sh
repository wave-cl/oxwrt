#!/bin/sh
# qemu-openwrt-boot.sh — boot OpenWrt 25.12.2 armsr/armv8 in QEMU with
# our overlay injected. Used to verify that our overlay (oxwrtctl
# binary + /etc/init.d + /etc/uci-defaults + /etc/oxwrt.toml) doesn't
# introduce a boot-blocking bug.
#
# Complementary to qemu-boot.sh, which smoke-tests `oxwrtctl --init`
# as PID 1 in a minimal initramfs. This script runs the FULL OpenWrt
# preinit + procd + netifd boot sequence with our overlay files in
# place, exactly as they'd be on a flashed device — just on a
# QEMU-emulatable target (armsr/armv8) instead of the hardware-
# specific mediatek/filogic we ship against.
#
# Usage:
#   ./scripts/qemu-openwrt-boot.sh           # build image, boot, capture log
#   ./scripts/qemu-openwrt-boot.sh --keep    # keep running (ctrl-c to exit)
#
# Prerequisites:
#   - Docker Desktop (for ext4 mount + overlay injection)
#   - qemu-system-aarch64 (brew install qemu)
#   - aarch64 oxwrtctl built:
#       cargo zigbuild --release --target aarch64-unknown-linux-musl -p oxwrtctl
#
# Output:
#   /tmp/armvirt-qemu/img-with-overlay.img (the boot image)
#   /tmp/armvirt-qemu/boot.log (serial console capture)

set -eu

KEEP=0
[ "${1:-}" = "--keep" ] && KEEP=1

PROJ_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="/tmp/armvirt-qemu"
OXWRTCTL="$PROJ_ROOT/target/aarch64-unknown-linux-musl/release/oxwrtctl"
IMG_URL_BASE="https://downloads.openwrt.org/releases/25.12.2/targets/armsr/armv8"
IMG_NAME="openwrt-25.12.2-armsr-armv8-generic-ext4-combined-efi.img"

if [ ! -f "$OXWRTCTL" ]; then
    echo "Error: oxwrtctl not built for aarch64. Run:" >&2
    echo "  cargo zigbuild --release --target aarch64-unknown-linux-musl -p oxwrtctl" >&2
    exit 1
fi

# Locate QEMU + EDK2 EFI firmware. Homebrew puts them in different
# places depending on macOS / arch; probe a few.
QEMU_BIN="$(command -v qemu-system-aarch64 || true)"
if [ -z "$QEMU_BIN" ]; then
    echo "Error: qemu-system-aarch64 not found. brew install qemu." >&2
    exit 1
fi
EFI_FW=""
for cand in \
    /opt/local/share/qemu/edk2-aarch64-code.fd \
    /opt/homebrew/share/qemu/edk2-aarch64-code.fd \
    /usr/local/share/qemu/edk2-aarch64-code.fd; do
    if [ -f "$cand" ]; then EFI_FW="$cand"; break; fi
done
if [ -z "$EFI_FW" ]; then
    echo "Error: edk2-aarch64-code.fd not found in expected locations." >&2
    exit 1
fi

mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# Download the stock armsr/armv8 ext4 combined EFI image once, re-use
# across runs. Unzip each time because we inject into a fresh copy.
if [ ! -f "${IMG_NAME}.gz" ]; then
    echo "=== downloading $IMG_NAME.gz ==="
    curl -sS --connect-timeout 10 --max-time 180 -O "$IMG_URL_BASE/${IMG_NAME}.gz"
fi

echo "=== preparing fresh image copy ==="
rm -f img-with-overlay.img
gunzip -ck "${IMG_NAME}.gz" > img-with-overlay.img

echo "=== injecting overlay via ext4 loopback mount ==="
# Rootfs partition starts at sector 262656 (EFI combined image
# layout: GPT table + ESP + rootfs). Fix offset rather than rely on
# kernel partition scanning, which is flaky inside Docker Desktop's
# Linux VM.
OFFSET=$((262656 * 512))
docker run --rm --privileged --platform linux/arm64 \
    -v "$BUILD_DIR:/work" -v "$PROJ_ROOT:/repo:ro" \
    alpine:latest sh -ec "
apk add --no-cache e2fsprogs util-linux >/dev/null
cd /work
mkdir -p /mnt/root
mount -o loop,offset=$OFFSET img-with-overlay.img /mnt/root

# Binary + config (bare layer)
mkdir -p /mnt/root/etc/oxwrt /mnt/root/usr/bin
cp /repo/target/aarch64-unknown-linux-musl/release/oxwrtctl /mnt/root/usr/bin/oxwrtctl
chmod 755 /mnt/root/usr/bin/oxwrtctl
cp /repo/config/oxwrt.toml /mnt/root/etc/oxwrt.toml
echo control-only > /mnt/root/etc/oxwrt/mode
touch /mnt/root/etc/oxwrt/authorized_keys

# init.d
cp /repo/openwrt-packages/imagebuilder-overlay/files/etc/init.d/oxwrtctl \
   /mnt/root/etc/init.d/oxwrtctl
chmod 755 /mnt/root/etc/init.d/oxwrtctl

# uci-defaults
for f in 99-oxwrtctl 98-oxwrt-diag-rootfs 97-oxwrt-debug-ssh-rootfs; do
    cp /repo/openwrt-packages/imagebuilder-overlay/files/etc/uci-defaults/\$f \
       /mnt/root/etc/uci-defaults/\$f
    chmod 755 /mnt/root/etc/uci-defaults/\$f
done

# SSH pubkey
if [ -f /repo/.ssh-id-ed25519.pub ]; then
    cp /repo/.ssh-id-ed25519.pub /mnt/root/etc/dropbear/authorized_keys
    chmod 600 /mnt/root/etc/dropbear/authorized_keys
fi

echo 'overlay injected:'
ls /mnt/root/etc/uci-defaults/ | grep oxwrt
ls -la /mnt/root/usr/bin/oxwrtctl

sync
umount /mnt/root
"

echo ""
echo "=== booting QEMU ==="
QEMU_FLAGS="\
    -M virt -cpu max -m 512M -smp 2 \
    -nographic -no-reboot \
    -bios $EFI_FW \
    -drive if=virtio,format=raw,file=img-with-overlay.img \
    -netdev user,id=net0,hostfwd=tcp::2222-:22,hostfwd=udp::51820-:51820 \
    -device virtio-net-pci,netdev=net0"

if [ "$KEEP" = "1" ]; then
    echo "(running in foreground — ctrl-a x to exit QEMU, log in as root on serial)"
    exec $QEMU_BIN $QEMU_FLAGS
fi

( $QEMU_BIN $QEMU_FLAGS > "$BUILD_DIR/boot.log" 2>&1 ) &
QPID=$!
sleep 45
kill $QPID 2>/dev/null || true
wait $QPID 2>/dev/null || true

echo ""
echo "=== boot log analysis ==="
if grep -q "br-lan: port 1(eth0) entered forwarding state" "$BUILD_DIR/boot.log"; then
    echo "✅ network bringup completed (br-lan forwarding)"
else
    echo "❌ br-lan did not reach forwarding state"
fi
if grep -q "procd: - init -" "$BUILD_DIR/boot.log"; then
    echo "✅ procd reached init phase"
else
    echo "❌ procd did not reach init phase"
fi
if grep -qE "panic|BUG|oops" "$BUILD_DIR/boot.log"; then
    echo "❌ kernel panic/BUG/oops detected:"
    grep -E "panic|BUG|oops" "$BUILD_DIR/boot.log" | head -3
fi

echo ""
echo "Full log: $BUILD_DIR/boot.log"
echo "Run with --keep to boot interactively."
