#!/bin/sh
# qemu-boot.sh — boot oxwrtd as PID 1 in QEMU aarch64-virt.
#
# Builds a minimal initramfs containing oxwrtd + a stub config,
# downloads an Alpine aarch64 kernel, and boots QEMU. This proves the
# full PID-1 init flow (early mounts, config load, hostname, cgroup
# setup, supervisor start) in a real kernel — not just Docker pre_exec.
#
# Usage:
#   ./scripts/qemu-boot.sh
#
# Prerequisites:
#   - Docker (for initramfs assembly — aarch64 native on Apple Silicon)
#   - qemu-system-aarch64 (brew install qemu)
#   - oxwrtd built: target/aarch64-unknown-linux-musl/release/oxwrtd
#
# The QEMU instance runs for ~5 seconds, captures serial output, and
# exits. Success = "oxwrtd: supervisor starting" in the output.

set -eu

PROJ_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="$PROJ_ROOT/build/qemu"
OXWRTCTL="$PROJ_ROOT/target/aarch64-unknown-linux-musl/release/oxwrtd"

if [ ! -f "$OXWRTCTL" ]; then
    echo "Error: oxwrtd not found. Run 'cargo zigbuild --release --target aarch64-unknown-linux-musl -p oxwrtd' first." >&2
    exit 1
fi

mkdir -p "$BUILD_DIR"

echo "=== Step 1: Build initramfs ==="
# --platform linux/arm64 is REQUIRED. Without it Docker Desktop on an
# Apple Silicon host may fall back to amd64 (emulated via Rosetta 2),
# which installs the wrong-arch Alpine linux-virt kernel (x86 bzImage)
# that qemu-system-aarch64 silently refuses to boot — manifests as a
# totally empty serial log. The kernel must match the -cpu in the
# QEMU step below.
docker run --rm \
    --platform linux/arm64 \
    -v "$OXWRTCTL:/oxwrtd:ro" \
    -v "$BUILD_DIR:/out" \
    alpine:latest sh -ec '
    # Install cpio for initramfs creation
    apk add --no-cache cpio linux-virt 2>/dev/null | tail -1

    # Build the initramfs directory tree
    INITRD=/tmp/initramfs
    for d in sbin etc/oxwrt proc sys dev dev/pts sys/fs/cgroup var/lib/oxwrt/coredhcp usr/lib/oxwrt/services; do
        mkdir -p $INITRD/$d
    done

    # Install oxwrtd as /sbin/init AND /init (kernel looks for
    # /init in initramfs, /sbin/init on disk-based rootfs).
    cp /oxwrtd $INITRD/sbin/oxwrtd
    ln -sf oxwrtd $INITRD/sbin/init
    ln -sf sbin/oxwrtd $INITRD/init
    chmod +x $INITRD/sbin/oxwrtd

    # Minimal config — no services, just enough to boot as PID 1 in
    # QEMU. Uses the unified `[[networks]]` array format (type-tagged
    # wan/lan/simple variants), which is what config::Config has
    # expected since the CRUD refactor. An older copy of this file
    # shipped with the pre-refactor `[wan]` + `[lan]` separate-section
    # layout, which now fails parse with "missing field `networks`".
    cat > $INITRD/etc/oxwrt.toml << "TOML"
hostname = "qemu-test"

[[networks]]
name = "wan"
type = "wan"
iface = "eth0"
mode = "dhcp"

[[networks]]
name = "lan"
type = "lan"
bridge = "br-lan"
members = []
address = "192.168.8.1"
prefix = 24

[control]
listen = ["[::1]:51820"]
authorized_keys = "/etc/oxwrt/authorized_keys"
TOML

    touch $INITRD/etc/oxwrt/authorized_keys

    # Create initramfs cpio archive
    cd $INITRD
    find . | cpio -o -H newc 2>/dev/null | gzip > /out/initramfs.cpio.gz
    echo "initramfs: $(stat -c %s /out/initramfs.cpio.gz) bytes"

    # Copy the Alpine aarch64 kernel for QEMU
    KERNEL=$(find /boot -name "vmlinuz-*" -type f 2>/dev/null | head -1)
    if [ -n "$KERNEL" ]; then
        cp "$KERNEL" /out/vmlinuz
        echo "kernel: $KERNEL → /out/vmlinuz"
    else
        echo "WARNING: no kernel found in Alpine, will need external kernel"
    fi
'

if [ ! -f "$BUILD_DIR/vmlinuz" ]; then
    echo "Error: no kernel. Download one manually or install qemu with firmware." >&2
    exit 1
fi

echo ""
echo "=== Step 2: Boot QEMU ==="
echo "initramfs: $(ls -lh "$BUILD_DIR/initramfs.cpio.gz" | awk '{print $5}')"
echo "kernel:    $(ls -lh "$BUILD_DIR/vmlinuz" | awk '{print $5}')"
echo ""

# Boot QEMU with serial console, auto-kill after 15 seconds.
# Background QEMU and kill it after the timeout.
qemu-system-aarch64 \
    -M virt \
    -cpu cortex-a53 \
    -m 256M \
    -nographic \
    -no-reboot \
    -kernel "$BUILD_DIR/vmlinuz" \
    -initrd "$BUILD_DIR/initramfs.cpio.gz" \
    -append "console=ttyAMA0 init=/sbin/init panic=5 loglevel=6" \
    > "$BUILD_DIR/boot.log" 2>&1 &
QEMU_PID=$!

# Wait up to 15 seconds, then kill
sleep 15
kill $QEMU_PID 2>/dev/null || true
wait $QEMU_PID 2>/dev/null || true

echo ""
echo "=== Boot log analysis ==="
if grep -q "supervisor starting" "$BUILD_DIR/boot.log"; then
    echo "✅ oxwrtd started as PID 1"
else
    echo "❌ oxwrtd did not reach supervisor start"
fi

if grep -q "sethostname" "$BUILD_DIR/boot.log" || grep -q "qemu-test" "$BUILD_DIR/boot.log"; then
    echo "✅ hostname set"
fi

if grep -q "cgroup" "$BUILD_DIR/boot.log"; then
    echo "✅ cgroup controllers detected"
fi

echo ""
echo "Full log: $BUILD_DIR/boot.log"
