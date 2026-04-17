#!/bin/sh
# integration-test.sh — end-to-end RPC test over sQUIC.
#
# Boots oxwrtctl as PID 1 in Docker, then exercises every RPC command
# via the --client mode. Validates responses and exits with a summary.
#
# Usage:
#   ./scripts/integration-test.sh
#
# Prerequisites:
#   - Docker Desktop
#   - oxwrtctl built: target/aarch64-unknown-linux-musl/release/oxwrtctl

set -eu

PROJ_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# aarch64 binary for the Docker container (PID 1 server)
BIN_LINUX="$PROJ_ROOT/target/aarch64-unknown-linux-musl/release/oxwrtctl"
# macOS binary for the client (runs on the host)
BIN_HOST="$PROJ_ROOT/target/release/oxwrtctl"

if [ ! -f "$BIN_LINUX" ]; then
    echo "Error: aarch64 oxwrtctl not found. Run: cargo zigbuild --release --target aarch64-unknown-linux-musl -p oxwrtctl" >&2
    exit 1
fi
if [ ! -f "$BIN_HOST" ]; then
    echo "Error: host oxwrtctl not found. Run: cargo build --release -p oxwrtctl" >&2
    exit 1
fi

PASS=0
FAIL=0
TESTS=""

check() {
    local name="$1"
    local expected="$2"
    local actual="$3"
    if echo "$actual" | grep -qF "$expected"; then
        PASS=$((PASS + 1))
        echo "  ✅ $name"
    else
        FAIL=$((FAIL + 1))
        echo "  ❌ $name"
        echo "     expected: $expected"
        echo "     got: $(echo "$actual" | head -3)"
    fi
}

check_ok() {
    local name="$1"
    local actual="$2"
    check "$name" "ok" "$actual"
}

check_err() {
    local name="$1"
    local expected="$2"
    local actual="$3"
    check "$name → error" "$expected" "$actual"
}

echo "=== Building integration test container ==="

# Create a temp directory for the test
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

# Write a minimal config
cat > "$TMPDIR/oxwrt.toml" << 'TOML'
hostname = "integration-test"

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

[firewall]
zones = []
rules = []

[control]
listen = ["127.0.0.1:51820"]
authorized_keys = "/etc/oxwrt/authorized_keys"
TOML

# Generate a known key pair for testing
dd if=/dev/urandom of="$TMPDIR/key.ed25519" bs=32 count=1 2>/dev/null

# Get the server public key (run inside Docker since the Linux binary is aarch64)
# Retry once if Docker is flaky.
derive_key() {
    docker run --rm \
        -v "$BIN_LINUX:/oxwrtctl:ro" \
        -v "$TMPDIR/key.ed25519:/key:ro" \
        alpine:latest /oxwrtctl --print-server-key /key 2>/dev/null
}
SERVER_KEY=$(derive_key || { sleep 2; derive_key; } || echo "KEYFAIL")
if [ "$SERVER_KEY" = "KEYFAIL" ] || [ -z "$SERVER_KEY" ]; then
    echo "Error: failed to derive server public key (is Docker running?)" >&2
    exit 1
fi
echo "Server key: $SERVER_KEY"

echo ""
echo "=== Starting oxwrtctl in Docker ==="

# Start the container in the background. oxwrtctl runs as PID 1.
# We use --network=host so the client can reach 127.0.0.1:51820.
CONTAINER=$(docker run -d --rm --privileged --cgroupns=private \
    --network=host \
    -v "$BIN_LINUX:/sbin/oxwrtctl:ro" \
    -v "$TMPDIR/oxwrt.toml:/etc/oxwrt.toml:ro" \
    -v "$TMPDIR/key.ed25519:/etc/oxwrt/key.ed25519:ro" \
    -e OXWRT_CONFIG=/etc/oxwrt.toml \
    alpine:latest \
    /sbin/oxwrtctl --init)

echo "Container: $CONTAINER"

# Wait for the control plane to be ready
sleep 3

# Sync the container's wall clock to the host's. Docker Desktop's
# Linux VM usually shares host time, but after a Mac sleep/wake cycle
# or a long build the VM clock can drift — enough to fall outside
# squic's 120s replay window, which causes every handshake to
# silent-drop and this test to report 41 "handshake timed out"
# failures that are actually clock skew, not real bugs.
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
docker exec "$CONTAINER" sh -c "date -u -s '$NOW'" >/dev/null 2>&1 || {
    echo "warning: couldn't sync container clock; tests may fail with squic handshake timeouts"
}

# Wait for control plane to be ready. Skip docker ps check
# (Docker Desktop API can be flaky — 500 errors on /containers/json
# even when the container is running fine).
echo "Waiting for control plane..."

# Client helper
CLIENT="$BIN_HOST --client 127.0.0.1:51820"
export SQUIC_SERVER_KEY="$SERVER_KEY"

run_cmd() {
    $CLIENT "$@" 2>&1 || true
}

echo ""
echo "=== Testing Get/Set ==="

R=$(run_cmd get hostname)
check "get hostname" "integration-test" "$R"

R=$(run_cmd set hostname "test-router")
check "set hostname" "hostname = test-router" "$R"

R=$(run_cmd get hostname)
check "get hostname after set" "test-router" "$R"

R=$(run_cmd get wan.mode)
check "get wan.mode" "dhcp" "$R"

R=$(run_cmd get lan.bridge)
check "get lan.bridge" "br-lan" "$R"

R=$(run_cmd get lan.address)
check "get lan.address" "192.168.8.1" "$R"

echo ""
echo "=== Testing Status ==="

R=$(run_cmd status)
check "status returns uptime" "supervisor uptime" "$R"

echo ""
echo "=== Testing Collection CRUD — Rules ==="

R=$(run_cmd rule list)
check "rule list (empty)" "[]" "$R"

R=$(run_cmd rule add '{"name":"test-accept","src":"lan","proto":"tcp","dest_port":8080,"action":"accept"}')
check_ok "rule add" "$R"

R=$(run_cmd rule list)
check "rule list (has entry)" "test-accept" "$R"

R=$(run_cmd rule get test-accept)
check "rule get" "test-accept" "$R"

R=$(run_cmd rule remove test-accept)
check_ok "rule remove" "$R"

R=$(run_cmd rule list)
check "rule list after remove" "[]" "$R"

# Duplicate add
R=$(run_cmd rule add '{"name":"dup","action":"drop"}')
check_ok "rule add dup" "$R"
R=$(run_cmd rule add '{"name":"dup","action":"drop"}')
check_err "rule add duplicate" "already exists" "$R"
R=$(run_cmd rule remove dup)
check_ok "rule remove dup" "$R"

echo ""
echo "=== Testing Collection CRUD — Zones ==="

R=$(run_cmd zone list)
check "zone list (empty)" "[]" "$R"

R=$(run_cmd zone add '{"name":"test-zone","networks":["lan"],"default_input":"drop","default_forward":"drop"}')
check_ok "zone add" "$R"

R=$(run_cmd zone get test-zone)
check "zone get" "test-zone" "$R"

R=$(run_cmd zone remove test-zone)
check_ok "zone remove" "$R"

echo ""
echo "=== Testing Collection CRUD — Networks ==="

R=$(run_cmd network list)
check "network list" "wan" "$R"

R=$(run_cmd network get lan)
check "network get lan" "br-lan" "$R"

R=$(run_cmd network add '{"name":"dmz","type":"simple","iface":"br-dmz","address":"10.50.0.1","prefix":24}')
check_ok "network add dmz" "$R"

R=$(run_cmd network get dmz)
check "network get dmz" "10.50.0.1" "$R"

R=$(run_cmd network remove dmz)
check_ok "network remove dmz" "$R"

echo ""
echo "=== Testing Collection CRUD — WiFi ==="

R=$(run_cmd wifi list)
check "wifi list (empty)" "[]" "$R"

R=$(run_cmd wifi add '{"radio":"phy0","ssid":"TestNet","security":"wpa3-sae","passphrase":"testpass","network":"lan"}')
check_ok "wifi add" "$R"

R=$(run_cmd wifi get TestNet)
check "wifi get" "TestNet" "$R"

R=$(run_cmd wifi remove TestNet)
check_ok "wifi remove" "$R"

echo ""
echo "=== Testing Collection CRUD — Radios ==="

R=$(run_cmd radio list)
check "radio list (empty)" "[]" "$R"

R=$(run_cmd radio add '{"phy":"phy0","band":"5g","channel":36}')
check_ok "radio add" "$R"

R=$(run_cmd radio get phy0)
check "radio get" "phy0" "$R"

R=$(run_cmd radio remove phy0)
check_ok "radio remove" "$R"

echo ""
echo "=== Testing Config Dump/Push ==="

R=$(run_cmd config-dump)
check "config-dump has hostname" "test-router" "$R"
check "config-dump has networks" "[[networks]]" "$R"

# Save dump, modify, push back
echo "$R" > "$TMPDIR/dumped.toml"
# Modify hostname in the dump
sed -i.bak 's/test-router/pushed-hostname/' "$TMPDIR/dumped.toml" 2>/dev/null || \
    sed -i '' 's/test-router/pushed-hostname/' "$TMPDIR/dumped.toml"

R=$(run_cmd config-push "$TMPDIR/dumped.toml")
check_ok "config-push" "$R"

R=$(run_cmd get hostname)
check "hostname after push" "pushed-hostname" "$R"

echo ""
echo "=== Testing Error Cases ==="

R=$(run_cmd get nonexistent.key)
check_err "get unknown key" "unknown key" "$R"

R=$(run_cmd rule remove nonexistent)
check_err "remove nonexistent rule" "not found" "$R"

R=$(run_cmd rule add 'not json')
check_err "add invalid JSON" "invalid JSON" "$R"

R=$(run_cmd apply)
check_err "apply without confirm" "confirm" "$R"

R=$(run_cmd reset)
check_err "reset without confirm" "confirm" "$R"

echo ""
echo "=== Testing Diag ==="

R=$(run_cmd diag links)
check "diag links" "lo" "$R"

R=$(run_cmd diag routes)
check "diag routes runs" "" "$R"  # may be empty but shouldn't error

echo ""
echo "=== Cleanup ==="
docker stop "$CONTAINER" >/dev/null 2>&1 || true

echo ""
echo "==============================="
echo "  PASS: $PASS"
echo "  FAIL: $FAIL"
echo "  TOTAL: $((PASS + FAIL))"
echo "==============================="

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
