# oxwrt top-level build orchestrator.
#
# This Makefile ties together the Rust workspace (oxwrtctl + services),
# the OpenWRT buildroot (kernel + image packaging), and the cross-built
# diag/service binaries into a single firmware image.
#
# Usage:
#   make setup        — clone openwrt, install feeds, copy config
#   make rust          — cross-build oxwrtctl + all Rust services
#   make image         — build the OpenWRT firmware image
#   make all           — setup + rust + image (full build)
#   make clean         — clean Rust + OpenWRT build artifacts
#
# Prerequisites:
#   - cargo-zigbuild (cargo install cargo-zigbuild)
#   - OpenWRT build dependencies (see openwrt docs)
#   - git

OPENWRT_DIR   := openwrt
OPENWRT_REPO  := https://github.com/openwrt/openwrt.git
OPENWRT_REF   := main
TARGET_ARCH   := aarch64-unknown-linux-musl
CARGO_PROFILE := release
NPROC         := $(shell nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)

# Rust output directory
RUST_TARGET_DIR := target/$(TARGET_ARCH)/$(CARGO_PROFILE)

# Build output
BUILD_DIR     := build
SQFS_IMAGE    := $(BUILD_DIR)/rootfs.squashfs
VERITY_IMAGE  := $(BUILD_DIR)/rootfs.verity
VERITY_CMDLINE := $(BUILD_DIR)/verity-cmdline.txt

.PHONY: all setup rust image verity clean

all: setup rust image

# ── Setup ────────────────────────────────────────────────────────────

setup: $(OPENWRT_DIR)/.config

$(OPENWRT_DIR)/.git:
	git clone --depth 1 --branch $(OPENWRT_REF) $(OPENWRT_REPO) $(OPENWRT_DIR)

$(OPENWRT_DIR)/feeds.conf: $(OPENWRT_DIR)/.git openwrt-config/feeds.conf
	cp openwrt-config/feeds.conf $(OPENWRT_DIR)/feeds.conf
	cd $(OPENWRT_DIR) && ./scripts/feeds update -a
	cd $(OPENWRT_DIR) && ./scripts/feeds install -a

$(OPENWRT_DIR)/.config: $(OPENWRT_DIR)/feeds.conf openwrt-config/.config
	cp openwrt-config/.config $(OPENWRT_DIR)/.config
	$(MAKE) -C $(OPENWRT_DIR) defconfig

# ── Rust builds ──────────────────────────────────────────────────────

rust: rust-oxwrtctl

rust-oxwrtctl:
	cargo zigbuild --release --target $(TARGET_ARCH) -p oxwrtctl

# ── Service binaries (cross-built out-of-band) ──────────────────────
#
# The hickory-dns, ntp-daemon, and coredhcp binaries are assembled
# from upstream sources with slightly different pipelines (cargo-zigbuild
# for the Rust ones, `go build` with `zig cc` for coredhcp's CGO).
# Staging them under build-services/<svc>/ gives the openwrt-packages
# Makefiles a stable path to consume.
#
# Prerequisites:
#   - cargo-zigbuild installed
#   - zig installed (for coredhcp's CGO cross)
#   - GNU ar from binutils — homebrew path hardcoded; adjust AR_AARCH64
#     below if yours lives elsewhere (see feedback_zigbuild_ar.md)
#   - go + git (for coredhcp)

BUILD_SERVICES := build-services
AR_AARCH64     ?= $(shell command -v /Users/c/homebrew/opt/binutils/bin/ar 2>/dev/null || command -v /opt/homebrew/opt/binutils/bin/ar 2>/dev/null || command -v aarch64-linux-gnu-ar 2>/dev/null || echo ar)

.PHONY: services-stage services-dns services-ntp services-dhcp

services-stage: services-dns services-ntp services-dhcp

services-dns: $(BUILD_SERVICES)/dns/hickory-dns
$(BUILD_SERVICES)/dns/hickory-dns:
	mkdir -p $(BUILD_SERVICES)/dns
	AR_aarch64_unknown_linux_musl=$(AR_AARCH64) \
	cargo-zigbuild install --locked \
	  --target $(TARGET_ARCH) \
	  --root /tmp/hickory-build \
	  hickory-dns
	cp /tmp/hickory-build/bin/hickory-dns $@

services-ntp: $(BUILD_SERVICES)/ntp/ntp-daemon
$(BUILD_SERVICES)/ntp/ntp-daemon:
	mkdir -p $(BUILD_SERVICES)/ntp
	AR_aarch64_unknown_linux_musl=$(AR_AARCH64) \
	cargo-zigbuild install --locked \
	  --target $(TARGET_ARCH) \
	  --root /tmp/ntpd-build \
	  ntpd
	cp /tmp/ntpd-build/bin/ntp-daemon $@

services-dhcp: $(BUILD_SERVICES)/dhcp/coredhcp
$(BUILD_SERVICES)/dhcp/coredhcp:
	# coredhcp requires CGO (range plugin uses sqlite3) — cross-built
	# via `zig cc` as CC. See project_oxwrt_services.md for the full
	# rationale.
	mkdir -p $(BUILD_SERVICES)/dhcp /tmp/coredhcp-src
	[ -d /tmp/coredhcp-src/.git ] || git clone --depth=1 \
	  https://github.com/coredhcp/coredhcp.git /tmp/coredhcp-src
	cd /tmp/coredhcp-src/cmds/coredhcp && \
	CGO_ENABLED=1 GOOS=linux GOARCH=arm64 \
	CC="zig cc -target aarch64-linux-musl" \
	CXX="zig c++ -target aarch64-linux-musl" \
	go build -o $(CURDIR)/$@ .

# ── OpenWRT image ────────────────────────────────────────────────────

image: rust $(OPENWRT_DIR)/.config
	@# Copy overlay files into the OpenWRT files/ directory so they
	@# appear in the final rootfs image.
	mkdir -p $(OPENWRT_DIR)/files
	cp -a openwrt-config/files/* $(OPENWRT_DIR)/files/
	$(MAKE) -C $(OPENWRT_DIR) -j$(NPROC) V=s

# ── dm-verity ────────────────────────────────────────────────────────
#
# Wraps the squashfs rootfs image with a dm-verity hash tree. The root
# hash is embedded in the kernel cmdline so block-level tampering is
# detected at read time — "even root can't change" guarantee.
#
# Requires: veritysetup (from cryptsetup). Run after the OpenWRT image
# build produces the squashfs, or standalone against any squashfs.

verity: $(VERITY_IMAGE)

$(VERITY_IMAGE): $(SQFS_IMAGE) scripts/verity-wrap.sh
	./scripts/verity-wrap.sh $(SQFS_IMAGE) $(VERITY_IMAGE) $(VERITY_CMDLINE)
	@echo ""
	@echo "Add the contents of $(VERITY_CMDLINE) to kernel bootargs."

# For standalone testing: create a test squashfs from the diag binaries.
verity-test:
	mkdir -p $(BUILD_DIR)
	mksquashfs diag-binaries $(BUILD_DIR)/test-rootfs.squashfs -noappend -comp xz
	./scripts/verity-wrap.sh $(BUILD_DIR)/test-rootfs.squashfs $(BUILD_DIR)/test-rootfs.verity $(BUILD_DIR)/test-verity-cmdline.txt

# ── Clean ────────────────────────────────────────────────────────────

clean:
	cargo clean
	rm -rf $(BUILD_DIR)
	[ -d $(OPENWRT_DIR) ] && $(MAKE) -C $(OPENWRT_DIR) clean || true
