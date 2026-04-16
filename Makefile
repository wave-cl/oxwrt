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
