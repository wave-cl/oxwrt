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

# ── OpenWrt imagebuilder ────────────────────────────────────────────
#
# Alternate path to an image: instead of rebuilding the OpenWrt kernel
# and packages from source (the `image` target above), the imagebuilder
# consumes prebuilt upstream packages for the target profile and just
# assembles them into a sysupgrade image along with our overlay.
#
# Why use it during bring-up: 2-minute builds vs 30+ for a full buildroot,
# and we don't need a custom kernel yet. Once oxwrt needs to change the
# kernel config (e.g. to trim, add verity, etc.), switch back to `image`.
#
# Requires:
#   - Docker (for the build sandbox — host libc != target libc)
#   - The imagebuilder tarball under imagebuilder/  (.gitignored; see
#     the README in openwrt-packages/imagebuilder-overlay/)
#
# The resulting sysupgrade image lands at:
#   imagebuilder/<imagebuilder-dir>/bin/targets/<target>/<image>-sysupgrade.bin
#
# kmod-veth is explicitly pulled in: hickory-dns + ntpd-rs run in
# isolated netns that are wired to the host via veth pairs. Without
# the module, container::spawn for an isolated service errors with
# "rtnetlink: Not supported (os error 95)".

IMAGEBUILDER_DIR ?= imagebuilder/openwrt-imagebuilder-25.12.2-mediatek-filogic.Linux-x86_64
IMAGEBUILDER_PROFILE ?= glinet_gl-mt6000
IMAGEBUILDER_PACKAGES := \
	kmod-veth \
	nftables \
	-dnsmasq -dnsmasq-full -odhcpd-ipv6only -odhcpd \
	-firewall4 -kmod-nft-offload

.PHONY: imagebuilder-stage imagebuilder-image

# Populate the imagebuilder's files/ overlay from our tracked overlay
# + the cross-built binaries. Separated from `imagebuilder-image` so an
# operator can inspect what gets shipped before the Docker build runs.
imagebuilder-stage: rust-oxwrtctl services-stage
	@if [ ! -d "$(IMAGEBUILDER_DIR)" ]; then \
		echo "ERROR: $(IMAGEBUILDER_DIR) not found. Download the imagebuilder for mediatek/filogic from"; \
		echo "  https://downloads.openwrt.org/releases/25.12.2/targets/mediatek/filogic/"; \
		echo "and extract under imagebuilder/."; \
		exit 1; \
	fi
	mkdir -p $(IMAGEBUILDER_DIR)/files
	# Clean previous stage so removed files don't linger.
	rm -rf $(IMAGEBUILDER_DIR)/files/*
	# Tracked overlay (init.d, uci-defaults, default authorized_keys).
	cp -a openwrt-packages/imagebuilder-overlay/files/. $(IMAGEBUILDER_DIR)/files/
	# Default runtime config. Operators can override via the sQUIC
	# control plane after first boot. (Using cp/install + mkdir pair
	# because macOS BSD install lacks -D.)
	mkdir -p $(IMAGEBUILDER_DIR)/files/etc $(IMAGEBUILDER_DIR)/files/etc/oxwrt \
	         $(IMAGEBUILDER_DIR)/files/usr/bin
	cp config/oxwrt.toml $(IMAGEBUILDER_DIR)/files/etc/oxwrt.toml
	cp $(RUST_TARGET_DIR)/oxwrtctl $(IMAGEBUILDER_DIR)/files/usr/bin/oxwrtctl
	chmod 0755 $(IMAGEBUILDER_DIR)/files/usr/bin/oxwrtctl
	# Service binaries at the rootfs-root paths the oxwrt.toml
	# entrypoints expect.
	for svc in dns ntp dhcp; do \
		mkdir -p $(IMAGEBUILDER_DIR)/files/usr/lib/oxwrt/services/$$svc/rootfs/etc; \
	done
	cp -L $(BUILD_SERVICES)/dns/hickory-dns \
		$(IMAGEBUILDER_DIR)/files/usr/lib/oxwrt/services/dns/rootfs/hickory-dns
	cp -L $(BUILD_SERVICES)/ntp/ntp-daemon \
		$(IMAGEBUILDER_DIR)/files/usr/lib/oxwrt/services/ntp/rootfs/ntp-daemon
	cp -L $(BUILD_SERVICES)/dhcp/coredhcp \
		$(IMAGEBUILDER_DIR)/files/usr/lib/oxwrt/services/dhcp/rootfs/coredhcp
	chmod 0755 $(IMAGEBUILDER_DIR)/files/usr/lib/oxwrt/services/dns/rootfs/hickory-dns \
		$(IMAGEBUILDER_DIR)/files/usr/lib/oxwrt/services/ntp/rootfs/ntp-daemon \
		$(IMAGEBUILDER_DIR)/files/usr/lib/oxwrt/services/dhcp/rootfs/coredhcp
	# Host-side config bind-mount sources.
	cp config/services/dns/named.toml \
		$(IMAGEBUILDER_DIR)/files/usr/lib/oxwrt/services/dns/named.toml
	cp config/services/ntp/ntp.toml \
		$(IMAGEBUILDER_DIR)/files/usr/lib/oxwrt/services/ntp/ntp.toml
	cp config/services/dhcp/coredhcp.yml \
		$(IMAGEBUILDER_DIR)/files/usr/lib/oxwrt/services/dhcp/coredhcp.yml
	# Minimal passwd/group inside service rootfs (see per-package
	# Makefiles for rationale — musl static getpwnam reads /etc/passwd).
	for svc in dns ntp dhcp; do \
		printf 'root:x:0:0:root:/:/bin/false\nnobody:x:65534:65534:nobody:/:/bin/false\n' \
			> $(IMAGEBUILDER_DIR)/files/usr/lib/oxwrt/services/$$svc/rootfs/etc/passwd; \
		printf 'root:x:0:\nnobody:x:65534:\n' \
			> $(IMAGEBUILDER_DIR)/files/usr/lib/oxwrt/services/$$svc/rootfs/etc/group; \
	done
	# Default mode: services-only. Operators who want full PID-1-like
	# behavior edit this file and reboot.
	echo services-only > $(IMAGEBUILDER_DIR)/files/etc/oxwrt/mode
	# SSH authorized_keys — pulled from the operator's ~/.ssh/id_ed25519.pub
	# at stage time so the flashed image lets them in. Not committed to
	# git (each operator bakes their own). If the key is missing, warn
	# and continue with an empty file — the image will still boot but
	# only the sQUIC control plane will be reachable until they push an
	# authorized_keys over it.
	mkdir -p $(IMAGEBUILDER_DIR)/files/etc/dropbear
	if [ -f "$$HOME/.ssh/id_ed25519.pub" ]; then \
		cp "$$HOME/.ssh/id_ed25519.pub" $(IMAGEBUILDER_DIR)/files/etc/dropbear/authorized_keys; \
		chmod 0600 $(IMAGEBUILDER_DIR)/files/etc/dropbear/authorized_keys; \
	else \
		echo "WARNING: ~/.ssh/id_ed25519.pub not found; flashed image will have no SSH keys"; \
		touch $(IMAGEBUILDER_DIR)/files/etc/dropbear/authorized_keys; \
	fi
	# Control-plane authorized_keys file is intentionally empty in the
	# default image — an empty file makes the sQUIC server accept any
	# valid MAC1 client. Operators who want pubkey pinning should push
	# their control key post-flash via the `oxwrtctl --print-server-key`
	# workflow. The file must exist (server fails to start without it).
	touch $(IMAGEBUILDER_DIR)/files/etc/oxwrt/authorized_keys
	@echo ""
	@echo "Staged $(IMAGEBUILDER_DIR)/files/ — inspect before running 'make imagebuilder-image'."

imagebuilder-image: imagebuilder-stage
	# Run inside a Docker sandbox because the host (macOS or similar)
	# isn't case-sensitive and the OpenWrt build refuses that. Copy
	# into an in-container ext4 dir first.
	docker run --rm -v $(CURDIR)/$(IMAGEBUILDER_DIR):/src \
		debian:bookworm-slim bash -c '\
		apt-get update && apt-get install -y --no-install-recommends \
			make gcc gettext zlib1g-dev libncurses-dev \
			python3 python3-setuptools file perl wget rsync \
			unzip gzip zstd xz-utils bzip2 gawk \
			2>&1 | tail -3 && \
		cp -a /src /build && cd /build && \
		make image PROFILE=$(IMAGEBUILDER_PROFILE) \
			PACKAGES="$(IMAGEBUILDER_PACKAGES)" \
			FILES=/build/files && \
		rm -rf /src/bin && cp -a /build/bin /src/bin'
	@echo ""
	@echo "Image(s) at:"
	@find $(IMAGEBUILDER_DIR)/bin -name '*sysupgrade*' -ls

# ── OpenWRT image (full buildroot) ──────────────────────────────────

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
