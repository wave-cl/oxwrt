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

.PHONY: services-stage services-dns services-ntp services-dhcp services-debug-ssh

services-stage: services-dns services-ntp services-dhcp services-debug-ssh

# ── Static dropbear for debug-ssh container ─────────────────────────
#
# Pulls dropbear + dropbearkey from Alpine's aarch64 repo and stages
# them under build-services/debug-ssh/. These get copied into
# files/usr/lib/oxwrt/services/debug-ssh/rootfs/ at image-stage time,
# so the squashfs ships a self-contained SSH binary and the stock
# `dropbear` OpenWrt package can be dropped from the base system.
#
# Why Alpine and not building from source:
#   - Alpine already ships dropbear linked against musl (same libc
#     we already bundle via /lib/ld-musl-aarch64.so.1 in the rootfs)
#   - apk fetch + tar -xz is 10 seconds vs a multi-minute source build
#   - No autotools / cross-toolchain setup on the host
#
# The binaries are DYNAMIC musl — they need the musl loader + (for
# dropbear) libcrypto. Alpine's libcrypto is ~3MB; we already ship
# libgcc_s.so.1. One additional .so is cheap.
#
# Output layout:
#   build-services/debug-ssh/sbin/dropbear
#   build-services/debug-ssh/bin/dropbearkey
#   build-services/debug-ssh/lib/libcrypto.so.3     (if needed)
#
# Re-running is cheap but not a no-op — `docker run` re-enters the
# container. Guarded by the target file existing.

services-debug-ssh: $(BUILD_SERVICES)/debug-ssh/sbin/dropbear
$(BUILD_SERVICES)/debug-ssh/sbin/dropbear:
	mkdir -p $(BUILD_SERVICES)/debug-ssh/sbin \
	         $(BUILD_SERVICES)/debug-ssh/bin \
	         $(BUILD_SERVICES)/debug-ssh/lib
	docker run --rm --platform linux/arm64 \
		-v $(CURDIR)/$(BUILD_SERVICES)/debug-ssh:/out \
		alpine:3.20 sh -c '\
		apk add --no-cache dropbear busybox && \
		cp /usr/sbin/dropbear /out/sbin/dropbear && \
		cp /usr/bin/dropbearkey /out/bin/dropbearkey && \
		cp /bin/busybox /out/bin/busybox && \
		cp /lib/ld-musl-aarch64.so.1 /out/lib/ld-musl-aarch64.so.1 && \
		for lib in $$(ldd /usr/sbin/dropbear 2>/dev/null | awk "/=>/{print \$$3}"); do \
			case "$$lib" in \
				/lib/ld-musl-*|/lib/libc.musl-*) ;; \
				*) [ -f "$$lib" ] && cp "$$lib" /out/lib/ || true ;; \
			esac; \
		done'
	@echo ""
	@echo "Staged static dropbear under $(BUILD_SERVICES)/debug-ssh/:"
	@find $(BUILD_SERVICES)/debug-ssh -type f -ls

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
	kmod-nft-nat \
	nftables \
	-netifd \
	-uci \
	-uclient-fetch \
	-libustream-mbedtls \
	-dnsmasq \
	-firewall4 \
	-odhcp6c \
	-odhcpd-ipv6only \
	-wpad-basic-mbedtls \
	-ppp \
	-ppp-mod-pppoe \
	-logd \
	-procd-ujail \
	-e2fsprogs \
	-f2fsck \
	-dropbear

# IMAGE PHILOSOPHY (pid1-standalone): oxwrtctl owns userspace. procd,
# netifd, firewall4, dnsmasq, odhcpd*, dropbear, ppp — all gone.
# Our Rust services (hickory-dns, coredhcp, ntpd-rs, debug-ssh) run
# under our supervisor, nftables rules are installed by net::
# install_firewall, WAN comes up via wan_dhcp, /sbin/init = oxwrtctl.
#
# Earlier we coexisted with the stock stack ("pid1-coexist") to reduce
# bring-up risk — oxwrtctl ran as /sbin/procd with procd-init handling
# preinit, /sbin/init still being stock. Stage 4 of the migration
# replaced /sbin/init with oxwrtctl and implemented mount_root +
# modules.dep + netdev rename in Rust (see oxwrtctl/src/init.rs).
# Stage 5 (this list) removes the packages that are now dead weight.
#
# Kept:
#   base-files       — shell stubs, /etc/passwd, busybox applet symlinks
#   libc, libgcc     — musl runtime
#   fstools          — /sbin/block for fstab mounts (rarely, but keep)
#   mkf2fs           — invoked by init::mount_root for first-boot format
#   ca-bundle        — TLS trust store for hickory-dns-over-tls etc.
#   urandom-seed, urngd — entropy
#   uboot-envtools   — u-boot env read/write (handy for recovery)
#   kmod-* (crypto, nft-offload, leds-gpio, gpio-button, usb3, mt7915e,
#                mt7986-firmware, mt7986-wo-firmware) — hw drivers
#
# Removed (see -package list above):
#   netifd, uci           — we use rtnetlink + TOML config
#   dnsmasq, odhcp6c, odhcpd-ipv6only — DNS/DHCP done by our services
#   firewall4             — we install nftables directly via rustables
#   wpad-basic-mbedtls    — wifi not yet wired up; bring back later
#   ppp, ppp-mod-pppoe    — PPPoE WAN; Flint 2 uses ethernet WAN
#   uclient-fetch, libustream-mbedtls — http fetch for opkg, we don't
#   logd, procd-ujail     — procd helpers, dead without procd
#   e2fsprogs, f2fsck     — ext4 tools and f2fs check we don't invoke
#   dropbear              — replaced by an Alpine-built static dropbear
#                           staged directly into the debug-ssh container
#                           rootfs (see services-debug-ssh target). The
#                           base OS has no SSH daemon; SSH only exists
#                           inside the hardened debug-ssh service.
#
# procd + procd-init themselves aren't in the default list — they come
# in as transitive deps of netifd / dropbear / etc. Once all their
# dependents are gone, apk drops them too.
#
# kmod-veth: needed for container::spawn's isolated netns.
# kmod-nft-nat: needed for MASQUERADE + DNAT chains.

.PHONY: imagebuilder-stage imagebuilder-image \
        imagebuilder-stage-bare imagebuilder-stage-init \
        imagebuilder-stage-uci99 imagebuilder-stage-uci98 \
        imagebuilder-stage-uci97 imagebuilder-stage-pid1 \
        imagebuilder-stage-pid1-standalone \
        imagebuilder-image-pid1 imagebuilder-image-pid1-standalone \
        .imagebuilder-build

# ── Bisect targets for the post-flash boot-hang investigation ───────
#
# The full image (`imagebuilder-stage`) doesn't boot cleanly on the
# Flint 2 — device is unreachable on the LAN after a clean flash.
# These progressively-richer staging targets let us bisect which
# layer of the overlay breaks boot. Each one `rm -rf`s files/ and
# stages only its own subset — so flashing a build from
# `imagebuilder-stage-bare` reveals whether the flash mechanism itself
# is OK, flashing `-init` reveals whether our init.d script is the
# problem, and so on up to the full image.
#
# Suggested sequence (see the "Image boot-hang: bisect via minimal
# images" task chip for the full workflow):
#   make imagebuilder-stage-bare  && make imagebuilder-image
#   [flash via sysupgrade -n, verify reachable]
#   make imagebuilder-stage-init  && make imagebuilder-image
#   [flash, verify]
#   ...continue escalating until one of them hangs boot.
#
# Invariant: each target is self-contained (cleans files/ first and
# rebuilds its subset). They are not chained via recipe dependency
# because make's mtime-based up-to-date logic would skip the rm-rf
# and leak artifacts from a previous layer.

# ── stage-bare: minimal image (oxwrtctl binary only) ────────────────
#
# Populates files/ with:
#   /usr/bin/oxwrtctl
#   /etc/oxwrt.toml
#   /etc/oxwrt/mode                (= "control-only" default)
#   /etc/oxwrt/authorized_keys     (empty — accept all MAC1 clients)
#   /etc/dropbear/authorized_keys  (operator's ~/.ssh/id_ed25519.pub)
#
# Deliberately OMITS:
#   /etc/init.d/oxwrtctl           (no procd integration)
#   /etc/uci-defaults/97, 98, 99   (no first-boot scripts)
#   /usr/lib/oxwrt/services/*      (no service rootfs, no binaries)
#
# Expected behavior post-flash: device boots stock OpenWrt with an
# unused binary present but no auto-start. Operator SSHes in, runs
# `/usr/bin/oxwrtctl --control-only` manually to confirm the binary
# works. This baseline proves the flash mechanism itself is fine
# (same assumption as stock OpenWrt).
imagebuilder-stage-bare: rust-oxwrtctl
	$(call imagebuilder_check_dir)
	$(call imagebuilder_clean_files)
	$(call imagebuilder_stage_bare)
	@echo ""
	@echo "Staged BARE layer (binary + /etc/oxwrt + ssh keys). No init.d, no uci-defaults, no service rootfs."

# ── stage-init: + /etc/init.d/oxwrtctl ──────────────────────────────
#
# Everything in -bare, plus the procd init script. Still no
# uci-defaults, so the init script is shipped but NOT enabled at
# boot — it doesn't appear in /etc/rc.d/S* on first boot. The
# operator has to `/etc/init.d/oxwrtctl enable; start` from a shell.
#
# Tests whether the init.d shell script itself (the one with the
# mode dispatcher) has a syntax / sourcing bug that breaks boot.
# Even unenabled, procd scans /etc/init.d/ at boot for metadata —
# a broken START=/STOP= directive or shellfail could in principle
# upset preinit.
imagebuilder-stage-init: rust-oxwrtctl
	$(call imagebuilder_check_dir)
	$(call imagebuilder_clean_files)
	$(call imagebuilder_stage_bare)
	$(call imagebuilder_stage_init)
	@echo ""
	@echo "Staged INIT layer (+ /etc/init.d/oxwrtctl). Still no uci-defaults."

# ── stage-uci99: + 99-oxwrtctl uci-defaults ─────────────────────────
#
# Adds only the enable-on-first-boot hook. If the full image's hang
# is caused by a misbehavior in /etc/init.d/oxwrtctl enable (which
# procd runs via uci-defaults at preinit), this layer should
# reproduce it — the 99 script's only action is `enable`.
imagebuilder-stage-uci99: rust-oxwrtctl
	$(call imagebuilder_check_dir)
	$(call imagebuilder_clean_files)
	$(call imagebuilder_stage_bare)
	$(call imagebuilder_stage_init)
	$(call imagebuilder_stage_uci, 99-oxwrtctl)
	@echo ""
	@echo "Staged UCI99 layer (+ 99-oxwrtctl uci-default = enable on first boot)."

# ── stage-uci98: + 98-oxwrt-diag-rootfs ─────────────────────────────
#
# Adds the diag rootfs provisioner (copies /bin/ping + musl libs into
# /usr/lib/oxwrt/diag at first boot). Pure filesystem work — no
# service registration or netlink — but it's the largest of our
# uci-defaults scripts and touches many files.
imagebuilder-stage-uci98: rust-oxwrtctl
	$(call imagebuilder_check_dir)
	$(call imagebuilder_clean_files)
	$(call imagebuilder_stage_bare)
	$(call imagebuilder_stage_init)
	$(call imagebuilder_stage_uci, 99-oxwrtctl)
	$(call imagebuilder_stage_uci, 98-oxwrt-diag-rootfs)
	@echo ""
	@echo "Staged UCI98 layer (+ 98-oxwrt-diag-rootfs)."

# ── stage-uci97: retained as alias for -uci98 ───────────────────────
#
# Previously layered 97-oxwrt-debug-ssh-rootfs on top — that script was
# a uci-defaults first-boot provisioner that copied /usr/sbin/dropbear +
# busybox into the debug-ssh container rootfs. As of the static-dropbear
# migration, the entire container rootfs is pre-staged in the squashfs
# at image-build time (see imagebuilder-stage's debug-ssh block). The
# script is gone, this bisect layer is now identical to -uci98.
imagebuilder-stage-uci97: imagebuilder-stage-uci98
	@echo "(alias for -uci98 since 97-oxwrt-debug-ssh-rootfs was removed)"

# Shared helpers — `define X` gives us macros we call via $(call X).
# make functions below use $(1), $(2) etc. for positional args.

define imagebuilder_check_dir
	@if [ ! -d "$(IMAGEBUILDER_DIR)" ]; then \
		echo "ERROR: $(IMAGEBUILDER_DIR) not found. Download the imagebuilder for mediatek/filogic from"; \
		echo "  https://downloads.openwrt.org/releases/25.12.2/targets/mediatek/filogic/"; \
		echo "and extract under imagebuilder/."; \
		exit 1; \
	fi
	mkdir -p $(IMAGEBUILDER_DIR)/files
endef

define imagebuilder_clean_files
	rm -rf $(IMAGEBUILDER_DIR)/files/*
endef

define imagebuilder_stage_bare
	mkdir -p $(IMAGEBUILDER_DIR)/files/etc $(IMAGEBUILDER_DIR)/files/etc/oxwrt \
	         $(IMAGEBUILDER_DIR)/files/usr/bin $(IMAGEBUILDER_DIR)/files/etc/dropbear
	cp config/oxwrt.toml $(IMAGEBUILDER_DIR)/files/etc/oxwrt.toml
	cp $(RUST_TARGET_DIR)/oxwrtctl $(IMAGEBUILDER_DIR)/files/usr/bin/oxwrtctl
	chmod 0755 $(IMAGEBUILDER_DIR)/files/usr/bin/oxwrtctl
	echo control-only > $(IMAGEBUILDER_DIR)/files/etc/oxwrt/mode
	touch $(IMAGEBUILDER_DIR)/files/etc/oxwrt/authorized_keys
	if [ -f "$$HOME/.ssh/id_ed25519.pub" ]; then \
		cp "$$HOME/.ssh/id_ed25519.pub" $(IMAGEBUILDER_DIR)/files/etc/dropbear/authorized_keys; \
		chmod 0600 $(IMAGEBUILDER_DIR)/files/etc/dropbear/authorized_keys; \
	else \
		echo "WARNING: ~/.ssh/id_ed25519.pub not found; flashed image will have no SSH keys"; \
		touch $(IMAGEBUILDER_DIR)/files/etc/dropbear/authorized_keys; \
	fi
endef

define imagebuilder_stage_init
	install -d $(IMAGEBUILDER_DIR)/files/etc/init.d
	cp openwrt-packages/imagebuilder-overlay/files/etc/init.d/oxwrtctl \
	   $(IMAGEBUILDER_DIR)/files/etc/init.d/oxwrtctl
	chmod 0755 $(IMAGEBUILDER_DIR)/files/etc/init.d/oxwrtctl
endef

# $(1) = uci-defaults script basename (e.g. "99-oxwrtctl"). Wrapped in
# $(strip) because `$(call F, arg)` — the idiomatic spelling with a
# space after the comma — passes " arg" with a leading space, which
# then corrupts the cp path. `$(strip)` canonicalizes.
define imagebuilder_stage_uci
	install -d $(IMAGEBUILDER_DIR)/files/etc/uci-defaults
	cp openwrt-packages/imagebuilder-overlay/files/etc/uci-defaults/$(strip $(1)) \
	   $(IMAGEBUILDER_DIR)/files/etc/uci-defaults/$(strip $(1))
	chmod 0755 $(IMAGEBUILDER_DIR)/files/etc/uci-defaults/$(strip $(1))
endef

# ── stage (full / default) — everything above + service rootfs ──────
#
# This is the "real" image. Same behavior as before the bisect
# scaffolding was added.

# Populate the imagebuilder's files/ overlay from our tracked overlay
# + the cross-built binaries. Separated from `imagebuilder-image` so an
# operator can inspect what gets shipped before the Docker build runs.
imagebuilder-stage: rust-oxwrtctl services-stage services-debug-ssh
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
	# Writable lease-file dir on the host side.
	#
	# DO NOT stage under files/var/ — OpenWrt ships /var as a symlink
	# to /tmp (tmpfs), and any files/ overlay path under var/
	# silently CLOBBERS that symlink by materializing /var as a real
	# squashfs directory. That breaks the entire userspace boot:
	# procd's ubus init calls chown(/var/run/ubus), which fails
	# because /var/run is now a read-only squashfs path instead of a
	# tmpfs. Device hangs before reaching uci-defaults, before any
	# service spawns. Diagnosed via UART console on 2026-04-17 after
	# many hours of bisect cycles.
	#
	# Stage the leases file under /etc/oxwrt/coredhcp/ instead — /etc
	# is writable overlayfs (persistent across reboots) and nothing
	# downstream depends on OpenWrt's /etc being a symlink. The
	# bind-mount source in config/oxwrt.toml [[services.binds]] for
	# coredhcp needs to match this path, or an init-time symlink /var/
	# lib/oxwrt/coredhcp -> /etc/oxwrt/coredhcp can be created by a
	# uci-defaults script if the in-container path must stay
	# /var/lib/coredhcp.
	mkdir -p $(IMAGEBUILDER_DIR)/files/etc/oxwrt/coredhcp
	touch $(IMAGEBUILDER_DIR)/files/etc/oxwrt/coredhcp/leases.txt
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
	# Pre-stage the debug-ssh container rootfs entirely in the squashfs.
	#
	# Rationale: under oxwrtctl-as-pid1 there is no procd-style
	# /etc/uci-defaults/* first-boot runner. The former
	# 97-oxwrt-debug-ssh-rootfs script only executed once (on a
	# stock-OpenWrt image that still had procd + preinit); after a
	# sysupgrade overlay reset, there was nothing to rebuild the
	# container rootfs. SSH silently broke.
	#
	# Moving everything into the squashfs makes the state deterministic
	# across every flash:
	#   - dropbear + dropbearkey + libz.so.1 + musl loader (from Alpine,
	#     see services-debug-ssh)
	#   - busybox + ~60 applet symlinks for the login shell
	#   - /etc/passwd, /etc/group, /etc/shells
	#   - /etc/dropbear/authorized_keys (operator's ~/.ssh/id_ed25519.pub)
	#
	# Per-device host keys are generated at RUNTIME by dropbear's `-R`
	# flag on startup, into a writable bind-mounted dir at
	# /etc/oxwrt/debug-ssh-keys/. That path is on the overlay and
	# preserved across sysupgrade (via /etc/oxwrt/ in sysupgrade.conf),
	# so host keys stay stable and clients don't get
	# REMOTE-HOST-IDENTIFICATION-CHANGED warnings after updates.
	$(eval R := $(IMAGEBUILDER_DIR)/files/usr/lib/oxwrt/services/debug-ssh/rootfs)
	mkdir -p $(R)/sbin $(R)/bin $(R)/lib $(R)/etc/dropbear \
	         $(R)/dev/pts $(R)/proc $(R)/sys $(R)/tmp $(R)/var/log $(R)/root
	chmod 1777 $(R)/tmp
	# Binaries + libs from Alpine stage.
	cp $(BUILD_SERVICES)/debug-ssh/sbin/dropbear      $(R)/sbin/dropbear
	cp $(BUILD_SERVICES)/debug-ssh/bin/dropbearkey    $(R)/bin/dropbearkey
	cp $(BUILD_SERVICES)/debug-ssh/bin/busybox        $(R)/bin/busybox
	cp $(BUILD_SERVICES)/debug-ssh/lib/libz.so.1      $(R)/lib/libz.so.1
	cp $(BUILD_SERVICES)/debug-ssh/lib/ld-musl-aarch64.so.1 $(R)/lib/ld-musl-aarch64.so.1
	chmod 0755 $(R)/sbin/dropbear $(R)/bin/dropbearkey $(R)/bin/busybox
	# Busybox applet symlinks. Bounded set — "what can an SSH attacker
	# do?" has a visible answer.
	cd $(R)/bin && for a in sh ash ls cat mount umount ps kill ip ping traceroute \
	    dmesg free head tail grep sed awk echo chmod chown stat df du tr find wc \
	    date touch mkdir rmdir rm cp mv ln readlink uname hostname nslookup netstat \
	    which env printf id whoami pwd true false xargs sleep clear reset login su \
	    tty who logger wget vi more less cut sort uniq; do \
	        ln -sf busybox $$a; done
	cd $(R)/sbin && for a in ifconfig route arp; do ln -sf /bin/busybox $$a; done
	# Minimal /etc.
	printf 'root:x:0:0:root:/root:/bin/sh\n' > $(R)/etc/passwd
	printf 'root:x:0:\n' > $(R)/etc/group
	printf '/bin/sh\n/bin/ash\n' > $(R)/etc/shells
	# authorized_keys at /root/.ssh/authorized_keys — dropbear reads
	# PER-USER keys from $HOME/.ssh/. We can't use /etc/dropbear/
	# because that path is about to be bind-mounted away for runtime
	# host-key storage (see debug-ssh-keys below). Baked from the
	# operator's ~/.ssh/id_ed25519.pub; empty-file fallback keeps
	# dropbear startable but refuses all logins.
	mkdir -p $(R)/root/.ssh
	chmod 0700 $(R)/root/.ssh
	if [ -f "$$HOME/.ssh/id_ed25519.pub" ]; then \
		cp "$$HOME/.ssh/id_ed25519.pub" $(R)/root/.ssh/authorized_keys; \
	else \
		touch $(R)/root/.ssh/authorized_keys; \
	fi
	chmod 0600 $(R)/root/.ssh/authorized_keys
	# Writable host-key dir on the host side — bind-mounted into the
	# container at /etc/dropbear/ by oxwrt.toml. Created empty; dropbear
	# `-R` populates it with ed25519/rsa keys on first start.
	mkdir -p $(IMAGEBUILDER_DIR)/files/etc/oxwrt/debug-ssh-keys
	# Preserve /etc/oxwrt/ across sysupgrade operations. Without this,
	# every firmware update regenerates the server signing key, changes
	# the sQUIC server pubkey, and locks out every client that was
	# previously pinned to the old key. The operator would have to
	# re-read the pubkey from UART and re-export SQUIC_SERVER_KEY on
	# every update — painful during bring-up, broken in production.
	#
	# /etc/sysupgrade.conf is the canonical OpenWrt hook: each line is
	# a path (or pattern) copied from the old rootfs to the new one
	# during `sysupgrade` (default, without -n). Doesn't help for
	# U-Boot HTTP recovery (raw full-flash wipes overlay unconditionally
	# — nothing on the squashfs can preserve across that), but that's
	# a recovery path anyway, not a normal update.
	echo "/etc/oxwrt/" > $(IMAGEBUILDER_DIR)/files/etc/sysupgrade.conf
	@echo ""
	@echo "Staged $(IMAGEBUILDER_DIR)/files/ — inspect before running 'make imagebuilder-image'."

# ── stage-pid1: full stage + PID-1 takeover (procd COEXIST) ────────
#
# Runs imagebuilder-stage, then layers the /sbin/procd override on top.
#
# The hook: OpenWrt's boot is
#   kernel → /sbin/init (procd-init, 65KB binary) → /lib/preinit/* →
#   execve("/sbin/procd")
# So /sbin/procd is pid 1 *after* preinit has already mounted the
# overlay, pivot_root'd, loaded modules, etc. By overwriting
# /sbin/procd with oxwrtctl, we inherit pid 1 with the filesystem
# fully set up — no need to reimplement mount_root in Rust.
#
# Safety properties:
#   - /sbin/init (procd-init) stays intact. If oxwrtctl fails to
#     start, procd-init's internal failsafe still runs (the rootfs
#     is already up, operator can boot into failsafe via uart and
#     inspect).
#   - debug-ssh service on :2222 (baked in via 97-oxwrt-debug-ssh-
#     rootfs) provides a recovery shell without procd-supervised
#     dropbear. Login works independently of oxwrtctl's own state.
#   - Mode is pinned to "init" so the supervisor activates the full
#     async_main path (network, firewall, WAN DHCP, containers).
#
# DO NOT FLASH BLINDLY. Run from UART-connected bench with a
# recovery plan (u-boot HTTP uploader ready with a stock image) in
# case the device wedges. The first successful boot here is the
# demo of "we replaced procd."
imagebuilder-stage-pid1: imagebuilder-stage
	# Overwrite stock procd binary with oxwrtctl. When /sbin/init
	# execve's /sbin/procd at the end of preinit, our binary takes
	# pid 1 — detected via getpid()==1 in main.rs and routed to
	# run_init() automatically (no CLI flag needed).
	mkdir -p $(IMAGEBUILDER_DIR)/files/sbin
	cp $(RUST_TARGET_DIR)/oxwrtctl $(IMAGEBUILDER_DIR)/files/sbin/procd
	chmod 0755 $(IMAGEBUILDER_DIR)/files/sbin/procd
	# Force mode=init. services-only would skip netlink + firewall
	# install, leaving the device without networking (pre-takeover
	# procd isn't there to do it either).
	echo init > $(IMAGEBUILDER_DIR)/files/etc/oxwrt/mode

# ── stage-pid1-standalone: full stage + DIRECT pid1 takeover ───────
#
# Beyond stage-pid1: ALSO replaces /sbin/init with oxwrtctl, so the
# kernel hands control to our Rust binary DIRECTLY at boot. procd-
# init never runs; neither do /etc/preinit or /lib/preinit/*.sh. All
# responsibilities they owned (kmodloader via finit_module + modules.
# dep, netdev rename from DTS labels, mount_root with loop0+f2fs+
# overlayfs+pivot_root, config-backup restore from DEADCODE marker)
# are owned by init::run() in src/init.rs.
#
# Safety changes vs stage-pid1:
#   - NO procd-init failsafe net. If our mount_root bugs out, the
#     device can't read /etc/oxwrt.toml, can't start the control
#     plane, can't be recovered over LAN.
#   - debug-ssh is still built into the rootfs, but it only spawns
#     AFTER mount_root (its rootfs lives in /usr/lib/oxwrt/services/
#     debug-ssh/, which is on the squashfs — readable, but its
#     dropbearkey-generated hostkeys live in /etc/oxwrt-ssh which is
#     on overlay). So debug-ssh is effectively tied to mount_root's
#     success.
#   - U-Boot web recovery (reset held at power-on) is the only
#     fallback for a broken boot.
#
# For the first deploy, the sensible path is: keep the currently-
# booted `stage-pid1` image installed, deploy `stage-pid1-standalone`
# via native-sysupgrade, and have U-Boot recovery staged.
imagebuilder-stage-pid1-standalone: imagebuilder-stage-pid1
	# Overwrite procd-init at /sbin/init. The kernel's default
	# init= argument resolves to /sbin/init; replacing that binary
	# (not a symlink — the stock image ships it as a 65KB ELF) with
	# oxwrtctl makes us pid 1 from the very first user-space
	# instruction.
	cp $(RUST_TARGET_DIR)/oxwrtctl $(IMAGEBUILDER_DIR)/files/sbin/init
	chmod 0755 $(IMAGEBUILDER_DIR)/files/sbin/init
	@echo ""
	@echo "⚠️  pid1-standalone staged."
	@echo "    Self-update from a working pid1 image ONLY, and keep"
	@echo "    U-Boot recovery ready."

imagebuilder-image-pid1-standalone: imagebuilder-stage-pid1-standalone .imagebuilder-build
	@echo ""
	@echo "PID-1 takeover layer applied:"
	@echo "  /sbin/procd  → oxwrtctl ($$(du -h $(IMAGEBUILDER_DIR)/files/sbin/procd | cut -f1))"
	@echo "  /etc/oxwrt/mode = init"
	@echo ""
	@echo "⚠️  FLASH WITH RECOVERY READY:"
	@echo "   - UART console connected"
	@echo "   - u-boot HTTP recovery image staged"
	@echo ""
	@echo "Next: make imagebuilder-image-pid1"

# Image-build variant for the PID-1 takeover. MUST NOT use
# `imagebuilder-image` — that depends on `imagebuilder-stage`, which
# rm -rf's files/ and re-stages from scratch, wiping the /sbin/procd
# override. Flashing the result of that sequence silently ships a
# services-only image (found out the hard way).
imagebuilder-image-pid1: imagebuilder-stage-pid1 .imagebuilder-build

# Internal: run the docker image-build step against whatever is
# currently staged in $(IMAGEBUILDER_DIR)/files. Shared between
# `imagebuilder-image` and `imagebuilder-image-pid1` so the two
# differ only in what overlay is staged, not in how the image is
# baked.
.imagebuilder-build:
	docker run --rm -v $(CURDIR)/$(IMAGEBUILDER_DIR):/src \
		debian:bookworm-slim bash -c '\
		apt-get update && apt-get install -y --no-install-recommends \
			make gcc gettext zlib1g-dev libncurses-dev \
			python3 python3-setuptools file perl wget rsync \
			unzip gzip zstd xz-utils bzip2 gawk patch git \
			diffutils findutils which ca-certificates \
			libelf-dev libssl-dev \
			2>&1 | tail -3 && \
		cp -a /src /build && cd /build && \
		make image PROFILE=$(IMAGEBUILDER_PROFILE) \
			PACKAGES="$(IMAGEBUILDER_PACKAGES)" \
			FILES=/build/files && \
		rm -rf /src/bin && cp -a /build/bin /src/bin'
	@echo ""
	@echo "Image(s) at:"
	@find $(IMAGEBUILDER_DIR)/bin -name '*sysupgrade*' -ls

imagebuilder-image: imagebuilder-stage
	# Run inside a Docker sandbox because the host (macOS or similar)
	# isn't case-sensitive and the OpenWrt build refuses that. Copy
	# into an in-container ext4 dir first.
	docker run --rm -v $(CURDIR)/$(IMAGEBUILDER_DIR):/src \
		debian:bookworm-slim bash -c '\
		apt-get update && apt-get install -y --no-install-recommends \
			make gcc gettext zlib1g-dev libncurses-dev \
			python3 python3-setuptools file perl wget rsync \
			unzip gzip zstd xz-utils bzip2 gawk patch git \
			diffutils findutils which ca-certificates \
			libelf-dev libssl-dev \
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
