# OpenWRT package Makefile for oxwrtd — the Rust PID-1 supervisor.
#
# This package wraps a pre-built static binary produced by
# `cargo zigbuild --release --target aarch64-unknown-linux-musl`.
# The binary is built by the top-level Makefile before the OpenWRT
# image build starts; this package just copies it into the rootfs.

include $(TOPDIR)/rules.mk

PKG_NAME:=oxwrtd
PKG_VERSION:=0.1.0
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/oxwrtd
  SECTION:=base
  CATEGORY:=Base system
  TITLE:=oxwrt firmware controller (PID 1)
  DEPENDS:=
endef

define Package/oxwrtd/description
  Single static Rust binary that serves as PID 1, service supervisor,
  network configurator, firewall installer, and sQUIC control plane
  for the oxwrt firmware. Replaces procd, netifd, dnsmasq,
  dropbear, firewall4, uci, ubus, and every other C daemon in a
  standard OpenWRT image.
endef

# The workspace root is two directories up from this Makefile.
OXWRT_ROOT:=$(CURDIR)/../..
OXWRT_BIN:=$(OXWRT_ROOT)/target/aarch64-unknown-linux-musl/release/oxwrtd

define Build/Compile
	# Pre-built by the top-level Makefile. Verify the binary exists.
	@if [ ! -f "$(OXWRT_BIN)" ]; then \
		echo "ERROR: oxwrtd binary not found at $(OXWRT_BIN)"; \
		echo "Run 'make rust' from the project root first."; \
		exit 1; \
	fi
endef

define Package/oxwrtd/install
	# Install the binary as /sbin/oxwrtd
	$(INSTALL_DIR) $(1)/sbin
	$(INSTALL_BIN) $(OXWRT_BIN) $(1)/sbin/oxwrtd

	# Symlink /sbin/init → oxwrtd so the kernel's default init=
	# path finds our binary. The preinit script (if kept) will also
	# find it. oxwrtd detects PID 1 mode via getpid() == 1.
	ln -sf oxwrtd $(1)/sbin/init

	# Default configuration. The operator customizes this over the
	# sQUIC control plane; it's never edited by hand on the device.
	$(INSTALL_DIR) $(1)/etc $(1)/etc/oxwrt
	$(INSTALL_DATA) $(OXWRT_ROOT)/config/oxwrt.toml $(1)/etc/oxwrt/oxwrt.toml
	touch $(1)/etc/oxwrt/authorized_keys
endef

$(eval $(call BuildPackage,oxwrtd))
