# OpenWRT package: ntpd-rs service rootfs.
#
# Installs the pre-built ntp-daemon (Rust, static musl) binary + its
# config into the rootfs the ntp container pivot_roots into.

include $(TOPDIR)/rules.mk

PKG_NAME:=oxwrt-ntp
PKG_VERSION:=0.1.0
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/oxwrt-ntp
  SECTION:=oxwrt
  CATEGORY:=oxwrt services
  TITLE:=ntpd-rs NTP client+server
  DEPENDS:=+oxwrtd
endef

OXWRT_ROOT:=$(CURDIR)/../..
# Cross-built via cargo-zigbuild (see project_oxwrt_services.md).
# Note: crate name is `ntpd`, not `ntpd-rs` (the latter is a placeholder
# on crates.io).
#
#   cargo-zigbuild install \
#     --locked --target aarch64-unknown-linux-musl \
#     --root build-services/ntp ntpd
#
# → build-services/ntp/bin/ntp-daemon (~5.5 MB).
NTPD_BIN:=$(OXWRT_ROOT)/build-services/ntp/ntp-daemon

define Build/Compile
	@true
endef

SVC_DIR:=/usr/lib/oxwrt/services/ntp

define Package/oxwrt-ntp/install
	# Rootfs: pivot_root target. Binary at root (`/ntp-daemon`),
	# matching the entrypoint in config/oxwrt.toml.
	$(INSTALL_DIR) $(1)$(SVC_DIR)/rootfs
	$(INSTALL_DIR) $(1)$(SVC_DIR)/rootfs/proc
	$(INSTALL_DIR) $(1)$(SVC_DIR)/rootfs/sys
	$(INSTALL_DIR) $(1)$(SVC_DIR)/rootfs/dev
	$(INSTALL_DIR) $(1)$(SVC_DIR)/rootfs/etc
	$(INSTALL_DIR) $(1)$(SVC_DIR)/rootfs/var/run/ntpd-rs

	printf 'root:x:0:0:root:/:/bin/false\nnobody:x:65534:65534:nobody:/:/bin/false\n' \
		> $(1)$(SVC_DIR)/rootfs/etc/passwd
	printf 'root:x:0:\nnobody:x:65534:\n' > $(1)$(SVC_DIR)/rootfs/etc/group

	# Resolve upstream pool names through the host dns service. musl's
	# static getaddrinfo reads this directly, no NSS.
	echo 'nameserver 10.53.0.1' > $(1)$(SVC_DIR)/rootfs/etc/resolv.conf

	if [ -f "$(NTPD_BIN)" ]; then \
		$(INSTALL_BIN) $(NTPD_BIN) $(1)$(SVC_DIR)/rootfs/ntp-daemon; \
	else \
		echo "WARNING: ntp-daemon binary not found at $(NTPD_BIN)"; \
		touch $(1)$(SVC_DIR)/rootfs/ntp-daemon; \
	fi

	$(INSTALL_DIR) $(1)$(SVC_DIR)
	$(INSTALL_DATA) $(OXWRT_ROOT)/config/services/ntp/ntp.toml \
		$(1)$(SVC_DIR)/ntp.toml
endef

$(eval $(call BuildPackage,oxwrt-ntp))
