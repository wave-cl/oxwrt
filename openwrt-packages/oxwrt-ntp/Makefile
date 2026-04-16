# OpenWRT package: ntpd-rs service rootfs.

include $(TOPDIR)/rules.mk

PKG_NAME:=oxwrt-ntp
PKG_VERSION:=0.1.0
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/oxwrt-ntp
  SECTION:=oxwrt
  CATEGORY:=oxwrt services
  TITLE:=ntpd-rs NTP client+server
  DEPENDS:=+oxwrtctl
endef

OXWRT_ROOT:=$(CURDIR)/../..
NTPD_BIN:=$(OXWRT_ROOT)/target/aarch64-unknown-linux-musl/release/ntp-daemon

define Build/Compile
	@true
endef

SVC_DIR:=/usr/lib/oxwrt/services/ntp

define Package/oxwrt-ntp/install
	$(INSTALL_DIR) $(1)$(SVC_DIR)/rootfs/bin
	$(INSTALL_DIR) $(1)$(SVC_DIR)/rootfs/proc
	$(INSTALL_DIR) $(1)$(SVC_DIR)/rootfs/sys
	$(INSTALL_DIR) $(1)$(SVC_DIR)/rootfs/dev
	$(INSTALL_DIR) $(1)$(SVC_DIR)/rootfs/etc
	if [ -f "$(NTPD_BIN)" ]; then \
		$(INSTALL_BIN) $(NTPD_BIN) $(1)$(SVC_DIR)/rootfs/bin/ntp-daemon; \
	else \
		echo "WARNING: ntp-daemon binary not found, creating placeholder"; \
		touch $(1)$(SVC_DIR)/rootfs/bin/ntp-daemon; \
	fi

	$(INSTALL_DIR) $(1)$(SVC_DIR)
	$(INSTALL_DATA) $(OXWRT_ROOT)/config/services/ntp/ntp.toml \
		$(1)$(SVC_DIR)/ntp.toml 2>/dev/null || \
		echo '# placeholder' > $(1)$(SVC_DIR)/ntp.toml
endef

$(eval $(call BuildPackage,oxwrt-ntp))
