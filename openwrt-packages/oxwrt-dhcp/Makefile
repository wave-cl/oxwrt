# OpenWRT package: coredhcp service rootfs.

include $(TOPDIR)/rules.mk

PKG_NAME:=oxwrt-dhcp
PKG_VERSION:=0.1.0
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/oxwrt-dhcp
  SECTION:=oxwrt
  CATEGORY:=oxwrt services
  TITLE:=coredhcp DHCPv4 server
  DEPENDS:=+oxwrtctl
endef

OXWRT_ROOT:=$(CURDIR)/../..
COREDHCP_BIN:=$(OXWRT_ROOT)/target/coredhcp/coredhcp

define Build/Compile
	@true
endef

SVC_DIR:=/usr/lib/oxwrt/services/dhcp

define Package/oxwrt-dhcp/install
	$(INSTALL_DIR) $(1)$(SVC_DIR)/rootfs/bin
	$(INSTALL_DIR) $(1)$(SVC_DIR)/rootfs/proc
	$(INSTALL_DIR) $(1)$(SVC_DIR)/rootfs/sys
	$(INSTALL_DIR) $(1)$(SVC_DIR)/rootfs/dev
	$(INSTALL_DIR) $(1)$(SVC_DIR)/rootfs/etc
	$(INSTALL_DIR) $(1)$(SVC_DIR)/rootfs/var/lib/coredhcp
	if [ -f "$(COREDHCP_BIN)" ]; then \
		$(INSTALL_BIN) $(COREDHCP_BIN) $(1)$(SVC_DIR)/rootfs/bin/coredhcp; \
	else \
		echo "WARNING: coredhcp binary not found, creating placeholder"; \
		touch $(1)$(SVC_DIR)/rootfs/bin/coredhcp; \
	fi

	$(INSTALL_DIR) $(1)$(SVC_DIR)
	$(INSTALL_DATA) $(OXWRT_ROOT)/config/services/dhcp/coredhcp.yml \
		$(1)$(SVC_DIR)/coredhcp.yml 2>/dev/null || \
		echo '# placeholder' > $(1)$(SVC_DIR)/coredhcp.yml

	# Writable lease file directory on the host side.
	$(INSTALL_DIR) $(1)/var/lib/oxwrt/coredhcp
	touch $(1)/var/lib/oxwrt/coredhcp/leases.txt
endef

$(eval $(call BuildPackage,oxwrt-dhcp))
