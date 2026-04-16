# OpenWRT package: hickory-dns service rootfs.
#
# Installs the pre-built hickory-dns binary + its config file into the
# service rootfs directory that oxwrtctl mounts as the container root.

include $(TOPDIR)/rules.mk

PKG_NAME:=oxwrt-dns
PKG_VERSION:=0.1.0
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/oxwrt-dns
  SECTION:=oxwrt
  CATEGORY:=oxwrt services
  TITLE:=hickory-dns forwarding resolver
  DEPENDS:=+oxwrtctl
endef

OXWRT_ROOT:=$(CURDIR)/../..
# The hickory-dns binary is cross-built separately (see diag-binaries/BUILD.md).
# Expected at this path after the cross-build step.
HICKORY_BIN:=$(OXWRT_ROOT)/target/aarch64-unknown-linux-musl/release/hickory-dns

define Build/Compile
	@true
endef

SVC_DIR:=/usr/lib/oxwrt/services/dns

define Package/oxwrt-dns/install
	# Service rootfs: single binary + mount-point stubs
	$(INSTALL_DIR) $(1)$(SVC_DIR)/rootfs/bin
	$(INSTALL_DIR) $(1)$(SVC_DIR)/rootfs/proc
	$(INSTALL_DIR) $(1)$(SVC_DIR)/rootfs/sys
	$(INSTALL_DIR) $(1)$(SVC_DIR)/rootfs/dev
	$(INSTALL_DIR) $(1)$(SVC_DIR)/rootfs/etc
	if [ -f "$(HICKORY_BIN)" ]; then \
		$(INSTALL_BIN) $(HICKORY_BIN) $(1)$(SVC_DIR)/rootfs/bin/hickory-dns; \
	else \
		echo "WARNING: hickory-dns binary not found, creating placeholder"; \
		touch $(1)$(SVC_DIR)/rootfs/bin/hickory-dns; \
	fi

	# Config file lives on the host side, bind-mounted read-only into
	# the container at /etc/named.toml.
	$(INSTALL_DIR) $(1)$(SVC_DIR)
	$(INSTALL_DATA) $(OXWRT_ROOT)/config/services/dns/named.toml \
		$(1)$(SVC_DIR)/named.toml 2>/dev/null || \
		echo '# placeholder — populate with hickory-dns config' > $(1)$(SVC_DIR)/named.toml
endef

$(eval $(call BuildPackage,oxwrt-dns))
