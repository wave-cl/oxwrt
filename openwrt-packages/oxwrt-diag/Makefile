# OpenWRT package: diagnostic binaries (iputils-ping, traceroute, etc.)
#
# These are curated upstream C binaries shipped as statically-linked
# aarch64 builds inside the verity-protected rootfs. Each runs through
# the same container hardening pipeline as Rust services (caps drop +
# no_new_privs + seccomp + landlock). See plan §6 for the policy.

include $(TOPDIR)/rules.mk

PKG_NAME:=oxwrt-diag
PKG_VERSION:=0.1.0
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/oxwrt-diag
  SECTION:=oxwrt
  CATEGORY:=oxwrt services
  TITLE:=diagnostic binaries (ping, traceroute, dig)
  DEPENDS:=+oxwrtctl
endef

OXWRT_ROOT:=$(CURDIR)/../..
DIAG_SRC:=$(OXWRT_ROOT)/diag-binaries

define Build/Compile
	@true
endef

DIAG_DIR:=/usr/lib/oxwrt/diag

define Package/oxwrt-diag/install
	# Rootfs structure for the diag container.
	$(INSTALL_DIR) $(1)$(DIAG_DIR)/bin
	$(INSTALL_DIR) $(1)$(DIAG_DIR)/lib
	$(INSTALL_DIR) $(1)$(DIAG_DIR)/proc
	$(INSTALL_DIR) $(1)$(DIAG_DIR)/sys
	$(INSTALL_DIR) $(1)$(DIAG_DIR)/dev

	# Install pre-built static binaries. Missing binaries get a warning
	# but don't fail the build — allows incremental addition.
	for bin in ping traceroute dig; do \
		if [ -f "$(DIAG_SRC)/$$$$bin" ]; then \
			$(INSTALL_BIN) $(DIAG_SRC)/$$$$bin $(1)$(DIAG_DIR)/bin/$$$$bin; \
		else \
			echo "WARNING: diag binary $$$$bin not found in $(DIAG_SRC)"; \
		fi; \
	done
endef

$(eval $(call BuildPackage,oxwrt-diag))
