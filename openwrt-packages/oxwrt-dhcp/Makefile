# OpenWRT package: coredhcp service rootfs.
#
# Installs the pre-built coredhcp (Go + CGO sqlite) binary + its YAML
# config into the rootfs the dhcp container pivot_roots into.

include $(TOPDIR)/rules.mk

PKG_NAME:=oxwrt-dhcp
PKG_VERSION:=0.1.0
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/oxwrt-dhcp
  SECTION:=oxwrt
  CATEGORY:=oxwrt services
  TITLE:=coredhcp DHCPv4 server
  DEPENDS:=+oxwrtd
endef

OXWRT_ROOT:=$(CURDIR)/../..
# Cross-built out-of-band. coredhcp needs CGO_ENABLED=1 (the `range`
# plugin uses mattn/go-sqlite3), cross-compiled via `zig cc` as the
# CC. See project_oxwrt_services.md for the exact invocation.
#
#   git clone ... /tmp/coredhcp-src
#   cd /tmp/coredhcp-src/cmds/coredhcp
#   CGO_ENABLED=1 GOOS=linux GOARCH=arm64 \
#   CC="zig cc -target aarch64-linux-musl" \
#   CXX="zig c++ -target aarch64-linux-musl" \
#   go build -o $OXWRT_ROOT/build-services/dhcp/coredhcp .
#
# → ~23 MB static aarch64 ELF. Copy/symlink to the path below before
# `make image`.
COREDHCP_BIN:=$(OXWRT_ROOT)/build-services/dhcp/coredhcp

define Build/Compile
	@true
endef

SVC_DIR:=/usr/lib/oxwrt/services/dhcp

define Package/oxwrt-dhcp/install
	# Rootfs: pivot_root target. Binary at rootfs root (`/coredhcp`),
	# matching the entrypoint in config/oxwrt.toml.
	$(INSTALL_DIR) $(1)$(SVC_DIR)/rootfs
	$(INSTALL_DIR) $(1)$(SVC_DIR)/rootfs/proc
	$(INSTALL_DIR) $(1)$(SVC_DIR)/rootfs/sys
	$(INSTALL_DIR) $(1)$(SVC_DIR)/rootfs/dev
	$(INSTALL_DIR) $(1)$(SVC_DIR)/rootfs/etc
	$(INSTALL_DIR) $(1)$(SVC_DIR)/rootfs/var/lib/coredhcp

	printf 'root:x:0:0:root:/:/bin/false\nnobody:x:65534:65534:nobody:/:/bin/false\n' \
		> $(1)$(SVC_DIR)/rootfs/etc/passwd
	printf 'root:x:0:\nnobody:x:65534:\n' > $(1)$(SVC_DIR)/rootfs/etc/group

	if [ -f "$(COREDHCP_BIN)" ]; then \
		$(INSTALL_BIN) $(COREDHCP_BIN) $(1)$(SVC_DIR)/rootfs/coredhcp; \
	else \
		echo "WARNING: coredhcp binary not found at $(COREDHCP_BIN)"; \
		touch $(1)$(SVC_DIR)/rootfs/coredhcp; \
	fi

	# YAML config bind-mounted into the container read-only at
	# /etc/coredhcp.yml.
	$(INSTALL_DIR) $(1)$(SVC_DIR)
	$(INSTALL_DATA) $(OXWRT_ROOT)/config/services/dhcp/coredhcp.yml \
		$(1)$(SVC_DIR)/coredhcp.yml

	# Writable lease-file directory on the host side — bind-mounted
	# read-write into the container at /var/lib/coredhcp/. This lets
	# leases survive service restart (coredhcp appends to a sqlite DB).
	$(INSTALL_DIR) $(1)/var/lib/oxwrt/coredhcp
	touch $(1)/var/lib/oxwrt/coredhcp/leases.txt
endef

$(eval $(call BuildPackage,oxwrt-dhcp))
