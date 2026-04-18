# OpenWRT package: hickory-dns service rootfs.
#
# Installs the pre-built hickory-dns binary + its config file into the
# service rootfs directory that oxwrtd pivot_roots into.

include $(TOPDIR)/rules.mk

PKG_NAME:=oxwrt-dns
PKG_VERSION:=0.1.0
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/oxwrt-dns
  SECTION:=oxwrt
  CATEGORY:=oxwrt services
  TITLE:=hickory-dns forwarding resolver
  DEPENDS:=+oxwrtd
endef

OXWRT_ROOT:=$(CURDIR)/../..
# Cross-built out-of-band (see project_oxwrt_services.md). Convention:
# service binaries land under OXWRT_ROOT/build-services/<svc>/ so this
# package finds them at a stable path. The cross-build pipeline is:
#
#   AR_aarch64_unknown_linux_musl=/opt/homebrew/opt/binutils/bin/ar \
#   cargo-zigbuild install \
#     --locked --target aarch64-unknown-linux-musl \
#     --root build-services/dns hickory-dns
#
# produces build-services/dns/bin/hickory-dns — copy/symlink to the
# path below before invoking `make image`.
HICKORY_BIN:=$(OXWRT_ROOT)/build-services/dns/hickory-dns

define Build/Compile
	@true
endef

SVC_DIR:=/usr/lib/oxwrt/services/dns

define Package/oxwrt-dns/install
	# Rootfs layout — the container pivot_roots here and execs
	# `/hickory-dns` per the entrypoint in config/oxwrt.toml. Binary
	# goes at the rootfs ROOT, not under /bin.
	$(INSTALL_DIR) $(1)$(SVC_DIR)/rootfs
	$(INSTALL_DIR) $(1)$(SVC_DIR)/rootfs/proc
	$(INSTALL_DIR) $(1)$(SVC_DIR)/rootfs/sys
	$(INSTALL_DIR) $(1)$(SVC_DIR)/rootfs/dev
	$(INSTALL_DIR) $(1)$(SVC_DIR)/rootfs/etc

	# Minimal passwd/group — hickory drops to `nobody` at startup and
	# musl-static getpwnam reads /etc/passwd directly (no NSS), so a
	# missing file produces "unable to lookup user 'nobody'. Exiting."
	printf 'root:x:0:0:root:/:/bin/false\nnobody:x:65534:65534:nobody:/:/bin/false\n' \
		> $(1)$(SVC_DIR)/rootfs/etc/passwd
	printf 'root:x:0:\nnobody:x:65534:\n' > $(1)$(SVC_DIR)/rootfs/etc/group

	if [ -f "$(HICKORY_BIN)" ]; then \
		$(INSTALL_BIN) $(HICKORY_BIN) $(1)$(SVC_DIR)/rootfs/hickory-dns; \
	else \
		echo "WARNING: hickory-dns binary not found at $(HICKORY_BIN)"; \
		touch $(1)$(SVC_DIR)/rootfs/hickory-dns; \
	fi

	# Config file lives on the host side and is bind-mounted read-only
	# into the container at /etc/named.toml at spawn time (see the
	# [[services.binds]] entry for dns in config/oxwrt.toml).
	$(INSTALL_DIR) $(1)$(SVC_DIR)
	$(INSTALL_DATA) $(OXWRT_ROOT)/config/services/dns/named.toml \
		$(1)$(SVC_DIR)/named.toml
endef

$(eval $(call BuildPackage,oxwrt-dns))
