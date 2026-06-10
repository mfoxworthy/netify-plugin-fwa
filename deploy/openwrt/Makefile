include $(TOPDIR)/rules.mk

PKG_NAME:=netify-plugin-fwa
PKG_VERSION:=0.1.0
PKG_RELEASE:=1

PKG_SOURCE:=v$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://github.com/mfoxworthy/netify-plugin-fwa/archive/refs/tags
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_HASH:=fef3e2362523ff6cc49fbc486624791a8e7db7b9870338cc0ff7042a1d9bef39

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_FIXUP:=autoreconf
PKG_INSTALL:=1
PKG_BUILD_PARALLEL:=1

PKG_LICENSE:=GPL-3.0-or-later
PKG_MAINTAINER:=mike.foxworthy@gmail.com

include $(INCLUDE_DIR)/package.mk

define Package/netify-plugin-fwa
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Netify firewall agent plugin (nftables sets)
  DEPENDS:=+netifyd +nftables-json +libuci +libstdcpp
endef

define Package/netify-plugin-fwa/description
  Netify Agent processor plugin that populates nftables named sets with
  destination IPs of DPI-classified flows for use by sd-wrt routing policy.
endef

define Package/netify-plugin-fwa/conffiles
/etc/config/netify-fwa
endef

define Build/Prepare
	$(call Build/Prepare/Default)
	mkdir -p $(PKG_BUILD_DIR)/m4 $(PKG_BUILD_DIR)/automake
endef

CONFIGURE_ARGS += --enable-package

define Package/netify-plugin-fwa/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/lib/netify-plugin-fwa.so $(1)/usr/lib/

	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) $(CURDIR)/files/etc/config/netify-fwa $(1)/etc/config/
endef

$(eval $(call BuildPackage,netify-plugin-fwa))
