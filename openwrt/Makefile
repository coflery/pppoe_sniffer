#
# OpenWrt package Makefile for PPPOE sniffer
#
# Usage in OpenWrt build system:
#   1. Copy this directory to <openwrt_root>/package/pppoe_sniffer/
#   2. Run make menuconfig -> Network -> pppoe_sniffer
#   3. Run make package/pppoe_sniffer/compile
#

include $(TOPDIR)/rules.mk

PKG_NAME:=pppoe_sniffer
PKG_VERSION:=1.4
PKG_RELEASE:=1

PKG_MAINTAINER:=Frand Ren <frand@example.com>
PKG_LICENSE:=Proprietary
PKG_LICENSE_FILES:=

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/pppoe_sniffer
  SECTION:=net
  CATEGORY:=Network
  DEPENDS:=+libpcap
  TITLE:=PPPOE Password Sniffer
endef

define Package/pppoe_sniffer/description
  PPPOE password sniffer - captures PAP authentication credentials
  from PPPOE traffic by acting as a PPPOE access concentrator.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	cp $(CURDIR)/common.h $(CURDIR)/common.cpp $(CURDIR)/pppoe.cpp $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(TARGET_CXX) $(TARGET_CXXFLAGS) $(FPIC) -O2 -Wall \
		-o $(PKG_BUILD_DIR)/PPPOE \
		$(PKG_BUILD_DIR)/pppoe.cpp $(PKG_BUILD_DIR)/common.cpp \
		$(TARGET_LDFLAGS) -lpcap
endef

define Package/pppoe_sniffer/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/PPPOE $(1)/usr/bin/PPPOE
endef

$(eval $(call BuildPackage,pppoe_sniffer))
