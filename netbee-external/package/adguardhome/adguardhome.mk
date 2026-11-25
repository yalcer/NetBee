################################################################################
#
# adguardhome
#
################################################################################

ADGUARDHOME_VERSION = 1.0.0
ADGUARDHOME_SOURCE = AdGuardHome_linux_arm64.tar.gz
ADGUARDHOME_SITE = https://github.com/AdguardTeam/AdGuardHome/releases/download/v$(ADGUARDHOME_VERSION)
ADGUARDHOME_LICENSE = GPL-3.0

define ADGUARDHOME_INSTALL_TARGET_CMDS
	$(INSTALL) -D -m 0755 $(@D)/AdGuardHome/AdGuardHome $(TARGET_DIR)/usr/bin/AdGuardHome
	$(INSTALL) -D -m 0640 $(ADGUARDHOME_PKGDIR)/AdGuardHome.yaml \
		$(TARGET_DIR)/etc/adguardhome/AdGuardHome.yaml
	mkdir -p $(TARGET_DIR)/var/lib/adguardhome
endef

define ADGUARDHOME_INSTALL_INIT_SYSV
	$(INSTALL) -D -m 0755 $(ADGUARDHOME_PKGDIR)/S85adguardhome \
		$(TARGET_DIR)/etc/init.d/S85adguardhome
endef

$(eval $(generic-package))

