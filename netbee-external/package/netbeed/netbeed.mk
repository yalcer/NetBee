################################################################################
#
# netbeed
#
################################################################################

NETBEED_VERSION = 0.1.0
NETBEED_SITE = $(NETBEED_PKGDIR)/src
NETBEED_SITE_METHOD = local
NETBEED_LICENSE = MIT
NETBEED_GOMOD = github.com/yalcer/netbee/netbeed
NETBEED_BUILD_TARGETS = .
NETBEED_GO_ENV = CGO_ENABLED=0
NETBEED_LDFLAGS = -s -w -X main.version=$(NETBEED_VERSION)

define NETBEED_INSTALL_TARGET_CMDS
	$(INSTALL) -D -m 0755 $(@D)/bin/netbeed $(TARGET_DIR)/usr/bin/netbeed
	$(INSTALL) -D -m 0600 $(NETBEED_PKGDIR)/netbeed.json \
		$(TARGET_DIR)/etc/netbee/netbeed.json
	mkdir -p $(TARGET_DIR)/usr/share/netbee/web
	rm -rf $(TARGET_DIR)/usr/share/netbee/web/assets
	$(INSTALL) -D -m 0644 $(NETBEED_PKGDIR)/../../../hive/index.html \
		$(TARGET_DIR)/usr/share/netbee/web/index.html
	cp -a $(NETBEED_PKGDIR)/../../../hive/assets \
		$(TARGET_DIR)/usr/share/netbee/web/assets
	rm -rf $(TARGET_DIR)/usr/share/netbee/web/assets/css/showcase.css \
		$(TARGET_DIR)/usr/share/netbee/web/assets/js/pages \
		$(TARGET_DIR)/usr/share/netbee/web/assets/js/data/mock-db.js \
		$(TARGET_DIR)/usr/share/netbee/web/assets/img/logo-mark.svg \
		$(TARGET_DIR)/usr/share/netbee/web/assets/vendor/fomantic/themes/default/assets/fonts/brand-icons.*
endef

define NETBEED_INSTALL_INIT_SYSV
	$(INSTALL) -D -m 0755 $(NETBEED_PKGDIR)/S90netbeed \
		$(TARGET_DIR)/etc/init.d/S90netbeed
endef

$(eval $(golang-package))
