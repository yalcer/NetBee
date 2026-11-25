#!/bin/sh
set -u
set -e

# Ensure executable permissions on NetBee init & CLI scripts
for script in \
	"${TARGET_DIR}/etc/init.d/S05firstboot-resize" \
	"${TARGET_DIR}/etc/init.d/S15watchdog" \
	"${TARGET_DIR}/etc/init.d/S42nft-offload" \
	"${TARGET_DIR}/etc/init.d/S45sqm" \
	"${TARGET_DIR}/etc/init.d/S86vnstatd" \
	"${TARGET_DIR}/usr/sbin/netbee-status" \
	"${TARGET_DIR}/usr/sbin/netbee-sqm"; do
	[ -f "$script" ] && chmod 0755 "$script"
done

# Secure PPP secrets and root crontab permissions
chmod 0600 "${TARGET_DIR}/etc/ppp/pap-secrets" 2>/dev/null || true
chmod 0600 "${TARGET_DIR}/etc/ppp/chap-secrets" 2>/dev/null || true
chmod 0600 "${TARGET_DIR}/etc/cron/crontabs/root" 2>/dev/null || true
