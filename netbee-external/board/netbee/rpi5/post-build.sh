#!/bin/sh
set -u
set -e

# Stamp NetBee OS identity into /usr/lib/os-release and /etc/netbee-release
cat > "${TARGET_DIR}/usr/lib/os-release" <<'EOF'
NAME="NetBee OS"
ID=netbee
VERSION="0.1.0"
VERSION_ID="0.1.0"
PRETTY_NAME="NetBee OS 0.1.0 (Raspberry Pi 5)"
HOME_URL="https://github.com/yalcer/NetBee"
BOARD="rpi5"
ARCH="aarch64"
BUILDROOT_VERSION="2026.08.2"
EOF

cat > "${TARGET_DIR}/etc/netbee-release" <<'EOF'
NetBee OS 0.1.0 (ARM64 / Raspberry Pi 5 Hardened Firewall & Router)
EOF

# Ensure persistent state & SSH key directories exist prior to makedevs permission pass
for dir in \
	"${TARGET_DIR}/root/.ssh" \
	"${TARGET_DIR}/home/netbee/.ssh" \
	"${TARGET_DIR}/etc/netbee/tls" \
	"${TARGET_DIR}/etc/nftables.d" \
	"${TARGET_DIR}/etc/wireguard" \
	"${TARGET_DIR}/var/lib/netbee"; do
	[ -e "$dir" ] || mkdir -p "$dir"
done
chmod 0700 "${TARGET_DIR}/root/.ssh" "${TARGET_DIR}/home/netbee/.ssh" "${TARGET_DIR}/etc/netbee/tls" "${TARGET_DIR}/etc/wireguard"

# Ensure executable permissions on all NetBee init, hook & CLI scripts
for script in \
	"${TARGET_DIR}/etc/init.d/S12firstboot-resize" \
	"${TARGET_DIR}/etc/init.d/S15watchdog" \
	"${TARGET_DIR}/etc/init.d/S42nft-offload" \
	"${TARGET_DIR}/etc/init.d/S45sqm" \
	"${TARGET_DIR}/etc/init.d/S86vnstatd" \
	"${TARGET_DIR}/etc/ppp/ip-up" \
	"${TARGET_DIR}/etc/ppp/ip-down" \
	"${TARGET_DIR}/usr/sbin/netbee-status" \
	"${TARGET_DIR}/usr/sbin/netbee-sqm" \
	"${TARGET_DIR}/usr/sbin/netbee-hotplug-wan" \
	"${TARGET_DIR}/usr/sbin/netbee-backup" \
	"${TARGET_DIR}/usr/sbin/netbee-passwd" \
	"${TARGET_DIR}/usr/sbin/netbee-user" \
	"${TARGET_DIR}/usr/sbin/netbee-factory-reset" \
	"${TARGET_DIR}/usr/sbin/netbee-cli"; do
	[ -f "$script" ] && chmod 0755 "$script"
done

# Secure PPP secrets and root crontab permissions
chmod 0600 "${TARGET_DIR}/etc/ppp/pap-secrets" 2>/dev/null || true
chmod 0600 "${TARGET_DIR}/etc/ppp/chap-secrets" 2>/dev/null || true
chmod 0600 "${TARGET_DIR}/etc/cron/crontabs/root" 2>/dev/null || true
