#!/bin/sh
set -u
set -e

# Ensure executable permissions on NetBee scripts
chmod 0755 "${TARGET_DIR}/etc/init.d/S30sysctl" 2>/dev/null || true
chmod 0755 "${TARGET_DIR}/usr/sbin/netbee-status" 2>/dev/null || true

# Secure PPP secrets file permissions
chmod 0600 "${TARGET_DIR}/etc/ppp/pap-secrets" 2>/dev/null || true
chmod 0600 "${TARGET_DIR}/etc/ppp/chap-secrets" 2>/dev/null || true
