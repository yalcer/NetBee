#!/usr/bin/env bash
set -euo pipefail

IMAGES_DIR="$(cd "$(dirname "$0")/.." && pwd)/output/images"
KERNEL="${IMAGES_DIR}/Image"
ROOTFS="${IMAGES_DIR}/rootfs.ext4"

if [ ! -f "$KERNEL" ] || [ ! -f "$ROOTFS" ]; then
    echo "Error: Build outputs not found in ${IMAGES_DIR}. Run 'make build' first." >&2
    exit 1
fi

OVERLAY="$(mktemp /tmp/netbee-rootfs-XXXXXX.qcow2)"
trap 'rm -f "$OVERLAY"' EXIT
qemu-img create -q -f qcow2 -F raw -b "$ROOTFS" "$OVERLAY"

echo "Starting NetBee OS in QEMU (ARM64 virt)..."
echo "  - Serial console : stdio (Ctrl-A then X to exit QEMU)"
echo "  - SSH            : ssh -p 2222 root@127.0.0.1  (password: netbee)"
echo "  - AdGuardHome UI : http://127.0.0.1:3000         (admin / netbee)"
echo "  - Future Web UI  : https://127.0.0.1:8443        (LAN port 443 forward)"
echo "  - LAN (eth0)     : 192.168.10.1/24"
echo "  - WAN (eth1)     : DHCP via QEMU virtual ISP (10.0.2.0/24)"
echo ""

qemu-system-aarch64 \
    -M virt \
    -cpu cortex-a76 \
    -smp 4 \
    -m 1024 \
    -nographic \
    -kernel "$KERNEL" \
    -append "root=/dev/vda rw console=ttyAMA0,115200 net.ifnames=0" \
    -drive "file=${OVERLAY},format=qcow2,if=none,id=hd0" \
    -device virtio-blk-pci,drive=hd0 \
    -netdev "user,id=lan,net=192.168.10.0/24,host=192.168.10.2,hostfwd=tcp:127.0.0.1:2222-192.168.10.1:22,hostfwd=tcp:127.0.0.1:3000-192.168.10.1:3000,hostfwd=tcp:127.0.0.1:8443-192.168.10.1:443" \
    -device virtio-net-pci,netdev=lan,mac=52:54:00:12:34:01 \
    -netdev "user,id=wan,net=10.0.2.0/24" \
    -device virtio-net-pci,netdev=wan,mac=52:54:00:12:34:02
