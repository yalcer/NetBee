# NetBee

Minimal, hardened Buildroot-based firewall and router OS for **Raspberry Pi 5** built with an out-of-tree `BR2_EXTERNAL` architecture.

---

## Features

- **Stateful Firewall & NAT (`nftables`)**: Default-drop `input`/`forward` policy, dynamic software `flowtable` offload, TCP MSS clamping for PPPoE/ONT, SSH rate-limiting, WireGuard (`wg0`) zone, and optional transparent DNS redirect.
- **DNS & LAN DHCP (`AdGuardHome v1.0.0`)**: Single-service DNS filtering (DoH + IP fallback to avoid 1970 RTC boot deadlock), RAM-only query logs, and built-in LAN DHCP (`192.168.10.100–200`).
- **WAN Connectivity**: Dual-Ethernet design (built-in RP1 Gigabit LAN + USB/PCIe WAN), DHCP via `dhcpcd`, PPPoE (`pppd`/`rp-pppoe`), direct Fiber ONT 802.1Q VLAN tagging (e.g. VLAN 35), and IPv6 (`dhcpcd` DHCPv6-PD + `radvd` SLAAC).
- **VPN & QoS**: Built-in kernel **WireGuard** (`wireguard-tools`) and **SQM/CAKE** anti-bufferbloat shaping (`netbee-sqm` + `/etc/netbee/sqm.conf`).
- **Monitoring & JSON-Ready Diagnostics**: `vnStat` (SQLite + `--json`), `mtr` (`--json`), `nft -j`, `conntrack-tools`, `tcpdump`, `iperf3`, and `chrony` (NTP client + local LAN time server).
- **Appliance Hardening & Resilience**:
  - `udev` rule pinning RPi 5 RP1 Ethernet (`macb`) permanently to `eth0` (LAN)
  - Hardware watchdog (`/dev/watchdog`), `noatime` rootfs + `tmpfs` `/var/log` (microSD wear protection), hourly `logrotate`
  - First-boot automatic microSD rootfs expansion (`sfdisk` + `partx` + `resize2fs`)
  - Headless RPi 5 boot config (`disable-wifi`, `disable-bt`, `audio=off`, `pciex1`, full USB current)
  - Server-only `dropbear` SSH bound strictly to LAN IP (`192.168.10.1:22`), legacy OpenSSL ciphers disabled

---

## Default Network & Access

| Interface / Service | Default Configuration |
| :--- | :--- |
| **LAN (`eth0`)** | Static `192.168.10.1/24` (RPi 5 built-in Ethernet) |
| **WAN (`eth1`)** | DHCP / IPv6-PD via `dhcpcd` (USB or PCIe NIC; PPPoE / ONT VLAN 35 ready) |
| **DHCP Pool** | `192.168.10.100` – `192.168.10.200` (`AdGuardHome`) |
| **SSH (`dropbear`)** | `ssh netbee@192.168.10.1` or `ssh root@192.168.10.1` (SHA-512 default password: `netbee` — rotate via `netbee-passwd`; root SSH can be disabled with `-w`) |
| **Web API / UI (`netbeed`)** | `https://192.168.10.1` (default: `admin` / `netbee`; static frontend dir: `/usr/share/netbee/web`, see [API.md](netbee-external/package/netbeed/API.md)) |
| **AdGuardHome UI** | `http://192.168.10.1:3000` (LAN only; default: `admin` / `netbee`) |
| **CLI Utilities** | `netbee-cli`, `netbee-status`, `netbee-passwd`, `netbee-user`, `netbee-sqm`, `netbee-backup`, `netbee-factory-reset` |

---

## Quick Start

### 1. Prepare Buildroot
NetBee uses an untouched upstream **Buildroot 2026.08.2** tree alongside `netbee-external/`:

```bash
git clone git@github.com:yalcer/NetBee.git
cd NetBee
wget https://buildroot.org/downloads/buildroot-2026.08.2.tar.xz
tar -xf buildroot-2026.08.2.tar.xz
```

### 2. Configure & Build
```bash
make defconfig
make build
```

This runs a full-core parallel build (`BR2_PER_PACKAGE_DIRECTORIES=y` + `-j$(nproc)`) and outputs:
- `output/images/sdcard.img` — Ready-to-flash Raspberry Pi 5 microSD image
- `output/images/Image` & `output/images/rootfs.ext4` — Kernel and rootfs (also bootable in QEMU ARM64)

### 3. Flash to microSD
```bash
sudo dd if=output/images/sdcard.img of=/dev/sdX bs=4M status=progress conv=fsync
```
*(Replace `/dev/sdX` with your microSD device. Rootfs expands automatically on first Raspberry Pi 5 boot.)*

---

## Testing in QEMU (ARM64)

No Raspberry Pi hardware is required to test changes (`qemu-system-aarch64` required):

```bash
make qemu
```

- **Serial Console:** Attached directly to terminal (exit with `Ctrl+A`, then `X`)
- **SSH from Host:** `ssh -p 2222 root@127.0.0.1` (password: `netbee`)
- **Virtual NICs:** `eth0` (`192.168.10.1/24` LAN) + `eth1` (`10.0.2.0/24` QEMU virtual WAN)

---

## Repository Structure

```text
NetBee/
├── Makefile                        # Build & QEMU wrapper targets
├── scripts/run-qemu.sh             # ARM64 QEMU launcher (non-destructive qcow2 overlay)
└── netbee-external/                # BR2_EXTERNAL tree
    ├── configs/netbee_rpi5_defconfig
    ├── package/adguardhome/        # AdGuardHome v1.0.0 package, SHA256 hash & init script
    ├── package/netbeed/            # Zero-dependency Go HTTPS/SSE management backend & API docs
    └── board/netbee/rpi5/
        ├── config_5.txt            # Headless RPi 5 firmware boot config
        ├── linux-netbee.fragment   # Router, nftables, WireGuard, SQM, NIC & VirtIO kernel options
        ├── busybox-netbee.fragment # BusyBox applet customizations (chpasswd with SHA-512)
        ├── users.table             # Pre-created OS users ('netbee' admin UID 1000 & 'iperf' UID 110)
        ├── device_table.txt        # Strict fakeroot ownership & 0700/0600 directory/file modes
        ├── post-build.sh           # OS identity stamp & script/secret permissions
        └── rootfs-overlay/         # Network, nftables, chrony, dhcpcd, radvd, SQM, CLI tools & profiles
```

---

## Useful Make Targets

| Command | Description |
| :--- | :--- |
| `make defconfig` | Load `netbee_rpi5_defconfig` into `output/` |
| `make build` | Parallel full-core build of `sdcard.img` |
| `make menuconfig` | Customize Buildroot packages |
| `make linux-menuconfig` | Customize Linux kernel configuration |
| `make savedefconfig` | Save changes back to `netbee_rpi5_defconfig` |
| `make qemu` | Boot built image in QEMU ARM64 |
| `make distclean` | Remove `output/` for a clean rebuild |

