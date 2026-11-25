# `netbeed` REST & SSE API Reference

`netbeed` is the lightweight, single-binary Go management daemon for **NetBee OS**.
It listens on `https://192.168.10.1:443` (with HTTP `:80` → HTTPS redirect) and serves any static frontend placed in `/usr/share/netbee/web/` (with SPA fallback to `index.html`).

In QEMU (`make qemu`), the API is forwarded to `https://127.0.0.1:8443`.
For local frontend dev servers (e.g. Vite on `http://localhost:5173`), add your origin to `cors_origins` in `/etc/netbee/netbeed.json`.

---

## Authentication

All `/api/v1/*` endpoints (except `/api/v1/health` and `/api/v1/auth/login`) require either:
- Session cookie `netbee_session` (set automatically on login) **plus required** `X-CSRF-Token` header on all `POST`/`PUT`/`PATCH`/`DELETE` requests, **or**
- `Authorization: Bearer <token>` header.

Default credentials on first boot: **`admin` / `netbee`** (`must_change_password: true`).

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/health` | Public liveness check |
| `POST` | `/api/v1/auth/login` | `{"username":"admin","password":"..."}` → returns `token`, `csrf_token`, `must_change_password` |
| `POST` | `/api/v1/auth/logout` | Invalidate session & clear cookie |
| `GET` | `/api/v1/auth/me` | Current session info |
| `POST` | `/api/v1/auth/password` | `{"current_password":"...","new_password":"...","sync_root_ssh":true}` |

---

## System, Live Telemetry, Rollback, Logs & Backup

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/system/overview` | OS release, hostname, uptime, load, CPU temp, RAM, `/` & `/var/log` disk, services, pending commit |
| `GET` | `/api/v1/system/stream` | **SSE stream** (2s interval): live `cpu_pct`, RAM, temp, per-interface `rx_bps` / `tx_bps` |
| `GET` | `/api/v1/system/services` | Status of all managed daemons (`adguardhome`, `dropbear`, `chronyd`, `dhcpcd`, `vnstatd`, `radvd`, `crond`, `watchdog`, `triggerhappy`, `pppd`, `nftables`, `nft-offload`, `sqm`) |
| `POST` | `/api/v1/system/services/{name}/{action}` | `action`: `start`, `stop`, `restart`, `reload` |
| `PUT` | `/api/v1/system/hostname` | `{"hostname":"netbee"}` |
| `PUT` | `/api/v1/system/timezone` | `{"timezone":"Europe/Istanbul"}` |
| `POST` | `/api/v1/system/reboot` | Reboot device |
| `POST` | `/api/v1/system/poweroff` | Clean shutdown |
| `GET` | `/api/v1/system/pending-commit` | Check active 60s rollback timer after WAN/LAN/Firewall edits |
| `POST` | `/api/v1/system/confirm` | Confirm risky changes and cancel auto-rollback |
| `POST` | `/api/v1/system/rollback` | Immediately revert pending changes |
| `GET` | `/api/v1/system/backup` | Download `.tar.gz` archive of all persistent configs (`netbee-backup`) |
| `POST` | `/api/v1/system/restore` | Upload `.tar.gz` archive in request body to restore configs |
| `GET` | `/api/v1/logs/system?lines=200&filter=` | Filtered `/var/log/messages` |
| `GET` | `/api/v1/logs/kernel?lines=200` | Kernel `dmesg` ring buffer |

---

## Network (Interfaces, Routes, Neighbors, LAN & WAN)

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/network/interfaces` | `ip -j -s addr show` enriched with `ethtool` speed/duplex/link |
| `GET` | `/api/v1/network/routes` | IPv4 & IPv6 routing tables (`ip -j route`) |
| `POST` | `/api/v1/network/routes` | Add static route: `{"destination":"10.20.0.0/24","gateway":"192.168.10.2","device":"eth0","metric":100}` |
| `DELETE` | `/api/v1/network/routes` | Delete route: `{"destination":"10.20.0.0/24"}` |
| `GET` | `/api/v1/network/neighbors` | ARP / IPv6 NDP neighbor table (`ip -j neigh`) |
| `GET` | `/api/v1/network/wan` | Current WAN config & `pppd_running` status |
| `PUT` | `/api/v1/network/wan` | Configure `dhcp`, `pppoe`, or `ont_vlan` (`vlan_id`, `pppoe_user`, `pppoe_password`, `mac_clone`, `mtu`, `ipv6_pd`) — **starts 60s rollback guard** |
| `POST` | `/api/v1/network/wan/reconnect` | Reconnect PPPoE or renew DHCP |
| `GET` | `/api/v1/network/lan` | Current LAN interface/IP/netmask |
| `PUT` | `/api/v1/network/lan` | Update LAN IP/netmask — **starts 60s rollback guard** |

---

## Firewall (`nftables`), Port Forwarding (DNAT), Offload & Conntrack

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/firewall/ruleset` | Live `nft -j list ruleset` JSON |
| `GET` | `/api/v1/firewall/config` | Toggles (`transparent_dns`, `expose_wireguard`, `flow_offload`), custom rules & port forwards |
| `PUT` | `/api/v1/firewall/config` | Replace full firewall config (dry-run validated via `nft -c` + **60s rollback guard**) |
| `PATCH` | `/api/v1/firewall/toggles` | Partial toggle update (`transparent_dns`, `expose_wireguard`, `wireguard_port`, `flow_offload`) without overwriting rules |
| `POST` | `/api/v1/firewall/rules` | Add custom filter rule (`input`/`forward` → `custom_input`/`custom_forward`, IPv4/IPv6, `accept`/`drop`/`reject`) |
| `DELETE` | `/api/v1/firewall/rules/{id}` | Delete custom rule |
| `POST` | `/api/v1/firewall/port-forwards` | Add DNAT port forward (`protocol`: `tcp`/`udp`/`both`, `ext_port`, `int_ip`, `int_port` — use `0` for 1:1 range) |
| `DELETE` | `/api/v1/firewall/port-forwards/{id}` | Delete port forward |
| `PUT` | `/api/v1/firewall/offload` | `{"enabled":true}` toggle `nftables` software flow offload |
| `POST` | `/api/v1/firewall/reload` | Reload `/etc/nftables.conf` |
| `GET` | `/api/v1/firewall/conntrack` | Parsed active NAT/conntrack sessions |
| `DELETE` | `/api/v1/firewall/conntrack` | Flush conntrack table |

---

## DNS & DHCP (`AdGuardHome` Integration)

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/dns/status` | AdGuardHome status |
| `GET` | `/api/v1/dns/stats` | Query statistics & top blocked domains |
| `GET` | `/api/v1/dns/querylog` | Recent DNS query log |
| `GET` | `/api/v1/dns/filters` | Blocklist filters status |
| `POST` | `/api/v1/dns/protection` | Toggle DNS protection (`{"enabled":true}`) |
| `GET` / `POST` / `DELETE` | `/api/v1/dns/rewrites` | Local DNS rewrite rules |
| `GET` | `/api/v1/dhcp/status` | Active & static DHCP leases |
| `PUT` | `/api/v1/dhcp/config` | Update DHCP pool/gateway/lease time |
| `POST` / `DELETE` | `/api/v1/dhcp/leases/static` | Add/remove static MAC → IP reservation |
| `ANY` | `/api/v1/adguard/{path...}` | Full authenticated proxy to `AdGuardHome /control/{path...}` |

---

## WireGuard VPN, SQM/CAKE QoS & vnStat Traffic

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/vpn/wireguard` | Server config, active state & live peer handshake/RX/TX (`wg show wg0 dump`) |
| `PUT` | `/api/v1/vpn/wireguard` | Enable/disable `wg0`, set `address`, `listen_port`, `endpoint`, `dns` (auto-generates server keys) |
| `POST` | `/api/v1/vpn/wireguard/peers` | Add peer (`name`, `allowed_ips`, optional `public_key`); returns ready-to-import `client_config` for QR rendering |
| `DELETE` | `/api/v1/vpn/wireguard/peers/{id}` | Remove peer |
| `GET` / `PUT` | `/api/v1/qos/sqm` | Read/update `/etc/netbee/sqm.conf` (`enabled`, `wan_interface`, `download_kbit`, `upload_kbit`, `overhead`) & apply CAKE |
| `GET` | `/api/v1/traffic/vnstat?iface=` | Native `vnstat --json` historical traffic stats |
| `POST` | `/api/v1/traffic/vnstat/interface` | `{"interface":"eth1","action":"add\|remove"}` |
| `GET` | `/api/v1/traffic/live` | Instant `/sys/class/net/*/statistics` counters |

---

## NTP, IPv6, SSH & Diagnostics

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` / `PUT` | `/api/v1/services/ntp` | Chrony tracking/sources & server list + `serve_lan` toggle |
| `GET` / `PUT` | `/api/v1/services/ipv6` | Toggle `radvd` LAN SLAAC & `dhcpcd` IPv6-PD |
| `GET` / `PUT` | `/api/v1/services/ssh` | Dropbear `password_auth`, `idle_timeout`, and `authorized_keys` |
| `POST` / `DELETE` | `/api/v1/services/ssh/keys` (`/{index}`) | Add/remove SSH public keys in `/root/.ssh/authorized_keys` |
| `POST` | `/api/v1/diag/ping` | `{"host":"1.1.1.1","count":4}` |
| `POST` | `/api/v1/diag/mtr` | `{"host":"1.1.1.1","cycles":5}` → native `mtr -j` JSON |
| `POST` | `/api/v1/diag/iperf3` | `{"host":"...","port":5201,"duration":5,"reverse":false}` → native `iperf3 -J` JSON |
| `POST` | `/api/v1/diag/dns` | `{"host":"example.com","server":"127.0.0.1"}` |
| `POST` | `/api/v1/diag/capture` | Safe bounded `tcpdump`: `{"interface":"eth0","count":20,"proto":"tcp","port":443}` |

