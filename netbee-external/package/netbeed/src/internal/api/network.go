package api

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/yalcer/netbee/netbeed/internal/config"
	"github.com/yalcer/netbee/netbeed/internal/sys"
)

const adguardYAMLPath = "/etc/adguardhome/AdGuardHome.yaml"

func sysMarshal(v any) ([]byte, error) {
	return json.Marshal(v)
}

func (s *Server) handleInterfaces(w http.ResponseWriter, r *http.Request) {
	res, err := sys.Run(5*time.Second, "ip", "-j", "-s", "addr", "show")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	var ifaces []map[string]any
	if err := json.Unmarshal([]byte(res.Stdout), &ifaces); err != nil {
		writeValidatedRawJSON(w, http.StatusOK, []byte(res.Stdout), "[]")
		return
	}
	// Enrich physical Ethernet interfaces with ethtool link speed/duplex when available
	for _, item := range ifaces {
		name, _ := item["ifname"].(string)
		if name == "" || name == "lo" || !sys.ValidIface(name) {
			continue
		}
		if et, err := sys.Run(2*time.Second, "ethtool", name); err == nil {
			for _, line := range strings.Split(et.Stdout, "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "Speed:") {
					item["speed"] = strings.TrimSpace(strings.TrimPrefix(line, "Speed:"))
				} else if strings.HasPrefix(line, "Duplex:") {
					item["duplex"] = strings.TrimSpace(strings.TrimPrefix(line, "Duplex:"))
				} else if strings.HasPrefix(line, "Link detected:") {
					item["link_detected"] = strings.TrimSpace(strings.TrimPrefix(line, "Link detected:")) == "yes"
				}
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"interfaces": ifaces})
}

func (s *Server) handleRoutes(w http.ResponseWriter, r *http.Request) {
	v4, err := sys.Run(5*time.Second, "ip", "-j", "route", "show")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	v6, _ := sys.Run(5*time.Second, "ip", "-6", "-j", "route", "show")
	r4 := []any{}
	r6 := []any{}
	_ = json.Unmarshal([]byte(v4.Stdout), &r4)
	_ = json.Unmarshal([]byte(v6.Stdout), &r6)
	writeJSON(w, http.StatusOK, map[string]any{"ipv4": r4, "ipv6": r6})
}

func (s *Server) handleAddRoute(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Destination string `json:"destination"` // e.g. "10.20.0.0/24" or "2001:db8:2::/64"
		Gateway     string `json:"gateway"`     // optional if device specified
		Device      string `json:"device"`      // optional if gateway specified
		Metric      int    `json:"metric"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json body")
		return
	}
	if !sys.ValidIPOrCIDR(req.Destination) {
		writeErr(w, http.StatusBadRequest, "invalid destination CIDR")
		return
	}
	if req.Gateway == "" && req.Device == "" {
		writeErr(w, http.StatusBadRequest, "specify at least gateway or device")
		return
	}
	dstV6 := isIPv6Addr(req.Destination)

	var args []string
	if dstV6 {
		args = append(args, "-6")
	}
	args = append(args, "route", "replace", req.Destination)

	if req.Gateway != "" {
		gwIP := net.ParseIP(req.Gateway)
		if gwIP == nil || (gwIP.To4() == nil) != dstV6 {
			writeErr(w, http.StatusBadRequest, "invalid gateway IP (must match destination IP family)")
			return
		}
		args = append(args, "via", req.Gateway)
	}
	if req.Device != "" {
		if !sys.ValidIface(req.Device) {
			writeErr(w, http.StatusBadRequest, "invalid device name")
			return
		}
		args = append(args, "dev", req.Device)
	}
	if req.Metric > 0 {
		args = append(args, "metric", fmt.Sprintf("%d", req.Metric))
	}
	if _, err := sys.Run(5*time.Second, "ip", args...); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleDelRoute(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Destination string `json:"destination"`
	}
	if err := decodeJSON(r, &req); err != nil || !sys.ValidIPOrCIDR(req.Destination) {
		writeErr(w, http.StatusBadRequest, "invalid destination CIDR")
		return
	}
	var args []string
	if isIPv6Addr(req.Destination) {
		args = append(args, "-6")
	}
	args = append(args, "route", "del", req.Destination)
	if _, err := sys.Run(5*time.Second, "ip", args...); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleNeighbors(w http.ResponseWriter, r *http.Request) {
	res, err := sys.Run(5*time.Second, "ip", "-j", "neigh", "show")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeValidatedRawJSON(w, http.StatusOK, []byte(res.Stdout), "[]")
}

func (s *Server) handleGetWAN(w http.ResponseWriter, r *http.Request) {
	st := s.Store.Get().WAN
	st.PPPoEPassword = "" // never return stored password in GET
	pppRunning := false
	if _, err := sys.Run(2*time.Second, "pidof", "pppd"); err == nil {
		pppRunning = true
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"config":       st,
		"pppd_running": pppRunning,
	})
}

func RenderInterfacesFile(lan config.LANState, wan config.WANState) string {
	var b strings.Builder
	b.WriteString("# Managed by NetBee OS (netbeed)\n\nauto lo\niface lo inet loopback\n\n")
	fmt.Fprintf(&b, "auto %s\niface %s inet static\n    address %s\n    netmask %s\n\n",
		lan.Interface, lan.Interface, lan.IP, lan.Netmask)

	iface := wan.Interface
	if iface == "" {
		iface = "eth1"
	}
	fmt.Fprintf(&b, "allow-hotplug %s\nauto %s\niface %s inet manual\n", iface, iface, iface)
	if wan.MACClone != "" {
		fmt.Fprintf(&b, "    pre-up ip link set dev %s address %s\n", iface, wan.MACClone)
	}
	switch wan.Mode {
	case "pppoe":
		fmt.Fprintf(&b, "    up ip link set %s up\n", iface)
		b.WriteString("    up pppd call wan-pppoe\n")
		b.WriteString("    down killall pppd || true\n")
		fmt.Fprintf(&b, "    down ip link set %s down\n", iface)
	case "ont_vlan":
		vlanIf := fmt.Sprintf("%s.%d", iface, wan.VLANID)
		fmt.Fprintf(&b, "    up ip link set %s up\n", iface)
		fmt.Fprintf(&b, "    up ip link add link %s name %s type vlan id %d || true\n", iface, vlanIf, wan.VLANID)
		fmt.Fprintf(&b, "    up ip link set %s up\n", vlanIf)
		b.WriteString("    up pppd call wan-pppoe\n")
		b.WriteString("    down killall pppd || true\n")
		fmt.Fprintf(&b, "    down ip link del %s || true\n", vlanIf)
		fmt.Fprintf(&b, "    down ip link set %s down\n", iface)
	default: // dhcp (managed by dhcpcd)
		if wan.MTU > 0 && wan.MTU != 1500 {
			fmt.Fprintf(&b, "    up ip link set dev %s mtu %d\n", iface, wan.MTU)
		}
		fmt.Fprintf(&b, "    up ip link set %s up\n", iface)
		fmt.Fprintf(&b, "    down ip link set %s down\n", iface)
	}
	return b.String()
}

func RenderDHCPCDConf(lan config.LANState, wan config.WANState) string {
	var b strings.Builder
	b.WriteString("# Managed by NetBee OS (netbeed)\n")
	deny := []string{lan.Interface}
	if wan.Mode == "pppoe" || wan.Mode == "ont_vlan" {
		deny = append(deny, wan.Interface)
	}
	fmt.Fprintf(&b, "denyinterfaces %s\n\n", strings.Join(deny, " "))
	b.WriteString("duid\npersistent\nvendorclassid\n")
	b.WriteString("option domain_name_servers, domain_name, domain_search\n")
	b.WriteString("option classless_static_routes\noption interface_mtu\noption host_name\n")
	b.WriteString("require dhcp_server_identifier\nslaac private\n")
	if wan.IPv6PD {
		pdIface := wan.Interface
		if wan.Mode == "pppoe" || wan.Mode == "ont_vlan" {
			pdIface = "ppp0"
		}
		fmt.Fprintf(&b, "\ninterface %s\n    ipv6rs\n    ia_na 1\n    ia_pd 2 %s/0\n", pdIface, lan.Interface)
	}
	return b.String()
}

func RenderPPPoEPeer(wan config.WANState) string {
	phys := wan.Interface
	if wan.Mode == "ont_vlan" {
		phys = fmt.Sprintf("%s.%d", wan.Interface, wan.VLANID)
	}
	mtu := wan.MTU
	if mtu < 576 || mtu > 1500 {
		mtu = 1492
	}
	return fmt.Sprintf(
		"# Managed by NetBee OS (netbeed)\n"+
			"plugin rp-pppoe.so %s\n"+
			"user %q\n"+
			"noauth\ndefaultroute\nreplacedefaultroute\nusepeerdns\npersist\n"+
			"maxfail 0\nholdoff 5\nlcp-echo-interval 20\nlcp-echo-failure 3\n"+
			"mtu %d\nmru %d\nnoipdefault\nhide-password\n",
		phys, wan.PPPoEUser, mtu, mtu,
	)
}

func (s *Server) handleSetWAN(w http.ResponseWriter, r *http.Request) {
	var req config.WANState
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json body")
		return
	}
	if req.Interface == "" {
		req.Interface = "eth1"
	}
	if !sys.ValidIface(req.Interface) {
		writeErr(w, http.StatusBadRequest, "invalid WAN interface name")
		return
	}
	cur := s.Store.Get()
	if req.Interface == cur.LAN.Interface {
		writeErr(w, http.StatusBadRequest, "WAN interface cannot be identical to LAN interface")
		return
	}
	if req.Mode != "dhcp" && req.Mode != "pppoe" && req.Mode != "ont_vlan" {
		writeErr(w, http.StatusBadRequest, "mode must be dhcp, pppoe, or ont_vlan")
		return
	}
	if req.Mode == "ont_vlan" {
		if err := sys.ValidateVLAN(req.VLANID); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if req.PPPoEPassword == "" {
		req.PPPoEPassword = cur.WAN.PPPoEPassword
	}
	if req.Mode == "pppoe" || req.Mode == "ont_vlan" {
		if req.PPPoEUser == "" || req.PPPoEPassword == "" || !sys.ValidSafeString(req.PPPoEUser) || !sys.ValidSafeString(req.PPPoEPassword) {
			writeErr(w, http.StatusBadRequest, "PPPoE username and password are required and must be valid")
			return
		}
	}
	if req.MACClone != "" && !sys.ValidMAC(req.MACClone) {
		writeErr(w, http.StatusBadRequest, "invalid MAC clone address (expected AA:BB:CC:DD:EE:FF)")
		return
	}
	if req.MTU == 0 {
		if req.Mode == "dhcp" {
			req.MTU = 1500
		} else {
			req.MTU = 1492
		}
	}
	if req.MTU < 576 || req.MTU > 1500 {
		writeErr(w, http.StatusBadRequest, "mtu must be between 576 and 1500")
		return
	}

	oldWAN := cur.WAN
	files := []string{
		"/etc/network/interfaces",
		"/etc/dhcpcd.conf",
		"/etc/ppp/peers/wan-pppoe",
		"/etc/ppp/pap-secrets",
		"/etc/ppp/chap-secrets",
		s.Cfg.StatePath,
	}
	s.Rollback.Begin("WAN configuration update", time.Duration(s.Cfg.RollbackSeconds)*time.Second, files, func() {
		_ = s.Store.Reload()
		_, _ = sys.Run(5*time.Second, "killall", "pppd")
		_, _ = sys.Run(10*time.Second, "/etc/init.d/S40network", "restart")
		_, _ = sys.Run(10*time.Second, "/etc/init.d/S41dhcpcd", "restart")
	})

	// Clean up previous WAN VLAN / PPPoE state BEFORE writing new interfaces file
	_, _ = sys.Run(5*time.Second, "killall", "pppd")
	if oldWAN.Mode == "ont_vlan" && oldWAN.VLANID > 0 {
		oldIf := oldWAN.Interface
		if oldIf == "" {
			oldIf = "eth1"
		}
		_, _ = sys.Run(3*time.Second, "ip", "link", "del", fmt.Sprintf("%s.%d", oldIf, oldWAN.VLANID))
	}

	if err := s.Store.Update(func(st *config.State) error {
		st.WAN = req
		return nil
	}); err != nil {
		s.Rollback.RevertNow()
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	lan := s.Store.Get().LAN
	if err := config.AtomicWriteFile("/etc/network/interfaces", []byte(RenderInterfacesFile(lan, req)), 0644); err != nil {
		s.Rollback.RevertNow()
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := config.AtomicWriteFile("/etc/dhcpcd.conf", []byte(RenderDHCPCDConf(lan, req)), 0644); err != nil {
		s.Rollback.RevertNow()
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if req.Mode == "pppoe" || req.Mode == "ont_vlan" {
		if err := config.AtomicWriteFile("/etc/ppp/peers/wan-pppoe", []byte(RenderPPPoEPeer(req)), 0644); err != nil {
			s.Rollback.RevertNow()
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		// Write both PAP and CHAP secret tables so ISPs using CHAP/MS-CHAPv2 or PAP both authenticate
		secret := fmt.Sprintf("%q * %q *\n", req.PPPoEUser, req.PPPoEPassword)
		if err := config.AtomicWriteFile("/etc/ppp/pap-secrets", []byte(secret), 0600); err != nil {
			s.Rollback.RevertNow()
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if err := config.AtomicWriteFile("/etc/ppp/chap-secrets", []byte(secret), 0600); err != nil {
			s.Rollback.RevertNow()
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
	}

	_, _ = sys.Run(10*time.Second, "/etc/init.d/S40network", "restart")
	_, _ = sys.Run(10*time.Second, "/etc/init.d/S41dhcpcd", "restart")

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":             true,
		"pending_commit": s.Rollback.Status(),
	})
}

func (s *Server) handleWANReconnect(w http.ResponseWriter, r *http.Request) {
	wan := s.Store.Get().WAN
	if wan.Mode == "pppoe" || wan.Mode == "ont_vlan" {
		_, _ = sys.Run(5*time.Second, "killall", "pppd")
		_, err := sys.Run(10*time.Second, "pppd", "call", "wan-pppoe")
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
	} else {
		_, err := sys.Run(10*time.Second, "/etc/init.d/S41dhcpcd", "restart")
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "mode": wan.Mode})
}

func (s *Server) handleGetLAN(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.Store.Get().LAN)
}

func deriveDHCPRange(ipStr, maskStr string) (string, string) {
	ip := net.ParseIP(ipStr).To4()
	maskIP := net.ParseIP(maskStr).To4()
	if ip == nil || maskIP == nil {
		return "192.168.10.100", "192.168.10.200"
	}
	mask := net.IPv4Mask(maskIP[0], maskIP[1], maskIP[2], maskIP[3])
	netIP := ip.Mask(mask)
	ones, _ := mask.Size()
	if ones <= 24 {
		start := net.IPv4(netIP[0], netIP[1], netIP[2], 100)
		end := net.IPv4(netIP[0], netIP[1], netIP[2], 200)
		if ip.Equal(start) {
			start = net.IPv4(netIP[0], netIP[1], netIP[2], 101)
		}
		return start.String(), end.String()
	}
	// Smaller subnets (/25../30): allocate safe host range inside subnet
	bcast := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		bcast[i] = netIP[i] | ^mask[i]
	}
	first := net.IPv4(netIP[0], netIP[1], netIP[2], netIP[3]+2)
	last := net.IPv4(bcast[0], bcast[1], bcast[2], bcast[3]-1)
	if ip.Equal(first) && first[3]+1 < last[3] {
		first[3]++
	}
	return first.String(), last.String()
}

// UpdateAdGuardLANConfig updates AdGuardHome.yaml DNS bind_hosts and DHCPv4 subnet/gateway/pool when LAN IP changes.
func UpdateAdGuardLANConfig(raw string, oldLAN, newLAN config.LANState) string {
	startIP, endIP := deriveDHCPRange(newLAN.IP, newLAN.Netmask)
	lines := strings.Split(raw, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
		switch {
		case oldLAN.IP != "" && trimmed == "- "+oldLAN.IP:
			lines[i] = indent + "- " + newLAN.IP
		case strings.HasPrefix(trimmed, "interface_name:"):
			lines[i] = indent + "interface_name: " + newLAN.Interface
		case strings.HasPrefix(trimmed, "gateway_ip:"):
			lines[i] = indent + "gateway_ip: " + newLAN.IP
		case strings.HasPrefix(trimmed, "subnet_mask:"):
			lines[i] = indent + "subnet_mask: " + newLAN.Netmask
		case strings.HasPrefix(trimmed, "range_start:"):
			lines[i] = indent + "range_start: " + startIP
		case strings.HasPrefix(trimmed, "range_end:"):
			lines[i] = indent + "range_end: " + endIP
		}
	}
	return strings.Join(lines, "\n")
}

func (s *Server) handleSetLAN(w http.ResponseWriter, r *http.Request) {
	var req config.LANState
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json body")
		return
	}
	if req.Interface == "" {
		req.Interface = "eth0"
	}
	if !sys.ValidIface(req.Interface) {
		writeErr(w, http.StatusBadRequest, "invalid LAN interface name")
		return
	}
	cur := s.Store.Get()
	if req.Interface == cur.WAN.Interface {
		writeErr(w, http.StatusBadRequest, "LAN interface cannot be identical to WAN interface")
		return
	}
	if !sys.ValidIPv4Netmask(req.Netmask) {
		writeErr(w, http.StatusBadRequest, "invalid LAN IPv4 subnet mask (expected e.g. 255.255.255.0)")
		return
	}
	if !sys.ValidUnicastIPv4Host(req.IP, req.Netmask) {
		writeErr(w, http.StatusBadRequest, "invalid LAN host IPv4 address for the given subnet mask")
		return
	}

	oldLAN := cur.LAN
	files := []string{
		"/etc/network/interfaces",
		"/etc/dhcpcd.conf",
		"/etc/default/dropbear",
		"/etc/hosts",
		adguardYAMLPath,
		uiNftDropInPath,
		s.Cfg.StatePath,
	}
	s.Rollback.Begin("LAN IP change", time.Duration(s.Cfg.RollbackSeconds)*time.Second, files, func() {
		_ = s.Store.Reload()
		_, _ = sys.Run(5*time.Second, "/etc/init.d/S85adguardhome", "stop")
		_, _ = sys.Run(10*time.Second, "/etc/init.d/S40network", "restart")
		_, _ = sys.Run(10*time.Second, "/etc/init.d/S41dhcpcd", "restart")
		_, _ = sys.Run(5*time.Second, "/etc/init.d/S50dropbear", "restart")
		_, _ = sys.Run(10*time.Second, "/etc/init.d/S35nftables", "reload")
		_, _ = sys.Run(5*time.Second, "/etc/init.d/S85adguardhome", "start")
	})

	if err := s.Store.Update(func(st *config.State) error {
		st.LAN = req
		if st.WireGuard.DNS == "" || st.WireGuard.DNS == oldLAN.IP {
			st.WireGuard.DNS = req.IP
		}
		return nil
	}); err != nil {
		s.Rollback.RevertNow()
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	st := s.Store.Get()
	if err := config.AtomicWriteFile("/etc/network/interfaces", []byte(RenderInterfacesFile(req, st.WAN)), 0644); err != nil {
		s.Rollback.RevertNow()
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := config.AtomicWriteFile("/etc/dhcpcd.conf", []byte(RenderDHCPCDConf(req, st.WAN)), 0644); err != nil {
		s.Rollback.RevertNow()
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Preserve existing SSH password_auth (-s) and idle_timeout (-I) flags while updating LAN IP bind
	rawDropbear, _ := os.ReadFile("/etc/default/dropbear")
	pwAuth, idleSec := ParseDropbearConf(string(rawDropbear))
	_ = config.AtomicWriteFile("/etc/default/dropbear", []byte(RenderDropbearConf(req.IP, pwAuth, idleSec)), 0644)

	host, _ := os.Hostname()
	_ = config.AtomicWriteFile("/etc/hosts", []byte(renderHostsFile(req.IP, host)), 0644)
	_ = config.AtomicWriteFile(uiNftDropInPath, []byte(RenderCustomNFT(st.Firewall, req.IP)), 0644)

	var updatedAGH []byte
	if aghRaw, err := os.ReadFile(adguardYAMLPath); err == nil {
		updatedAGH = []byte(UpdateAdGuardLANConfig(string(aghRaw), oldLAN, req))
		_ = config.AtomicWriteFile(adguardYAMLPath, updatedAGH, 0600)
	}

	// Apply live after flushing HTTP 200 response so the 60s rollback timer genuinely guards reachability
	if _, err := os.Stat("/etc/init.d/S40network"); err == nil {
		go func(aghData []byte) {
			time.Sleep(400 * time.Millisecond)
			if len(aghData) > 0 {
				_, _ = sys.Run(5*time.Second, "/etc/init.d/S85adguardhome", "stop")
				_ = config.AtomicWriteFile(adguardYAMLPath, aghData, 0600)
			}
			_, _ = sys.Run(10*time.Second, "/etc/init.d/S40network", "restart")
			_, _ = sys.Run(10*time.Second, "/etc/init.d/S41dhcpcd", "restart")
			_, _ = sys.Run(5*time.Second, "/etc/init.d/S50dropbear", "restart")
			_, _ = sys.Run(10*time.Second, "/etc/init.d/S35nftables", "reload")
			if len(aghData) > 0 {
				_, _ = sys.Run(5*time.Second, "/etc/init.d/S85adguardhome", "start")
			}
		}(updatedAGH)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":             true,
		"new_url":        "https://" + req.IP,
		"pending_commit": s.Rollback.Status(),
		"message":        "LAN IP, DHCP/DNS, SSH bind, and firewall updated; confirm at new_url within rollback window.",
	})
}
