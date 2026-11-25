package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/yalcer/netbee/netbeed/internal/config"
	"github.com/yalcer/netbee/netbeed/internal/sys"
)

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
		writeRawJSON(w, http.StatusOK, []byte(res.Stdout))
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
	var r4, r6 any
	_ = json.Unmarshal([]byte(v4.Stdout), &r4)
	_ = json.Unmarshal([]byte(v6.Stdout), &r6)
	writeJSON(w, http.StatusOK, map[string]any{"ipv4": r4, "ipv6": r6})
}

func (s *Server) handleAddRoute(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Destination string `json:"destination"` // e.g. "10.20.0.0/24"
		Gateway     string `json:"gateway"`     // optional if device specified
		Device      string `json:"device"`      // optional
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
	args := []string{"route", "replace", req.Destination}
	if req.Gateway != "" {
		if !sys.ValidIPOrCIDR(req.Gateway) {
			writeErr(w, http.StatusBadRequest, "invalid gateway IP")
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
	if _, err := sys.Run(5*time.Second, "ip", "route", "del", req.Destination); err != nil {
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
	writeRawJSON(w, http.StatusOK, []byte(res.Stdout))
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
	if req.Mode == "pppoe" || req.Mode == "ont_vlan" {
		if req.PPPoEUser == "" || !sys.ValidSafeString(req.PPPoEUser) || !sys.ValidSafeString(req.PPPoEPassword) {
			writeErr(w, http.StatusBadRequest, "invalid PPPoE username or password")
			return
		}
	}
	if req.MACClone != "" && !sys.ValidMAC(req.MACClone) {
		writeErr(w, http.StatusBadRequest, "invalid MAC clone address (expected AA:BB:CC:DD:EE:FF)")
		return
	}
	if req.MTU == 0 {
		req.MTU = 1492
	}

	cur := s.Store.Get()
	if req.PPPoEPassword == "" {
		req.PPPoEPassword = cur.WAN.PPPoEPassword
	}

	files := []string{"/etc/network/interfaces", "/etc/dhcpcd.conf", "/etc/ppp/peers/wan-pppoe", "/etc/ppp/pap-secrets", s.Cfg.StatePath}
	s.Rollback.Begin("WAN configuration update", time.Duration(s.Cfg.RollbackSeconds)*time.Second, files, func() {
		_, _ = sys.Run(10*time.Second, "/etc/init.d/S40network", "restart")
		_, _ = sys.Run(10*time.Second, "/etc/init.d/S41dhcpcd", "restart")
	})

	if err := s.Store.Update(func(st *config.State) error {
		st.WAN = req
		return nil
	}); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	lan := s.Store.Get().LAN
	if err := config.AtomicWriteFile("/etc/network/interfaces", []byte(RenderInterfacesFile(lan, req)), 0644); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := config.AtomicWriteFile("/etc/dhcpcd.conf", []byte(RenderDHCPCDConf(lan, req)), 0644); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if req.Mode == "pppoe" || req.Mode == "ont_vlan" {
		_ = config.AtomicWriteFile("/etc/ppp/peers/wan-pppoe", []byte(RenderPPPoEPeer(req)), 0644)
		secret := fmt.Sprintf("%q * %q *\n", req.PPPoEUser, req.PPPoEPassword)
		_ = config.AtomicWriteFile("/etc/ppp/pap-secrets", []byte(secret), 0600)
	}

	// Re-apply WAN networking cleanly
	_, _ = sys.Run(5*time.Second, "killall", "pppd")
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

func (s *Server) handleSetLAN(w http.ResponseWriter, r *http.Request) {
	var req config.LANState
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json body")
		return
	}
	if req.Interface == "" {
		req.Interface = "eth0"
	}
	if !sys.ValidIface(req.Interface) || !sys.ValidIPv4(req.IP) || !sys.ValidIPv4(req.Netmask) {
		writeErr(w, http.StatusBadRequest, "invalid LAN interface, IPv4, or netmask")
		return
	}

	files := []string{"/etc/network/interfaces", s.Cfg.StatePath}
	s.Rollback.Begin("LAN IP change", time.Duration(s.Cfg.RollbackSeconds)*time.Second, files, func() {
		_, _ = sys.Run(10*time.Second, "/etc/init.d/S40network", "restart")
	})

	if err := s.Store.Update(func(st *config.State) error {
		st.LAN = req
		return nil
	}); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	wan := s.Store.Get().WAN
	if err := config.AtomicWriteFile("/etc/network/interfaces", []byte(RenderInterfacesFile(req, wan)), 0644); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":             true,
		"pending_commit": s.Rollback.Status(),
		"message":        "LAN config updated; restart network or reboot to apply IP change.",
	})
}
