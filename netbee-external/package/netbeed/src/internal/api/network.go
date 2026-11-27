package api

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/yalcer/netbee/netbeed/internal/config"
	"github.com/yalcer/netbee/netbeed/internal/sys"
)

var (
	adguardYAMLPath     = "/etc/adguardhome/AdGuardHome.yaml"
	nftVarsPath         = "/etc/nftables.vars"
	netifEnvPath        = "/etc/netbee/netif.env"
	customUdevNetRules  = "/etc/udev/rules.d/11-netbee-custom-net.rules"
	interfacesConfPath  = "/etc/network/interfaces"
	dhcpcdConfPath      = "/etc/dhcpcd.conf"
	pppPeerPath         = "/etc/ppp/peers/wan-pppoe"
	papSecretsPath      = "/etc/ppp/pap-secrets"
	chapSecretsPath     = "/etc/ppp/chap-secrets"
	dropbearDefaultPath = "/etc/default/dropbear"
	hostsConfPath       = "/etc/hosts"
)

func sysMarshal(v any) ([]byte, error) {
	return json.Marshal(v)
}

func wanUsesVLAN(wan config.WANState) bool {
	return (wan.VLANEnabled || wan.Mode == "ont_vlan") && wan.VLANID > 0
}

func wanUsesPPPoE(wan config.WANState) bool {
	return wan.Mode == "pppoe" || wan.Mode == "ont_vlan"
}

func wanPeerDNS(wan config.WANState) bool {
	return wan.PeerDNS == nil || *wan.PeerDNS
}

func wanLogicalDev(wan config.WANState) string {
	phys := wan.Interface
	if phys == "" || !sys.ValidIface(phys) {
		phys = "eth1"
	}
	if wanUsesVLAN(wan) {
		return fmt.Sprintf("%s.%d", phys, wan.VLANID)
	}
	return phys
}

func ipv4MaskPrefixLen(maskStr string) int {
	ip := net.ParseIP(maskStr).To4()
	if ip == nil {
		return 24
	}
	ones, _ := net.IPv4Mask(ip[0], ip[1], ip[2], ip[3]).Size()
	return ones
}

// RenderNftablesVars generates /etc/nftables.vars so nftables.conf always tracks configured LAN/WAN/WG interfaces.
func RenderNftablesVars(st config.State) string {
	lanIf := st.LAN.Interface
	if lanIf == "" || !sys.ValidIface(lanIf) {
		lanIf = "eth0"
	}
	wanIf := st.WAN.Interface
	if wanIf == "" || !sys.ValidIface(wanIf) {
		wanIf = "eth1"
	}
	wgIf := st.WireGuard.Interface
	if wgIf == "" || !sys.ValidIface(wgIf) {
		wgIf = "wg0"
	}
	wanList := []string{fmt.Sprintf("%q", wanIf)}
	if wanUsesVLAN(st.WAN) {
		wanList = append(wanList, fmt.Sprintf("%q", wanLogicalDev(st.WAN)))
	}
	wanList = append(wanList, `"ppp0"`)
	return fmt.Sprintf(
		"# Managed by NetBee OS (netbeed) - Dynamic interface definitions\n"+
			"define LAN_IF = %q\n"+
			"define WAN_IFS = { %s }\n"+
			"define WG_IF = %q\n",
		lanIf, strings.Join(wanList, ", "), wgIf,
	)
}

// RenderNetifEnv generates /etc/netbee/netif.env consumed by S42nft-offload, S86vnstatd, netbee-sqm, and netbee-hotplug-wan.
func RenderNetifEnv(st config.State) string {
	lanIf := st.LAN.Interface
	if lanIf == "" || !sys.ValidIface(lanIf) {
		lanIf = "eth0"
	}
	wanIf := st.WAN.Interface
	if wanIf == "" || !sys.ValidIface(wanIf) {
		wanIf = "eth1"
	}
	wgIf := st.WireGuard.Interface
	if wgIf == "" || !sys.ValidIface(wgIf) {
		wgIf = "wg0"
	}
	mode := st.WAN.Mode
	if mode == "" {
		mode = "dhcp"
	}
	return fmt.Sprintf(
		"# Managed by NetBee OS (netbeed)\n"+
			"LAN_IF=%q\n"+
			"WAN_IF=%q\n"+
			"WAN_LOGICAL_IF=%q\n"+
			"WAN_MODE=%q\n"+
			"WG_IF=%q\n",
		lanIf, wanIf, wanLogicalDev(st.WAN), mode, wgIf,
	)
}

// RenderNetUdevRules generates persistent MAC->interface pinning rules when PinMAC is configured.
func RenderNetUdevRules(lan config.LANState, wan config.WANState) string {
	var b strings.Builder
	if lan.PinMAC != "" && sys.ValidMAC(lan.PinMAC) && sys.ValidIface(lan.Interface) {
		fmt.Fprintf(&b, "SUBSYSTEM==\"net\", ACTION==\"add\", ATTR{address}==%q, NAME=%q\n",
			strings.ToLower(lan.PinMAC), lan.Interface)
	}
	if wan.PinMAC != "" && sys.ValidMAC(wan.PinMAC) && sys.ValidIface(wan.Interface) && !strings.EqualFold(wan.PinMAC, lan.PinMAC) {
		fmt.Fprintf(&b, "SUBSYSTEM==\"net\", ACTION==\"add\", ATTR{address}==%q, NAME=%q\n",
			strings.ToLower(wan.PinMAC), wan.Interface)
	}
	if b.Len() == 0 {
		return ""
	}
	return "# Managed by NetBee OS (netbeed) - Persistent MAC Interface Pinning\n" + b.String()
}

func syncNetIfConfigs(st config.State) error {
	if err := config.AtomicWriteFile(nftVarsPath, []byte(RenderNftablesVars(st)), 0644); err != nil {
		return err
	}
	if err := config.AtomicWriteFile(netifEnvPath, []byte(RenderNetifEnv(st)), 0644); err != nil {
		return err
	}
	udevRules := RenderNetUdevRules(st.LAN, st.WAN)
	if udevRules == "" {
		_ = os.Remove(customUdevNetRules)
	} else if _, err := os.Stat("/etc/udev/rules.d"); err == nil {
		_ = config.AtomicWriteFile(customUdevNetRules, []byte(udevRules), 0644)
	}
	return nil
}

func syncCustomWANDNS(wan config.WANState) {
	if !wanPeerDNS(wan) && len(wan.DNSServers) > 0 {
		var b strings.Builder
		b.WriteString("# Managed by NetBee OS (netbeed) - Custom WAN DNS\n")
		for _, srv := range wan.DNSServers {
			srv = strings.TrimSpace(srv)
			if net.ParseIP(srv) != nil {
				fmt.Fprintf(&b, "nameserver %s\n", srv)
			}
		}
		if b.Len() > 0 {
			_ = config.AtomicWriteFile("/etc/resolv.conf", []byte(b.String()), 0644)
		}
	}
}

func readSysfsDriver(iface string) string {
	target, err := os.Readlink(filepath.Join("/sys/class/net", iface, "device", "driver"))
	if err != nil || target == "" {
		return ""
	}
	return filepath.Base(target)
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
	st := s.Store.Get()
	lanIf := st.LAN.Interface
	wanIf := st.WAN.Interface
	wanLogIf := wanLogicalDev(st.WAN)
	wgIf := st.WireGuard.Interface

	for _, item := range ifaces {
		name, _ := item["ifname"].(string)
		if name == "" || name == "lo" || !sys.ValidIface(name) {
			continue
		}
		if drv := readSysfsDriver(name); drv != "" {
			item["driver"] = drv
		}
		if lbl := st.InterfaceLabels[name]; lbl != "" {
			item["custom_label"] = lbl
		}
		switch {
		case name == lanIf:
			item["role"] = "lan"
		case name == wanIf:
			item["role"] = "wan"
		case wanUsesVLAN(st.WAN) && name == wanLogIf:
			item["role"] = "wan_vlan"
		case name == "ppp0":
			item["role"] = "wan_pppoe"
		case name == wgIf || strings.HasPrefix(name, "wg"):
			item["role"] = "vpn"
		default:
			item["role"] = "unassigned"
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

func (s *Server) handleSetInterfaceState(w http.ResponseWriter, r *http.Request) {
	iface := r.PathValue("iface")
	if !sys.ValidIface(iface) || iface == "lo" {
		writeErr(w, http.StatusBadRequest, "invalid interface name")
		return
	}
	var req struct {
		Up bool `json:"up"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json body")
		return
	}
	st := s.Store.Get()
	if !req.Up && iface == st.LAN.Interface {
		writeErr(w, http.StatusBadRequest, "bringing down the active LAN interface over the API is blocked to prevent management lockout")
		return
	}
	stateArg := "down"
	if req.Up {
		stateArg = "up"
	}
	if _, err := sys.Run(5*time.Second, "ip", "link", "set", "dev", iface, stateArg); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "interface": iface, "up": req.Up})
}

func (s *Server) handleSetInterfaceLabel(w http.ResponseWriter, r *http.Request) {
	iface := r.PathValue("iface")
	if !sys.ValidIface(iface) || iface == "lo" {
		writeErr(w, http.StatusBadRequest, "invalid interface name")
		return
	}
	var req struct {
		Label string `json:"label"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json body")
		return
	}
	lbl := strings.TrimSpace(req.Label)
	if len(lbl) > 48 || !sys.ValidSafeString(lbl) {
		writeErr(w, http.StatusBadRequest, "label must be at most 48 safe characters")
		return
	}
	if err := s.Store.Update(func(st *config.State) error {
		if lbl == "" {
			delete(st.InterfaceLabels, iface)
		} else {
			st.InterfaceLabels[iface] = lbl
		}
		return nil
	}); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "interface": iface, "label": lbl})
}

func validateStaticRoute(rt config.StaticRoute) error {
	if rt.ID != "" && !sys.ValidID(rt.ID) {
		return fmt.Errorf("invalid route id")
	}
	if !sys.ValidIPOrCIDR(rt.Destination) {
		return fmt.Errorf("invalid destination CIDR")
	}
	if rt.Gateway == "" && rt.Device == "" {
		return fmt.Errorf("specify at least gateway or device")
	}
	dstV6 := isIPv6Addr(rt.Destination)
	if rt.Gateway != "" {
		gwIP := net.ParseIP(rt.Gateway)
		if gwIP == nil || (gwIP.To4() == nil) != dstV6 {
			return fmt.Errorf("invalid gateway IP (must match destination IP family)")
		}
	}
	if rt.Device != "" && !sys.ValidIface(rt.Device) {
		return fmt.Errorf("invalid device name")
	}
	if rt.Metric < 0 || rt.Metric > 65535 {
		return fmt.Errorf("metric must be between 0 and 65535")
	}
	return nil
}

func applyStaticRoute(rt config.StaticRoute) error {
	var args []string
	if isIPv6Addr(rt.Destination) {
		args = append(args, "-6")
	}
	args = append(args, "route", "replace", rt.Destination)
	if rt.Gateway != "" {
		args = append(args, "via", rt.Gateway)
	}
	if rt.Device != "" {
		args = append(args, "dev", rt.Device)
	}
	if rt.Metric > 0 {
		args = append(args, "metric", fmt.Sprintf("%d", rt.Metric))
	}
	_, err := sys.Run(5*time.Second, "ip", args...)
	return err
}

func deleteStaticRoute(rt config.StaticRoute) error {
	var args []string
	if isIPv6Addr(rt.Destination) {
		args = append(args, "-6")
	}
	args = append(args, "route", "del", rt.Destination)
	if rt.Gateway != "" {
		args = append(args, "via", rt.Gateway)
	}
	if rt.Device != "" {
		args = append(args, "dev", rt.Device)
	}
	_, err := sys.Run(5*time.Second, "ip", args...)
	return err
}

func restorePersistedRoutes(routes []config.StaticRoute) {
	for _, rt := range routes {
		if rt.Enabled {
			_ = applyStaticRoute(rt)
		}
	}
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
	writeJSON(w, http.StatusOK, map[string]any{
		"ipv4":          r4,
		"ipv6":          r6,
		"static_routes": s.Store.Get().StaticRoutes,
	})
}

func (s *Server) handleAddRoute(w http.ResponseWriter, r *http.Request) {
	var req config.StaticRoute
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json body")
		return
	}
	if req.ID == "" {
		req.ID = fmt.Sprintf("rt%d", time.Now().UnixMilli())
	}
	req.Enabled = true
	if err := validateStaticRoute(req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := applyStaticRoute(req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.Store.Update(func(st *config.State) error {
		updated := false
		for i, existing := range st.StaticRoutes {
			if existing.ID == req.ID || existing.Destination == req.Destination {
				req.ID = existing.ID
				st.StaticRoutes[i] = req
				updated = true
				break
			}
		}
		if !updated {
			st.StaticRoutes = append(st.StaticRoutes, req)
		}
		return nil
	}); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"ok": true, "route": req})
}

func (s *Server) handleDelRoute(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID          string `json:"id"`
		Destination string `json:"destination"`
	}
	if err := decodeJSON(r, &req); err != nil || (req.ID == "" && !sys.ValidIPOrCIDR(req.Destination)) {
		writeErr(w, http.StatusBadRequest, "provide valid route id or destination CIDR")
		return
	}
	var removed *config.StaticRoute
	_ = s.Store.Update(func(st *config.State) error {
		next := make([]config.StaticRoute, 0, len(st.StaticRoutes))
		for _, rt := range st.StaticRoutes {
			if (req.ID != "" && rt.ID == req.ID) || (req.Destination != "" && rt.Destination == req.Destination) {
				cp := rt
				removed = &cp
				continue
			}
			next = append(next, rt)
		}
		st.StaticRoutes = next
		return nil
	})
	if removed != nil {
		_ = deleteStaticRoute(*removed)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}
	if req.Destination != "" {
		if err := deleteStaticRoute(config.StaticRoute{Destination: req.Destination}); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}
	writeErr(w, http.StatusNotFound, "static route not found")
}

func (s *Server) handleDelRouteByID(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var removed *config.StaticRoute
	_ = s.Store.Update(func(st *config.State) error {
		next := make([]config.StaticRoute, 0, len(st.StaticRoutes))
		for _, rt := range st.StaticRoutes {
			if rt.ID == id {
				cp := rt
				removed = &cp
				continue
			}
			next = append(next, rt)
		}
		st.StaticRoutes = next
		return nil
	})
	if removed == nil {
		writeErr(w, http.StatusNotFound, "static route not found")
		return
	}
	_ = deleteStaticRoute(*removed)
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
	fmt.Fprintf(&b, "auto %s\niface %s inet static\n    address %s\n    netmask %s\n",
		lan.Interface, lan.Interface, lan.IP, lan.Netmask)
	if lan.MTU > 0 && lan.MTU != 1500 {
		fmt.Fprintf(&b, "    up ip link set dev %s mtu %d\n", lan.Interface, lan.MTU)
	}
	b.WriteString("\n")

	iface := wan.Interface
	if iface == "" {
		iface = "eth1"
	}
	useVLAN := wanUsesVLAN(wan)
	vlanIf := wanLogicalDev(wan)

	fmt.Fprintf(&b, "allow-hotplug %s\nauto %s\niface %s inet manual\n", iface, iface, iface)
	if wan.MACClone != "" {
		fmt.Fprintf(&b, "    pre-up ip link set dev %s address %s\n", iface, wan.MACClone)
	}

	switch {
	case wanUsesPPPoE(wan):
		if wan.MTU > 1492 {
			carrierMTU := wan.MTU + 8
			fmt.Fprintf(&b, "    up ip link set dev %s mtu %d || true\n", iface, carrierMTU)
		}
		fmt.Fprintf(&b, "    up ip link set %s up\n", iface)
		if useVLAN {
			fmt.Fprintf(&b, "    up ip link add link %s name %s type vlan id %d || true\n", iface, vlanIf, wan.VLANID)
			if wan.MTU > 1492 {
				fmt.Fprintf(&b, "    up ip link set dev %s mtu %d || true\n", vlanIf, wan.MTU+8)
			}
			fmt.Fprintf(&b, "    up ip link set %s up\n", vlanIf)
		}
		b.WriteString("    up pppd call wan-pppoe\n")
		b.WriteString("    down killall pppd || true\n")
		if useVLAN {
			fmt.Fprintf(&b, "    down ip link del %s || true\n", vlanIf)
		}
		fmt.Fprintf(&b, "    down ip link set %s down\n", iface)

	case wan.Mode == "static":
		prefix := ipv4MaskPrefixLen(wan.StaticNetmask)
		fmt.Fprintf(&b, "    up ip link set %s up\n", iface)
		if useVLAN {
			fmt.Fprintf(&b, "    up ip link add link %s name %s type vlan id %d || true\n", iface, vlanIf, wan.VLANID)
			fmt.Fprintf(&b, "    up ip link set %s up\n", vlanIf)
		}
		if wan.MTU > 0 && wan.MTU != 1500 {
			fmt.Fprintf(&b, "    up ip link set dev %s mtu %d\n", vlanIf, wan.MTU)
		}
		fmt.Fprintf(&b, "    up ip addr flush dev %s || true\n", vlanIf)
		fmt.Fprintf(&b, "    up ip addr add %s/%d dev %s\n", wan.StaticIP, prefix, vlanIf)
		fmt.Fprintf(&b, "    up ip route replace default via %s dev %s\n", wan.StaticGateway, vlanIf)
		fmt.Fprintf(&b, "    down ip route del default via %s dev %s || true\n", wan.StaticGateway, vlanIf)
		fmt.Fprintf(&b, "    down ip addr flush dev %s || true\n", vlanIf)
		if useVLAN {
			fmt.Fprintf(&b, "    down ip link del %s || true\n", vlanIf)
		}
		fmt.Fprintf(&b, "    down ip link set %s down\n", iface)

	default: // dhcp (untagged or over 802.1Q VLAN)
		if useVLAN {
			fmt.Fprintf(&b, "    up ip link set %s up\n", iface)
			fmt.Fprintf(&b, "    up ip link add link %s name %s type vlan id %d || true\n", iface, vlanIf, wan.VLANID)
			if wan.MTU > 0 && wan.MTU != 1500 {
				fmt.Fprintf(&b, "    up ip link set dev %s mtu %d\n", vlanIf, wan.MTU)
			}
			fmt.Fprintf(&b, "    up ip link set %s up\n", vlanIf)
			fmt.Fprintf(&b, "    down ip link del %s || true\n", vlanIf)
			fmt.Fprintf(&b, "    down ip link set %s down\n", iface)
		} else {
			if wan.MTU > 0 && wan.MTU != 1500 {
				fmt.Fprintf(&b, "    up ip link set dev %s mtu %d\n", iface, wan.MTU)
			}
			fmt.Fprintf(&b, "    up ip link set %s up\n", iface)
			fmt.Fprintf(&b, "    down ip link set %s down\n", iface)
		}
	}
	return b.String()
}

func RenderDHCPCDConf(lan config.LANState, wan config.WANState) string {
	var b strings.Builder
	b.WriteString("# Managed by NetBee OS (netbeed)\n")
	deny := []string{lan.Interface}
	switch {
	case wanUsesPPPoE(wan):
		deny = append(deny, wan.Interface)
		if wanUsesVLAN(wan) {
			deny = append(deny, wanLogicalDev(wan))
		}
	case wan.Mode == "static":
		deny = append(deny, wan.Interface)
		if wanUsesVLAN(wan) && !wan.IPv6PD {
			deny = append(deny, wanLogicalDev(wan))
		}
	case wanUsesVLAN(wan): // dhcp over 802.1Q VLAN: prevent DHCP on untagged carrier
		deny = append(deny, wan.Interface)
	}
	fmt.Fprintf(&b, "denyinterfaces %s\n\n", strings.Join(deny, " "))
	b.WriteString("duid\npersistent\nvendorclassid\n")
	if wanPeerDNS(wan) {
		b.WriteString("option domain_name_servers, domain_name, domain_search\n")
	} else {
		b.WriteString("nohook resolv.conf\n")
	}
	b.WriteString("option classless_static_routes\noption interface_mtu\noption host_name\n")
	b.WriteString("require dhcp_server_identifier\nslaac private\n")
	if wan.IPv6PD {
		pdIface := wanLogicalDev(wan)
		if wanUsesPPPoE(wan) {
			pdIface = "ppp0"
		}
		fmt.Fprintf(&b, "\ninterface %s\n    ipv6rs\n    ia_na 1\n    ia_pd 2 %s/0\n", pdIface, lan.Interface)
	}
	return b.String()
}

func RenderPPPoEPeer(wan config.WANState) string {
	phys := wanLogicalDev(wan)
	mtu := wan.MTU
	if mtu < 576 || mtu > 1508 {
		mtu = 1492
	}
	peerDNSLine := ""
	if wanPeerDNS(wan) {
		peerDNSLine = "usepeerdns\n"
	}
	return fmt.Sprintf(
		"# Managed by NetBee OS (netbeed)\n"+
			"plugin rp-pppoe.so %s\n"+
			"user %q\n"+
			"noauth\nnoaccomp\nnopcomp\ndefaultroute\nreplacedefaultroute\n%spersist\n"+
			"maxfail 0\nholdoff 5\nlcp-echo-interval 5\nlcp-echo-failure 3\nlcp-echo-adaptive\n"+
			"mtu %d\nmru %d\nnoipdefault\nhide-password\n",
		phys, wan.PPPoEUser, peerDNSLine, mtu, mtu,
	)
}

func normalizeAndValidateWAN(req *config.WANState, prevWAN config.WANState) error {
	if req.Interface == "" {
		req.Interface = "eth1"
	}
	if !sys.ValidIface(req.Interface) || req.Interface == "lo" {
		return fmt.Errorf("invalid WAN interface name")
	}
	if req.Mode != "dhcp" && req.Mode != "static" && req.Mode != "pppoe" && req.Mode != "ont_vlan" {
		return fmt.Errorf("mode must be dhcp, static, pppoe, or ont_vlan")
	}
	if req.Mode == "ont_vlan" {
		req.VLANEnabled = true
	}
	if wanUsesVLAN(*req) {
		if err := sys.ValidateVLAN(req.VLANID); err != nil {
			return err
		}
	}
	if req.Mode == "static" {
		if !sys.ValidIPv4Netmask(req.StaticNetmask) {
			return fmt.Errorf("invalid static_netmask (expected IPv4 netmask, e.g. 255.255.255.0)")
		}
		if !sys.ValidUnicastIPv4Host(req.StaticIP, req.StaticNetmask) {
			return fmt.Errorf("invalid static_ip for the given static_netmask")
		}
		if !sys.ValidIPv4(req.StaticGateway) {
			return fmt.Errorf("invalid static_gateway (IPv4 address required)")
		}
	}
	if req.PPPoEPassword == "" {
		req.PPPoEPassword = prevWAN.PPPoEPassword
	}
	if wanUsesPPPoE(*req) {
		if req.PPPoEUser == "" || req.PPPoEPassword == "" || !sys.ValidSafeString(req.PPPoEUser) || !sys.ValidSafeString(req.PPPoEPassword) {
			return fmt.Errorf("PPPoE username and password are required and must be valid")
		}
	}
	var cleanedDNS []string
	for _, s := range req.DNSServers {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if net.ParseIP(s) == nil {
			return fmt.Errorf("invalid WAN DNS server IP: %s", s)
		}
		cleanedDNS = append(cleanedDNS, s)
	}
	if len(cleanedDNS) > 8 {
		return fmt.Errorf("at most 8 WAN DNS servers are supported")
	}
	req.DNSServers = cleanedDNS
	if !wanPeerDNS(*req) && len(req.DNSServers) == 0 {
		return fmt.Errorf("provide at least one WAN DNS server when peerdns is disabled")
	}
	if req.MACClone != "" && !sys.ValidMAC(req.MACClone) {
		return fmt.Errorf("invalid MAC clone address (expected AA:BB:CC:DD:EE:FF)")
	}
	if req.PinMAC != "" && !sys.ValidMAC(req.PinMAC) {
		return fmt.Errorf("invalid pin_mac address (expected AA:BB:CC:DD:EE:FF)")
	}
	if req.MTU == 0 {
		if wanUsesPPPoE(*req) {
			req.MTU = 1492
		} else {
			req.MTU = 1500
		}
	}
	if req.MTU < 576 || req.MTU > 1508 {
		return fmt.Errorf("mtu must be between 576 and 1508")
	}
	return nil
}

func normalizeAndValidateLAN(req *config.LANState) error {
	if req.Interface == "" {
		req.Interface = "eth0"
	}
	if !sys.ValidIface(req.Interface) || req.Interface == "lo" {
		return fmt.Errorf("invalid LAN interface name")
	}
	if !sys.ValidIPv4Netmask(req.Netmask) {
		return fmt.Errorf("invalid LAN IPv4 subnet mask (expected e.g. 255.255.255.0)")
	}
	if !sys.ValidUnicastIPv4Host(req.IP, req.Netmask) {
		return fmt.Errorf("invalid LAN host IPv4 address for the given subnet mask")
	}
	if req.MTU == 0 {
		req.MTU = 1500
	}
	if req.MTU < 576 || req.MTU > 9000 {
		return fmt.Errorf("LAN mtu must be between 576 and 9000")
	}
	if req.PinMAC != "" && !sys.ValidMAC(req.PinMAC) {
		return fmt.Errorf("invalid pin_mac address (expected AA:BB:CC:DD:EE:FF)")
	}
	return nil
}

func (s *Server) handleSetWAN(w http.ResponseWriter, r *http.Request) {
	var req config.WANState
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json body")
		return
	}
	cur := s.Store.Get()
	if err := normalizeAndValidateWAN(&req, cur.WAN); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Interface == cur.LAN.Interface {
		writeErr(w, http.StatusBadRequest, "WAN interface cannot be identical to LAN interface (use /api/v1/network/swap to swap roles)")
		return
	}

	oldWAN := cur.WAN
	oldIf := oldWAN.Interface
	if oldIf == "" {
		oldIf = "eth1"
	}
	files := []string{
		"/etc/network/interfaces",
		"/etc/dhcpcd.conf",
		"/etc/ppp/peers/wan-pppoe",
		"/etc/ppp/pap-secrets",
		"/etc/ppp/chap-secrets",
		sqmConfPath,
		nftVarsPath,
		netifEnvPath,
		customUdevNetRules,
		s.Cfg.StatePath,
	}
	s.Rollback.Begin("WAN configuration update", time.Duration(s.Cfg.RollbackSeconds)*time.Second, files, func() {
		_ = s.Store.Reload()
		_, _ = sys.Run(5*time.Second, "killall", "pppd")
		if wanUsesVLAN(req) {
			_, _ = sys.Run(3*time.Second, "ip", "link", "del", wanLogicalDev(req))
		}
		_, _ = sys.Run(5*time.Second, "ifdown", "--force", req.Interface)
		_, _ = sys.Run(5*time.Second, "ifup", oldIf)
		_, _ = sys.Run(5*time.Second, "/usr/sbin/netbee-packet-steering", "start")
		_, _ = sys.Run(10*time.Second, "/etc/init.d/S41dhcpcd", "restart")
		_, _ = sys.Run(10*time.Second, "/etc/init.d/S35nftables", "reload")
		if sqmRaw, err := os.ReadFile(sqmConfPath); err == nil && ParseSQMConf(string(sqmRaw)).Enabled {
			_, _ = sys.Run(5*time.Second, "/usr/sbin/netbee-sqm", "restart")
		} else if s.Store.Get().Firewall.FlowOffload {
			_, _ = sys.Run(5*time.Second, "/etc/init.d/S42nft-offload", "start")
		}
		restorePersistedRoutes(s.Store.Get().StaticRoutes)
	})

	// Bring down ONLY the old WAN interface BEFORE overwriting /etc/network/interfaces (never drops LAN!)
	_, _ = sys.Run(5*time.Second, "ifdown", "--force", oldIf)
	_, _ = sys.Run(5*time.Second, "killall", "pppd")
	if wanUsesVLAN(oldWAN) {
		_, _ = sys.Run(3*time.Second, "ip", "link", "del", wanLogicalDev(oldWAN))
	}

	if err := s.Store.Update(func(st *config.State) error {
		st.WAN = req
		return nil
	}); err != nil {
		s.Rollback.RevertNow()
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	st := s.Store.Get()
	if err := syncNetIfConfigs(st); err != nil {
		s.Rollback.RevertNow()
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := config.AtomicWriteFile("/etc/network/interfaces", []byte(RenderInterfacesFile(st.LAN, req)), 0644); err != nil {
		s.Rollback.RevertNow()
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := config.AtomicWriteFile("/etc/dhcpcd.conf", []byte(RenderDHCPCDConf(st.LAN, req)), 0644); err != nil {
		s.Rollback.RevertNow()
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if wanUsesPPPoE(req) {
		if err := config.AtomicWriteFile("/etc/ppp/peers/wan-pppoe", []byte(RenderPPPoEPeer(req)), 0644); err != nil {
			s.Rollback.RevertNow()
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
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
	syncCustomWANDNS(req)

	_, _ = sys.Run(5*time.Second, "vnstat", "--add", "-i", req.Interface)
	_, _ = sys.Run(10*time.Second, "ifup", req.Interface)
	_, _ = sys.Run(5*time.Second, "/usr/sbin/netbee-packet-steering", "start")
	if etCfg, ok := st.Ethtool[req.Interface]; ok {
		_ = applyEthtoolConfig(req.Interface, etCfg)
	}
	_, _ = sys.Run(10*time.Second, "/etc/init.d/S41dhcpcd", "restart")
	_, _ = sys.Run(10*time.Second, "/etc/init.d/S35nftables", "reload")
	if sqmRaw, err := os.ReadFile(sqmConfPath); err == nil {
		sqmCfg := ParseSQMConf(string(sqmRaw))
		sqmCfg.WANInterface = EffectiveSQMInterface(sqmCfg.WANInterface, req)
		_ = config.AtomicWriteFile(sqmConfPath, []byte(RenderSQMConf(sqmCfg)), 0644)
		if sqmCfg.Enabled {
			_, _ = sys.Run(5*time.Second, "/usr/sbin/netbee-sqm", "restart")
		} else if st.Firewall.FlowOffload {
			_, _ = sys.Run(5*time.Second, "/etc/init.d/S42nft-offload", "start")
		}
	} else if st.Firewall.FlowOffload {
		_, _ = sys.Run(5*time.Second, "/etc/init.d/S42nft-offload", "start")
	}
	restorePersistedRoutes(st.StaticRoutes)

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":             true,
		"pending_commit": s.Rollback.Status(),
	})
}

func (s *Server) handleWANReconnect(w http.ResponseWriter, r *http.Request) {
	wan := s.Store.Get().WAN
	switch {
	case wanUsesPPPoE(wan):
		_, _ = sys.Run(5*time.Second, "killall", "pppd")
		if _, err := sys.Run(10*time.Second, "pppd", "call", "wan-pppoe"); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
	case wan.Mode == "static":
		_, _ = sys.Run(5*time.Second, "ifdown", "--force", wan.Interface)
		if _, err := sys.Run(10*time.Second, "ifup", wan.Interface); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
	default:
		if _, err := sys.Run(10*time.Second, "/etc/init.d/S41dhcpcd", "restart"); err != nil {
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
	if err := normalizeAndValidateLAN(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	cur := s.Store.Get()
	if req.Interface == cur.WAN.Interface {
		writeErr(w, http.StatusBadRequest, "LAN interface cannot be identical to WAN interface (use /api/v1/network/swap to swap roles)")
		return
	}

	oldLAN := cur.LAN
	files := []string{
		"/etc/network/interfaces",
		"/etc/dhcpcd.conf",
		"/etc/default/dropbear",
		"/etc/hosts",
		adguardYAMLPath,
		nftVarsPath,
		netifEnvPath,
		customUdevNetRules,
		uiNftDropInPath,
		s.Cfg.StatePath,
	}
	s.Rollback.Begin("LAN configuration update", time.Duration(s.Cfg.RollbackSeconds)*time.Second, files, func() {
		_ = s.Store.Reload()
		reverted := s.Store.Get()
		_, _ = sys.Run(5*time.Second, "/etc/init.d/S85adguardhome", "stop")
		_, _ = sys.Run(3*time.Second, "ip", "addr", "flush", "dev", req.Interface)
		_, _ = sys.Run(3*time.Second, "ip", "addr", "flush", "dev", reverted.LAN.Interface)
		_, _ = sys.Run(10*time.Second, "ifup", "--force", reverted.LAN.Interface)
		_, _ = sys.Run(5*time.Second, "/usr/sbin/netbee-packet-steering", "start")
		_, _ = sys.Run(10*time.Second, "/etc/init.d/S41dhcpcd", "restart")
		_, _ = sys.Run(5*time.Second, "/etc/init.d/S50dropbear", "restart")
		_, _ = sys.Run(10*time.Second, "/etc/init.d/S35nftables", "reload")
		if reverted.Firewall.FlowOffload {
			_, _ = sys.Run(5*time.Second, "/etc/init.d/S42nft-offload", "start")
		}
		_, _ = sys.Run(5*time.Second, "/etc/init.d/S85adguardhome", "start")
		restorePersistedRoutes(reverted.StaticRoutes)
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
	if err := syncNetIfConfigs(st); err != nil {
		s.Rollback.RevertNow()
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
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

	rawDropbear, _ := os.ReadFile("/etc/default/dropbear")
	pwAuth, allowRoot, idleSec := ParseDropbearConfEx(string(rawDropbear))
	_ = config.AtomicWriteFile("/etc/default/dropbear", []byte(RenderDropbearConfEx(req.IP, pwAuth, allowRoot, idleSec)), 0644)

	host, _ := os.Hostname()
	_ = config.AtomicWriteFile("/etc/hosts", []byte(renderHostsFile(req.IP, host)), 0644)
	_ = config.AtomicWriteFile(uiNftDropInPath, []byte(RenderCustomNFT(st.Firewall, req.IP)), 0644)

	var updatedAGH []byte
	if aghRaw, err := os.ReadFile(adguardYAMLPath); err == nil {
		updatedAGH = []byte(UpdateAdGuardLANConfig(string(aghRaw), oldLAN, req))
		_ = config.AtomicWriteFile(adguardYAMLPath, updatedAGH, 0600)
	}

	// Apply live after flushing HTTP 200 response, flushing the old LAN IP first so phantom IPs never remain
	if _, err := os.Stat("/etc/init.d/S40network"); err == nil {
		go func(aghData []byte, stateSnap config.State) {
			time.Sleep(400 * time.Millisecond)
			if len(aghData) > 0 {
				_, _ = sys.Run(5*time.Second, "/etc/init.d/S85adguardhome", "stop")
				_ = config.AtomicWriteFile(adguardYAMLPath, aghData, 0600)
			}
			_, _ = sys.Run(5*time.Second, "vnstat", "--add", "-i", req.Interface)
			_, _ = sys.Run(3*time.Second, "ip", "addr", "flush", "dev", oldLAN.Interface)
			_, _ = sys.Run(10*time.Second, "ifup", "--force", req.Interface)
			_, _ = sys.Run(5*time.Second, "/usr/sbin/netbee-packet-steering", "start")
			if etCfg, ok := stateSnap.Ethtool[req.Interface]; ok {
				_ = applyEthtoolConfig(req.Interface, etCfg)
			}
			_, _ = sys.Run(10*time.Second, "/etc/init.d/S41dhcpcd", "restart")
			_, _ = sys.Run(5*time.Second, "/etc/init.d/S50dropbear", "restart")
			_, _ = sys.Run(10*time.Second, "/etc/init.d/S35nftables", "reload")
			if stateSnap.Firewall.FlowOffload {
				_, _ = sys.Run(5*time.Second, "/etc/init.d/S42nft-offload", "start")
			}
			if len(aghData) > 0 {
				_, _ = sys.Run(5*time.Second, "/etc/init.d/S85adguardhome", "start")
			}
			restorePersistedRoutes(stateSnap.StaticRoutes)
		}(updatedAGH, st)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":             true,
		"new_url":        "https://" + req.IP,
		"pending_commit": s.Rollback.Status(),
		"message":        "LAN IP, DHCP/DNS, SSH bind, and firewall updated; confirm at new_url within rollback window.",
	})
}

// handleSwapNetworkRoles atomically updates or swaps LAN and WAN physical interfaces in a single
// rollback-protected transaction (e.g. assigning a 2.5GbE USB/PCIe NIC to LAN and built-in eth0 to WAN).
func (s *Server) handleSwapNetworkRoles(w http.ResponseWriter, r *http.Request) {
	cur := s.Store.Get()
	nextLAN := cur.LAN
	nextWAN := cur.WAN
	nextLAN.Interface = cur.WAN.Interface
	nextWAN.Interface = cur.LAN.Interface
	nextLAN.PinMAC = cur.WAN.PinMAC
	nextWAN.PinMAC = cur.LAN.PinMAC

	if r.ContentLength > 0 {
		var body struct {
			LAN *config.LANState `json:"lan"`
			WAN *config.WANState `json:"wan"`
		}
		if err := decodeJSON(r, &body); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid json body")
			return
		}
		if body.LAN != nil {
			nextLAN = *body.LAN
		}
		if body.WAN != nil {
			nextWAN = *body.WAN
		}
	}

	if err := normalizeAndValidateLAN(&nextLAN); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := normalizeAndValidateWAN(&nextWAN, cur.WAN); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if nextLAN.Interface == nextWAN.Interface {
		writeErr(w, http.StatusBadRequest, "LAN and WAN interfaces must be distinct")
		return
	}

	oldLAN := cur.LAN
	oldWAN := cur.WAN
	files := []string{
		interfacesConfPath,
		dhcpcdConfPath,
		pppPeerPath,
		papSecretsPath,
		chapSecretsPath,
		dropbearDefaultPath,
		hostsConfPath,
		adguardYAMLPath,
		sqmConfPath,
		nftVarsPath,
		netifEnvPath,
		customUdevNetRules,
		uiNftDropInPath,
		s.Cfg.StatePath,
	}

	s.Rollback.Begin("LAN/WAN interface role swap", time.Duration(s.Cfg.RollbackSeconds)*time.Second, files, func() {
		_ = s.Store.Reload()
		reverted := s.Store.Get()
		_, _ = sys.Run(5*time.Second, "/etc/init.d/S85adguardhome", "stop")
		_, _ = sys.Run(5*time.Second, "killall", "pppd")
		if wanUsesVLAN(nextWAN) {
			_, _ = sys.Run(3*time.Second, "ip", "link", "del", wanLogicalDev(nextWAN))
		}
		_, _ = sys.Run(3*time.Second, "ip", "addr", "flush", "dev", nextLAN.Interface)
		_, _ = sys.Run(3*time.Second, "ip", "addr", "flush", "dev", nextWAN.Interface)
		_, _ = sys.Run(10*time.Second, "ifup", "--force", reverted.LAN.Interface)
		_, _ = sys.Run(10*time.Second, "ifup", "--force", reverted.WAN.Interface)
		_, _ = sys.Run(5*time.Second, "/usr/sbin/netbee-packet-steering", "start")
		_, _ = sys.Run(10*time.Second, "/etc/init.d/S41dhcpcd", "restart")
		_, _ = sys.Run(5*time.Second, "/etc/init.d/S50dropbear", "restart")
		_, _ = sys.Run(10*time.Second, "/etc/init.d/S35nftables", "reload")
		if sqmRaw, err := os.ReadFile(sqmConfPath); err == nil && ParseSQMConf(string(sqmRaw)).Enabled {
			_, _ = sys.Run(5*time.Second, "/usr/sbin/netbee-sqm", "restart")
		} else if reverted.Firewall.FlowOffload {
			_, _ = sys.Run(5*time.Second, "/etc/init.d/S42nft-offload", "start")
		}
		_, _ = sys.Run(5*time.Second, "/etc/init.d/S85adguardhome", "start")
		restorePersistedRoutes(reverted.StaticRoutes)
	})

	if err := s.Store.Update(func(st *config.State) error {
		st.LAN = nextLAN
		st.WAN = nextWAN
		if st.WireGuard.DNS == "" || st.WireGuard.DNS == oldLAN.IP {
			st.WireGuard.DNS = nextLAN.IP
		}
		return nil
	}); err != nil {
		s.Rollback.RevertNow()
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	st := s.Store.Get()
	if err := syncNetIfConfigs(st); err != nil {
		s.Rollback.RevertNow()
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := config.AtomicWriteFile(interfacesConfPath, []byte(RenderInterfacesFile(nextLAN, nextWAN)), 0644); err != nil {
		s.Rollback.RevertNow()
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := config.AtomicWriteFile(dhcpcdConfPath, []byte(RenderDHCPCDConf(nextLAN, nextWAN)), 0644); err != nil {
		s.Rollback.RevertNow()
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if wanUsesPPPoE(nextWAN) {
		if err := config.AtomicWriteFile(pppPeerPath, []byte(RenderPPPoEPeer(nextWAN)), 0644); err != nil {
			s.Rollback.RevertNow()
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		secret := fmt.Sprintf("%q * %q *\n", nextWAN.PPPoEUser, nextWAN.PPPoEPassword)
		_ = config.AtomicWriteFile(papSecretsPath, []byte(secret), 0600)
		_ = config.AtomicWriteFile(chapSecretsPath, []byte(secret), 0600)
	}
	syncCustomWANDNS(nextWAN)

	rawDropbear, _ := os.ReadFile(dropbearDefaultPath)
	pwAuth, allowRoot, idleSec := ParseDropbearConfEx(string(rawDropbear))
	_ = config.AtomicWriteFile(dropbearDefaultPath, []byte(RenderDropbearConfEx(nextLAN.IP, pwAuth, allowRoot, idleSec)), 0644)

	host, _ := os.Hostname()
	_ = config.AtomicWriteFile(hostsConfPath, []byte(renderHostsFile(nextLAN.IP, host)), 0644)
	_ = config.AtomicWriteFile(uiNftDropInPath, []byte(RenderCustomNFT(st.Firewall, nextLAN.IP)), 0644)

	var updatedAGH []byte
	if aghRaw, err := os.ReadFile(adguardYAMLPath); err == nil {
		updatedAGH = []byte(UpdateAdGuardLANConfig(string(aghRaw), oldLAN, nextLAN))
		_ = config.AtomicWriteFile(adguardYAMLPath, updatedAGH, 0600)
	}

	var sqmEnabled bool
	if sqmRaw, err := os.ReadFile(sqmConfPath); err == nil {
		sqmCfg := ParseSQMConf(string(sqmRaw))
		sqmCfg.WANInterface = EffectiveSQMInterface(sqmCfg.WANInterface, nextWAN)
		sqmEnabled = sqmCfg.Enabled
		_ = config.AtomicWriteFile(sqmConfPath, []byte(RenderSQMConf(sqmCfg)), 0644)
	}

	if _, err := os.Stat("/etc/init.d/S40network"); err == nil {
		go func(aghData []byte, stateSnap config.State, runSQM bool) {
			time.Sleep(400 * time.Millisecond)
			if len(aghData) > 0 {
				_, _ = sys.Run(5*time.Second, "/etc/init.d/S85adguardhome", "stop")
				_ = config.AtomicWriteFile(adguardYAMLPath, aghData, 0600)
			}
			_, _ = sys.Run(5*time.Second, "killall", "pppd")
			if wanUsesVLAN(oldWAN) {
				_, _ = sys.Run(3*time.Second, "ip", "link", "del", wanLogicalDev(oldWAN))
			}
			_, _ = sys.Run(3*time.Second, "ip", "addr", "flush", "dev", oldLAN.Interface)
			_, _ = sys.Run(3*time.Second, "ip", "addr", "flush", "dev", oldWAN.Interface)
			_, _ = sys.Run(5*time.Second, "vnstat", "--add", "-i", nextLAN.Interface)
			_, _ = sys.Run(5*time.Second, "vnstat", "--add", "-i", nextWAN.Interface)
			_, _ = sys.Run(10*time.Second, "ifup", "--force", nextLAN.Interface)
			_, _ = sys.Run(10*time.Second, "ifup", "--force", nextWAN.Interface)
			_, _ = sys.Run(5*time.Second, "/usr/sbin/netbee-packet-steering", "start")
			if etCfg, ok := stateSnap.Ethtool[nextLAN.Interface]; ok {
				_ = applyEthtoolConfig(nextLAN.Interface, etCfg)
			}
			if etCfg, ok := stateSnap.Ethtool[nextWAN.Interface]; ok {
				_ = applyEthtoolConfig(nextWAN.Interface, etCfg)
			}
			_, _ = sys.Run(10*time.Second, "/etc/init.d/S41dhcpcd", "restart")
			_, _ = sys.Run(5*time.Second, "/etc/init.d/S50dropbear", "restart")
			_, _ = sys.Run(10*time.Second, "/etc/init.d/S35nftables", "reload")
			if runSQM {
				_, _ = sys.Run(5*time.Second, "/usr/sbin/netbee-sqm", "restart")
			} else if stateSnap.Firewall.FlowOffload {
				_, _ = sys.Run(5*time.Second, "/etc/init.d/S42nft-offload", "start")
			}
			if len(aghData) > 0 {
				_, _ = sys.Run(5*time.Second, "/etc/init.d/S85adguardhome", "start")
			}
			restorePersistedRoutes(stateSnap.StaticRoutes)
		}(updatedAGH, st, sqmEnabled)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":             true,
		"lan":            nextLAN,
		"wan":            nextWAN,
		"new_url":        "https://" + nextLAN.IP,
		"pending_commit": s.Rollback.Status(),
	})
}

// --- Ethtool Link, Wake-on-LAN & Hardware Offload Management ---

var ethtoolFeatureMap = map[string]string{
	"rx":     "rx-checksumming",
	"tx":     "tx-checksumming",
	"sg":     "scatter-gather",
	"tso":    "tcp-segmentation-offload",
	"gso":    "generic-segmentation-offload",
	"gro":    "generic-receive-offload",
	"rxvlan": "rx-vlan-offload",
	"txvlan": "tx-vlan-offload",
}

type EthtoolFeatureState struct {
	Active bool `json:"active"`
	Fixed  bool `json:"fixed"`
}

func ParseEthtoolSettings(stdout string) map[string]any {
	info := map[string]any{
		"speed":                "",
		"duplex":               "",
		"autoneg":              true,
		"supports_autoneg":     false,
		"link_detected":        false,
		"wake_on":              "",
		"supports_wake_on":     "",
		"supported_link_modes": []string{},
	}
	var modes []string
	inModes := false
	for _, raw := range strings.Split(stdout, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "Supported link modes:") {
			rest := strings.TrimSpace(strings.TrimPrefix(line, "Supported link modes:"))
			if strings.EqualFold(rest, "Not reported") {
				inModes = false
				continue
			}
			inModes = true
			if rest != "" {
				modes = append(modes, strings.Fields(rest)...)
			}
			continue
		}
		if inModes {
			if strings.Contains(line, ":") {
				inModes = false
			} else {
				modes = append(modes, strings.Fields(line)...)
				continue
			}
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch strings.TrimSpace(k) {
		case "Speed":
			info["speed"] = v
		case "Duplex":
			info["duplex"] = v
		case "Supports auto-negotiation":
			info["supports_autoneg"] = strings.EqualFold(v, "yes")
		case "Auto-negotiation":
			info["autoneg"] = strings.EqualFold(v, "on")
		case "Supports Wake-on":
			info["supports_wake_on"] = v
		case "Wake-on":
			info["wake_on"] = v
		case "Link detected":
			info["link_detected"] = strings.EqualFold(v, "yes")
		}
	}
	if len(modes) > 0 {
		info["supported_link_modes"] = modes
	}
	return info
}

func ParseEthtoolFeatures(stdout string) map[string]EthtoolFeatureState {
	reverseMap := make(map[string]string, len(ethtoolFeatureMap))
	for short, full := range ethtoolFeatureMap {
		reverseMap[full] = short
	}
	out := make(map[string]EthtoolFeatureState, len(ethtoolFeatureMap))
	for _, raw := range strings.Split(stdout, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(raw), ":")
		if !ok {
			continue
		}
		short, tracked := reverseMap[strings.TrimSpace(k)]
		if !tracked {
			continue
		}
		v = strings.TrimSpace(v)
		fixed := strings.Contains(v, "[fixed]")
		active := strings.HasPrefix(v, "on")
		out[short] = EthtoolFeatureState{Active: active, Fixed: fixed}
	}
	return out
}

func ValidateEthtoolConfig(cfg config.EthtoolConfig) error {
	validSpeeds := map[int]bool{0: true, 10: true, 100: true, 1000: true, 2500: true, 5000: true, 10000: true}
	if !validSpeeds[cfg.Speed] {
		return fmt.Errorf("invalid speed (supported: 10, 100, 1000, 2500, 5000, 10000)")
	}
	if cfg.Duplex != "" && cfg.Duplex != "half" && cfg.Duplex != "full" {
		return fmt.Errorf("duplex must be 'half', 'full', or empty")
	}
	if !cfg.Autoneg && (cfg.Speed == 0 || (cfg.Duplex != "half" && cfg.Duplex != "full")) {
		return fmt.Errorf("speed and duplex ('half' or 'full') are required when autoneg is false")
	}
	if cfg.WoL != "" && cfg.WoL != "d" && cfg.WoL != "g" {
		return fmt.Errorf("wol must be 'd' (disabled), 'g' (MagicPacket), or empty")
	}
	for k := range cfg.Offloads {
		if _, ok := ethtoolFeatureMap[k]; !ok {
			return fmt.Errorf("unsupported offload feature %q (allowed: rx, tx, sg, tso, gso, gro, rxvlan, txvlan)", k)
		}
	}
	return nil
}

func applyEthtoolConfig(iface string, cfg config.EthtoolConfig) error {
	var sArgs []string
	if !cfg.Autoneg {
		sArgs = append(sArgs, "speed", fmt.Sprintf("%d", cfg.Speed), "duplex", cfg.Duplex, "autoneg", "off")
	} else {
		// Only invoke 'autoneg on' when PHY explicitly supports autonegotiation and previously had it disabled
		if cur, err := sys.Run(3*time.Second, "ethtool", iface); err == nil {
			link := ParseEthtoolSettings(cur.Stdout)
			if link["autoneg"] == false && link["supports_autoneg"] == true {
				sArgs = append(sArgs, "autoneg", "on")
			}
		}
	}
	if cfg.WoL != "" {
		sArgs = append(sArgs, "wol", cfg.WoL)
	}
	if len(sArgs) > 0 {
		args := append([]string{"-s", iface}, sArgs...)
		if _, err := sys.Run(5*time.Second, "ethtool", args...); err != nil {
			return err
		}
	}

	if len(cfg.Offloads) > 0 {
		keys := make([]string, 0, len(cfg.Offloads))
		for k := range cfg.Offloads {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		kArgs := []string{"-K", iface}
		for _, k := range keys {
			val := "off"
			if cfg.Offloads[k] {
				val = "on"
			}
			kArgs = append(kArgs, k, val)
		}
		if _, err := sys.Run(5*time.Second, "ethtool", kArgs...); err != nil {
			return err
		}
	}
	return nil
}

func restorePersistedEthtool(cfgs map[string]config.EthtoolConfig) {
	for iface, cfg := range cfgs {
		if !sys.ValidIface(iface) || iface == "lo" {
			continue
		}
		if _, err := os.Stat("/sys/class/net/" + iface); err == nil {
			_ = applyEthtoolConfig(iface, cfg)
		}
	}
}

func (s *Server) handleGetEthtool(w http.ResponseWriter, r *http.Request) {
	iface := r.PathValue("iface")
	if !sys.ValidIface(iface) || iface == "lo" {
		writeErr(w, http.StatusBadRequest, "invalid Ethernet interface name")
		return
	}
	if _, err := os.Stat("/sys/class/net/" + iface); err != nil {
		writeErr(w, http.StatusNotFound, "interface not found")
		return
	}
	linkRes, _ := sys.Run(3*time.Second, "ethtool", iface)
	featRes, _ := sys.Run(3*time.Second, "ethtool", "-k", iface)
	persisted, hasPersisted := s.Store.Get().Ethtool[iface]
	var persistedPtr *config.EthtoolConfig
	if hasPersisted {
		persistedPtr = &persisted
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"interface": iface,
		"link":      ParseEthtoolSettings(linkRes.Stdout),
		"offloads":  ParseEthtoolFeatures(featRes.Stdout),
		"persisted": persistedPtr,
	})
}

func (s *Server) handleSetEthtool(w http.ResponseWriter, r *http.Request) {
	iface := r.PathValue("iface")
	if !sys.ValidIface(iface) || iface == "lo" {
		writeErr(w, http.StatusBadRequest, "invalid Ethernet interface name")
		return
	}
	if _, err := os.Stat("/sys/class/net/" + iface); err != nil {
		writeErr(w, http.StatusNotFound, "interface not found")
		return
	}
	var req config.EthtoolConfig
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json body")
		return
	}
	req.Duplex = strings.ToLower(strings.TrimSpace(req.Duplex))
	req.WoL = strings.ToLower(strings.TrimSpace(req.WoL))
	if err := ValidateEthtoolConfig(req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	cur := s.Store.Get()
	// Guard manual LAN speed/duplex override with 60s auto-rollback so link mismatch cannot permanently lock out LAN
	guarded := iface == cur.LAN.Interface && !req.Autoneg
	if guarded {
		s.Rollback.Begin("LAN ethtool link speed/duplex change", time.Duration(s.Cfg.RollbackSeconds)*time.Second, []string{s.Cfg.StatePath}, func() {
			_ = s.Store.Reload()
			if prev, ok := s.Store.Get().Ethtool[iface]; ok {
				_ = applyEthtoolConfig(iface, prev)
			} else {
				_, _ = sys.Run(5*time.Second, "ethtool", "-s", iface, "autoneg", "on")
			}
		})
	}

	if err := applyEthtoolConfig(iface, req); err != nil {
		if guarded {
			s.Rollback.RevertNow()
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.Store.Update(func(st *config.State) error {
		st.Ethtool[iface] = req
		return nil
	}); err != nil {
		if guarded {
			s.Rollback.RevertNow()
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	resp := map[string]any{"ok": true, "interface": iface, "config": req}
	if guarded {
		resp["pending_commit"] = s.Rollback.Status()
	}
	writeJSON(w, http.StatusOK, resp)
}
