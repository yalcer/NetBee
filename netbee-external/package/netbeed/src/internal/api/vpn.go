package api

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/yalcer/netbee/netbeed/internal/config"
	"github.com/yalcer/netbee/netbeed/internal/sys"
)

const wgConfPath = "/etc/wireguard/wg0.conf"

func RenderWireGuardConf(wg config.WireGuardState) string {
	var b strings.Builder
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", wg.PrivateKey)
	fmt.Fprintf(&b, "ListenPort = %d\n", wg.ListenPort)
	for _, p := range wg.Peers {
		if !p.Enabled {
			continue
		}
		fmt.Fprintf(&b, "\n# %s (%s)\n[Peer]\n", p.Name, p.ID)
		fmt.Fprintf(&b, "PublicKey = %s\n", p.PublicKey)
		if p.PresharedKey != "" {
			fmt.Fprintf(&b, "PresharedKey = %s\n", p.PresharedKey)
		}
		fmt.Fprintf(&b, "AllowedIPs = %s\n", p.AllowedIPs)
	}
	return b.String()
}

func applyWireGuard(wg config.WireGuardState) error {
	iface := wg.Interface
	if iface == "" {
		iface = "wg0"
	}
	if !wg.Enabled {
		_, _ = sys.Run(5*time.Second, "ip", "link", "del", iface)
		return nil
	}
	if err := config.AtomicWriteFile(wgConfPath, []byte(RenderWireGuardConf(wg)), 0600); err != nil {
		return err
	}
	_, _ = sys.Run(3*time.Second, "modprobe", "wireguard")
	_, _ = sys.Run(3*time.Second, "ip", "link", "add", iface, "type", "wireguard")
	_, _ = sys.Run(3*time.Second, "ip", "address", "flush", "dev", iface)
	if _, err := sys.Run(3*time.Second, "ip", "address", "add", wg.Address, "dev", iface); err != nil {
		return err
	}
	if _, err := sys.Run(5*time.Second, "wg", "setconf", iface, wgConfPath); err != nil {
		return err
	}
	_, err := sys.Run(3*time.Second, "ip", "link", "set", "up", "dev", iface)
	return err
}

func readLiveWGPeers(iface string) map[string]map[string]any {
	out := make(map[string]map[string]any)
	res, err := sys.Run(3*time.Second, "wg", "show", iface, "dump")
	if err != nil {
		return out
	}
	lines := strings.Split(strings.TrimSpace(res.Stdout), "\n")
	for i, line := range lines {
		if i == 0 || line == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 7 {
			continue
		}
		hs, _ := strconv.ParseInt(f[4], 10, 64)
		rx, _ := strconv.ParseUint(f[5], 10, 64)
		tx, _ := strconv.ParseUint(f[6], 10, 64)
		out[f[0]] = map[string]any{
			"endpoint":         f[2],
			"allowed_ips":      f[3],
			"latest_handshake": hs,
			"rx_bytes":         rx,
			"tx_bytes":         tx,
		}
	}
	return out
}

func redactWGState(wg config.WireGuardState) config.WireGuardState {
	wg.PrivateKey = ""
	for i := range wg.Peers {
		wg.Peers[i].HasPSK = wg.Peers[i].PresharedKey != ""
		wg.Peers[i].PresharedKey = ""
	}
	return wg
}

func (s *Server) handleGetWireGuard(w http.ResponseWriter, r *http.Request) {
	wg := redactWGState(s.Store.Get().WireGuard)
	iface := wg.Interface
	if iface == "" {
		iface = "wg0"
	}
	_, err := os.Stat("/sys/class/net/" + iface)
	active := err == nil
	live := map[string]map[string]any{}
	if active {
		live = readLiveWGPeers(iface)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"config":     wg,
		"active":     active,
		"live_peers": live,
	})
}

func normalizePeerAllowedIPs(raw string) (string, net.IP, error) {
	raw = strings.TrimSpace(raw)
	if ip := net.ParseIP(raw); ip != nil {
		if ip.To4() != nil {
			return ip.String() + "/32", ip, nil
		}
		return ip.String() + "/128", ip, nil
	}
	ip, ipNet, err := net.ParseCIDR(raw)
	if err != nil {
		return "", nil, err
	}
	ones, bits := ipNet.Mask.Size()
	if bits == 0 {
		return "", nil, fmt.Errorf("invalid prefix")
	}
	return fmt.Sprintf("%s/%d", ip.String(), ones), ip, nil
}

func (s *Server) handleSetWireGuard(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled    bool   `json:"enabled"`
		Address    string `json:"address"`
		ListenPort int    `json:"listen_port"`
		Endpoint   string `json:"endpoint"`
		DNS        string `json:"dns"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json body")
		return
	}
	if req.Address == "" {
		req.Address = "10.66.66.1/24"
	}
	srvIP, srvNet, err := net.ParseCIDR(req.Address)
	if err != nil || srvIP == nil || srvNet == nil {
		writeErr(w, http.StatusBadRequest, "invalid WireGuard CIDR address (expected e.g. 10.66.66.1/24)")
		return
	}
	ones, bits := srvNet.Mask.Size()
	if (srvIP.To4() != nil && ones >= 32) || (srvIP.To4() == nil && ones >= bits) {
		writeErr(w, http.StatusBadRequest, "WireGuard interface address must include a subnet prefix (e.g. /24, not /32)")
		return
	}
	if req.ListenPort == 0 {
		req.ListenPort = 51820
	}
	if !sys.ValidPort(req.ListenPort) {
		writeErr(w, http.StatusBadRequest, "invalid listen_port")
		return
	}
	req.Endpoint = strings.TrimSpace(req.Endpoint)
	if req.Endpoint != "" {
		if h, _, splitErr := net.SplitHostPort(req.Endpoint); splitErr == nil && net.ParseIP(req.Endpoint) == nil {
			req.Endpoint = h
		}
		if !sys.ValidHost(req.Endpoint) {
			writeErr(w, http.StatusBadRequest, "invalid endpoint host or IP")
			return
		}
	}
	if req.DNS == "" {
		req.DNS = s.Store.Get().LAN.IP
	}
	if !sys.ValidIPList(req.DNS) {
		writeErr(w, http.StatusBadRequest, "invalid DNS address list (expected comma-separated IPs)")
		return
	}

	var next config.WireGuardState
	var syncFW bool
	var fullState config.State
	if err := s.Store.Update(func(st *config.State) error {
		wg := st.WireGuard
		if wg.Interface == "" {
			wg.Interface = "wg0"
		}
		if wg.PrivateKey == "" {
			privRes, err := sys.Run(3*time.Second, "wg", "genkey")
			if err != nil {
				return fmt.Errorf("failed to generate server key: %w", err)
			}
			priv := strings.TrimSpace(privRes.Stdout)
			pubRes, err := sys.RunWithInput(3*time.Second, priv+"\n", "wg", "pubkey")
			if err != nil {
				return fmt.Errorf("failed to derive public key: %w", err)
			}
			wg.PrivateKey = priv
			wg.PublicKey = strings.TrimSpace(pubRes.Stdout)
		}
		wg.Enabled = req.Enabled
		wg.Address = req.Address
		wg.ListenPort = req.ListenPort
		wg.Endpoint = req.Endpoint
		wg.DNS = req.DNS
		st.WireGuard = wg
		if st.Firewall.WireGuardPort != req.ListenPort {
			st.Firewall.WireGuardPort = req.ListenPort
			syncFW = st.Firewall.ExposeWireGuard
		}
		next = wg
		fullState = *st
		return nil
	}); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	if err := applyWireGuard(next); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if _, err := os.Stat(nftVarsPath); err == nil {
		_ = syncNetIfConfigs(fullState)
	}
	if syncFW {
		_ = config.AtomicWriteFile(uiNftDropInPath, []byte(RenderCustomNFT(fullState.Firewall, fullState.LAN.IP)), 0644)
		_, _ = sys.Run(10*time.Second, "/etc/init.d/S35nftables", "reload")
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "config": redactWGState(next)})
}

func BuildWGClientConfig(clientPriv, peerAllowedIPs, presharedKey string, wg config.WireGuardState) string {
	endpointHost := wg.Endpoint
	endpointStr := "<YOUR_PUBLIC_IP_OR_DDNS>:" + strconv.Itoa(wg.ListenPort)
	if endpointHost != "" {
		endpointStr = net.JoinHostPort(endpointHost, strconv.Itoa(wg.ListenPort))
	}
	dns := wg.DNS
	if !sys.ValidIPList(dns) {
		dns = "192.168.10.1"
	}
	pskLine := ""
	if presharedKey != "" && sys.ValidWGKey(presharedKey) {
		pskLine = fmt.Sprintf("PresharedKey = %s\n", strings.TrimSpace(presharedKey))
	}
	return fmt.Sprintf(
		"[Interface]\nPrivateKey = %s\nAddress = %s\nDNS = %s\n\n[Peer]\nPublicKey = %s\n%sEndpoint = %s\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n",
		clientPriv, peerAllowedIPs, dns, wg.PublicKey, pskLine, endpointStr,
	)
}

func (s *Server) handleAddWireGuardPeer(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name         string `json:"name"`
		AllowedIPs   string `json:"allowed_ips"`   // e.g. "10.66.66.2/32"
		PublicKey    string `json:"public_key"`    // optional; auto-generated if omitted
		PresharedKey string `json:"preshared_key"` // optional
		UsePSK       bool   `json:"use_psk"`       // auto-generate PresharedKey via wg genpsk
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json body")
		return
	}
	if req.Name == "" || !sys.ValidSafeString(req.Name) {
		writeErr(w, http.StatusBadRequest, "invalid peer name")
		return
	}
	normalizedAllowed, peerIP, err := normalizePeerAllowedIPs(req.AllowedIPs)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid allowed_ips (expected e.g. 10.66.66.2/32)")
		return
	}

	clientPriv := ""
	clientPub := strings.TrimSpace(req.PublicKey)
	if clientPub == "" {
		privRes, err := sys.Run(3*time.Second, "wg", "genkey")
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		clientPriv = strings.TrimSpace(privRes.Stdout)
		pubRes, err := sys.RunWithInput(3*time.Second, clientPriv+"\n", "wg", "pubkey")
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		clientPub = strings.TrimSpace(pubRes.Stdout)
	} else if !sys.ValidWGKey(clientPub) {
		writeErr(w, http.StatusBadRequest, "invalid WireGuard public_key")
		return
	}

	psk := strings.TrimSpace(req.PresharedKey)
	if psk != "" && !sys.ValidWGKey(psk) {
		writeErr(w, http.StatusBadRequest, "invalid WireGuard preshared_key")
		return
	}
	if psk == "" && req.UsePSK {
		pskRes, err := sys.Run(3*time.Second, "wg", "genpsk")
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		psk = strings.TrimSpace(pskRes.Stdout)
	}

	peer := config.WireGuardPeer{
		ID:           fmt.Sprintf("peer%d", time.Now().UnixMilli()),
		Name:         req.Name,
		PublicKey:    clientPub,
		PresharedKey: psk,
		AllowedIPs:   normalizedAllowed,
		Enabled:      true,
	}

	var wg config.WireGuardState
	if err := s.Store.Update(func(st *config.State) error {
		if srvIP, _, parseErr := net.ParseCIDR(st.WireGuard.Address); parseErr == nil && srvIP.Equal(peerIP) {
			return fmt.Errorf("conflict: peer allowed_ips cannot match server tunnel IP (%s)", srvIP.String())
		}
		if st.WireGuard.PrivateKey == "" {
			privRes, err := sys.Run(3*time.Second, "wg", "genkey")
			if err != nil {
				return fmt.Errorf("failed to generate server key: %w", err)
			}
			priv := strings.TrimSpace(privRes.Stdout)
			pubRes, err := sys.RunWithInput(3*time.Second, priv+"\n", "wg", "pubkey")
			if err != nil {
				return fmt.Errorf("failed to derive server public key: %w", err)
			}
			st.WireGuard.PrivateKey = priv
			st.WireGuard.PublicKey = strings.TrimSpace(pubRes.Stdout)
		}
		if peer.PublicKey == st.WireGuard.PublicKey {
			return fmt.Errorf("conflict: peer public_key cannot equal server public_key")
		}
		for _, existing := range st.WireGuard.Peers {
			if existing.PublicKey == peer.PublicKey {
				return fmt.Errorf("duplicate peer public_key")
			}
			if existing.AllowedIPs == peer.AllowedIPs {
				return fmt.Errorf("duplicate peer allowed_ips: %s", peer.AllowedIPs)
			}
		}
		st.WireGuard.Peers = append(st.WireGuard.Peers, peer)
		wg = st.WireGuard
		return nil
	}); err != nil {
		status := http.StatusInternalServerError
		if strings.Contains(err.Error(), "duplicate") || strings.Contains(err.Error(), "conflict") {
			status = http.StatusConflict
		}
		writeErr(w, status, err.Error())
		return
	}
	if wg.Enabled {
		if err := applyWireGuard(wg); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
	}

	clientConf := ""
	if clientPriv != "" {
		clientConf = BuildWGClientConfig(clientPriv, peer.AllowedIPs, psk, wg)
	}
	peer.HasPSK = peer.PresharedKey != ""
	peer.PresharedKey = ""

	writeJSON(w, http.StatusCreated, map[string]any{
		"ok":            true,
		"peer":          peer,
		"client_config": clientConf,
	})
}

func (s *Server) handlePatchWireGuardPeer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req struct {
		Name       *string `json:"name"`
		Enabled    *bool   `json:"enabled"`
		AllowedIPs *string `json:"allowed_ips"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json body")
		return
	}
	if req.Name != nil && (*req.Name == "" || !sys.ValidSafeString(*req.Name)) {
		writeErr(w, http.StatusBadRequest, "invalid peer name")
		return
	}

	var normAllowed string
	var peerIP net.IP
	if req.AllowedIPs != nil {
		var err error
		normAllowed, peerIP, err = normalizePeerAllowedIPs(*req.AllowedIPs)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid allowed_ips")
			return
		}
	}

	found := false
	var updatedPeer config.WireGuardPeer
	var wg config.WireGuardState
	if err := s.Store.Update(func(st *config.State) error {
		if peerIP != nil {
			if srvIP, _, parseErr := net.ParseCIDR(st.WireGuard.Address); parseErr == nil && srvIP.Equal(peerIP) {
				return fmt.Errorf("conflict: peer allowed_ips cannot match server tunnel IP")
			}
			for _, existing := range st.WireGuard.Peers {
				if existing.ID != id && existing.AllowedIPs == normAllowed {
					return fmt.Errorf("duplicate peer allowed_ips: %s", normAllowed)
				}
			}
		}
		for i, p := range st.WireGuard.Peers {
			if p.ID == id {
				if req.Name != nil {
					p.Name = *req.Name
				}
				if req.Enabled != nil {
					p.Enabled = *req.Enabled
				}
				if req.AllowedIPs != nil {
					p.AllowedIPs = normAllowed
				}
				st.WireGuard.Peers[i] = p
				updatedPeer = p
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("peer not found")
		}
		wg = st.WireGuard
		return nil
	}); err != nil {
		status := http.StatusBadRequest
		if !found {
			status = http.StatusNotFound
		} else if strings.Contains(err.Error(), "duplicate") || strings.Contains(err.Error(), "conflict") {
			status = http.StatusConflict
		}
		writeErr(w, status, err.Error())
		return
	}

	if wg.Enabled {
		if err := applyWireGuard(wg); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	updatedPeer.HasPSK = updatedPeer.PresharedKey != ""
	updatedPeer.PresharedKey = ""
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "peer": updatedPeer})
}

func (s *Server) handleDelWireGuardPeer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	found := false
	var wg config.WireGuardState
	if err := s.Store.Update(func(st *config.State) error {
		next := make([]config.WireGuardPeer, 0, len(st.WireGuard.Peers))
		for _, p := range st.WireGuard.Peers {
			if p.ID == id {
				found = true
				continue
			}
			next = append(next, p)
		}
		if !found {
			return fmt.Errorf("peer not found")
		}
		st.WireGuard.Peers = next
		wg = st.WireGuard
		return nil
	}); err != nil {
		if !found {
			writeErr(w, http.StatusNotFound, "peer not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if wg.Enabled {
		if err := applyWireGuard(wg); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
