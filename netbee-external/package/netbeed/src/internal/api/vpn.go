package api

import (
	"fmt"
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
	_, _ = sys.Run(3*time.Second, "ip", "address", "replace", wg.Address, "dev", iface)
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
			continue // first line is interface info
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

func (s *Server) handleGetWireGuard(w http.ResponseWriter, r *http.Request) {
	wg := s.Store.Get().WireGuard
	wg.PrivateKey = "" // never expose server private key
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
	if !sys.ValidIPOrCIDR(req.Address) {
		writeErr(w, http.StatusBadRequest, "invalid WireGuard CIDR address")
		return
	}
	if req.ListenPort == 0 {
		req.ListenPort = 51820
	}
	if !sys.ValidPort(req.ListenPort) {
		writeErr(w, http.StatusBadRequest, "invalid listen_port")
		return
	}
	if req.Endpoint != "" && !sys.ValidHost(req.Endpoint) {
		writeErr(w, http.StatusBadRequest, "invalid endpoint host")
		return
	}
	if req.DNS == "" {
		req.DNS = s.Store.Get().LAN.IP
	}

	var next config.WireGuardState
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
		next = wg
		return nil
	}); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	if err := applyWireGuard(next); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	next.PrivateKey = ""
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "config": next})
}

func (s *Server) handleAddWireGuardPeer(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name       string `json:"name"`
		AllowedIPs string `json:"allowed_ips"` // e.g. "10.66.66.2/32"
		PublicKey  string `json:"public_key"`  // optional; auto-generated if omitted
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json body")
		return
	}
	if req.Name == "" || !sys.ValidSafeString(req.Name) {
		writeErr(w, http.StatusBadRequest, "invalid peer name")
		return
	}
	if !sys.ValidIPOrCIDR(req.AllowedIPs) {
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

	peer := config.WireGuardPeer{
		ID:         fmt.Sprintf("peer%d", time.Now().UnixMilli()),
		Name:       req.Name,
		PublicKey:  clientPub,
		AllowedIPs: req.AllowedIPs,
		Enabled:    true,
	}

	var wg config.WireGuardState
	if err := s.Store.Update(func(st *config.State) error {
		// Ensure server keypair exists so client_config always has a valid server PublicKey
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
		if strings.Contains(err.Error(), "duplicate") {
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

	// Build ready-to-import WireGuard client config (ideal for QR code rendering in frontend)
	clientConf := ""
	if clientPriv != "" {
		endpoint := wg.Endpoint
		if endpoint == "" {
			endpoint = "<YOUR_PUBLIC_IP_OR_DDNS>"
		}
		clientConf = fmt.Sprintf(
			"[Interface]\nPrivateKey = %s\nAddress = %s\nDNS = %s\n\n[Peer]\nPublicKey = %s\nEndpoint = %s:%d\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n",
			clientPriv, peer.AllowedIPs, wg.DNS, wg.PublicKey, endpoint, wg.ListenPort,
		)
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"ok":            true,
		"peer":          peer,
		"client_config": clientConf,
	})
}

func (s *Server) handleDelWireGuardPeer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	found := false
	var wg config.WireGuardState
	_ = s.Store.Update(func(st *config.State) error {
		next := make([]config.WireGuardPeer, 0, len(st.WireGuard.Peers))
		for _, p := range st.WireGuard.Peers {
			if p.ID == id {
				found = true
				continue
			}
			next = append(next, p)
		}
		st.WireGuard.Peers = next
		wg = st.WireGuard
		return nil
	})
	if !found {
		writeErr(w, http.StatusNotFound, "peer not found")
		return
	}
	if wg.Enabled {
		_ = applyWireGuard(wg)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

