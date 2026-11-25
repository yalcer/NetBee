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

// --- NTP (Chrony) ---

func (s *Server) handleGetNTP(w http.ResponseWriter, r *http.Request) {
	tracking, _ := sys.Run(3*time.Second, "chronyc", "tracking")
	sources, _ := sys.Run(3*time.Second, "chronyc", "sources")
	conf, _ := os.ReadFile("/etc/chrony.conf")
	var servers []string
	serveLAN := false
	for _, line := range strings.Split(string(conf), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && (f[0] == "server" || f[0] == "pool") {
			servers = append(servers, f[1])
		}
		if len(f) >= 2 && f[0] == "allow" {
			serveLAN = true
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"servers":   servers,
		"serve_lan": serveLAN,
		"tracking":  tracking.Stdout,
		"sources":   sources.Stdout,
	})
}

func (s *Server) handleSetNTP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Servers  []string `json:"servers"`
		ServeLAN bool     `json:"serve_lan"`
	}
	if err := decodeJSON(r, &req); err != nil || len(req.Servers) == 0 {
		writeErr(w, http.StatusBadRequest, "provide at least one NTP server")
		return
	}
	var b strings.Builder
	b.WriteString("# Managed by NetBee OS (netbeed)\n")
	for _, srv := range req.Servers {
		srv = strings.TrimSpace(srv)
		if !sys.ValidHost(srv) {
			writeErr(w, http.StatusBadRequest, "invalid NTP server: "+srv)
			return
		}
		if sys.ValidIPv4(srv) {
			fmt.Fprintf(&b, "server %s iburst\n", srv)
		} else {
			fmt.Fprintf(&b, "pool %s iburst\n", srv)
		}
	}
	b.WriteString("driftfile /var/lib/chrony/drift\nmakestep 1.0 -1\nrtcsync\n")
	if req.ServeLAN {
		b.WriteString("allow 192.168.10.0/24\nlocal stratum 10\n")
	}
	if err := config.AtomicWriteFile("/etc/chrony.conf", []byte(b.String()), 0644); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	_, _ = sys.Run(10*time.Second, "/etc/init.d/S49chronyd", "restart")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// --- IPv6 (radvd SLAAC + dhcpcd PD) ---

func (s *Server) handleGetIPv6(w http.ResponseWriter, r *http.Request) {
	_, err := os.Stat("/etc/radvd.conf")
	radvdEnabled := err == nil
	radvdRunning := false
	if _, err := sys.Run(2*time.Second, "pidof", "radvd"); err == nil {
		radvdRunning = true
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"radvd_enabled": radvdEnabled,
		"radvd_running": radvdRunning,
		"ipv6_pd":       s.Store.Get().WAN.IPv6PD,
	})
}

func (s *Server) handleSetIPv6(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RadvdEnabled bool `json:"radvd_enabled"`
		IPv6PD       bool `json:"ipv6_pd"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json body")
		return
	}
	_ = s.Store.Update(func(st *config.State) error {
		st.WAN.IPv6PD = req.IPv6PD
		return nil
	})
	st := s.Store.Get()
	_ = config.AtomicWriteFile("/etc/dhcpcd.conf", []byte(RenderDHCPCDConf(st.LAN, st.WAN)), 0644)
	_, _ = sys.Run(10*time.Second, "/etc/init.d/S41dhcpcd", "restart")

	if req.RadvdEnabled {
		tpl, err := os.ReadFile("/etc/radvd.conf.example")
		if err != nil {
			tpl = []byte("interface eth0\n{\n    AdvSendAdvert on;\n    IgnoreIfMissing on;\n    prefix ::/64 { AdvOnLink on; AdvAutonomous on; AdvRouterAddr off; };\n};\n")
		}
		_ = config.AtomicWriteFile("/etc/radvd.conf", tpl, 0644)
		_, _ = sys.Run(10*time.Second, "/etc/init.d/S50radvd", "restart")
	} else {
		_, _ = sys.Run(5*time.Second, "/etc/init.d/S50radvd", "stop")
		_ = os.Remove("/etc/radvd.conf")
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// --- SSH (Dropbear & Authorized Keys) ---

const authorizedKeysPath = "/root/.ssh/authorized_keys"

func readAuthorizedKeys() []string {
	data, err := os.ReadFile(authorizedKeysPath)
	if err != nil {
		return []string{}
	}
	var keys []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			keys = append(keys, line)
		}
	}
	return keys
}

func (s *Server) handleGetSSH(w http.ResponseWriter, r *http.Request) {
	def, _ := os.ReadFile("/etc/default/dropbear")
	raw := string(def)
	writeJSON(w, http.StatusOK, map[string]any{
		"dropbear_default": strings.TrimSpace(raw),
		"password_auth":    !strings.Contains(raw, "-s"),
		"authorized_keys":  readAuthorizedKeys(),
	})
}

func (s *Server) handleSetSSH(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PasswordAuth bool `json:"password_auth"`
		IdleTimeout  int  `json:"idle_timeout"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json body")
		return
	}
	if !req.PasswordAuth && len(readAuthorizedKeys()) == 0 {
		writeErr(w, http.StatusBadRequest, "add at least one SSH public key before disabling password auth")
		return
	}
	if req.IdleTimeout < 0 || req.IdleTimeout > 86400 {
		writeErr(w, http.StatusBadRequest, "idle_timeout must be 0..86400")
		return
	}
	lanIP := s.Store.Get().LAN.IP
	if lanIP == "" {
		lanIP = "192.168.10.1"
	}
	args := fmt.Sprintf("-p %s:22", lanIP)
	if req.IdleTimeout > 0 {
		args += fmt.Sprintf(" -I %d", req.IdleTimeout)
	}
	if !req.PasswordAuth {
		args += " -s"
	}
	content := fmt.Sprintf("# Managed by NetBee OS (netbeed)\nDROPBEAR_ARGS=%q\n", args)
	if err := config.AtomicWriteFile("/etc/default/dropbear", []byte(content), 0644); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	_, _ = sys.Run(5*time.Second, "/etc/init.d/S50dropbear", "restart")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "args": args})
}

func (s *Server) handleAddSSHKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PublicKey string `json:"public_key"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json body")
		return
	}
	key := strings.TrimSpace(req.PublicKey)
	if strings.ContainsAny(key, "\n\r") || !(strings.HasPrefix(key, "ssh-ed25519 ") || strings.HasPrefix(key, "ssh-rsa ") || strings.HasPrefix(key, "ecdsa-sha2-")) {
		writeErr(w, http.StatusBadRequest, "invalid SSH public key format")
		return
	}
	keys := append(readAuthorizedKeys(), key)
	_ = os.MkdirAll("/root/.ssh", 0700)
	if err := config.AtomicWriteFile(authorizedKeysPath, []byte(strings.Join(keys, "\n")+"\n"), 0600); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"ok": true, "count": len(keys)})
}

func (s *Server) handleDelSSHKey(w http.ResponseWriter, r *http.Request) {
	idx, err := strconv.Atoi(r.PathValue("index"))
	keys := readAuthorizedKeys()
	if err != nil || idx < 0 || idx >= len(keys) {
		writeErr(w, http.StatusBadRequest, "invalid key index")
		return
	}
	next := append(keys[:idx], keys[idx+1:]...)
	content := ""
	if len(next) > 0 {
		content = strings.Join(next, "\n") + "\n"
	}
	if err := config.AtomicWriteFile(authorizedKeysPath, []byte(content), 0600); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "count": len(next)})
}
