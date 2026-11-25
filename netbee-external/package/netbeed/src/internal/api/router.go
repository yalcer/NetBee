package api

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/yalcer/netbee/netbeed/internal/auth"
	"github.com/yalcer/netbee/netbeed/internal/config"
	"github.com/yalcer/netbee/netbeed/internal/sys"
)

type Server struct {
	Cfg      config.RuntimeConfig
	Store    *config.Store
	Auth     *auth.Manager
	Rollback *sys.RollbackManager
	Version  string
	HTTPCli  *http.Client
}

func NewServer(cfg config.RuntimeConfig, store *config.Store, authMgr *auth.Manager, version string) *Server {
	return &Server{
		Cfg:      cfg,
		Store:    store,
		Auth:     authMgr,
		Rollback: sys.NewRollbackManager(),
		Version:  version,
		HTTPCli:  &http.Client{Timeout: 8 * time.Second},
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Public / Auth endpoints
	mux.HandleFunc("GET /api/v1/health", s.handleHealth)
	mux.HandleFunc("POST /api/v1/auth/login", s.handleLogin)
	mux.HandleFunc("POST /api/v1/auth/logout", s.requireAuth(s.handleLogout))
	mux.HandleFunc("GET /api/v1/auth/me", s.requireAuth(s.handleMe))
	mux.HandleFunc("POST /api/v1/auth/password", s.requireAuth(s.handleChangePassword))

	// System, Telemetry, Logs, Rollback & Backup
	mux.HandleFunc("GET /api/v1/system/overview", s.requireAuth(s.handleSystemOverview))
	mux.HandleFunc("GET /api/v1/system/stream", s.requireAuth(s.handleSystemStream))
	mux.HandleFunc("GET /api/v1/system/services", s.requireAuth(s.handleListServices))
	mux.HandleFunc("POST /api/v1/system/services/{name}/{action}", s.requireAuth(s.handleServiceAction))
	mux.HandleFunc("PUT /api/v1/system/hostname", s.requireAuth(s.handleSetHostname))
	mux.HandleFunc("PUT /api/v1/system/timezone", s.requireAuth(s.handleSetTimezone))
	mux.HandleFunc("POST /api/v1/system/reboot", s.requireAuth(s.handleReboot))
	mux.HandleFunc("POST /api/v1/system/poweroff", s.requireAuth(s.handlePoweroff))
	mux.HandleFunc("GET /api/v1/system/pending-commit", s.requireAuth(s.handlePendingCommit))
	mux.HandleFunc("POST /api/v1/system/confirm", s.requireAuth(s.handleConfirmCommit))
	mux.HandleFunc("POST /api/v1/system/rollback", s.requireAuth(s.handleRollbackNow))
	mux.HandleFunc("GET /api/v1/system/backup", s.requireAuth(s.handleBackupDownload))
	mux.HandleFunc("POST /api/v1/system/restore", s.requireAuth(s.handleBackupRestore))
	mux.HandleFunc("GET /api/v1/logs/system", s.requireAuth(s.handleSystemLogs))
	mux.HandleFunc("GET /api/v1/logs/kernel", s.requireAuth(s.handleKernelLogs))

	// Network: Interfaces, Routes, Neighbors, LAN & WAN (DHCP/PPPoE/ONT VLAN/IPv6-PD)
	mux.HandleFunc("GET /api/v1/network/interfaces", s.requireAuth(s.handleInterfaces))
	mux.HandleFunc("GET /api/v1/network/routes", s.requireAuth(s.handleRoutes))
	mux.HandleFunc("POST /api/v1/network/routes", s.requireAuth(s.handleAddRoute))
	mux.HandleFunc("DELETE /api/v1/network/routes", s.requireAuth(s.handleDelRoute))
	mux.HandleFunc("GET /api/v1/network/neighbors", s.requireAuth(s.handleNeighbors))
	mux.HandleFunc("GET /api/v1/network/wan", s.requireAuth(s.handleGetWAN))
	mux.HandleFunc("PUT /api/v1/network/wan", s.requireAuth(s.handleSetWAN))
	mux.HandleFunc("POST /api/v1/network/wan/reconnect", s.requireAuth(s.handleWANReconnect))
	mux.HandleFunc("GET /api/v1/network/lan", s.requireAuth(s.handleGetLAN))
	mux.HandleFunc("PUT /api/v1/network/lan", s.requireAuth(s.handleSetLAN))

	// Firewall (nftables), Port Forwards (DNAT), Flow Offload & Conntrack
	mux.HandleFunc("GET /api/v1/firewall/ruleset", s.requireAuth(s.handleFirewallRuleset))
	mux.HandleFunc("GET /api/v1/firewall/config", s.requireAuth(s.handleGetFirewallConfig))
	mux.HandleFunc("PUT /api/v1/firewall/config", s.requireAuth(s.handleSetFirewallConfig))
	mux.HandleFunc("POST /api/v1/firewall/rules", s.requireAuth(s.handleAddFirewallRule))
	mux.HandleFunc("DELETE /api/v1/firewall/rules/{id}", s.requireAuth(s.handleDelFirewallRule))
	mux.HandleFunc("POST /api/v1/firewall/port-forwards", s.requireAuth(s.handleAddPortForward))
	mux.HandleFunc("DELETE /api/v1/firewall/port-forwards/{id}", s.requireAuth(s.handleDelPortForward))
	mux.HandleFunc("PUT /api/v1/firewall/offload", s.requireAuth(s.handleSetFlowOffload))
	mux.HandleFunc("POST /api/v1/firewall/reload", s.requireAuth(s.handleReloadFirewall))
	mux.HandleFunc("GET /api/v1/firewall/conntrack", s.requireAuth(s.handleGetConntrack))
	mux.HandleFunc("DELETE /api/v1/firewall/conntrack", s.requireAuth(s.handleFlushConntrack))

	// DNS & DHCP (AdGuardHome integration + full transparent proxy)
	mux.HandleFunc("GET /api/v1/dns/status", s.requireAuth(s.handleDNSStatus))
	mux.HandleFunc("GET /api/v1/dns/stats", s.requireAuth(s.handleDNSStats))
	mux.HandleFunc("GET /api/v1/dns/querylog", s.requireAuth(s.handleDNSQueryLog))
	mux.HandleFunc("GET /api/v1/dns/filters", s.requireAuth(s.handleDNSFilters))
	mux.HandleFunc("POST /api/v1/dns/protection", s.requireAuth(s.handleDNSProtection))
	mux.HandleFunc("GET /api/v1/dns/rewrites", s.requireAuth(s.handleDNSRewritesList))
	mux.HandleFunc("POST /api/v1/dns/rewrites", s.requireAuth(s.handleDNSRewriteAdd))
	mux.HandleFunc("DELETE /api/v1/dns/rewrites", s.requireAuth(s.handleDNSRewriteDel))
	mux.HandleFunc("GET /api/v1/dhcp/status", s.requireAuth(s.handleDHCPStatus))
	mux.HandleFunc("PUT /api/v1/dhcp/config", s.requireAuth(s.handleDHCPSetConfig))
	mux.HandleFunc("POST /api/v1/dhcp/leases/static", s.requireAuth(s.handleDHCPStaticAdd))
	mux.HandleFunc("DELETE /api/v1/dhcp/leases/static", s.requireAuth(s.handleDHCPStaticDel))
	mux.HandleFunc("/api/v1/adguard/", s.requireAuth(s.handleAdGuardProxy))

	// WireGuard VPN
	mux.HandleFunc("GET /api/v1/vpn/wireguard", s.requireAuth(s.handleGetWireGuard))
	mux.HandleFunc("PUT /api/v1/vpn/wireguard", s.requireAuth(s.handleSetWireGuard))
	mux.HandleFunc("POST /api/v1/vpn/wireguard/peers", s.requireAuth(s.handleAddWireGuardPeer))
	mux.HandleFunc("DELETE /api/v1/vpn/wireguard/peers/{id}", s.requireAuth(s.handleDelWireGuardPeer))

	// SQM/CAKE QoS & vnStat Traffic
	mux.HandleFunc("GET /api/v1/qos/sqm", s.requireAuth(s.handleGetSQM))
	mux.HandleFunc("PUT /api/v1/qos/sqm", s.requireAuth(s.handleSetSQM))
	mux.HandleFunc("GET /api/v1/traffic/vnstat", s.requireAuth(s.handleGetVnStat))
	mux.HandleFunc("POST /api/v1/traffic/vnstat/interface", s.requireAuth(s.handleVnStatIface))
	mux.HandleFunc("GET /api/v1/traffic/live", s.requireAuth(s.handleLiveTraffic))

	// NTP (Chrony), IPv6 (radvd/dhcpcd) & SSH (Dropbear)
	mux.HandleFunc("GET /api/v1/services/ntp", s.requireAuth(s.handleGetNTP))
	mux.HandleFunc("PUT /api/v1/services/ntp", s.requireAuth(s.handleSetNTP))
	mux.HandleFunc("GET /api/v1/services/ipv6", s.requireAuth(s.handleGetIPv6))
	mux.HandleFunc("PUT /api/v1/services/ipv6", s.requireAuth(s.handleSetIPv6))
	mux.HandleFunc("GET /api/v1/services/ssh", s.requireAuth(s.handleGetSSH))
	mux.HandleFunc("PUT /api/v1/services/ssh", s.requireAuth(s.handleSetSSH))
	mux.HandleFunc("POST /api/v1/services/ssh/keys", s.requireAuth(s.handleAddSSHKey))
	mux.HandleFunc("DELETE /api/v1/services/ssh/keys/{index}", s.requireAuth(s.handleDelSSHKey))

	// Diagnostics
	mux.HandleFunc("POST /api/v1/diag/ping", s.requireAuth(s.handleDiagPing))
	mux.HandleFunc("POST /api/v1/diag/mtr", s.requireAuth(s.handleDiagMTR))
	mux.HandleFunc("POST /api/v1/diag/iperf3", s.requireAuth(s.handleDiagIperf3))
	mux.HandleFunc("POST /api/v1/diag/dns", s.requireAuth(s.handleDiagDNS))
	mux.HandleFunc("POST /api/v1/diag/capture", s.requireAuth(s.handleDiagCapture))

	// Static User Frontend Hosting (SPA fallback from web_dir)
	mux.HandleFunc("/", s.handleStaticFrontend)

	return s.corsMiddleware(s.securityHeaders(mux))
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && s.originAllowed(origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-CSRF-Token")
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) originAllowed(origin string) bool {
	for _, allowed := range s.Cfg.CORSOrigins {
		if allowed == "*" || allowed == origin {
			return true
		}
	}
	return false
}

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, ok := s.Auth.Authenticate(r)
		if !ok {
			writeErr(w, http.StatusUnauthorized, "authentication required")
			return
		}
		// Enforce CSRF header for cookie-authenticated mutating requests
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
			if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
				if hdr := r.Header.Get("X-CSRF-Token"); hdr != "" && hdr != sess.CSRFToken {
					writeErr(w, http.StatusForbidden, "invalid CSRF token")
					return
				}
			}
		}
		next(w, r)
	}
}

func (s *Server) handleStaticFrontend(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		writeErr(w, http.StatusNotFound, "endpoint not found")
		return
	}
	indexPath := filepath.Join(s.Cfg.WebDir, "index.html")
	if _, err := os.Stat(indexPath); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"service": "netbeed",
			"version": s.Version,
			"status":  "ready",
			"web_dir": s.Cfg.WebDir,
			"message": "Place your frontend build files (index.html, assets/) in web_dir to serve the UI.",
			"api":     "/api/v1/health",
		})
		return
	}

	clean := filepath.Clean("/" + r.URL.Path)
	target := filepath.Join(s.Cfg.WebDir, clean)
	if info, err := os.Stat(target); err == nil && !info.IsDir() {
		http.ServeFile(w, r, target)
		return
	}
	http.ServeFile(w, r, indexPath)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeRawJSON(w http.ResponseWriter, status int, raw []byte) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(raw)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": msg})
}

func decodeJSON(r *http.Request, dst any) error {
	defer r.Body.Close()
	lim := io.LimitReader(r.Body, 1<<20) // 1 MB max JSON payload
	dec := json.NewDecoder(lim)
	return dec.Decode(dst)
}
