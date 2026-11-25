package api

import (
	"bytes"
	"crypto/hmac"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/yalcer/netbee/netbeed/internal/auth"
	"github.com/yalcer/netbee/netbeed/internal/config"
	"github.com/yalcer/netbee/netbeed/internal/sys"
)

var errPayloadTooLarge = errors.New("request body exceeds maximum allowed size")

type Server struct {
	Cfg      config.RuntimeConfig
	Store    *config.Store
	Auth     *auth.Manager
	Rollback *sys.RollbackManager
	Version  string
	HTTPCli  *http.Client
	diagSem  chan struct{}
	iperfSrv *iperfServerManager
}

func NewServer(cfg config.RuntimeConfig, store *config.Store, authMgr *auth.Manager, version string) *Server {
	return &Server{
		Cfg:      cfg,
		Store:    store,
		Auth:     authMgr,
		Rollback: sys.NewRollbackManager(),
		Version:  version,
		HTTPCli:  &http.Client{Timeout: 8 * time.Second},
		diagSem:  make(chan struct{}, 2),
		iperfSrv: newIperfServerManager(),
	}
}

func (s *Server) Close() {
	if s.iperfSrv != nil {
		s.iperfSrv.Stop()
	}
}

func (s *Server) acquireDiagSlot() (func(), bool) {
	select {
	case s.diagSem <- struct{}{}:
		return func() { <-s.diagSem }, true
	default:
		return nil, false
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

	// System, Hardware Telemetry, Sysctl, TLS, Logs, Rollback & Backup
	mux.HandleFunc("GET /api/v1/system/overview", s.requireAuth(s.handleSystemOverview))
	mux.HandleFunc("GET /api/v1/system/stream", s.requireAuth(s.handleSystemStream))
	mux.HandleFunc("GET /api/v1/system/services", s.requireAuth(s.handleListServices))
	mux.HandleFunc("POST /api/v1/system/services/{name}/{action}", s.requireAuth(s.handleServiceAction))
	mux.HandleFunc("GET /api/v1/system/users", s.requireAuth(s.handleGetOSUsers))
	mux.HandleFunc("PUT /api/v1/system/users/{username}/password", s.requireAuth(s.handleSetOSUserPassword))
	mux.HandleFunc("PUT /api/v1/system/hostname", s.requireAuth(s.handleSetHostname))
	mux.HandleFunc("GET /api/v1/system/timezones", s.requireAuth(s.handleGetTimezones))
	mux.HandleFunc("PUT /api/v1/system/timezone", s.requireAuth(s.handleSetTimezone))
	mux.HandleFunc("GET /api/v1/system/sysctl", s.requireAuth(s.handleGetSysctl))
	mux.HandleFunc("PUT /api/v1/system/sysctl", s.requireAuth(s.handleSetSysctl))
	mux.HandleFunc("GET /api/v1/system/tls", s.requireAuth(s.handleGetTLS))
	mux.HandleFunc("PUT /api/v1/system/tls", s.requireAuth(s.handleSetTLS))
	mux.HandleFunc("DELETE /api/v1/system/tls", s.requireAuth(s.handleDeleteTLS))
	mux.HandleFunc("POST /api/v1/system/reboot", s.requireAuth(s.handleReboot))
	mux.HandleFunc("POST /api/v1/system/poweroff", s.requireAuth(s.handlePoweroff))
	mux.HandleFunc("GET /api/v1/system/pending-commit", s.requireAuth(s.handlePendingCommit))
	mux.HandleFunc("POST /api/v1/system/confirm", s.requireAuth(s.handleConfirmCommit))
	mux.HandleFunc("POST /api/v1/system/rollback", s.requireAuth(s.handleRollbackNow))
	mux.HandleFunc("GET /api/v1/system/backup", s.requireAuth(s.handleBackupDownload))
	mux.HandleFunc("POST /api/v1/system/restore", s.requireAuth(s.handleBackupRestore))
	mux.HandleFunc("GET /api/v1/logs/system", s.requireAuth(s.handleSystemLogs))
	mux.HandleFunc("GET /api/v1/logs/kernel", s.requireAuth(s.handleKernelLogs))
	mux.HandleFunc("POST /api/v1/logs/rotate", s.requireAuth(s.handleLogsRotate))
	mux.HandleFunc("POST /api/v1/logs/clear", s.requireAuth(s.handleLogsClear))

	// Network: Interfaces, Ethtool, Persisted Static Routes, Neighbors, LAN & WAN (DHCP/PPPoE/ONT VLAN/IPv6-PD)
	mux.HandleFunc("GET /api/v1/network/interfaces", s.requireAuth(s.handleInterfaces))
	mux.HandleFunc("GET /api/v1/network/ethtool/{iface}", s.requireAuth(s.handleGetEthtool))
	mux.HandleFunc("PUT /api/v1/network/ethtool/{iface}", s.requireAuth(s.handleSetEthtool))
	mux.HandleFunc("GET /api/v1/network/routes", s.requireAuth(s.handleRoutes))
	mux.HandleFunc("POST /api/v1/network/routes", s.requireAuth(s.handleAddRoute))
	mux.HandleFunc("DELETE /api/v1/network/routes", s.requireAuth(s.handleDelRoute))
	mux.HandleFunc("DELETE /api/v1/network/routes/{id}", s.requireAuth(s.handleDelRouteByID))
	mux.HandleFunc("GET /api/v1/network/neighbors", s.requireAuth(s.handleNeighbors))
	mux.HandleFunc("GET /api/v1/network/wan", s.requireAuth(s.handleGetWAN))
	mux.HandleFunc("PUT /api/v1/network/wan", s.requireAuth(s.handleSetWAN))
	mux.HandleFunc("POST /api/v1/network/wan/reconnect", s.requireAuth(s.handleWANReconnect))
	mux.HandleFunc("GET /api/v1/network/lan", s.requireAuth(s.handleGetLAN))
	mux.HandleFunc("PUT /api/v1/network/lan", s.requireAuth(s.handleSetLAN))

	// Firewall (nftables), Rules/Port-Forwards CRUD, Raw Custom .nft, Flow Offload & Conntrack
	mux.HandleFunc("GET /api/v1/firewall/ruleset", s.requireAuth(s.handleFirewallRuleset))
	mux.HandleFunc("GET /api/v1/firewall/config", s.requireAuth(s.handleGetFirewallConfig))
	mux.HandleFunc("PUT /api/v1/firewall/config", s.requireAuth(s.handleSetFirewallConfig))
	mux.HandleFunc("PATCH /api/v1/firewall/toggles", s.requireAuth(s.handlePatchFirewallToggles))
	mux.HandleFunc("POST /api/v1/firewall/rules", s.requireAuth(s.handleAddFirewallRule))
	mux.HandleFunc("PUT /api/v1/firewall/rules/{id}", s.requireAuth(s.handleUpdateFirewallRule))
	mux.HandleFunc("DELETE /api/v1/firewall/rules/{id}", s.requireAuth(s.handleDelFirewallRule))
	mux.HandleFunc("POST /api/v1/firewall/port-forwards", s.requireAuth(s.handleAddPortForward))
	mux.HandleFunc("PUT /api/v1/firewall/port-forwards/{id}", s.requireAuth(s.handleUpdatePortForward))
	mux.HandleFunc("DELETE /api/v1/firewall/port-forwards/{id}", s.requireAuth(s.handleDelPortForward))
	mux.HandleFunc("GET /api/v1/firewall/raw", s.requireAuth(s.handleGetFirewallRaw))
	mux.HandleFunc("PUT /api/v1/firewall/raw", s.requireAuth(s.handleSetFirewallRaw))
	mux.HandleFunc("PUT /api/v1/firewall/offload", s.requireAuth(s.handleSetFlowOffload))
	mux.HandleFunc("POST /api/v1/firewall/reload", s.requireAuth(s.handleReloadFirewall))
	mux.HandleFunc("GET /api/v1/firewall/conntrack", s.requireAuth(s.handleGetConntrack))
	mux.HandleFunc("DELETE /api/v1/firewall/conntrack", s.requireAuth(s.handleFlushConntrack))

	// DNS & DHCP (AdGuardHome full integration + transparent proxy)
	mux.HandleFunc("GET /api/v1/dns/status", s.requireAuth(s.handleDNSStatus))
	mux.HandleFunc("GET /api/v1/dns/config", s.requireAuth(s.handleDNSGetConfig))
	mux.HandleFunc("PUT /api/v1/dns/config", s.requireAuth(s.handleDNSSetConfig))
	mux.HandleFunc("GET /api/v1/dns/stats", s.requireAuth(s.handleDNSStats))
	mux.HandleFunc("GET /api/v1/dns/querylog", s.requireAuth(s.handleDNSQueryLog))
	mux.HandleFunc("GET /api/v1/dns/filters", s.requireAuth(s.handleDNSFilters))
	mux.HandleFunc("POST /api/v1/dns/filters", s.requireAuth(s.handleDNSFilterAdd))
	mux.HandleFunc("PUT /api/v1/dns/filters", s.requireAuth(s.handleDNSFilterSet))
	mux.HandleFunc("DELETE /api/v1/dns/filters", s.requireAuth(s.handleDNSFilterDel))
	mux.HandleFunc("POST /api/v1/dns/filters/refresh", s.requireAuth(s.handleDNSFiltersRefresh))
	mux.HandleFunc("PUT /api/v1/dns/rules", s.requireAuth(s.handleDNSSetUserRules))
	mux.HandleFunc("GET /api/v1/dns/blocked-services", s.requireAuth(s.handleDNSBlockedServicesGet))
	mux.HandleFunc("GET /api/v1/dns/blocked-services/all", s.requireAuth(s.handleDNSBlockedServicesAll))
	mux.HandleFunc("PUT /api/v1/dns/blocked-services", s.requireAuth(s.handleDNSBlockedServicesSet))
	mux.HandleFunc("POST /api/v1/dns/cache/clear", s.requireAuth(s.handleDNSCacheClear))
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
	mux.HandleFunc("PATCH /api/v1/vpn/wireguard/peers/{id}", s.requireAuth(s.handlePatchWireGuardPeer))
	mux.HandleFunc("DELETE /api/v1/vpn/wireguard/peers/{id}", s.requireAuth(s.handleDelWireGuardPeer))

	// SQM/CAKE QoS & vnStat Traffic
	mux.HandleFunc("GET /api/v1/qos/sqm", s.requireAuth(s.handleGetSQM))
	mux.HandleFunc("PUT /api/v1/qos/sqm", s.requireAuth(s.handleSetSQM))
	mux.HandleFunc("GET /api/v1/traffic/vnstat", s.requireAuth(s.handleGetVnStat))
	mux.HandleFunc("POST /api/v1/traffic/vnstat/interface", s.requireAuth(s.handleVnStatIface))
	mux.HandleFunc("GET /api/v1/traffic/live", s.requireAuth(s.handleLiveTraffic))

	// NTP (Chrony), IPv6 (radvd/dhcpcd), SSH (Dropbear) & Scheduled Tasks (crond)
	mux.HandleFunc("GET /api/v1/services/ntp", s.requireAuth(s.handleGetNTP))
	mux.HandleFunc("PUT /api/v1/services/ntp", s.requireAuth(s.handleSetNTP))
	mux.HandleFunc("GET /api/v1/services/ipv6", s.requireAuth(s.handleGetIPv6))
	mux.HandleFunc("PUT /api/v1/services/ipv6", s.requireAuth(s.handleSetIPv6))
	mux.HandleFunc("GET /api/v1/services/ssh", s.requireAuth(s.handleGetSSH))
	mux.HandleFunc("PUT /api/v1/services/ssh", s.requireAuth(s.handleSetSSH))
	mux.HandleFunc("POST /api/v1/services/ssh/keys", s.requireAuth(s.handleAddSSHKey))
	mux.HandleFunc("DELETE /api/v1/services/ssh/keys/{index}", s.requireAuth(s.handleDelSSHKey))
	mux.HandleFunc("GET /api/v1/services/cron", s.requireAuth(s.handleGetCron))
	mux.HandleFunc("POST /api/v1/services/cron", s.requireAuth(s.handleAddCron))
	mux.HandleFunc("PUT /api/v1/services/cron/{id}", s.requireAuth(s.handleUpdateCron))
	mux.HandleFunc("DELETE /api/v1/services/cron/{id}", s.requireAuth(s.handleDelCron))

	// Diagnostics & Temporary Local iperf3 Benchmark Server
	mux.HandleFunc("POST /api/v1/diag/ping", s.requireAuth(s.handleDiagPing))
	mux.HandleFunc("POST /api/v1/diag/mtr", s.requireAuth(s.handleDiagMTR))
	mux.HandleFunc("POST /api/v1/diag/iperf3", s.requireAuth(s.handleDiagIperf3))
	mux.HandleFunc("GET /api/v1/diag/iperf3/server", s.requireAuth(s.handleGetIperf3Server))
	mux.HandleFunc("POST /api/v1/diag/iperf3/server", s.requireAuth(s.handleStartIperf3Server))
	mux.HandleFunc("DELETE /api/v1/diag/iperf3/server", s.requireAuth(s.handleStopIperf3Server))
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
		if origin != "" {
			w.Header().Add("Vary", "Origin")
			if s.originAllowed(origin) {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-CSRF-Token")
				if r.Method == http.MethodOptions {
					w.WriteHeader(http.StatusNoContent)
					return
				}
			} else if r.Method == http.MethodOptions && !isSameOrigin(r, origin) {
				writeErr(w, http.StatusForbidden, "origin not allowed")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// originAllowed never permits wildcard "*" with credentials, preventing cross-origin credential theft.
func (s *Server) originAllowed(origin string) bool {
	if origin == "" || origin == "*" {
		return false
	}
	for _, allowed := range s.Cfg.CORSOrigins {
		if allowed != "" && allowed != "*" && strings.EqualFold(allowed, origin) {
			return true
		}
	}
	return false
}

func normalizeHostPort(hostPort, scheme string) string {
	hostPort = strings.ToLower(strings.TrimSpace(hostPort))
	h, p, err := net.SplitHostPort(hostPort)
	if err != nil {
		return hostPort
	}
	if (scheme == "https" && p == "443") || (scheme == "http" && p == "80") {
		return h
	}
	return net.JoinHostPort(h, p)
}

func isSameOrigin(r *http.Request, origin string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" || r.Host == "" {
		return false
	}
	reqScheme := "http"
	if r.TLS != nil {
		reqScheme = "https"
	}
	return normalizeHostPort(u.Host, strings.ToLower(u.Scheme)) == normalizeHostPort(r.Host, reqScheme)
}

func (s *Server) RestoreRuntimeOnBoot() {
	st := s.Store.Get()
	if _, err := os.Stat(nftVarsPath); err == nil {
		_ = syncNetIfConfigs(st)
	}
	restorePersistedEthtool(st.Ethtool)
	if len(st.CronJobs) > 0 {
		_ = s.syncRootCrontab(st.CronJobs)
	}
	if st.WireGuard.Enabled && st.WireGuard.PrivateKey != "" {
		if err := applyWireGuard(st.WireGuard); err != nil {
			log.Printf("boot restore WireGuard failed: %v", err)
		} else {
			log.Printf("boot restore WireGuard (%s) active", st.WireGuard.Interface)
		}
	}
	restorePersistedRoutes(st.StaticRoutes)
}

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, src, ok := s.Auth.AuthenticateWithSource(r)
		if !ok {
			writeErr(w, http.StatusUnauthorized, "authentication required")
			return
		}
		// Enforce Origin/Sec-Fetch-Site + X-CSRF-Token on all cookie-authenticated mutating requests
		if src == auth.SourceCookie && r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
			if origin := r.Header.Get("Origin"); origin != "" {
				if !isSameOrigin(r, origin) && !s.originAllowed(origin) {
					writeErr(w, http.StatusForbidden, "cross-origin cookie request rejected")
					return
				}
			} else if strings.EqualFold(r.Header.Get("Sec-Fetch-Site"), "cross-site") {
				writeErr(w, http.StatusForbidden, "cross-site cookie request rejected")
				return
			}
			hdr := r.Header.Get("X-CSRF-Token")
			if hdr == "" || !hmac.Equal([]byte(hdr), []byte(sess.CSRFToken)) {
				writeErr(w, http.StatusForbidden, "missing or invalid CSRF token")
				return
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
	baseDir := filepath.Clean(s.Cfg.WebDir)
	indexPath := filepath.Join(baseDir, "index.html")
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
	target := filepath.Join(baseDir, clean)
	if strings.HasPrefix(target, baseDir+string(os.PathSeparator)) {
		if info, err := os.Stat(target); err == nil && !info.IsDir() {
			http.ServeFile(w, r, target)
			return
		}
	}
	http.ServeFile(w, r, indexPath)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeValidatedRawJSON(w http.ResponseWriter, status int, raw []byte, emptyFallback string) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		if emptyFallback == "" {
			emptyFallback = "{}"
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(emptyFallback))
		return
	}
	if !json.Valid(trimmed) {
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"error": "command returned invalid JSON output",
			"raw":   string(trimmed),
		})
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(trimmed)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": msg})
}

func readBoundedBody(r *http.Request, maxBytes int64) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	defer r.Body.Close()
	buf, err := io.ReadAll(io.LimitReader(r.Body, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(buf)) > maxBytes {
		return nil, errPayloadTooLarge
	}
	return buf, nil
}

func decodeJSON(r *http.Request, dst any) error {
	buf, err := readBoundedBody(r, 1<<20) // 1 MB max JSON payload
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(buf))
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return errors.New("unexpected trailing data after JSON payload")
	}
	return nil
}
