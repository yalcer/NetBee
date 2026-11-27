package api

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yalcer/netbee/netbeed/internal/auth"
	"github.com/yalcer/netbee/netbeed/internal/config"
	"github.com/yalcer/netbee/netbeed/internal/sys"
)

func newTestServer(t *testing.T, adguardURL string, corsOrigins ...string) (*Server, string) {
	t.Helper()
	dir := t.TempDir()
	webDir := filepath.Join(dir, "web")
	_ = os.MkdirAll(webDir, 0755)
	_ = os.WriteFile(filepath.Join(webDir, "index.html"), []byte("<html>netbee-spa</html>"), 0644)

	if len(corsOrigins) == 0 {
		corsOrigins = []string{"http://localhost:5173"}
	}
	cfg := config.RuntimeConfig{
		TLSDIR:          filepath.Join(dir, "tls"),
		WebDir:          webDir,
		StatePath:       filepath.Join(dir, "state.json"),
		AuthPath:        filepath.Join(dir, "auth.json"),
		CrontabPath:     filepath.Join(dir, "crontabs", "root"),
		AdGuardURL:      adguardURL,
		AdGuardUser:     "admin",
		AdGuardPass:     "netbee",
		RollbackSeconds: 2,
		CORSOrigins:     corsOrigins,
	}
	store, err := config.NewStore(cfg.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	authMgr, err := auth.NewManager(cfg.AuthPath)
	if err != nil {
		t.Fatal(err)
	}
	return NewServer(cfg, store, authMgr, "test"), dir
}

func buildTarGz(t *testing.T, entries []tar.Header, bodies []string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for i, hdr := range entries {
		body := ""
		if i < len(bodies) {
			body = bodies[i]
		}
		if hdr.Typeflag == tar.TypeReg || hdr.Typeflag == 0 {
			hdr.Typeflag = tar.TypeReg
			hdr.Size = int64(len(body))
		}
		if hdr.Mode == 0 {
			hdr.Mode = 0600
		}
		if err := tw.WriteHeader(&hdr); err != nil {
			t.Fatal(err)
		}
		if hdr.Typeflag == tar.TypeReg && len(body) > 0 {
			if _, err := tw.Write([]byte(body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestAuthCORSOriginAndCSRFProtection(t *testing.T) {
	srv, _ := newTestServer(t, "", "*", "http://localhost:5173")
	h := srv.Handler()

	// Wildcard CORS must NEVER echo arbitrary evil origin with credentials
	req := httptest.NewRequest(http.MethodOptions, "/api/v1/system/overview", nil)
	req.Host = "192.168.10.1"
	req.Header.Set("Origin", "https://evil.example")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("wildcard CORS allowed untrusted origin: code=%d allow=%q", rec.Code, rec.Header().Get("Access-Control-Allow-Origin"))
	}

	// Explicit whitelisted origin succeeds preflight
	req = httptest.NewRequest(http.MethodOptions, "/api/v1/system/overview", nil)
	req.Host = "192.168.10.1"
	req.Header.Set("Origin", "http://localhost:5173")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent || rec.Header().Get("Access-Control-Allow-Origin") != "http://localhost:5173" {
		t.Fatalf("expected 204 for explicit CORS origin, got %d", rec.Code)
	}

	login := func() (string, string, *http.Cookie) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString(`{"username":"admin","password":"netbee"}`)))
		if rec.Code != http.StatusOK {
			t.Fatalf("login failed: %d %s", rec.Code, rec.Body.String())
		}
		var resp struct {
			Token     string `json:"token"`
			CSRFToken string `json:"csrf_token"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		var ck *http.Cookie
		for _, c := range rec.Result().Cookies() {
			if c.Name == auth.SessionCookieName {
				ck = c
			}
		}
		return resp.Token, resp.CSRFToken, ck
	}
	tok1, csrf1, ck1 := login()
	tok2, _, _ := login()

	// Cookie POST without X-CSRF-Token -> 403
	req = httptest.NewRequest(http.MethodPost, "/api/v1/system/confirm", nil)
	req.AddCookie(ck1)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when CSRF header missing, got %d", rec.Code)
	}

	// Cookie POST with valid CSRF token BUT untrusted cross-origin Origin header -> 403
	req = httptest.NewRequest(http.MethodPost, "/api/v1/system/confirm", nil)
	req.Host = "192.168.10.1"
	req.Header.Set("Origin", "https://attacker.invalid")
	req.Header.Set("X-CSRF-Token", csrf1)
	req.AddCookie(ck1)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 on cross-origin cookie POST, got %d", rec.Code)
	}

	// Cookie POST with same-origin + valid X-CSRF-Token -> 200
	req = httptest.NewRequest(http.MethodPost, "/api/v1/system/confirm", nil)
	req.Host = "192.168.10.1"
	req.Header.Set("Origin", "http://192.168.10.1")
	req.Header.Set("X-CSRF-Token", csrf1)
	req.AddCookie(ck1)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 on same-origin cookie POST, got %d %s", rec.Code, rec.Body.String())
	}

	// Trailing garbage JSON must be rejected
	req = httptest.NewRequest(http.MethodPut, "/api/v1/system/hostname", bytes.NewBufferString(`{"hostname":"netbee"}{"extra":1}`))
	req.Header.Set("Authorization", "Bearer "+tok1)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on trailing JSON garbage, got %d", rec.Code)
	}

	// Password change revokes tok2 while keeping tok1 valid
	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/password", bytes.NewBufferString(`{"current_password":"netbee","new_password":"StrongPassword123"}`))
	req.Header.Set("Authorization", "Bearer "+tok1)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("password change failed: %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+tok2)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for revoked session, got %d", rec.Code)
	}

	if err := srv.Auth.Reload(); err != nil {
		t.Fatalf("Auth.Reload failed: %v", err)
	}
	req = httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+tok1)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 after Auth.Reload(), got %d", rec.Code)
	}
}

func TestValidatorsBackupTarGzAndSymlinkProtection(t *testing.T) {
	for _, okHost := range []string{"1.1.1.1", "2606:4700:4700::1111", "netbee", "dns.cloudflare.com"} {
		if !sys.ValidHost(okHost) {
			t.Fatalf("ValidHost rejected valid host %q", okHost)
		}
	}
	for _, badHost := range []string{"", "-v", "..:..", "example.com:8080", "bad..domain", "evil.com/path"} {
		if sys.ValidHost(badHost) {
			t.Fatalf("ValidHost accepted invalid host %q", badHost)
		}
	}

	if !sys.ValidIPv4Netmask("255.255.255.0") || sys.ValidIPv4Netmask("192.168.10.1") || sys.ValidIPv4Netmask("255.255.255.255") {
		t.Fatal("ValidIPv4Netmask check failed")
	}
	if !sys.ValidUnicastIPv4Host("192.168.10.1", "255.255.255.0") ||
		sys.ValidUnicastIPv4Host("192.168.10.0", "255.255.255.0") ||
		sys.ValidUnicastIPv4Host("192.168.10.255", "255.255.255.0") ||
		sys.ValidUnicastIPv4Host("127.0.0.1", "255.0.0.0") {
		t.Fatal("ValidUnicastIPv4Host check failed")
	}

	validKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
	if !sys.ValidWGKey(validKey) || sys.ValidWGKey("shortkey====") || sys.ValidWGKey(strings.Repeat("A", 43)) {
		t.Fatal("ValidWGKey check failed")
	}
	if !sys.ValidIPList("192.168.10.1, 1.1.1.1") || sys.ValidIPList("1.1.1.1\nPostUp = id") {
		t.Fatal("ValidIPList check failed")
	}

	// Valid NetBee backup tar.gz (including nftables.vars and 99-netbee-router.conf) passes
	goodTar := buildTarGz(t, []tar.Header{
		{Name: "etc/netbee", Typeflag: tar.TypeDir, Mode: 0755},
		{Name: "etc/netbee/state.json", Typeflag: tar.TypeReg},
		{Name: "etc/netbee/netif.env", Typeflag: tar.TypeReg},
		{Name: "etc/nftables.vars", Typeflag: tar.TypeReg},
		{Name: "etc/sysctl.d/99-netbee-router.conf", Typeflag: tar.TypeReg},
		{Name: "etc/ppp/chap-secrets", Typeflag: tar.TypeReg},
		{Name: "root/.ssh/authorized_keys", Typeflag: tar.TypeReg},
	}, []string{"", `{"lan":{"ip":"192.168.10.1"}}`, `WAN_IF="eth1"`, `define LAN_IF = "eth0"`, `net.ipv4.ip_forward = 1`, `"u" * "p" *`, "ssh-ed25519 AAAA..."})
	if err := ValidateBackupTarGz(goodTar); err != nil {
		t.Fatalf("expected valid backup tar.gz to pass, got: %v", err)
	}

	symlinkTar := buildTarGz(t, []tar.Header{
		{Name: "etc/netbee/evil", Typeflag: tar.TypeSymlink, Linkname: "/usr/sbin"},
	}, nil)
	if err := ValidateBackupTarGz(symlinkTar); err == nil {
		t.Fatal("symlink inside backup archive was NOT rejected")
	}

	for _, forbidden := range []string{"etc/shadow", "etc/passwd", "etc/init.d/S90netbeed", "etc/ppp/ip-up", "etc/cron/crontabs/root", "../etc/hostname"} {
		badTar := buildTarGz(t, []tar.Header{{Name: forbidden, Typeflag: tar.TypeReg}}, []string{"pwn"})
		if err := ValidateBackupTarGz(badTar); err == nil {
			t.Fatalf("forbidden backup path %q was NOT rejected", forbidden)
		}
	}
}

func TestSubsystemIntegrationsWireGuardTLSAndServices(t *testing.T) {
	srv, _ := newTestServer(t, "")
	h := srv.Handler()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString(`{"username":"admin","password":"netbee"}`)))
	var lr struct{ Token string }
	_ = json.Unmarshal(rec.Body.Bytes(), &lr)
	authHdr := "Bearer " + lr.Token

	// Stopping netbeed over the API MUST be blocked (prevents UI self-lockout)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/system/services/netbeed/stop", nil)
	req.Header.Set("Authorization", authHdr)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when trying to stop netbeed via API, got %d", rec.Code)
	}

	// Dynamic nftables.vars & netif.env rendering for ONT VLAN + custom NICs
	st := config.DefaultState()
	st.LAN.Interface = "eth0"
	st.WAN.Interface = "eth2"
	st.WAN.Mode = "ont_vlan"
	st.WAN.VLANID = 35
	nftVars := RenderNftablesVars(st)
	if !strings.Contains(nftVars, `define WAN_IFS = { "eth2", "eth2.35", "ppp0" }`) {
		t.Fatalf("unexpected nftables.vars:\n%s", nftVars)
	}
	netEnv := RenderNetifEnv(st)
	if !strings.Contains(netEnv, `WAN_IF="eth2"`) || !strings.Contains(netEnv, `WAN_MODE="ont_vlan"`) {
		t.Fatalf("unexpected netif.env:\n%s", netEnv)
	}

	// Custom TLS upload + inspection + delete lifecycle
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := x509.Certificate{
		SerialNumber: big.NewInt(99),
		Subject:      pkix.Name{CommonName: "router.home.arpa", Organization: []string{"Home Lab CA"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"router.home.arpa"},
	}
	der, _ := x509.CreateCertificate(rand.Reader, &tpl, &tpl, &priv.PublicKey, priv)
	keyDER, _ := x509.MarshalECPrivateKey(priv)
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))

	tlsPayload, _ := json.Marshal(map[string]any{"cert_pem": certPEM, "key_pem": keyPEM, "reload": false})
	req = httptest.NewRequest(http.MethodPut, "/api/v1/system/tls", bytes.NewReader(tlsPayload))
	req.Header.Set("Authorization", authHdr)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT /api/v1/system/tls failed: %d %s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/system/tls", nil)
	req.Header.Set("Authorization", authHdr)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"auto_self_signed":false`) || !strings.Contains(rec.Body.String(), "router.home.arpa") {
		t.Fatalf("unexpected GET /api/v1/system/tls: %s", rec.Body.String())
	}

	// WireGuard peer PSK redaction & PATCH peer lifecycle
	pubKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x21}, 32))
	pskKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x33}, 32))
	_ = srv.Store.Update(func(s *config.State) error {
		s.WireGuard.Peers = append(s.WireGuard.Peers, config.WireGuardPeer{
			ID: "peer1", Name: "Phone", PublicKey: pubKey, PresharedKey: pskKey, AllowedIPs: "10.66.66.2/32", Enabled: true,
		})
		return nil
	})

	req = httptest.NewRequest(http.MethodGet, "/api/v1/vpn/wireguard", nil)
	req.Header.Set("Authorization", authHdr)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if strings.Contains(rec.Body.String(), pskKey) || !strings.Contains(rec.Body.String(), `"has_psk":true`) {
		t.Fatalf("WireGuard PSK was not redacted properly: %s", rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPatch, "/api/v1/vpn/wireguard/peers/peer1", bytes.NewBufferString(`{"name":"Laptop","enabled":false,"allowed_ips":"10.66.66.9"}`))
	req.Header.Set("Authorization", authHdr)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"10.66.66.9/32"`) || !strings.Contains(rec.Body.String(), `"enabled":false`) {
		t.Fatalf("PATCH WireGuard peer failed: %d %s", rec.Code, rec.Body.String())
	}

	// Installed timezones & sysctl GET endpoints
	for _, ep := range []string{"/api/v1/system/timezones", "/api/v1/system/sysctl"} {
		req = httptest.NewRequest(http.MethodGet, ep, nil)
		req.Header.Set("Authorization", authHdr)
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s failed: %d %s", ep, rec.Code, rec.Body.String())
		}
	}

	// Ethtool parser & validator checks
	sampleEthtool := "Settings for eth0:\n\tSupported link modes:   100baseT/Full\n\t                        1000baseT/Full 2500baseT/Full\n\tSpeed: 2500Mb/s\n\tDuplex: Full\n\tAuto-negotiation: on\n\tSupports Wake-on: pumbg\n\tWake-on: g\n\tLink detected: yes\n"
	parsedLink := ParseEthtoolSettings(sampleEthtool)
	if parsedLink["speed"] != "2500Mb/s" || parsedLink["wake_on"] != "g" || parsedLink["link_detected"] != true {
		t.Fatalf("unexpected ParseEthtoolSettings: %+v", parsedLink)
	}
	sampleFeatures := "Features for eth0:\nrx-checksumming: on\ntcp-segmentation-offload: off\nrx-vlan-offload: off [fixed]\n"
	parsedFeat := ParseEthtoolFeatures(sampleFeatures)
	if !parsedFeat["rx"].Active || parsedFeat["tso"].Active || !parsedFeat["rxvlan"].Fixed {
		t.Fatalf("unexpected ParseEthtoolFeatures: %+v", parsedFeat)
	}
	if err := ValidateEthtoolConfig(config.EthtoolConfig{Autoneg: false, Speed: 0}); err == nil {
		t.Fatal("expected error when autoneg=false without speed/duplex")
	}
	if err := ValidateEthtoolConfig(config.EthtoolConfig{Autoneg: true, Offloads: map[string]bool{"evil": true}}); err == nil {
		t.Fatal("expected error for unknown offload key")
	}

	// Scheduled Tasks (crond) full CRUD + 0600 crontab verification + injection rejection
	req = httptest.NewRequest(http.MethodPost, "/api/v1/services/cron", bytes.NewBufferString(`{"id":"nightly_wan","name":"Nightly WAN Renew","schedule":"0 4 * * *","action":"wan_reconnect","enabled":true}`))
	req.Header.Set("Authorization", authHdr)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /api/v1/services/cron failed: %d %s", rec.Code, rec.Body.String())
	}
	cronBytes, err := os.ReadFile(srv.Cfg.CrontabPath)
	if err != nil || !strings.Contains(string(cronBytes), "logrotate") || !strings.Contains(string(cronBytes), "0 4 * * *") {
		t.Fatalf("unexpected rendered root crontab: err=%v content=%q", err, string(cronBytes))
	}
	cronStat, _ := os.Stat(srv.Cfg.CrontabPath)
	if cronStat.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 crontab mode, got %o", cronStat.Mode().Perm())
	}

	// Reject arbitrary command / invalid schedule / disallowed service target in cron
	for _, badCron := range []string{
		`{"name":"Bad1","schedule":"99 4 * * *","action":"reboot","enabled":true}`,
		`{"name":"Bad2","schedule":"0 4 * * *","action":"rm -rf /","enabled":true}`,
		`{"name":"Bad3","schedule":"0 4 * * *","action":"service_restart","target":"netbeed","enabled":true}`,
	} {
		req = httptest.NewRequest(http.MethodPost, "/api/v1/services/cron", bytes.NewBufferString(badCron))
		req.Header.Set("Authorization", authHdr)
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for invalid cron payload %s, got %d", badCron, rec.Code)
		}
	}

	// Update & Delete cron job
	req = httptest.NewRequest(http.MethodPut, "/api/v1/services/cron/nightly_wan", bytes.NewBufferString(`{"name":"Weekly Reboot","schedule":"30 3 * * 0","action":"reboot","enabled":false}`))
	req.Header.Set("Authorization", authHdr)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT /api/v1/services/cron/nightly_wan failed: %d %s", rec.Code, rec.Body.String())
	}
	cronBytes, _ = os.ReadFile(srv.Cfg.CrontabPath)
	if strings.Contains(string(cronBytes), "/sbin/reboot") {
		t.Fatalf("disabled cron job should not appear as active crontab entry:\n%s", string(cronBytes))
	}

	req = httptest.NewRequest(http.MethodDelete, "/api/v1/services/cron/nightly_wan", nil)
	req.Header.Set("Authorization", authHdr)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("DELETE /api/v1/services/cron/nightly_wan failed: %d", rec.Code)
	}

	// iperf3 server status & port validation guard (port 3000 AdGuardHome and <1024 rejected)
	req = httptest.NewRequest(http.MethodGet, "/api/v1/diag/iperf3/server", nil)
	req.Header.Set("Authorization", authHdr)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"running":false`) {
		t.Fatalf("GET /api/v1/diag/iperf3/server unexpected: %d %s", rec.Code, rec.Body.String())
	}
	for _, badPort := range []string{`{"port":80}`, `{"port":3000}`} {
		req = httptest.NewRequest(http.MethodPost, "/api/v1/diag/iperf3/server", bytes.NewBufferString(badPort))
		req.Header.Set("Authorization", authHdr)
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for reserved iperf3 server port %s, got %d", badPort, rec.Code)
		}
	}
}

func TestFirewallDropbearAndAdGuardExtendedEndpoints(t *testing.T) {
	if err := validateFirewallRule(config.FirewallRule{
		ID: "badport", Chain: "forward", Action: "drop", Protocol: "any", DstPort: "443",
	}); err == nil {
		t.Fatal("expected error when dst_port is set with protocol=any")
	}
	if err := validateFirewallRule(config.FirewallRule{
		ID: "badout", Chain: "input", Action: "drop", Protocol: "tcp", OutIface: "eth1",
	}); err == nil {
		t.Fatal("expected error when out_iface is set on input chain")
	}
	if err := validatePortForward(config.PortForward{
		ID: "badpf", Protocol: "tcp", ExtPort: "8000-8010", IntIP: "192.168.10.50", IntPort: 8000,
	}); err == nil {
		t.Fatal("expected error when int_port != 0 with ext_port range")
	}

	wg := config.WireGuardState{
		PublicKey:  base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, 32)),
		Endpoint:   "2001:db8::1",
		ListenPort: 51820,
		DNS:        "192.168.10.1",
	}
	psk := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x55}, 32))
	conf := BuildWGClientConfig("privkey", "10.66.66.2/32", psk, wg)
	if !strings.Contains(conf, "Endpoint = [2001:db8::1]:51820") || !strings.Contains(conf, "PresharedKey = "+psk) {
		t.Fatalf("unexpected WG client config:\n%s", conf)
	}

	// AdGuard extended DNS endpoints (dns_info, filtering/refresh, blocked_services, cache_clear)
	seen := map[string]bool{}
	mockAGH := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen[r.Method+" "+r.URL.Path] = true
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer mockAGH.Close()

	srv, _ := newTestServer(t, mockAGH.URL)
	h := srv.Handler()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString(`{"username":"admin","password":"netbee"}`)))
	var lr struct{ Token string }
	_ = json.Unmarshal(rec.Body.Bytes(), &lr)

	calls := []struct{ method, path, body string }{
		{http.MethodGet, "/api/v1/dns/config", ""},
		{http.MethodPost, "/api/v1/dns/filters/refresh", ""},
		{http.MethodGet, "/api/v1/dns/blocked-services", ""},
		{http.MethodPost, "/api/v1/dns/cache/clear", ""},
	}
	for _, c := range calls {
		req := httptest.NewRequest(c.method, c.path, bytes.NewBufferString(c.body))
		req.Header.Set("Authorization", "Bearer "+lr.Token)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s %s failed: %d", c.method, c.path, rec.Code)
		}
	}
	for _, wantUpstream := range []string{
		"GET /control/dns_info",
		"POST /control/filtering/refresh",
		"GET /control/blocked_services/get",
		"POST /control/cache_clear",
	} {
		if !seen[wantUpstream] {
			t.Fatalf("missing upstream AdGuard call %q (seen=%v)", wantUpstream, seen)
		}
	}
}

func TestDiagnosticsConcurrencySemaphoreAndRollback(t *testing.T) {
	srv, _ := newTestServer(t, "")
	rel1, ok1 := srv.acquireDiagSlot()
	rel2, ok2 := srv.acquireDiagSlot()
	_, ok3 := srv.acquireDiagSlot()
	if !ok1 || !ok2 || ok3 {
		t.Fatalf("expected 2 diag slots max: ok1=%v ok2=%v ok3=%v", ok1, ok2, ok3)
	}
	rel1()
	rel2()

	dir := t.TempDir()
	secretFile := filepath.Join(dir, "chap-secrets")
	stateFile := filepath.Join(dir, "state.json")
	_ = os.WriteFile(secretFile, []byte("orig"), 0600)
	store, _ := config.NewStore(stateFile)
	rm := sys.NewRollbackManager()
	done := make(chan struct{}, 1)
	rm.Begin("test", 100*time.Millisecond, []string{secretFile, stateFile}, func() {
		_ = store.Reload()
		done <- struct{}{}
	})
	_ = os.WriteFile(secretFile, []byte("bad"), 0644)
	_ = store.Update(func(st *config.State) error {
		st.LAN.IP = "10.10.10.1"
		return nil
	})
	<-done
	info, _ := os.Stat(secretFile)
	if info.Mode().Perm() != 0600 || store.Get().LAN.IP != "192.168.10.1" {
		t.Fatalf("rollback failed: mode=%o ip=%s", info.Mode().Perm(), store.Get().LAN.IP)
	}
}

func TestPreCreatedOSUsersDropbearRootFlagAndBackupAllowlist(t *testing.T) {
	pw, allowRoot, idle := ParseDropbearConfEx("# comment -s -w\nDROPBEAR_ARGS=\"-p 192.168.10.1:22 -I 900 -s -w\"\n")
	if pw || allowRoot || idle != 900 {
		t.Fatalf("unexpected ParseDropbearConfEx result: pw=%v allowRoot=%v idle=%d", pw, allowRoot, idle)
	}
	pw2, allowRoot2, idle2 := ParseDropbearConfEx("DROPBEAR_ARGS=\"-p 192.168.10.1:22 -sw -I300\"")
	if pw2 || allowRoot2 || idle2 != 300 {
		t.Fatalf("unexpected combined flag parse: pw=%v allowRoot=%v idle=%d", pw2, allowRoot2, idle2)
	}
	rendered := RenderDropbearConfEx("192.168.20.1", false, false, 600)
	if !strings.Contains(rendered, "-p 192.168.20.1:22 -I 600 -s -w") {
		t.Fatalf("unexpected RenderDropbearConfEx output: %s", rendered)
	}

	// Backup allowlist allows home/netbee/.ssh/authorized_keys, rejects home/netbee/.profile
	if err := ValidateBackupArchiveEntries("home/\nhome/netbee/\nhome/netbee/.ssh/\nhome/netbee/.ssh/authorized_keys\n"); err != nil {
		t.Fatalf("expected netbee authorized_keys to be allowed in backup: %v", err)
	}
	if err := ValidateBackupArchiveEntries("home/netbee/.profile\n"); err == nil {
		t.Fatal("expected home/netbee/.profile to be rejected by backup allowlist")
	}

	// Mock /etc/passwd & /etc/group to test OS user discovery and SSH user resolution
	tmp := t.TempDir()
	nbHome := filepath.Join(tmp, "home-netbee")
	_ = os.MkdirAll(filepath.Join(nbHome, ".ssh"), 0700)
	_ = os.WriteFile(filepath.Join(nbHome, ".ssh", "authorized_keys"), []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl nb@test\n"), 0600)

	origPasswd, origGroup := passwdFilePath, groupFilePath
	passwdFilePath = filepath.Join(tmp, "passwd")
	groupFilePath = filepath.Join(tmp, "group")
	defer func() {
		passwdFilePath = origPasswd
		groupFilePath = origGroup
	}()

	_ = os.WriteFile(passwdFilePath, []byte(
		"root:x:0:0:root:/root:/bin/sh\n"+
			"daemon:x:1:1:daemon:/usr/sbin:/bin/false\n"+
			"iperf:x:110:110:NetBee iperf3 Benchmark Daemon:/:/bin/false\n"+
			"netbee:x:1000:1000:NetBee Administrator:"+nbHome+":/bin/sh\n"+
			"nobody:x:65534:65534:nobody:/home:/bin/false\n",
	), 0644)
	_ = os.WriteFile(groupFilePath, []byte(
		"root:x:0:\n"+
			"adm:x:4:netbee\n"+
			"wheel:x:10:root,netbee\n"+
			"netdev:x:82:netbee\n"+
			"iperf:x:110:\n"+
			"netbee:x:1000:\n",
	), 0644)

	srv, _ := newTestServer(t, "")
	h := srv.Handler()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString(`{"username":"admin","password":"netbee"}`)))
	var lr struct{ Token string }
	_ = json.Unmarshal(rec.Body.Bytes(), &lr)

	// GET /api/v1/system/users
	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/users", nil)
	req.Header.Set("Authorization", "Bearer "+lr.Token)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"netbee"`) || !strings.Contains(rec.Body.String(), `"iperf"`) {
		t.Fatalf("GET /api/v1/system/users failed: %d %s", rec.Code, rec.Body.String())
	}

	// Reject password update on locked service user 'iperf'
	req = httptest.NewRequest(http.MethodPut, "/api/v1/system/users/iperf/password", bytes.NewBufferString(`{"password":"StrongPassword123"}`))
	req.Header.Set("Authorization", "Bearer "+lr.Token)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for service account password change, got %d", rec.Code)
	}

	// GET /api/v1/services/ssh?user=netbee returns netbee's authorized_keys
	req = httptest.NewRequest(http.MethodGet, "/api/v1/services/ssh?user=netbee", nil)
	req.Header.Set("Authorization", "Bearer "+lr.Token)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "nb@test") {
		t.Fatalf("GET /api/v1/services/ssh?user=netbee failed: %d %s", rec.Code, rec.Body.String())
	}

	// SetPasswordDirect revokes existing tokens and allows new login
	if err := srv.Auth.SetPasswordDirect("DirectCLIReset#99"); err != nil {
		t.Fatalf("SetPasswordDirect failed: %v", err)
	}
	req = httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+lr.Token)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected old session revoked after SetPasswordDirect, got %d", rec.Code)
	}
	if !srv.Auth.VerifyPassword("admin", "DirectCLIReset#99") {
		t.Fatal("expected new password set via SetPasswordDirect to verify")
	}
}

func TestHiveStaticWebCachingAndSingleFlowConntrackValidation(t *testing.T) {
	srv, dir := newTestServer(t, "")
	vendorDir := filepath.Join(dir, "web", "assets", "vendor")
	if err := os.MkdirAll(vendorDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vendorDir, "jquery.min.js"), []byte("/*jquery*/"), 0644); err != nil {
		t.Fatal(err)
	}

	h := srv.Handler()

	// Root index.html uses no-cache
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-cache" {
		t.Fatalf("expected 200 + Cache-Control: no-cache on /, got %d (%q)", rec.Code, rec.Header().Get("Cache-Control"))
	}

	// Bundled offline vendor asset uses public max-age caching
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/assets/vendor/jquery.min.js", nil))
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "public, max-age=86400" {
		t.Fatalf("expected 200 + vendor Cache-Control on /assets/vendor/jquery.min.js, got %d (%q)", rec.Code, rec.Header().Get("Cache-Control"))
	}

	// Authenticate and verify single-flow conntrack query parameter validation
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString(`{"username":"admin","password":"netbee"}`)))
	var lr struct{ Token string }
	_ = json.Unmarshal(rec.Body.Bytes(), &lr)

	badQueries := []string{
		"/api/v1/firewall/conntrack?proto=gre&src=192.168.10.50&dst=1.1.1.1",
		"/api/v1/firewall/conntrack?proto=tcp&src=192.168.10.50",
		"/api/v1/firewall/conntrack?proto=tcp&src=192.168.10.50&dst=1.1.1.1&sport=99999&dport=443",
		"/api/v1/firewall/conntrack?proto=tcp&src=not-an-ip&dst=1.1.1.1",
	}
	for _, q := range badQueries {
		req := httptest.NewRequest(http.MethodDelete, q, nil)
		req.Header.Set("Authorization", "Bearer "+lr.Token)
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for invalid conntrack query %q, got %d", q, rec.Code)
		}
	}
}

func TestApplianceHardeningRejectSyntaxVirtualEthtoolAndRollbackIsolation(t *testing.T) {
	srv, _ := newTestServer(t, "")
	h := srv.Handler()

	// Session cookie must use relative MaxAge (43200s) rather than wall-clock Expires for cold-boot 1970-01-01 safety
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString(`{"username":"admin","password":"netbee"}`)))
	var sessCk *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == auth.SessionCookieName {
			sessCk = c
		}
	}
	if sessCk == nil || sessCk.MaxAge != 43200 {
		t.Fatalf("expected session cookie MaxAge=43200, got %+v", sessCk)
	}
	var lr struct{ Token string }
	_ = json.Unmarshal(rec.Body.Bytes(), &lr)

	// RenderCustomNFT emits protocol-aware reject statements inside inet table
	nft := RenderCustomNFT(config.FirewallState{
		CustomRules: []config.FirewallRule{
			{ID: "r_tcp", Enabled: true, Chain: "input", Action: "reject", Protocol: "tcp", DstPort: "25"},
			{ID: "r_v4", Enabled: true, Chain: "forward", Action: "reject", Protocol: "udp", SrcAddr: "192.168.10.0/24", DstPort: "1900"},
			{ID: "r_v6", Enabled: true, Chain: "forward", Action: "reject", Protocol: "udp", SrcAddr: "2001:db8::/64", DstPort: "1900"},
		},
	}, "192.168.10.1")
	for _, want := range []string{
		"tcp dport 25 reject with tcp reset",
		"ip saddr 192.168.10.0/24 udp dport 1900 reject with icmp type port-unreachable",
		"ip6 saddr 2001:db8::/64 udp dport 1900 reject with icmpv6 type port-unreachable",
	} {
		if !strings.Contains(nft, want) {
			t.Fatalf("RenderCustomNFT missing %q in:\n%s", want, nft)
		}
	}

	// Virtual NIC ("Supported link modes: Not reported") must report empty supported_link_modes and supports_autoneg=false
	virtLink := ParseEthtoolSettings("Settings for eth0:\n\tSupported link modes:   Not reported\n\tSupports auto-negotiation: No\n\tAuto-negotiation: off\n\tLink detected: yes\n")
	modes, _ := virtLink["supported_link_modes"].([]string)
	if len(modes) != 0 || virtLink["supports_autoneg"] != false {
		t.Fatalf("unexpected virtual NIC ethtool parse: %+v", virtLink)
	}

	// Duplicate/missing firewall rule errors must NOT revert an already-active pending rollback session
	if err := srv.Store.Update(func(st *config.State) error {
		st.Firewall.CustomRules = []config.FirewallRule{{
			ID: "block_smtp", Name: "Block SMTP", Enabled: true, Chain: "input", Action: "reject", Protocol: "tcp", DstPort: "25",
		}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	srv.Rollback.Begin("Pending firewall edit", 10*time.Second, []string{srv.Cfg.StatePath}, func() {
		_ = srv.Store.Reload()
	})
	defer srv.Rollback.Confirm()

	// Duplicate POST -> 409 Conflict without wiping block_smtp or cancelling active rollback
	req := httptest.NewRequest(http.MethodPost, "/api/v1/firewall/rules", bytes.NewBufferString(`{"id":"block_smtp","name":"Dup","enabled":true,"chain":"input","action":"drop","protocol":"tcp","dst_port":"25"}`))
	req.Header.Set("Authorization", "Bearer "+lr.Token)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409 on duplicate firewall rule id, got %d %s", rec.Code, rec.Body.String())
	}
	if !srv.Rollback.Status().Active || len(srv.Store.Get().Firewall.CustomRules) != 1 {
		t.Fatalf("duplicate rule error unexpectedly reverted active rollback or wiped rules: active=%v rules=%+v",
			srv.Rollback.Status().Active, srv.Store.Get().Firewall.CustomRules)
	}

	// Non-existent DELETE -> 404 Not Found without wiping block_smtp or cancelling active rollback
	req = httptest.NewRequest(http.MethodDelete, "/api/v1/firewall/rules/nonexistent", nil)
	req.Header.Set("Authorization", "Bearer "+lr.Token)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound || !srv.Rollback.Status().Active || len(srv.Store.Get().Firewall.CustomRules) != 1 {
		t.Fatalf("404 delete unexpectedly affected rollback or rules: code=%d active=%v", rec.Code, srv.Rollback.Status().Active)
	}

	// EffectiveSQMInterface auto-maps between eth1 (DHCP) and ppp0 (PPPoE / ONT VLAN)
	if got := EffectiveSQMInterface("eth1", config.WANState{Mode: "ont_vlan", Interface: "eth1", VLANID: 35}); got != "ppp0" {
		t.Fatalf("expected EffectiveSQMInterface to map eth1 -> ppp0 in ont_vlan mode, got %q", got)
	}
	if got := EffectiveSQMInterface("ppp0", config.WANState{Mode: "dhcp", Interface: "eth1"}); got != "eth1" {
		t.Fatalf("expected EffectiveSQMInterface to map ppp0 -> eth1 in dhcp mode, got %q", got)
	}

	// RenderPPPoEPeer includes fast LCP echo (5s x 3 + lcp-echo-adaptive) and header compression disables
	pppConf := RenderPPPoEPeer(config.WANState{Mode: "ont_vlan", Interface: "eth1", VLANID: 35, PPPoEUser: "u@isp", MTU: 1492})
	for _, want := range []string{"plugin rp-pppoe.so eth1.35", "noaccomp", "nopcomp", "lcp-echo-interval 5", "lcp-echo-adaptive"} {
		if !strings.Contains(pppConf, want) {
			t.Fatalf("RenderPPPoEPeer missing %q in:\n%s", want, pppConf)
		}
	}

	// RenderRouterSysctlConf preserves fq_codel default qdisc, backlog, conntrack timeouts, and kernel.panic
	sysConf := RenderRouterSysctlConf(RouterSysctlConfig{
		ConntrackMax: 131072, TCPSynCookies: true, RPFilter: 1, IgnoreBroadcast: true, IPv4Forwarding: true, IPv6Forwarding: true,
	})
	for _, want := range []string{
		"kernel.panic = 3",
		"net.core.default_qdisc = fq_codel",
		"net.core.netdev_max_backlog = 4096",
		"net.netfilter.nf_conntrack_tcp_timeout_established = 7440",
	} {
		if !strings.Contains(sysConf, want) {
			t.Fatalf("RenderRouterSysctlConf missing %q in:\n%s", want, sysConf)
		}
	}
}

func TestDynamicInterfacesRoleSwapOrthogonalVLANAndStaticWAN(t *testing.T) {
	srv, _ := newTestServer(t, "")
	h := srv.Handler()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString(`{"username":"admin","password":"netbee"}`)))
	var lr struct{ Token string }
	_ = json.Unmarshal(rec.Body.Bytes(), &lr)
	authHdr := "Bearer " + lr.Token

	// 1. Orthogonal 802.1Q VLAN + DHCP (IPoE) + custom WAN DNS (peerdns=false) + LAN Jumbo MTU 9000
	peerDNSFalse := false
	lanJumbo := config.LANState{Interface: "eth1", IP: "192.168.10.1", Netmask: "255.255.255.0", MTU: 9000, PinMAC: "00:E0:4C:68:02:5D"}
	wanVlanDHCP := config.WANState{
		Mode: "dhcp", Interface: "eth0", VLANEnabled: true, VLANID: 35,
		PeerDNS: &peerDNSFalse, DNSServers: []string{"1.1.1.1", "9.9.9.9"},
		PinMAC: "2C:CF:67:F0:F4:21", MTU: 1500, IPv6PD: true,
	}
	ifFile := RenderInterfacesFile(lanJumbo, wanVlanDHCP)
	for _, want := range []string{
		"iface eth1 inet static",
		"up ip link set dev eth1 mtu 9000",
		"up ip link add link eth0 name eth0.35 type vlan id 35",
	} {
		if !strings.Contains(ifFile, want) {
			t.Fatalf("RenderInterfacesFile (VLAN DHCP + LAN Jumbo) missing %q in:\n%s", want, ifFile)
		}
	}
	dhcpConf := RenderDHCPCDConf(lanJumbo, wanVlanDHCP)
	for _, want := range []string{"denyinterfaces eth1 eth0", "nohook resolv.conf", "interface eth0.35", "ia_pd 2 eth1/0"} {
		if !strings.Contains(dhcpConf, want) {
			t.Fatalf("RenderDHCPCDConf (VLAN DHCP + peerdns=false) missing %q in:\n%s", want, dhcpConf)
		}
	}
	udevRules := RenderNetUdevRules(lanJumbo, wanVlanDHCP)
	if !strings.Contains(udevRules, `ATTR{address}=="00:e0:4c:68:02:5d", NAME="eth1"`) ||
		!strings.Contains(udevRules, `ATTR{address}=="2c:cf:67:f0:f4:21", NAME="eth0"`) {
		t.Fatalf("unexpected RenderNetUdevRules:\n%s", udevRules)
	}
	if got := EffectiveSQMInterface("", wanVlanDHCP); got != "eth0.35" {
		t.Fatalf("expected EffectiveSQMInterface to target eth0.35 for VLAN DHCP WAN, got %q", got)
	}

	// 2. Orthogonal 802.1Q VLAN + Static IPv4 WAN + RFC 4638 Baby Jumbo 1500 PPPoE check
	wanStaticVLAN := config.WANState{
		Mode: "static", Interface: "eth1", VLANEnabled: true, VLANID: 100,
		StaticIP: "198.51.100.10", StaticNetmask: "255.255.255.0", StaticGateway: "198.51.100.1", MTU: 1500,
	}
	staticIf := RenderInterfacesFile(config.DefaultState().LAN, wanStaticVLAN)
	for _, want := range []string{
		"up ip link add link eth1 name eth1.100 type vlan id 100",
		"up ip addr add 198.51.100.10/24 dev eth1.100",
		"up ip route replace default via 198.51.100.1 dev eth1.100",
	} {
		if !strings.Contains(staticIf, want) {
			t.Fatalf("RenderInterfacesFile (VLAN Static WAN) missing %q in:\n%s", want, staticIf)
		}
	}
	babyJumboIf := RenderInterfacesFile(config.DefaultState().LAN, config.WANState{
		Mode: "ont_vlan", Interface: "eth1", VLANID: 35, PPPoEUser: "u@isp", PPPoEPassword: "p", MTU: 1500,
	})
	if !strings.Contains(babyJumboIf, "mtu 1508") {
		t.Fatalf("expected RFC 4638 carrier mtu 1508 for 1500 PPPoE MTU, got:\n%s", babyJumboIf)
	}

	// 3. Interface label persistence & active-LAN link-down lockout guard
	req := httptest.NewRequest(http.MethodPut, "/api/v1/network/interfaces/eth1/label", bytes.NewBufferString(`{"label":"TurkNet 2.5G ONT"}`))
	req.Header.Set("Authorization", authHdr)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || srv.Store.Get().InterfaceLabels["eth1"] != "TurkNet 2.5G ONT" {
		t.Fatalf("PUT /network/interfaces/eth1/label failed: %d %s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/network/interfaces/eth0/state", bytes.NewBufferString(`{"up":false}`))
	req.Header.Set("Authorization", authHdr)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 lockout guard when bringing down active LAN eth0, got %d", rec.Code)
	}

	// 4. Atomic LAN <-> WAN role swap endpoint (eth0 <-> eth1) with rollback safety & disk output verification
	tmpEtc := t.TempDir()
	origVars, origEnv, origIfs, origDhcp := nftVarsPath, netifEnvPath, interfacesConfPath, dhcpcdConfPath
	origDrop, origHosts, origUINft, origSqm, origUdev := dropbearDefaultPath, hostsConfPath, uiNftDropInPath, sqmConfPath, customUdevNetRules
	nftVarsPath = filepath.Join(tmpEtc, "nftables.vars")
	netifEnvPath = filepath.Join(tmpEtc, "netif.env")
	interfacesConfPath = filepath.Join(tmpEtc, "interfaces")
	dhcpcdConfPath = filepath.Join(tmpEtc, "dhcpcd.conf")
	dropbearDefaultPath = filepath.Join(tmpEtc, "dropbear")
	hostsConfPath = filepath.Join(tmpEtc, "hosts")
	uiNftDropInPath = filepath.Join(tmpEtc, "10-ui-rules.nft")
	sqmConfPath = filepath.Join(tmpEtc, "sqm.conf")
	customUdevNetRules = filepath.Join(tmpEtc, "11-netbee-custom-net.rules")
	defer func() {
		nftVarsPath, netifEnvPath, interfacesConfPath, dhcpcdConfPath = origVars, origEnv, origIfs, origDhcp
		dropbearDefaultPath, hostsConfPath, uiNftDropInPath, sqmConfPath, customUdevNetRules = origDrop, origHosts, origUINft, origSqm, origUdev
	}()

	req = httptest.NewRequest(http.MethodPost, "/api/v1/network/swap", bytes.NewBufferString(`{}`))
	req.Header.Set("Authorization", authHdr)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/v1/network/swap failed: %d %s", rec.Code, rec.Body.String())
	}
	defer srv.Rollback.Confirm()
	swapped := srv.Store.Get()
	if swapped.LAN.Interface != "eth1" || swapped.WAN.Interface != "eth0" || !srv.Rollback.Status().Active {
		t.Fatalf("unexpected state after role swap: lan=%s wan=%s active=%v",
			swapped.LAN.Interface, swapped.WAN.Interface, srv.Rollback.Status().Active)
	}
	varsData, _ := os.ReadFile(nftVarsPath)
	dhcpData, _ := os.ReadFile(dhcpcdConfPath)
	if !strings.Contains(string(varsData), `define LAN_IF = "eth1"`) || !strings.Contains(string(dhcpData), "denyinterfaces eth1") {
		t.Fatalf("swapped disk configs did not update LAN_IF/denyinterfaces to eth1:\nvars=%s\ndhcpcd=%s", string(varsData), string(dhcpData))
	}
}

func TestFirewallMultiMemberSetsAndCSPHeader(t *testing.T) {
	srv, _ := newTestServer(t, "")
	h := srv.Handler()

	// 1. Verify strict Content-Security-Policy header on responses
	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'self'") || !strings.Contains(csp, "script-src 'self'") || !strings.Contains(csp, "object-src 'none'") {
		t.Fatalf("expected hardened Content-Security-Policy header, got %q", csp)
	}

	// 2. Validate multi-member anonymous set firewall rule & reject mixed IPv4/IPv6 families
	validRule := config.FirewallRule{
		ID:       "r_multi_alias",
		Name:     "Block private subnets to web ports",
		Enabled:  true,
		Chain:    "forward",
		Action:   "drop",
		Protocol: "tcp",
		InIface:  "eth0",
		OutIface: "eth1",
		SrcAddr:  "192.168.10.0/24, 10.0.0.0/8, 172.16.0.0/12",
		DstPort:  "80, 443, 8000-8080",
	}
	if err := validateFirewallRule(validRule); err != nil {
		t.Fatalf("expected multi-member firewall rule to validate cleanly, got %v", err)
	}

	mixedRule := validRule
	mixedRule.SrcAddr = "192.168.10.0/24, 2001:db8::/32"
	if err := validateFirewallRule(mixedRule); err == nil {
		t.Fatalf("expected mixed IPv4/IPv6 src_addr set to be rejected")
	}

	rendered := RenderCustomNFT(config.FirewallState{CustomRules: []config.FirewallRule{validRule}}, "192.168.10.1")
	expected := `add rule inet netbee_fw custom_forward iifname "eth0" oifname "eth1" ip saddr { 192.168.10.0/24, 10.0.0.0/8, 172.16.0.0/12 } tcp dport { 80, 443, 8000-8080 } drop`
	if !strings.Contains(rendered, expected) {
		t.Fatalf("expected rendered nftables anonymous set:\nwant: %s\ngot:\n%s", expected, rendered)
	}
}

func TestAdGuardV1BlockedServicesAndTLSReset(t *testing.T) {
	var lastMethod, lastPath string
	var lastBody map[string]any
	mockAGH := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastMethod = r.Method
		lastPath = r.URL.Path
		lastBody = nil
		_ = json.NewDecoder(r.Body).Decode(&lastBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer mockAGH.Close()

	srv, _ := newTestServer(t, mockAGH.URL)
	defer srv.Close()
	h := srv.Handler()

	loginReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{"username":"admin","password":"netbee"}`))
	loginReq.Header.Set("Content-Type", "application/json")
	loginRec := httptest.NewRecorder()
	h.ServeHTTP(loginRec, loginReq)
	var loginBody struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(loginRec.Body.Bytes(), &loginBody); err != nil || loginBody.Token == "" {
		t.Fatalf("login failed: %d %s", loginRec.Code, loginRec.Body.String())
	}
	authHeader := "Bearer " + loginBody.Token

	// 1. Bare array to PUT /api/v1/dns/blocked-services must normalize to PUT /control/blocked_services/update with {ids, schedule}
	req1 := httptest.NewRequest(http.MethodPut, "/api/v1/dns/blocked-services", strings.NewReader(`["youtube","tiktok"]`))
	req1.Header.Set("Authorization", authHeader)
	req1.Header.Set("Content-Type", "application/json")
	rec1 := httptest.NewRecorder()
	h.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusOK || lastMethod != http.MethodPut || lastPath != "/control/blocked_services/update" {
		t.Fatalf("expected PUT /control/blocked_services/update (200), got code=%d method=%s path=%s", rec1.Code, lastMethod, lastPath)
	}
	idsSlice, _ := lastBody["ids"].([]any)
	schedMap, _ := lastBody["schedule"].(map[string]any)
	if len(idsSlice) != 2 || schedMap == nil || schedMap["time_zone"] != "Local" {
		t.Fatalf("unexpected normalized blocked_services payload: %+v", lastBody)
	}

	// 2. POST /api/v1/dns/filtering/config forwards to POST /control/filtering/config
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/dns/filtering/config", strings.NewReader(`{"enabled":true,"interval":24}`))
	req2.Header.Set("Authorization", authHeader)
	req2.Header.Set("Content-Type", "application/json")
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK || lastMethod != http.MethodPost || lastPath != "/control/filtering/config" {
		t.Fatalf("expected POST /control/filtering/config (200), got code=%d method=%s path=%s", rec2.Code, lastMethod, lastPath)
	}

	// 3. DELETE /api/v1/system/tls regenerates self-signed ECDSA cert immediately so GET /api/v1/system/tls reports auto_self_signed=true
	delReq := httptest.NewRequest(http.MethodDelete, "/api/v1/system/tls", nil)
	delReq.Header.Set("Authorization", authHeader)
	delRec := httptest.NewRecorder()
	h.ServeHTTP(delRec, delReq)
	if delRec.Code != http.StatusOK {
		t.Fatalf("expected DELETE /api/v1/system/tls 200, got %d: %s", delRec.Code, delRec.Body.String())
	}

	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/system/tls", nil)
	getReq.Header.Set("Authorization", authHeader)
	getRec := httptest.NewRecorder()
	h.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK || !strings.Contains(getRec.Body.String(), `"present":true`) || !strings.Contains(getRec.Body.String(), `"auto_self_signed":true`) {
		t.Fatalf("expected regenerated auto_self_signed TLS cert, got %d: %s", getRec.Code, getRec.Body.String())
	}
}
