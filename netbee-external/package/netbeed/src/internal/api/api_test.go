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
