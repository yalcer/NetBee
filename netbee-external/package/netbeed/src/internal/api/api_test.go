package api

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
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
	// Include "*" in CORSOrigins to verify wildcard reflection is strictly blocked
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

	// Auth.Reload() invalidates active in-memory sessions (used after backup restore)
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
	// Strict ValidHost (no colons/ports on hostnames, valid IPv4/IPv6/FQDN only)
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

	// Strict IPv4 subnet mask & unicast host checks
	if !sys.ValidIPv4Netmask("255.255.255.0") || sys.ValidIPv4Netmask("192.168.10.1") || sys.ValidIPv4Netmask("255.255.255.255") {
		t.Fatal("ValidIPv4Netmask check failed")
	}
	if !sys.ValidUnicastIPv4Host("192.168.10.1", "255.255.255.0") ||
		sys.ValidUnicastIPv4Host("192.168.10.0", "255.255.255.0") || // network addr
		sys.ValidUnicastIPv4Host("192.168.10.255", "255.255.255.0") || // broadcast addr
		sys.ValidUnicastIPv4Host("127.0.0.1", "255.0.0.0") {
		t.Fatal("ValidUnicastIPv4Host check failed")
	}

	// Exact 32-byte base64 WireGuard key check
	validKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
	if !sys.ValidWGKey(validKey) || sys.ValidWGKey("shortkey====") || sys.ValidWGKey(strings.Repeat("A", 43)) {
		t.Fatal("ValidWGKey check failed")
	}

	// WireGuard DNS IP-list check (blocks newline/PostUp injection)
	if !sys.ValidIPList("192.168.10.1, 1.1.1.1") || sys.ValidIPList("1.1.1.1\nPostUp = id") {
		t.Fatal("ValidIPList check failed")
	}

	// Valid NetBee backup tar.gz passes
	goodTar := buildTarGz(t, []tar.Header{
		{Name: "etc/netbee", Typeflag: tar.TypeDir, Mode: 0755},
		{Name: "etc/netbee/state.json", Typeflag: tar.TypeReg},
		{Name: "etc/ppp/chap-secrets", Typeflag: tar.TypeReg},
		{Name: "root/.ssh/authorized_keys", Typeflag: tar.TypeReg},
	}, []string{"", `{"lan":{"ip":"192.168.10.1"}}`, `"u" * "p" *`, "ssh-ed25519 AAAA..."})
	if err := ValidateBackupTarGz(goodTar); err != nil {
		t.Fatalf("expected valid backup tar.gz to pass, got: %v", err)
	}

	// Symlink tar-slip attack inside etc/ MUST be rejected
	symlinkTar := buildTarGz(t, []tar.Header{
		{Name: "etc/netbee/evil", Typeflag: tar.TypeSymlink, Linkname: "/usr/sbin"},
	}, nil)
	if err := ValidateBackupTarGz(symlinkTar); err == nil {
		t.Fatal("symlink inside backup archive was NOT rejected")
	}

	// Sensitive / executable system paths inside etc/ (/etc/shadow, /etc/ppp/ip-up, /etc/cron/crontabs/root) MUST be rejected
	for _, forbidden := range []string{"etc/shadow", "etc/passwd", "etc/init.d/S90netbeed", "etc/ppp/ip-up", "etc/cron/crontabs/root", "../etc/hostname"} {
		badTar := buildTarGz(t, []tar.Header{{Name: forbidden, Typeflag: tar.TypeReg}}, []string{"pwn"})
		if err := ValidateBackupTarGz(badTar); err == nil {
			t.Fatalf("forbidden backup path %q was NOT rejected", forbidden)
		}
	}
}

func TestFirewallWireGuardDropbearAndAdGuardSync(t *testing.T) {
	// Firewall: DstPort with protocol "any" or "icmp" must be rejected (prevents silent match-all drop)
	if err := validateFirewallRule(config.FirewallRule{
		ID: "badport", Chain: "forward", Action: "drop", Protocol: "any", DstPort: "443",
	}); err == nil {
		t.Fatal("expected error when dst_port is set with protocol=any")
	}
	// OutIface on input chain must be rejected
	if err := validateFirewallRule(config.FirewallRule{
		ID: "badout", Chain: "input", Action: "drop", Protocol: "tcp", OutIface: "eth1",
	}); err == nil {
		t.Fatal("expected error when out_iface is set on input chain")
	}
	// Port-forward range with non-zero IntPort must be rejected
	if err := validatePortForward(config.PortForward{
		ID: "badpf", Protocol: "tcp", ExtPort: "8000-8010", IntIP: "192.168.10.50", IntPort: 8000,
	}); err == nil {
		t.Fatal("expected error when int_port != 0 with ext_port range")
	}

	// WireGuard client config brackets IPv6 endpoint properly
	wg := config.WireGuardState{
		PublicKey:  base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, 32)),
		Endpoint:   "2001:db8::1",
		ListenPort: 51820,
		DNS:        "192.168.10.1",
	}
	conf := BuildWGClientConfig("privkey", "10.66.66.2/32", wg)
	if !strings.Contains(conf, "Endpoint = [2001:db8::1]:51820") {
		t.Fatalf("expected bracketed IPv6 Endpoint in client config:\n%s", conf)
	}

	// Dropbear parser ignores comments containing "-s" and preserves -s / -I across LAN IP changes
	rawDropbear := "# Note: -s disables password login\nDROPBEAR_ARGS=\"-p 192.168.10.1:22 -I 900\"\n"
	pwAuth, idle := ParseDropbearConf(rawDropbear)
	if !pwAuth || idle != 900 {
		t.Fatalf("unexpected ParseDropbearConf result: pwAuth=%v idle=%d", pwAuth, idle)
	}
	renderedDropbear := RenderDropbearConf("192.168.50.1", false, 300)
	pwAuth2, idle2 := ParseDropbearConf(renderedDropbear)
	if pwAuth2 || idle2 != 300 || !strings.Contains(renderedDropbear, "-p 192.168.50.1:22") {
		t.Fatalf("RenderDropbearConf round-trip failed: %q", renderedDropbear)
	}

	// AdGuardHome.yaml LAN IP & DHCP pool sync
	sampleAGH := "dns:\n  bind_hosts:\n    - 127.0.0.1\n    - 192.168.10.1\ndhcp:\n  interface_name: eth0\n  dhcpv4:\n    gateway_ip: 192.168.10.1\n    subnet_mask: 255.255.255.0\n    range_start: 192.168.10.100\n    range_end: 192.168.10.200\n"
	updatedAGH := UpdateAdGuardLANConfig(
		sampleAGH,
		config.LANState{Interface: "eth0", IP: "192.168.10.1", Netmask: "255.255.255.0"},
		config.LANState{Interface: "eth0", IP: "192.168.50.1", Netmask: "255.255.255.0"},
	)
	for _, want := range []string{"- 192.168.50.1", "gateway_ip: 192.168.50.1", "range_start: 192.168.50.100", "range_end: 192.168.50.200"} {
		if !strings.Contains(updatedAGH, want) {
			t.Fatalf("missing %q in updated AdGuardHome.yaml:\n%s", want, updatedAGH)
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

	// Atomic rollback preserves 0600 permissions & reloads Store
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

func TestAdGuardProxySafePathCleaning(t *testing.T) {
	var seenPath string
	mockAGH := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"running":true}`))
	}))
	defer mockAGH.Close()

	srv, _ := newTestServer(t, mockAGH.URL)
	h := srv.Handler()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString(`{"username":"admin","password":"netbee"}`)))
	var lr struct{ Token string }
	_ = json.Unmarshal(rec.Body.Bytes(), &lr)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/adguard/filtering/status", nil)
	req.Header.Set("Authorization", "Bearer "+lr.Token)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || seenPath != "/control/filtering/status" {
		t.Fatalf("unexpected proxy result: %d path=%q", rec.Code, seenPath)
	}
}
