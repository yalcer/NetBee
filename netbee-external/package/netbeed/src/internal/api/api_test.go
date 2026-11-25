package api

import (
	"bytes"
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

func newTestServer(t *testing.T, adguardURL string) (*Server, string) {
	t.Helper()
	dir := t.TempDir()
	webDir := filepath.Join(dir, "web")
	_ = os.MkdirAll(webDir, 0755)
	_ = os.WriteFile(filepath.Join(webDir, "index.html"), []byte("<html>netbee-spa</html>"), 0644)

	cfg := config.RuntimeConfig{
		WebDir:          webDir,
		StatePath:       filepath.Join(dir, "state.json"),
		AuthPath:        filepath.Join(dir, "auth.json"),
		AdGuardURL:      adguardURL,
		AdGuardUser:     "admin",
		AdGuardPass:     "netbee",
		RollbackSeconds: 2,
		CORSOrigins:     []string{"http://localhost:5173"},
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

func TestAuthCSRFAndSessionInvalidation(t *testing.T) {
	srv, _ := newTestServer(t, "")
	h := srv.Handler()

	// Unauthenticated request to protected endpoint must return 401
	req := httptest.NewRequest(http.MethodGet, "/api/v1/system/overview", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}

	// Health endpoint must be public
	req = httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 on health, got %d", rec.Code)
	}

	// Create two sessions (admin + second session)
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

	// Cookie-authenticated POST WITHOUT X-CSRF-Token MUST be rejected (403)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/system/confirm", nil)
	req.AddCookie(ck1)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when CSRF header missing on cookie POST, got %d", rec.Code)
	}

	// Cookie-authenticated POST WITH valid X-CSRF-Token succeeds (200)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/system/confirm", nil)
	req.AddCookie(ck1)
	req.Header.Set("X-CSRF-Token", csrf1)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 with valid CSRF token, got %d", rec.Code)
	}

	// Password containing newline must be rejected (prevents chpasswd injection)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/password", bytes.NewBufferString(`{"current_password":"netbee","new_password":"goodpass\nroot:evil"}`))
	req.Header.Set("Authorization", "Bearer "+tok1)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on newline password, got %d", rec.Code)
	}

	// Valid password change keeps session 1 alive and invalidates session 2
	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/password", bytes.NewBufferString(`{"current_password":"netbee","new_password":"StrongPassword123"}`))
	req.Header.Set("Authorization", "Bearer "+tok1)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 on password change, got %d %s", rec.Code, rec.Body.String())
	}

	// Session 2 must now be invalidated (401)
	req = httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+tok2)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for revoked session after password change, got %d", rec.Code)
	}

	// Session 1 stays valid (200)
	req = httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+tok1)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for current session, got %d", rec.Code)
	}

	// SPA static fallback serves index.html
	req = httptest.NewRequest(http.MethodGet, "/firewall/rules", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "netbee-spa") {
		t.Fatalf("expected SPA index.html fallback, got %d %q", rec.Code, rec.Body.String())
	}
}

func TestValidatorsAndTarSlipProtection(t *testing.T) {
	if !sys.ValidIface("eth1.35") || sys.ValidIface("eth0;rm -rf /") {
		t.Fatal("ValidIface check failed")
	}
	if !sys.ValidMAC("AA:BB:CC:DD:EE:FF") || sys.ValidMAC("invalid-mac") {
		t.Fatal("ValidMAC check failed")
	}
	if !sys.ValidPortSpec("8000-8100") || sys.ValidPortSpec("9000-8000") || sys.ValidPortSpec("99999") {
		t.Fatal("ValidPortSpec check failed")
	}
	if !sys.ValidHost("1.1.1.1") || sys.ValidHost("-v") || sys.ValidHost("1.1.1.1;id") {
		t.Fatal("ValidHost check failed")
	}

	// Backup tar-slip protection
	if err := ValidateBackupArchiveEntries("etc/nftables.conf\netc/netbee/state.json\n"); err != nil {
		t.Fatalf("valid archive entries rejected: %v", err)
	}
	for _, bad := range []string{"../etc/shadow", "/etc/passwd", "usr/bin/netbeed", "etc/../../bin/sh"} {
		if err := ValidateBackupArchiveEntries(bad); err == nil {
			t.Fatalf("unsafe archive entry was NOT rejected: %q", bad)
		}
	}

	// LAN CIDR helper
	if got := lanCIDR(config.LANState{IP: "192.168.50.1", Netmask: "255.255.255.0"}); got != "192.168.50.0/24" {
		t.Fatalf("expected 192.168.50.0/24, got %q", got)
	}
}

func TestRenderersAndCustomChains(t *testing.T) {
	fw := config.FirewallState{
		TransparentDNS:  true,
		ExposeWireGuard: true,
		WireGuardPort:   51820,
		PortForwards: []config.PortForward{
			{ID: "pf1", Name: "Web", Enabled: true, Protocol: "tcp", ExtPort: "443", IntIP: "192.168.10.50", IntPort: 8443},
			{ID: "pf2", Name: "Range", Enabled: true, Protocol: "udp", ExtPort: "27015-27030", IntIP: "192.168.10.60", IntPort: 0},
		},
		CustomRules: []config.FirewallRule{
			{ID: "r1", Name: "BlockIoT", Enabled: true, Chain: "forward", Action: "drop", Protocol: "tcp", SrcAddr: "192.168.10.150", DstPort: "25", Log: true},
			{ID: "r2", Name: "BlockV6", Enabled: true, Chain: "forward", Action: "reject", Protocol: "icmp", SrcAddr: "2001:db8::/32"},
		},
	}
	nft := RenderCustomNFT(fw, "192.168.10.1")
	for _, want := range []string{
		"add rule inet netbee_fw custom_input iifname $WAN_IFS udp dport 51820 accept",
		"ip daddr != 192.168.10.1 udp dport 53 redirect to :53",
		"tcp dport 443 dnat to 192.168.10.50:8443",
		"add rule inet netbee_fw custom_forward iifname $WAN_IFS ip daddr 192.168.10.50 tcp dport 8443 accept",
		"udp dport 27015-27030 dnat to 192.168.10.60\n",
		"add rule inet netbee_fw custom_forward ip saddr 192.168.10.150 tcp dport 25",
		"add rule inet netbee_fw custom_forward ip6 saddr 2001:db8::/32 ip6 nexthdr icmpv6 reject",
	} {
		if !strings.Contains(nft, want) {
			t.Fatalf("missing %q in rendered nft:\n%s", want, nft)
		}
	}

	// Mixed IPv4/IPv6 rule must be rejected
	err := validateFirewallRule(config.FirewallRule{
		ID: "badmix", Chain: "forward", Action: "drop", Protocol: "tcp",
		SrcAddr: "192.168.10.5", DstAddr: "2001:db8::1",
	})
	if err == nil {
		t.Fatal("expected error for mixed IPv4/IPv6 addresses in single rule")
	}

	lan := config.LANState{Interface: "eth0", IP: "192.168.10.1", Netmask: "255.255.255.0"}
	wan := config.WANState{Mode: "ont_vlan", Interface: "eth1", VLANID: 35, PPPoEUser: "u@isp", MACClone: "AA:BB:CC:DD:EE:FF", MTU: 1492, IPv6PD: true}
	ifaces := RenderInterfacesFile(lan, wan)
	if !strings.Contains(ifaces, "eth1.35 type vlan id 35") || !strings.Contains(ifaces, "address AA:BB:CC:DD:EE:FF") {
		t.Fatalf("unexpected interfaces output:\n%s", ifaces)
	}
	dhcpcd := RenderDHCPCDConf(lan, wan)
	if !strings.Contains(dhcpcd, "denyinterfaces eth0 eth1") || !strings.Contains(dhcpcd, "ia_pd 2 eth0/0") {
		t.Fatalf("unexpected dhcpcd output:\n%s", dhcpcd)
	}
	peer := RenderPPPoEPeer(wan)
	if !strings.Contains(peer, "plugin rp-pppoe.so eth1.35") {
		t.Fatalf("unexpected pppoe peer output:\n%s", peer)
	}

	sqm := ParseSQMConf(RenderSQMConf(SQMConfig{Enabled: true, WANInterface: "ppp0", DownloadKbit: 90000, UploadKbit: 18000, Overhead: 44}))
	if !sqm.Enabled || sqm.WANInterface != "ppp0" || sqm.DownloadKbit != 90000 {
		t.Fatalf("SQM round-trip mismatch: %+v", sqm)
	}
}

func TestRollbackPreservesPermissionsAndReloadsStore(t *testing.T) {
	dir := t.TempDir()
	secretFile := filepath.Join(dir, "pap-secrets")
	stateFile := filepath.Join(dir, "state.json")
	_ = os.WriteFile(secretFile, []byte("original-secret"), 0600)

	store, err := config.NewStore(stateFile)
	if err != nil {
		t.Fatal(err)
	}
	_ = store.Update(func(st *config.State) error {
		st.LAN.IP = "192.168.10.1"
		return nil
	})

	rm := sys.NewRollbackManager()
	reverted := make(chan bool, 1)
	rm.Begin("test change", 150*time.Millisecond, []string{secretFile, stateFile}, func() {
		_ = store.Reload()
		reverted <- true
	})

	_ = os.WriteFile(secretFile, []byte("broken-secret"), 0600)
	_ = store.Update(func(st *config.State) error {
		st.LAN.IP = "10.99.99.1"
		return nil
	})

	select {
	case <-reverted:
	case <-time.After(2 * time.Second):
		t.Fatal("rollback timer did not fire")
	}

	gotSecret, _ := os.ReadFile(secretFile)
	if string(gotSecret) != "original-secret" {
		t.Fatalf("expected secret file to revert, got %q", string(gotSecret))
	}
	info, _ := os.Stat(secretFile)
	if info.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 perms preserved after rollback, got %o", info.Mode().Perm())
	}
	if store.Get().LAN.IP != "192.168.10.1" {
		t.Fatalf("expected in-memory Store.Reload() to restore 192.168.10.1, got %q", store.Get().LAN.IP)
	}
}

func TestAdGuardProxy(t *testing.T) {
	mockAGH := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/control/status" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"running":true,"protection_enabled":true}`))
	}))
	defer mockAGH.Close()

	srv, _ := newTestServer(t, mockAGH.URL)
	h := srv.Handler()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBufferString(`{"username":"admin","password":"netbee"}`)))
	var lr struct{ Token string }
	_ = json.Unmarshal(rec.Body.Bytes(), &lr)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/dns/status", nil)
	req.Header.Set("Authorization", "Bearer "+lr.Token)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"protection_enabled":true`) {
		t.Fatalf("AdGuard proxy failed: %d %s", rec.Code, rec.Body.String())
	}
}
