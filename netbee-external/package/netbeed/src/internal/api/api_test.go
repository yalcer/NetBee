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

func TestAuthLifecycleAndProtection(t *testing.T) {
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

	// Login with default credentials (admin / netbee)
	body := bytes.NewBufferString(`{"username":"admin","password":"netbee"}`)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", body)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("login failed: %d %s", rec.Code, rec.Body.String())
	}
	var loginResp struct {
		Token              string `json:"token"`
		CSRFToken          string `json:"csrf_token"`
		MustChangePassword bool   `json:"must_change_password"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &loginResp); err != nil {
		t.Fatal(err)
	}
	if loginResp.Token == "" || !loginResp.MustChangePassword {
		t.Fatalf("unexpected login response: %+v", loginResp)
	}

	// Authenticated request with Bearer token succeeds
	req = httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+loginResp.Token)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 on /auth/me, got %d", rec.Code)
	}

	// SPA static fallback serves index.html
	req = httptest.NewRequest(http.MethodGet, "/firewall/rules", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "netbee-spa") {
		t.Fatalf("expected SPA index.html fallback, got %d %q", rec.Code, rec.Body.String())
	}
}

func TestValidators(t *testing.T) {
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
}

func TestRenderers(t *testing.T) {
	fw := config.FirewallState{
		TransparentDNS:  true,
		ExposeWireGuard: true,
		WireGuardPort:   51820,
		PortForwards: []config.PortForward{
			{ID: "pf1", Name: "Web", Enabled: true, Protocol: "tcp", ExtPort: "443", IntIP: "192.168.10.50", IntPort: 8443},
		},
		CustomRules: []config.FirewallRule{
			{ID: "r1", Name: "BlockIoT", Enabled: true, Chain: "forward", Action: "drop", Protocol: "tcp", SrcAddr: "192.168.10.150", DstPort: "25", Log: true},
		},
	}
	nft := RenderCustomNFT(fw, "192.168.10.1")
	for _, want := range []string{
		"udp dport 51820 accept",
		"ip daddr != 192.168.10.1 udp dport 53 redirect to :53",
		"tcp dport 443 dnat to 192.168.10.50:8443",
		"ip saddr 192.168.10.150 tcp dport 25",
		`log prefix "netbee-r1: " drop`,
	} {
		if !strings.Contains(nft, want) {
			t.Fatalf("missing %q in rendered nft:\n%s", want, nft)
		}
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

	wgConf := RenderWireGuardConf(config.WireGuardState{
		PrivateKey: "PRIV",
		ListenPort: 51820,
		Peers:      []config.WireGuardPeer{{ID: "p1", Name: "Phone", PublicKey: "PUB", AllowedIPs: "10.66.66.2/32", Enabled: true}},
	})
	if !strings.Contains(wgConf, "PublicKey = PUB") || !strings.Contains(wgConf, "AllowedIPs = 10.66.66.2/32") {
		t.Fatalf("unexpected wg conf:\n%s", wgConf)
	}
}

func TestRollbackAutoRevert(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "test.conf")
	_ = os.WriteFile(f, []byte("original"), 0644)

	rm := sys.NewRollbackManager()
	reverted := make(chan bool, 1)
	rm.Begin("test change", 150*time.Millisecond, []string{f}, func() {
		reverted <- true
	})
	_ = os.WriteFile(f, []byte("broken"), 0644)

	select {
	case <-reverted:
	case <-time.After(2 * time.Second):
		t.Fatal("rollback timer did not fire")
	}
	got, _ := os.ReadFile(f)
	if string(got) != "original" {
		t.Fatalf("expected file to revert to 'original', got %q", string(got))
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

	// Login first
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
