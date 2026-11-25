package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestBuildHTTPSRedirectURL(t *testing.T) {
	// Valid LAN IPv4 host
	req := httptest.NewRequest("GET", "http://192.168.10.1/dashboard?tab=wan", nil)
	req.Host = "192.168.10.1:80"
	if got := buildHTTPSRedirectURL(req, ":443", "192.168.10.1"); got != "https://192.168.10.1/dashboard?tab=wan" {
		t.Fatalf("unexpected redirect URL: %q", got)
	}

	// Non-443 HTTPS port preserved
	if got := buildHTTPSRedirectURL(req, ":8443", "192.168.10.1"); got != "https://192.168.10.1:8443/dashboard?tab=wan" {
		t.Fatalf("expected :8443 preserved, got %q", got)
	}

	// IPv6 literal properly bracketed
	reqV6 := httptest.NewRequest("GET", "http://[::1]/login", nil)
	reqV6.Host = "[::1]:80"
	if got := buildHTTPSRedirectURL(reqV6, ":443", "192.168.10.1"); got != "https://[::1]/login" {
		t.Fatalf("expected bracketed IPv6 redirect, got %q", got)
	}

	// Host-header open redirect poisoning (@evil.com, slash injection) falls back to safe LAN IP
	for _, poisoned := range []string{"@evil.com", "evil.com/pwn", "..:..", "-badhost"} {
		r := httptest.NewRequest("GET", "http://192.168.10.1/app", nil)
		r.Host = poisoned
		if got := buildHTTPSRedirectURL(r, ":443", "192.168.50.1"); got != "https://192.168.50.1/app" {
			t.Fatalf("poisoned Host %q was not sanitized: %q", poisoned, got)
		}
	}

	// Protocol-relative URI open redirect (//evil.com) sanitized to /
	reqSlash := httptest.NewRequest("GET", "http://netbee.lan/", nil)
	reqSlash.URL.Opaque = "//evil.com/phish"
	if got := buildHTTPSRedirectURL(reqSlash, ":443", "192.168.10.1"); got != "https://netbee.lan/" {
		t.Fatalf("protocol-relative URI was not sanitized: %q", got)
	}
}

func TestEnsureSelfSignedTLSRegeneratesOnLANIPChangeOnlyForAutoCert(t *testing.T) {
	dir := t.TempDir()
	certPath, _, err := ensureSelfSignedTLS(dir, "192.168.10.1")
	if err != nil {
		t.Fatalf("ensureSelfSignedTLS initial failed: %v", err)
	}
	if !certCoversAutoLANIP(certPath, net.ParseIP("192.168.10.1")) {
		t.Fatal("initial cert should cover 192.168.10.1")
	}
	if certCoversAutoLANIP(certPath, net.ParseIP("192.168.50.1")) {
		t.Fatal("initial cert should NOT cover 192.168.50.1 yet")
	}

	// Regenerates automatically when LAN IP changes to 192.168.50.1
	if _, _, err := ensureSelfSignedTLS(dir, "192.168.50.1"); err != nil {
		t.Fatalf("ensureSelfSignedTLS regen failed: %v", err)
	}
	if !certCoversAutoLANIP(certPath, net.ParseIP("192.168.50.1")) {
		t.Fatal("regenerated cert must cover 192.168.50.1")
	}

	// Custom user-supplied cert (different Organization) must NEVER be overwritten
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "custom.user.lan", Organization: []string{"User Custom CA"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, &tpl, &tpl, &priv.PublicKey, priv)
	customPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	_ = os.WriteFile(certPath, customPEM, 0644)

	if _, _, err := ensureSelfSignedTLS(dir, "10.0.0.1"); err != nil {
		t.Fatalf("ensureSelfSignedTLS with custom cert failed: %v", err)
	}
	after, _ := os.ReadFile(certPath)
	if string(after) != string(customPEM) {
		t.Fatal("custom user TLS certificate was unexpectedly overwritten")
	}
}

