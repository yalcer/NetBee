package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"io"
	"log"
	"log/syslog"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/yalcer/netbee/netbeed/internal/api"
	"github.com/yalcer/netbee/netbeed/internal/auth"
	"github.com/yalcer/netbee/netbeed/internal/config"
	"github.com/yalcer/netbee/netbeed/internal/sys"
)

var version = "0.1.0"

func certCoversAutoLANIP(certPath string, targetIP net.IP) bool {
	pemBytes, err := os.ReadFile(certPath)
	if err != nil {
		return false
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}
	// Never overwrite a custom user-supplied TLS certificate
	isAutoCert := len(cert.Issuer.Organization) == 1 && cert.Issuer.Organization[0] == "NetBee OS" && cert.Subject.CommonName == "netbee.lan"
	if !isAutoCert {
		return true
	}
	if targetIP == nil {
		return true
	}
	for _, ip := range cert.IPAddresses {
		if ip.Equal(targetIP) {
			return true
		}
	}
	return false
}

func ensureSelfSignedTLS(tlsDir, lanIP string) (string, string, error) {
	if err := os.MkdirAll(tlsDir, 0700); err != nil {
		return "", "", err
	}
	certPath := filepath.Join(tlsDir, "server.crt")
	keyPath := filepath.Join(tlsDir, "server.key")

	parsedLAN := net.ParseIP(lanIP)
	if parsedLAN == nil {
		parsedLAN = net.ParseIP("192.168.10.1")
	}

	if _, err := os.Stat(certPath); err == nil {
		if _, err := os.Stat(keyPath); err == nil && certCoversAutoLANIP(certPath, parsedLAN) {
			return certPath, keyPath, nil
		}
	}

	ips := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1"), parsedLAN}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", err
	}
	now := time.Now()
	// Ensure cert is valid even if generated on a 1970 RTC-less first boot
	notBefore := time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := now.AddDate(10, 0, 0)
	if notAfter.Year() < 2040 {
		notAfter = time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC)
	}

	tpl := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "netbee.lan",
			Organization: []string{"NetBee OS"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"netbee", "netbee.lan", "localhost"},
		IPAddresses:           ips,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &tpl, &tpl, &priv.PublicKey, priv)
	if err != nil {
		return "", "", err
	}
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return "", "", err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	if err := config.AtomicWriteFile(certPath, certPEM, 0644); err != nil {
		return "", "", err
	}
	if err := config.AtomicWriteFile(keyPath, keyPEM, 0600); err != nil {
		return "", "", err
	}
	return certPath, keyPath, nil
}

// buildHTTPSRedirectURL safely constructs an HTTPS redirect target, preventing Host-header open redirects,
// preserving non-443 HTTPS ports, and properly bracketing IPv6 literals.
func buildHTTPSRedirectURL(r *http.Request, httpsAddr, fallbackHost string) string {
	host := strings.TrimSpace(r.Host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	} else if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	if !sys.ValidHost(host) {
		if sys.ValidHost(fallbackHost) {
			host = fallbackHost
		} else {
			host = "192.168.10.1"
		}
	}

	httpsPort := "443"
	if _, p, err := net.SplitHostPort(httpsAddr); err == nil && p != "" {
		httpsPort = p
	}

	authority := host
	if httpsPort != "443" {
		authority = net.JoinHostPort(host, httpsPort)
	} else if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		authority = "[" + host + "]"
	}

	reqURI := r.URL.RequestURI()
	if !strings.HasPrefix(reqURI, "/") || strings.HasPrefix(reqURI, "//") {
		reqURI = "/"
	}
	return "https://" + authority + reqURI
}

func main() {
	cfgPath := flag.String("config", "/etc/netbee/netbeed.json", "Path to netbeed JSON config")
	flag.Parse()

	if sl, err := syslog.New(syslog.LOG_DAEMON|syslog.LOG_INFO, "netbeed"); err == nil {
		defer sl.Close()
		log.SetOutput(io.MultiWriter(os.Stderr, sl))
	}

	cfg, err := config.LoadRuntimeConfig(*cfgPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	store, err := config.NewStore(cfg.StatePath)
	if err != nil {
		log.Fatalf("init state store: %v", err)
	}
	authMgr, err := auth.NewManager(cfg.AuthPath)
	if err != nil {
		log.Fatalf("init auth manager: %v", err)
	}

	certPath, keyPath, err := ensureSelfSignedTLS(cfg.TLSDIR, store.Get().LAN.IP)
	if err != nil {
		log.Fatalf("ensure TLS cert: %v", err)
	}

	appCtx, appCancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer appCancel()

	apiSrv := api.NewServer(cfg, store, authMgr, version)
	// Restore persisted runtime interfaces (e.g. WireGuard wg0) after reboot
	go apiSrv.RestoreRuntimeOnBoot()

	httpsSrv := &http.Server{
		Addr:              cfg.HTTPSAddr,
		Handler:           apiSrv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    64 << 10,
		BaseContext: func(_ net.Listener) context.Context {
			return appCtx
		},
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			},
		},
	}

	var httpSrv *http.Server
	if cfg.HTTPAddr != "" {
		httpSrv = &http.Server{
			Addr: cfg.HTTPAddr,
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				target := buildHTTPSRedirectURL(r, cfg.HTTPSAddr, store.Get().LAN.IP)
				http.Redirect(w, r, target, http.StatusTemporaryRedirect)
			}),
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      10 * time.Second,
			IdleTimeout:       30 * time.Second,
			MaxHeaderBytes:    16 << 10,
		}
		go func() {
			log.Printf("netbeed HTTP->HTTPS redirect listening on %s", cfg.HTTPAddr)
			if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("HTTP redirect server error: %v", err)
			}
		}()
	}

	go func() {
		log.Printf("netbeed %s HTTPS API listening on %s (web_dir=%s)", version, cfg.HTTPSAddr, cfg.WebDir)
		if err := httpsSrv.ListenAndServeTLS(certPath, keyPath); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTPS server error: %v", err)
		}
	}()

	<-appCtx.Done()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpsSrv.Shutdown(ctx)
	if httpSrv != nil {
		_ = httpSrv.Shutdown(ctx)
	}
}
