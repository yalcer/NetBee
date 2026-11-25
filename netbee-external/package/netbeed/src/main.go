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
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/yalcer/netbee/netbeed/internal/api"
	"github.com/yalcer/netbee/netbeed/internal/auth"
	"github.com/yalcer/netbee/netbeed/internal/config"
)

var version = "0.1.0"

func ensureSelfSignedTLS(tlsDir, lanIP string) (string, string, error) {
	if err := os.MkdirAll(tlsDir, 0700); err != nil {
		return "", "", err
	}
	certPath := filepath.Join(tlsDir, "server.crt")
	keyPath := filepath.Join(tlsDir, "server.key")
	if _, err := os.Stat(certPath); err == nil {
		if _, err := os.Stat(keyPath); err == nil {
			return certPath, keyPath, nil
		}
	}

	ips := []net.IP{net.ParseIP("127.0.0.1")}
	if parsed := net.ParseIP(lanIP); parsed != nil {
		ips = append(ips, parsed)
	} else {
		ips = append(ips, net.ParseIP("192.168.10.1"))
	}

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
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
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

func main() {
	cfgPath := flag.String("config", "/etc/netbee/netbeed.json", "Path to netbeed JSON config")
	flag.Parse()

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

	apiSrv := api.NewServer(cfg, store, authMgr, version)
	// Restore persisted runtime interfaces (e.g. WireGuard wg0) after reboot
	go apiSrv.RestoreRuntimeOnBoot()

	httpsSrv := &http.Server{
		Addr:              cfg.HTTPSAddr,
		Handler:           apiSrv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	var httpSrv *http.Server
	if cfg.HTTPAddr != "" {
		httpSrv = &http.Server{
			Addr: cfg.HTTPAddr,
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				host := r.Host
				if h, _, err := net.SplitHostPort(host); err == nil {
					host = h
				}
				http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), http.StatusMovedPermanently)
			}),
			ReadHeaderTimeout: 5 * time.Second,
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

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpsSrv.Shutdown(ctx)
	if httpSrv != nil {
		_ = httpSrv.Shutdown(ctx)
	}
}

