package api

import (
	"bytes"
	"encoding/base64"
	"io"
	"net/http"
	"strings"
)

func (s *Server) proxyAdGuard(w http.ResponseWriter, method, path, rawQuery string, body io.Reader) {
	base := strings.TrimRight(s.Cfg.AdGuardURL, "/")
	target := base + "/control/" + strings.TrimLeft(path, "/")
	if rawQuery != "" {
		target += "?" + rawQuery
	}

	req, err := http.NewRequest(method, target, body)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if s.Cfg.AdGuardUser != "" {
		creds := base64.StdEncoding.EncodeToString([]byte(s.Cfg.AdGuardUser + ":" + s.Cfg.AdGuardPass))
		req.Header.Set("Authorization", "Basic "+creds)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := s.HTTPCli.Do(req)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "AdGuardHome unreachable: "+err.Error())
		return
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	ct := resp.Header.Get("Content-Type")
	if ct == "" {
		ct = "application/json; charset=utf-8"
	}
	w.Header().Set("Content-Type", ct)
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(respBody)
}

// handleAdGuardProxy forwards /api/v1/adguard/<subpath> directly to AdGuardHome /control/<subpath>.
func (s *Server) handleAdGuardProxy(w http.ResponseWriter, r *http.Request) {
	sub := strings.TrimPrefix(r.URL.Path, "/api/v1/adguard/")
	if sub == "" || strings.Contains(sub, "..") {
		writeErr(w, http.StatusBadRequest, "invalid adguard path")
		return
	}
	var body io.Reader
	if r.Body != nil && r.Method != http.MethodGet && r.Method != http.MethodHead {
		defer r.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		body = bytes.NewReader(b)
	}
	s.proxyAdGuard(w, r.Method, sub, r.URL.RawQuery, body)
}

func (s *Server) handleDNSStatus(w http.ResponseWriter, r *http.Request) {
	s.proxyAdGuard(w, http.MethodGet, "status", "", nil)
}

func (s *Server) handleDNSStats(w http.ResponseWriter, r *http.Request) {
	s.proxyAdGuard(w, http.MethodGet, "stats", r.URL.RawQuery, nil)
}

func (s *Server) handleDNSQueryLog(w http.ResponseWriter, r *http.Request) {
	s.proxyAdGuard(w, http.MethodGet, "querylog", r.URL.RawQuery, nil)
}

func (s *Server) handleDNSFilters(w http.ResponseWriter, r *http.Request) {
	s.proxyAdGuard(w, http.MethodGet, "filtering/status", "", nil)
}

func (s *Server) handleDNSProtection(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(r.Body, 65536))
	s.proxyAdGuard(w, http.MethodPost, "protection", "", bytes.NewReader(b))
}

func (s *Server) handleDNSRewritesList(w http.ResponseWriter, r *http.Request) {
	s.proxyAdGuard(w, http.MethodGet, "rewrite/list", "", nil)
}

func (s *Server) handleDNSRewriteAdd(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(r.Body, 65536))
	s.proxyAdGuard(w, http.MethodPost, "rewrite/add", "", bytes.NewReader(b))
}

func (s *Server) handleDNSRewriteDel(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(r.Body, 65536))
	s.proxyAdGuard(w, http.MethodPost, "rewrite/delete", "", bytes.NewReader(b))
}

func (s *Server) handleDHCPStatus(w http.ResponseWriter, r *http.Request) {
	s.proxyAdGuard(w, http.MethodGet, "dhcp/status", "", nil)
}

func (s *Server) handleDHCPSetConfig(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(r.Body, 65536))
	s.proxyAdGuard(w, http.MethodPost, "dhcp/set_config", "", bytes.NewReader(b))
}

func (s *Server) handleDHCPStaticAdd(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(r.Body, 65536))
	s.proxyAdGuard(w, http.MethodPost, "dhcp/add_static_lease", "", bytes.NewReader(b))
}

func (s *Server) handleDHCPStaticDel(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(r.Body, 65536))
	s.proxyAdGuard(w, http.MethodPost, "dhcp/remove_static_lease", "", bytes.NewReader(b))
}
