package api

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
)

func (s *Server) proxyAdGuard(w http.ResponseWriter, method, subPath, rawQuery, contentType string, body io.Reader) {
	baseURL, err := url.Parse(s.Cfg.AdGuardURL)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "invalid configured adguard_url")
		return
	}
	cleanSub := path.Clean("/" + strings.TrimLeft(subPath, "/"))
	if cleanSub == "/" || strings.HasPrefix(cleanSub, "/..") {
		writeErr(w, http.StatusBadRequest, "invalid adguard path")
		return
	}
	baseURL.Path = path.Join(baseURL.Path, "control", cleanSub)
	baseURL.RawQuery = rawQuery

	req, err := http.NewRequest(method, baseURL.String(), body)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if s.Cfg.AdGuardUser != "" {
		creds := base64.StdEncoding.EncodeToString([]byte(s.Cfg.AdGuardUser + ":" + s.Cfg.AdGuardPass))
		req.Header.Set("Authorization", "Basic "+creds)
	}
	if body != nil {
		if contentType == "" {
			contentType = "application/json"
		}
		req.Header.Set("Content-Type", contentType)
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

func (s *Server) proxyAdGuardJSONPost(w http.ResponseWriter, r *http.Request, subPath string) {
	b, err := readBoundedBody(r, 65536)
	if err != nil {
		if errors.Is(err, errPayloadTooLarge) {
			writeErr(w, http.StatusRequestEntityTooLarge, err.Error())
			return
		}
		writeErr(w, http.StatusBadRequest, "failed to read request body")
		return
	}
	s.proxyAdGuard(w, http.MethodPost, subPath, "", "application/json", bytes.NewReader(b))
}

// handleAdGuardProxy forwards /api/v1/adguard/<subpath> directly to AdGuardHome /control/<subpath>.
func (s *Server) handleAdGuardProxy(w http.ResponseWriter, r *http.Request) {
	sub := strings.TrimPrefix(r.URL.Path, "/api/v1/adguard/")
	if sub == "" || strings.Contains(sub, "..") || strings.Contains(sub, `\`) {
		writeErr(w, http.StatusBadRequest, "invalid adguard path")
		return
	}
	var body io.Reader
	if r.Body != nil && r.Method != http.MethodGet && r.Method != http.MethodHead {
		b, err := readBoundedBody(r, 1<<20)
		if err != nil {
			if errors.Is(err, errPayloadTooLarge) {
				writeErr(w, http.StatusRequestEntityTooLarge, err.Error())
				return
			}
			writeErr(w, http.StatusBadRequest, "failed to read request body")
			return
		}
		body = bytes.NewReader(b)
	}
	s.proxyAdGuard(w, r.Method, sub, r.URL.RawQuery, r.Header.Get("Content-Type"), body)
}

func (s *Server) handleDNSStatus(w http.ResponseWriter, r *http.Request) {
	s.proxyAdGuard(w, http.MethodGet, "status", "", "", nil)
}

func (s *Server) handleDNSStats(w http.ResponseWriter, r *http.Request) {
	s.proxyAdGuard(w, http.MethodGet, "stats", r.URL.RawQuery, "", nil)
}

func (s *Server) handleDNSQueryLog(w http.ResponseWriter, r *http.Request) {
	s.proxyAdGuard(w, http.MethodGet, "querylog", r.URL.RawQuery, "", nil)
}

func (s *Server) handleDNSFilters(w http.ResponseWriter, r *http.Request) {
	s.proxyAdGuard(w, http.MethodGet, "filtering/status", "", "", nil)
}

func (s *Server) handleDNSProtection(w http.ResponseWriter, r *http.Request) {
	s.proxyAdGuardJSONPost(w, r, "protection")
}

func (s *Server) handleDNSRewritesList(w http.ResponseWriter, r *http.Request) {
	s.proxyAdGuard(w, http.MethodGet, "rewrite/list", "", "", nil)
}

func (s *Server) handleDNSRewriteAdd(w http.ResponseWriter, r *http.Request) {
	s.proxyAdGuardJSONPost(w, r, "rewrite/add")
}

func (s *Server) handleDNSRewriteDel(w http.ResponseWriter, r *http.Request) {
	s.proxyAdGuardJSONPost(w, r, "rewrite/delete")
}

func (s *Server) handleDHCPStatus(w http.ResponseWriter, r *http.Request) {
	s.proxyAdGuard(w, http.MethodGet, "dhcp/status", "", "", nil)
}

func (s *Server) handleDHCPSetConfig(w http.ResponseWriter, r *http.Request) {
	s.proxyAdGuardJSONPost(w, r, "dhcp/set_config")
}

func (s *Server) handleDHCPStaticAdd(w http.ResponseWriter, r *http.Request) {
	s.proxyAdGuardJSONPost(w, r, "dhcp/add_static_lease")
}

func (s *Server) handleDHCPStaticDel(w http.ResponseWriter, r *http.Request) {
	s.proxyAdGuardJSONPost(w, r, "dhcp/remove_static_lease")
}
