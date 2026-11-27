package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
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
	b, err := readBoundedBody(r, 262144) // 256 KB max for custom filter rules / DNS lists
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

func (s *Server) handleDNSGetConfig(w http.ResponseWriter, r *http.Request) {
	s.proxyAdGuard(w, http.MethodGet, "dns_info", "", "", nil)
}

func (s *Server) handleDNSSetConfig(w http.ResponseWriter, r *http.Request) {
	s.proxyAdGuardJSONPost(w, r, "dns_config")
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

func (s *Server) handleDNSFilterAdd(w http.ResponseWriter, r *http.Request) {
	s.proxyAdGuardJSONPost(w, r, "filtering/add_url")
}

func (s *Server) handleDNSFilterSet(w http.ResponseWriter, r *http.Request) {
	s.proxyAdGuardJSONPost(w, r, "filtering/set_url")
}

func (s *Server) handleDNSFilterDel(w http.ResponseWriter, r *http.Request) {
	s.proxyAdGuardJSONPost(w, r, "filtering/remove_url")
}

func (s *Server) handleDNSFiltersRefresh(w http.ResponseWriter, r *http.Request) {
	b, _ := readBoundedBody(r, 4096)
	if len(bytes.TrimSpace(b)) == 0 {
		b = []byte(`{"whitelist":false}`)
	}
	s.proxyAdGuard(w, http.MethodPost, "filtering/refresh", "", "application/json", bytes.NewReader(b))
}

func (s *Server) handleDNSFilteringConfig(w http.ResponseWriter, r *http.Request) {
	s.proxyAdGuardJSONPost(w, r, "filtering/config")
}

func (s *Server) handleDNSSetUserRules(w http.ResponseWriter, r *http.Request) {
	s.proxyAdGuardJSONPost(w, r, "filtering/set_rules")
}

func (s *Server) handleDNSBlockedServicesGet(w http.ResponseWriter, r *http.Request) {
	s.proxyAdGuard(w, http.MethodGet, "blocked_services/get", "", "", nil)
}

func (s *Server) handleDNSBlockedServicesAll(w http.ResponseWriter, r *http.Request) {
	s.proxyAdGuard(w, http.MethodGet, "blocked_services/all", "", "", nil)
}

func (s *Server) handleDNSBlockedServicesSet(w http.ResponseWriter, r *http.Request) {
	b, err := readBoundedBody(r, 65536)
	if err != nil {
		if errors.Is(err, errPayloadTooLarge) {
			writeErr(w, http.StatusRequestEntityTooLarge, err.Error())
			return
		}
		writeErr(w, http.StatusBadRequest, "failed to read request body")
		return
	}
	trimmed := bytes.TrimSpace(b)
	if len(trimmed) == 0 {
		writeErr(w, http.StatusBadRequest, "empty request body")
		return
	}

	// AdGuardHome v0.107.36+ / v1.0.0 uses PUT /control/blocked_services/update
	// with {"ids":[...], "schedule":{"time_zone":"Local"}} instead of legacy POST /blocked_services/set.
	var normalized []byte
	if trimmed[0] == '[' {
		var ids []string
		if err := json.Unmarshal(trimmed, &ids); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid blocked services array")
			return
		}
		if ids == nil {
			ids = []string{}
		}
		normalized, _ = json.Marshal(map[string]any{
			"ids":      ids,
			"schedule": map[string]any{"time_zone": "Local"},
		})
	} else {
		var obj map[string]any
		if err := json.Unmarshal(trimmed, &obj); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid json body")
			return
		}
		if _, ok := obj["ids"]; !ok || obj["ids"] == nil {
			obj["ids"] = []string{}
		}
		if _, ok := obj["schedule"]; !ok || obj["schedule"] == nil {
			obj["schedule"] = map[string]any{"time_zone": "Local"}
		}
		normalized, _ = json.Marshal(obj)
	}

	s.proxyAdGuard(w, http.MethodPut, "blocked_services/update", "", "application/json", bytes.NewReader(normalized))
}

func (s *Server) handleDNSCacheClear(w http.ResponseWriter, r *http.Request) {
	s.proxyAdGuard(w, http.MethodPost, "cache_clear", "", "", nil)
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

func (s *Server) handleDNSRewriteUpdate(w http.ResponseWriter, r *http.Request) {
	b, err := readBoundedBody(r, 65536)
	if err != nil {
		if errors.Is(err, errPayloadTooLarge) {
			writeErr(w, http.StatusRequestEntityTooLarge, err.Error())
			return
		}
		writeErr(w, http.StatusBadRequest, "failed to read request body")
		return
	}
	s.proxyAdGuard(w, http.MethodPut, "rewrite/update", "", "application/json", bytes.NewReader(b))
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

func (s *Server) handleDHCPStaticUpdate(w http.ResponseWriter, r *http.Request) {
	s.proxyAdGuardJSONPost(w, r, "dhcp/update_static_lease")
}

func (s *Server) handleDHCPStaticDel(w http.ResponseWriter, r *http.Request) {
	s.proxyAdGuardJSONPost(w, r, "dhcp/remove_static_lease")
}
