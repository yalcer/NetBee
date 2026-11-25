package api

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/yalcer/netbee/netbeed/internal/config"
	"github.com/yalcer/netbee/netbeed/internal/sys"
)

const sqmConfPath = "/etc/netbee/sqm.conf"

type SQMConfig struct {
	Enabled      bool   `json:"enabled"`
	WANInterface string `json:"wan_interface"`
	DownloadKbit int    `json:"download_kbit"`
	UploadKbit   int    `json:"upload_kbit"`
	Overhead     int    `json:"overhead"`
}

func ParseSQMConf(data string) SQMConfig {
	cfg := SQMConfig{
		Enabled:      false,
		WANInterface: "eth1",
		DownloadKbit: 95000,
		UploadKbit:   19000,
		Overhead:     44,
	}
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		switch strings.TrimSpace(k) {
		case "ENABLED":
			cfg.Enabled = v == "1" || strings.EqualFold(v, "true")
		case "WAN_IF":
			cfg.WANInterface = v
		case "DOWNLOAD_KBIT":
			if n, err := strconv.Atoi(v); err == nil {
				cfg.DownloadKbit = n
			}
		case "UPLOAD_KBIT":
			if n, err := strconv.Atoi(v); err == nil {
				cfg.UploadKbit = n
			}
		case "OVERHEAD":
			if n, err := strconv.Atoi(v); err == nil {
				cfg.Overhead = n
			}
		}
	}
	return cfg
}

func RenderSQMConf(cfg SQMConfig) string {
	en := 0
	if cfg.Enabled {
		en = 1
	}
	return fmt.Sprintf(
		"# Managed by NetBee OS (netbeed)\n"+
			"ENABLED=%d\nWAN_IF=%q\nDOWNLOAD_KBIT=%d\nUPLOAD_KBIT=%d\nOVERHEAD=%d\n",
		en, cfg.WANInterface, cfg.DownloadKbit, cfg.UploadKbit, cfg.Overhead,
	)
}

func (s *Server) handleGetSQM(w http.ResponseWriter, r *http.Request) {
	data, _ := os.ReadFile(sqmConfPath)
	cfg := ParseSQMConf(string(data))
	statusRes, _ := sys.Run(3*time.Second, "/usr/sbin/netbee-sqm", "status")
	writeJSON(w, http.StatusOK, map[string]any{
		"config": cfg,
		"status": statusRes.Stdout,
	})
}

func (s *Server) handleSetSQM(w http.ResponseWriter, r *http.Request) {
	var req SQMConfig
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json body")
		return
	}
	if req.WANInterface == "" {
		req.WANInterface = "eth1"
	}
	if !sys.ValidIface(req.WANInterface) {
		writeErr(w, http.StatusBadRequest, "invalid wan_interface")
		return
	}
	if req.DownloadKbit < 500 || req.DownloadKbit > 10000000 || req.UploadKbit < 250 || req.UploadKbit > 10000000 {
		writeErr(w, http.StatusBadRequest, "download/upload kbit out of range")
		return
	}
	if req.Overhead < 0 || req.Overhead > 128 {
		writeErr(w, http.StatusBadRequest, "overhead must be between 0 and 128")
		return
	}
	if err := config.AtomicWriteFile(sqmConfPath, []byte(RenderSQMConf(req)), 0644); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	act := "stop"
	if req.Enabled {
		act = "restart"
	}
	res, err := sys.Run(10*time.Second, "/usr/sbin/netbee-sqm", act)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !req.Enabled && s.Store.Get().Firewall.FlowOffload {
		_, _ = sys.Run(5*time.Second, "/etc/init.d/S42nft-offload", "start")
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "output": strings.TrimSpace(res.Stdout)})
}

func (s *Server) handleGetVnStat(w http.ResponseWriter, r *http.Request) {
	args := []string{"--json"}
	if iface := r.URL.Query().Get("iface"); iface != "" {
		if !sys.ValidIface(iface) {
			writeErr(w, http.StatusBadRequest, "invalid iface")
			return
		}
		args = append(args, "-i", iface)
	}
	res, err := sys.Run(5*time.Second, "vnstat", args...)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeRawJSON(w, http.StatusOK, []byte(res.Stdout))
}

func (s *Server) handleVnStatIface(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Interface string `json:"interface"`
		Action    string `json:"action"` // "add" or "remove"
	}
	if err := decodeJSON(r, &req); err != nil || !sys.ValidIface(req.Interface) {
		writeErr(w, http.StatusBadRequest, "invalid interface")
		return
	}
	var args []string
	switch req.Action {
	case "add":
		args = []string{"--add", "-i", req.Interface}
	case "remove":
		args = []string{"--remove", "--force", "-i", req.Interface}
	default:
		writeErr(w, http.StatusBadRequest, "action must be add or remove")
		return
	}
	res, err := sys.Run(5*time.Second, "vnstat", args...)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "output": strings.TrimSpace(res.Stdout)})
}

func (s *Server) handleLiveTraffic(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"time":       time.Now().Format(time.RFC3339),
		"interfaces": sys.ReadAllNetCounters(),
	})
}
