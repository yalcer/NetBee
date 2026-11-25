package api

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/yalcer/netbee/netbeed/internal/auth"
	"github.com/yalcer/netbee/netbeed/internal/config"
	"github.com/yalcer/netbee/netbeed/internal/sys"
)

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"service": "netbeed",
		"version": s.Version,
		"time":    time.Now().Format(time.RFC3339),
	})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json body")
		return
	}
	sess, err := s.Auth.Login(r, req.Username, req.Password)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, err.Error())
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     auth.SessionCookieName,
		Value:    sess.Token,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		Expires:  sess.ExpiresAt,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"username":             sess.Username,
		"token":                sess.Token,
		"csrf_token":           sess.CSRFToken,
		"expires_at":           sess.ExpiresAt,
		"must_change_password": s.Auth.MustChangePassword(),
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if sess, ok := s.Auth.Authenticate(r); ok {
		s.Auth.Logout(sess.Token)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     auth.SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	sess, _ := s.Auth.Authenticate(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"username":             sess.Username,
		"csrf_token":           sess.CSRFToken,
		"expires_at":           sess.ExpiresAt,
		"must_change_password": s.Auth.MustChangePassword(),
	})
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
		SyncRootSSH     bool   `json:"sync_root_ssh"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json body")
		return
	}
	if err := s.Auth.ChangePassword(req.CurrentPassword, req.NewPassword); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.SyncRootSSH {
		if _, err := sys.RunWithInput(5*time.Second, "root:"+req.NewPassword+"\n", "chpasswd"); err != nil {
			writeJSON(w, http.StatusOK, map[string]any{
				"ok":          true,
				"ssh_synced":  false,
				"ssh_warning": err.Error(),
			})
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "ssh_synced": req.SyncRootSSH})
}

func (s *Server) handleSystemOverview(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"system":         sys.ReadOverview(),
		"services":       sys.ListServices(),
		"pending_commit": s.Rollback.Status(),
	})
}

// handleSystemStream sends Server-Sent Events (SSE) every 2 seconds with live CPU %, RAM, temp & per-iface bps.
func (s *Server) handleSystemStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	prevCPU := sys.ReadCPUTimes()
	prevNet := sys.ReadAllNetCounters()
	prevAt := time.Now()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case now := <-ticker.C:
			dt := now.Sub(prevAt).Seconds()
			if dt <= 0 {
				dt = 1
			}
			curCPU := sys.ReadCPUTimes()
			curNet := sys.ReadAllNetCounters()

			cpuPct := 0.0
			if curCPU.Total > prevCPU.Total {
				dTotal := float64(curCPU.Total - prevCPU.Total)
				dIdle := float64(curCPU.Idle - prevCPU.Idle)
				cpuPct = (1.0 - dIdle/dTotal) * 100.0
				if cpuPct < 0 {
					cpuPct = 0
				}
			}

			rates := make(map[string]map[string]uint64, len(curNet))
			for name, cur := range curNet {
				p := prevNet[name]
				var rxBps, txBps uint64
				if cur.RxBytes >= p.RxBytes {
					rxBps = uint64(float64(cur.RxBytes-p.RxBytes) / dt)
				}
				if cur.TxBytes >= p.TxBytes {
					txBps = uint64(float64(cur.TxBytes-p.TxBytes) / dt)
				}
				rates[name] = map[string]uint64{
					"rx_bps":   rxBps,
					"tx_bps":   txBps,
					"rx_bytes": cur.RxBytes,
					"tx_bytes": cur.TxBytes,
				}
			}

			ov := sys.ReadOverview()
			payload := fmt.Sprintf(
				`{"time":%q,"cpu_pct":%.1f,"mem_used_mb":%d,"mem_total_mb":%d,"load_avg":[%.2f,%.2f,%.2f],"uptime_seconds":%d,"cpu_temp_c":%v,"interfaces":%s}`,
				now.Format(time.RFC3339), cpuPct, ov.MemUsedMB, ov.MemTotalMB,
				ov.LoadAvg[0], ov.LoadAvg[1], ov.LoadAvg[2], ov.UptimeSec,
				formatFloatPtr(ov.CPUTempC), mustJSON(rates),
			)
			_, _ = fmt.Fprintf(w, "data: %s\n\n", payload)
			flusher.Flush()

			prevCPU = curCPU
			prevNet = curNet
			prevAt = now
		}
	}
}

func formatFloatPtr(f *float64) string {
	if f == nil {
		return "null"
	}
	return fmt.Sprintf("%.1f", *f)
}

func mustJSON(v any) string {
	b, _ := sysMarshal(v)
	return string(b)
}

func (s *Server) handleListServices(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"services": sys.ListServices()})
}

func (s *Server) handleServiceAction(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	action := r.PathValue("action")
	if action != "start" && action != "stop" && action != "restart" && action != "reload" {
		writeErr(w, http.StatusBadRequest, "invalid action (use start, stop, restart, reload)")
		return
	}
	var script string
	for _, svc := range sys.ManagedServices {
		if svc.Name == name {
			script = svc.InitScript
			break
		}
	}
	if script == "" {
		writeErr(w, http.StatusNotFound, "unknown or non-controllable service")
		return
	}
	res, err := sys.Run(15*time.Second, script, action)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "output": strings.TrimSpace(res.Stdout)})
}

func (s *Server) handleSetHostname(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Hostname string `json:"hostname"`
	}
	if err := decodeJSON(r, &req); err != nil || !sys.ValidHostname(req.Hostname) {
		writeErr(w, http.StatusBadRequest, "invalid hostname")
		return
	}
	if err := config.AtomicWriteFile("/etc/hostname", []byte(req.Hostname+"\n"), 0644); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	_, _ = sys.Run(5*time.Second, "hostname", req.Hostname)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "hostname": req.Hostname})
}

func (s *Server) handleSetTimezone(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Timezone string `json:"timezone"`
	}
	if err := decodeJSON(r, &req); err != nil || !sys.ValidTimezone(req.Timezone) {
		writeErr(w, http.StatusBadRequest, "invalid timezone")
		return
	}
	zoneFile := filepath.Join("/usr/share/zoneinfo", req.Timezone)
	if _, err := os.Stat(zoneFile); err != nil {
		writeErr(w, http.StatusBadRequest, "timezone not installed on device")
		return
	}
	_ = os.Remove("/etc/localtime")
	if err := os.Symlink(zoneFile, "/etc/localtime"); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "timezone": req.Timezone})
}

func (s *Server) handleReboot(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "rebooting in 1 second"})
	go func() {
		time.Sleep(1 * time.Second)
		_, _ = sys.Run(5*time.Second, "/sbin/reboot")
	}()
}

func (s *Server) handlePoweroff(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "powering off in 1 second"})
	go func() {
		time.Sleep(1 * time.Second)
		_, _ = sys.Run(5*time.Second, "/sbin/poweroff")
	}()
}

func (s *Server) handlePendingCommit(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.Rollback.Status())
}

func (s *Server) handleConfirmCommit(w http.ResponseWriter, r *http.Request) {
	ok := s.Rollback.Confirm()
	writeJSON(w, http.StatusOK, map[string]any{"confirmed": ok})
}

func (s *Server) handleRollbackNow(w http.ResponseWriter, r *http.Request) {
	ok := s.Rollback.RevertNow()
	writeJSON(w, http.StatusOK, map[string]any{"reverted": ok})
}

func (s *Server) handleBackupDownload(w http.ResponseWriter, r *http.Request) {
	tmp := fmt.Sprintf("/tmp/netbee-backup-%d.tar.gz", time.Now().UnixNano())
	defer os.Remove(tmp)
	if _, err := sys.Run(15*time.Second, "/usr/sbin/netbee-backup", "create", tmp); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	data, err := os.ReadFile(tmp)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="netbee-backup-%s.tar.gz"`, time.Now().Format("20060102-150405")))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (s *Server) handleBackupRestore(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	data, err := io.ReadAll(io.LimitReader(r.Body, 16<<20)) // 16 MB max
	if err != nil || len(data) == 0 {
		writeErr(w, http.StatusBadRequest, "empty or unreadable backup archive")
		return
	}
	tmp := fmt.Sprintf("/tmp/netbee-restore-%d.tar.gz", time.Now().UnixNano())
	defer os.Remove(tmp)
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	res, err := sys.Run(20*time.Second, "/usr/sbin/netbee-backup", "restore", tmp)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "output": strings.TrimSpace(res.Stdout)})
}

func (s *Server) handleSystemLogs(w http.ResponseWriter, r *http.Request) {
	lines := 200
	if q := r.URL.Query().Get("lines"); q != "" {
		if n, err := strconv.Atoi(q); err == nil && n > 0 && n <= 2000 {
			lines = n
		}
	}
	filter := strings.ToLower(r.URL.Query().Get("filter"))
	data, err := os.ReadFile("/var/log/messages")
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"lines": []string{}})
		return
	}
	all := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	var out []string
	for _, line := range all {
		if filter != "" && !strings.Contains(strings.ToLower(line), filter) {
			continue
		}
		out = append(out, line)
	}
	if len(out) > lines {
		out = out[len(out)-lines:]
	}
	writeJSON(w, http.StatusOK, map[string]any{"lines": out, "count": len(out)})
}

func (s *Server) handleKernelLogs(w http.ResponseWriter, r *http.Request) {
	lines := 200
	if q := r.URL.Query().Get("lines"); q != "" {
		if n, err := strconv.Atoi(q); err == nil && n > 0 && n <= 2000 {
			lines = n
		}
	}
	res, err := sys.Run(5*time.Second, "dmesg")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	all := strings.Split(strings.TrimRight(res.Stdout, "\n"), "\n")
	if len(all) > lines {
		all = all[len(all)-lines:]
	}
	writeJSON(w, http.StatusOK, map[string]any{"lines": all, "count": len(all)})
}
