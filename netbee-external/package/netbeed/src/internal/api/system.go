package api

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
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

const (
	maxBackupUploadBytes       = 16 << 20 // 16 MB compressed max
	maxBackupUncompressedBytes = 32 << 20 // 32 MB uncompressed max (gzip-bomb guard)
	maxBackupEntries           = 256
)

var allowedBackupExactFiles = map[string]bool{
	"etc/hostname":                  true,
	"etc/hosts":                     true,
	"etc/network/interfaces":        true,
	"etc/nftables.conf":             true,
	"etc/dhcpcd.conf":               true,
	"etc/chrony.conf":               true,
	"etc/radvd.conf":                true,
	"etc/ppp/pap-secrets":           true,
	"etc/ppp/chap-secrets":          true,
	"etc/adguardhome/AdGuardHome.yaml": true,
	"etc/default/dropbear":          true,
	"root/.ssh/authorized_keys":     true,
}

var allowedBackupDirs = map[string]bool{
	"etc":             true,
	"etc/network":     true,
	"etc/ppp":         true,
	"etc/adguardhome": true,
	"etc/default":     true,
	"root":            true,
	"root/.ssh":       true,
}

var allowedBackupTreePrefixes = []string{
	"etc/nftables.d",
	"etc/ppp/peers",
	"etc/netbee",
	"etc/wireguard",
	"etc/dropbear",
}

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
		if errors.Is(err, errPayloadTooLarge) {
			writeErr(w, http.StatusRequestEntityTooLarge, err.Error())
			return
		}
		writeErr(w, http.StatusBadRequest, "invalid json body")
		return
	}
	sess, err := s.Auth.Login(r, req.Username, req.Password)
	if err != nil {
		status := http.StatusUnauthorized
		if strings.Contains(err.Error(), "too many") {
			status = http.StatusTooManyRequests
		}
		writeErr(w, status, err.Error())
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
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
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
	sess, _ := s.Auth.Authenticate(r)
	if err := s.Auth.ChangePassword(req.CurrentPassword, req.NewPassword, sess.Token); err != nil {
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
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{})

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	_, _ = fmt.Fprint(w, ": connected\n\n")
	flusher.Flush()

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
			frame := map[string]any{
				"time":           now.Format(time.RFC3339),
				"cpu_pct":        float64(int(cpuPct*10+0.5)) / 10.0,
				"mem_used_mb":    ov.MemUsedMB,
				"mem_total_mb":   ov.MemTotalMB,
				"load_avg":       ov.LoadAvg,
				"uptime_seconds": ov.UptimeSec,
				"cpu_temp_c":     ov.CPUTempC,
				"interfaces":     rates,
			}
			if b, err := sysMarshal(frame); err == nil {
				_ = rc.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if _, wErr := fmt.Fprintf(w, "data: %s\n\n", b); wErr != nil {
					return
				}
				flusher.Flush()
				_ = rc.SetWriteDeadline(time.Time{})
			}

			prevCPU = curCPU
			prevNet = curNet
			prevAt = now
		}
	}
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

func renderHostsFile(lanIP, hostname string) string {
	if lanIP == "" {
		lanIP = "192.168.10.1"
	}
	if hostname == "" || !sys.ValidHostname(hostname) {
		hostname = "netbee"
	}
	names := "netbee.lan netbee"
	if !strings.EqualFold(hostname, "netbee") {
		names = fmt.Sprintf("%s.lan %s netbee.lan netbee", hostname, hostname)
	}
	return fmt.Sprintf("127.0.0.1       localhost\n%s    %s\n::1             localhost ip6-localhost ip6-loopback\n", lanIP, names)
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
	_ = config.AtomicWriteFile("/etc/hosts", []byte(renderHostsFile(s.Store.Get().LAN.IP, req.Hostname)), 0644)
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

func isAllowedBackupEntry(raw string, isDir bool) error {
	if raw == "" {
		return errors.New("empty archive entry name")
	}
	trimmed := strings.TrimPrefix(raw, "./")
	trimmed = strings.TrimSuffix(trimmed, "/")
	if trimmed == "" || trimmed == "." {
		if isDir {
			return nil
		}
		return errors.New("invalid root archive entry")
	}
	if strings.HasPrefix(raw, "/") || strings.HasPrefix(trimmed, "/") || strings.Contains(raw, "..") || strings.Contains(raw, `\`) {
		return fmt.Errorf("unsafe archive path rejected: %s", raw)
	}
	clean := filepath.Clean(trimmed)
	if strings.HasPrefix(clean, "/") || clean == ".." || strings.HasPrefix(clean, "../") {
		return fmt.Errorf("unsafe archive path rejected: %s", raw)
	}

	if isDir {
		if allowedBackupDirs[clean] {
			return nil
		}
		for _, prefix := range allowedBackupTreePrefixes {
			if clean == prefix || strings.HasPrefix(clean, prefix+"/") {
				return nil
			}
		}
		return fmt.Errorf("disallowed backup directory rejected: %s", raw)
	}

	if allowedBackupExactFiles[clean] {
		return nil
	}
	for _, prefix := range allowedBackupTreePrefixes {
		if strings.HasPrefix(clean, prefix+"/") {
			return nil
		}
	}
	return fmt.Errorf("disallowed backup file path rejected: %s", raw)
}

// ValidateBackupArchiveEntries validates newline-separated relative paths against the strict NetBee backup allowlist.
func ValidateBackupArchiveEntries(listing string) error {
	for _, line := range strings.Split(listing, "\n") {
		entry := strings.TrimSpace(line)
		if entry == "" {
			continue
		}
		isDir := strings.HasSuffix(entry, "/")
		if err := isAllowedBackupEntry(entry, isDir); err != nil {
			return err
		}
	}
	return nil
}

// ValidateBackupTarGz inspects the .tar.gz archive in-memory using Go's stdlib compress/gzip + archive/tar,
// blocking tar-slip, symlinks, hardlinks, device nodes, gzip decompression bombs, and /etc/shadow or hook overwrites.
func ValidateBackupTarGz(data []byte) error {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("invalid gzip archive: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	var totalBytes int64
	entries := 0
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("invalid tar header: %w", err)
		}
		entries++
		if entries > maxBackupEntries {
			return fmt.Errorf("backup archive contains too many entries (max %d)", maxBackupEntries)
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := isAllowedBackupEntry(hdr.Name, true); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := isAllowedBackupEntry(hdr.Name, false); err != nil {
				return err
			}
			if hdr.Size < 0 || hdr.Size > 8<<20 {
				return fmt.Errorf("archive file too large: %s", hdr.Name)
			}
			n, copyErr := io.Copy(io.Discard, io.LimitReader(tr, (maxBackupUncompressedBytes-totalBytes)+1))
			if copyErr != nil {
				return fmt.Errorf("corrupt archive stream in %s: %w", hdr.Name, copyErr)
			}
			totalBytes += n
			if totalBytes > maxBackupUncompressedBytes {
				return errors.New("backup archive exceeds maximum uncompressed size (32 MB)")
			}
		case tar.TypeXHeader, tar.TypeXGlobalHeader:
			continue
		default:
			// Reject TypeSymlink, TypeLink, TypeChar, TypeBlock, TypeFifo
			return fmt.Errorf("unsupported or unsafe tar entry type (%c) for %s", hdr.Typeflag, hdr.Name)
		}
	}
	if entries == 0 {
		return errors.New("backup archive contains no files")
	}
	return nil
}

func (s *Server) handleBackupRestore(w http.ResponseWriter, r *http.Request) {
	data, err := readBoundedBody(r, maxBackupUploadBytes)
	if err != nil {
		if errors.Is(err, errPayloadTooLarge) {
			writeErr(w, http.StatusRequestEntityTooLarge, "backup archive exceeds 16 MB limit")
			return
		}
		writeErr(w, http.StatusBadRequest, "unreadable backup archive")
		return
	}
	if len(data) == 0 {
		writeErr(w, http.StatusBadRequest, "empty backup archive")
		return
	}
	if err := ValidateBackupTarGz(data); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	f, err := os.CreateTemp("/tmp", "netbee-restore-*.tar.gz")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	_ = f.Chmod(0600)
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = f.Close()

	res, err := sys.Run(20*time.Second, "/usr/sbin/netbee-backup", "restore", tmp)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = s.Store.Reload()
	_ = s.Auth.Reload()
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
		writeJSON(w, http.StatusOK, map[string]any{"lines": []string{}, "count": 0})
		return
	}
	trimmed := strings.TrimRight(string(data), "\n")
	out := []string{}
	if trimmed != "" {
		for _, line := range strings.Split(trimmed, "\n") {
			if filter != "" && !strings.Contains(strings.ToLower(line), filter) {
				continue
			}
			out = append(out, line)
		}
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
	trimmed := strings.TrimRight(res.Stdout, "\n")
	out := []string{}
	if trimmed != "" {
		out = strings.Split(trimmed, "\n")
	}
	if len(out) > lines {
		out = out[len(out)-lines:]
	}
	writeJSON(w, http.StatusOK, map[string]any{"lines": out, "count": len(out)})
}
