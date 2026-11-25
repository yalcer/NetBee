package api

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/yalcer/netbee/netbeed/internal/sys"
)

const iperfNftComment = "netbee-iperf3"

type iperfServerManager struct {
	mu        sync.Mutex
	running   bool
	pid       int
	bindIP    string
	port      int
	lanIface  string
	wgIface   string
	expiresAt time.Time
	cancel    context.CancelFunc
	timer     *time.Timer
}

func newIperfServerManager() *iperfServerManager {
	return &iperfServerManager{}
}

func addIperfFirewallRules(lanIf, wgIf string, port int) {
	var b strings.Builder
	for _, ifc := range []string{lanIf, wgIf} {
		if !sys.ValidIface(ifc) {
			continue
		}
		fmt.Fprintf(&b, "add rule inet netbee_fw custom_input iifname %q tcp dport %d comment %q accept\n", ifc, port, iperfNftComment)
		fmt.Fprintf(&b, "add rule inet netbee_fw custom_input iifname %q udp dport %d comment %q accept\n", ifc, port, iperfNftComment)
	}
	if b.Len() > 0 {
		_, _ = sys.RunWithInput(3*time.Second, b.String(), "nft", "-f", "-")
	}
}

func removeIperfFirewallRules() {
	res, err := sys.Run(3*time.Second, "nft", "-a", "list", "chain", "inet", "netbee_fw", "custom_input")
	if err != nil {
		return
	}
	for _, line := range strings.Split(res.Stdout, "\n") {
		if !strings.Contains(line, iperfNftComment) {
			continue
		}
		if idx := strings.LastIndex(line, "# handle "); idx >= 0 {
			handle := strings.TrimSpace(line[idx+len("# handle "):])
			if _, err := strconv.Atoi(handle); err == nil {
				_, _ = sys.Run(3*time.Second, "nft", "delete", "rule", "inet", "netbee_fw", "custom_input", "handle", handle)
			}
		}
	}
}

func (m *iperfServerManager) ReapplyFirewallRules() {
	m.mu.Lock()
	running := m.running
	lanIf := m.lanIface
	wgIf := m.wgIface
	port := m.port
	m.mu.Unlock()
	if running && port > 0 {
		removeIperfFirewallRules()
		addIperfFirewallRules(lanIf, wgIf, port)
	}
}

func (m *iperfServerManager) Stop() bool {
	m.mu.Lock()
	wasRunning := m.running
	cancel := m.cancel
	if m.timer != nil {
		m.timer.Stop()
		m.timer = nil
	}
	m.running = false
	m.pid = 0
	m.cancel = nil
	m.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	removeIperfFirewallRules()
	return wasRunning
}

func (m *iperfServerManager) Status() map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.running {
		return map[string]any{
			"running":           false,
			"remaining_seconds": 0,
		}
	}
	rem := int(time.Until(m.expiresAt).Seconds())
	if rem < 0 {
		rem = 0
	}
	return map[string]any{
		"running":           true,
		"pid":               m.pid,
		"bind_ip":           m.bindIP,
		"port":              m.port,
		"expires_at":        m.expiresAt.Format(time.RFC3339),
		"remaining_seconds": rem,
		"client_command":    fmt.Sprintf("iperf3 -c %s -p %d", m.bindIP, m.port),
	}
}

func (m *iperfServerManager) Start(bindIP string, port, durationSec int, lanIf, wgIf string) (map[string]any, error) {
	if port < 1024 || port > 65535 || port == 3000 {
		return nil, fmt.Errorf("port must be between 1024 and 65535 (excluding 3000)")
	}
	if durationSec < 10 || durationSec > 3600 {
		return nil, fmt.Errorf("duration_seconds must be between 10 and 3600")
	}
	if net.ParseIP(bindIP) == nil {
		return nil, fmt.Errorf("invalid bind_ip")
	}

	m.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, "iperf3", "-s", "-p", strconv.Itoa(port), "-B", bindIP)
	// Drop root privileges to the pre-created 'iperf' system user (UID 110) when running on NetBee OS
	if os.Geteuid() == 0 {
		if u, ok := lookupPasswdUser("iperf"); ok && u.UID > 0 && u.GID > 0 {
			cmd.SysProcAttr = &syscall.SysProcAttr{
				Credential: &syscall.Credential{
					Uid: uint32(u.UID),
					Gid: uint32(u.GID),
				},
			}
		}
	}
	var errBuf strings.Builder
	cmd.Stderr = &errBuf
	if err := cmd.Start(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to start iperf3 server: %w", err)
	}

	exitCh := make(chan error, 1)
	go func() {
		exitCh <- cmd.Wait()
	}()

	// Verify iperf3 did not immediately fail to bind
	select {
	case err := <-exitCh:
		cancel()
		msg := strings.TrimSpace(errBuf.String())
		if msg == "" && err != nil {
			msg = err.Error()
		}
		return nil, fmt.Errorf("iperf3 server exited immediately: %s", msg)
	case <-time.After(150 * time.Millisecond):
	}

	addIperfFirewallRules(lanIf, wgIf, port)

	ttl := time.Duration(durationSec) * time.Second
	exp := time.Now().Add(ttl)
	pid := cmd.Process.Pid

	m.mu.Lock()
	m.running = true
	m.pid = pid
	m.bindIP = bindIP
	m.port = port
	m.lanIface = lanIf
	m.wgIface = wgIf
	m.expiresAt = exp
	m.cancel = cancel
	m.timer = time.AfterFunc(ttl, func() {
		m.Stop()
	})
	m.mu.Unlock()

	// Clean up state & firewall rules if the process terminates unexpectedly
	go func(expectedPID int) {
		<-exitCh
		m.mu.Lock()
		same := m.running && m.pid == expectedPID
		m.mu.Unlock()
		if same {
			m.Stop()
		}
	}(pid)

	return m.Status(), nil
}

func (s *Server) handleGetIperf3Server(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.iperfSrv.Status())
}

func (s *Server) handleStartIperf3Server(w http.ResponseWriter, r *http.Request) {
	var req struct {
		BindIP      string `json:"bind_ip"`
		Port        int    `json:"port"`
		DurationSec int    `json:"duration_seconds"`
	}
	if r.ContentLength != 0 {
		if err := decodeJSON(r, &req); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid json body")
			return
		}
	}
	st := s.Store.Get()
	if req.BindIP == "" {
		req.BindIP = st.LAN.IP
	}
	if req.Port == 0 {
		req.Port = 5201
	}
	if req.DurationSec == 0 {
		req.DurationSec = 300
	}
	status, err := s.iperfSrv.Start(req.BindIP, req.Port, req.DurationSec, st.LAN.Interface, st.WireGuard.Interface)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (s *Server) handleStopIperf3Server(w http.ResponseWriter, r *http.Request) {
	stopped := s.iperfSrv.Stop()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "stopped": stopped})
}

func (s *Server) handleDiagPing(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Host  string `json:"host"`
		Count int    `json:"count"`
	}
	if err := decodeJSON(r, &req); err != nil || !sys.ValidHost(req.Host) {
		writeErr(w, http.StatusBadRequest, "invalid host")
		return
	}
	release, ok := s.acquireDiagSlot()
	if !ok {
		writeErr(w, http.StatusTooManyRequests, "too many diagnostic tasks running; please wait")
		return
	}
	defer release()

	if req.Count <= 0 || req.Count > 10 {
		req.Count = 4
	}
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(30 * time.Second))
	res, err := sys.Run(20*time.Second, "ping", "-c", fmt.Sprintf("%d", req.Count), "-W", "2", req.Host)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":     err == nil,
		"output": strings.TrimSpace(res.Stdout + "\n" + res.Stderr),
	})
}

func (s *Server) handleDiagMTR(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Host   string `json:"host"`
		Cycles int    `json:"cycles"`
	}
	if err := decodeJSON(r, &req); err != nil || !sys.ValidHost(req.Host) {
		writeErr(w, http.StatusBadRequest, "invalid host")
		return
	}
	release, ok := s.acquireDiagSlot()
	if !ok {
		writeErr(w, http.StatusTooManyRequests, "too many diagnostic tasks running; please wait")
		return
	}
	defer release()

	if req.Cycles <= 0 || req.Cycles > 10 {
		req.Cycles = 5
	}
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(40 * time.Second))
	res, err := sys.Run(30*time.Second, "mtr", "-j", "-c", fmt.Sprintf("%d", req.Cycles), req.Host)
	if err != nil && strings.TrimSpace(res.Stdout) == "" {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeValidatedRawJSON(w, http.StatusOK, []byte(res.Stdout), "{}")
}

func (s *Server) handleDiagIperf3(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Host     string `json:"host"`
		Port     int    `json:"port"`
		Duration int    `json:"duration"`
		Reverse  bool   `json:"reverse"`
	}
	if err := decodeJSON(r, &req); err != nil || !sys.ValidHost(req.Host) {
		writeErr(w, http.StatusBadRequest, "invalid host")
		return
	}
	if req.Port == 0 {
		req.Port = 5201
	}
	if !sys.ValidPort(req.Port) {
		writeErr(w, http.StatusBadRequest, "invalid port")
		return
	}
	release, ok := s.acquireDiagSlot()
	if !ok {
		writeErr(w, http.StatusTooManyRequests, "too many diagnostic tasks running; please wait")
		return
	}
	defer release()

	if req.Duration <= 0 || req.Duration > 15 {
		req.Duration = 5
	}
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(time.Duration(req.Duration+20) * time.Second))
	args := []string{"-c", req.Host, "-p", fmt.Sprintf("%d", req.Port), "-t", fmt.Sprintf("%d", req.Duration), "-J"}
	if req.Reverse {
		args = append(args, "-R")
	}
	res, err := sys.Run(time.Duration(req.Duration+10)*time.Second, "iperf3", args...)
	if err != nil && strings.TrimSpace(res.Stdout) == "" {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeValidatedRawJSON(w, http.StatusOK, []byte(res.Stdout), "{}")
}

func (s *Server) handleDiagDNS(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Host   string `json:"host"`
		Server string `json:"server"`
	}
	if err := decodeJSON(r, &req); err != nil || !sys.ValidHost(req.Host) {
		writeErr(w, http.StatusBadRequest, "invalid host")
		return
	}
	args := []string{req.Host}
	if req.Server != "" {
		if !sys.ValidHost(req.Server) {
			writeErr(w, http.StatusBadRequest, "invalid DNS server")
			return
		}
		args = append(args, req.Server)
	}
	release, ok := s.acquireDiagSlot()
	if !ok {
		writeErr(w, http.StatusTooManyRequests, "too many diagnostic tasks running; please wait")
		return
	}
	defer release()

	res, err := sys.Run(10*time.Second, "nslookup", args...)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":     err == nil,
		"output": strings.TrimSpace(res.Stdout + "\n" + res.Stderr),
	})
}

func (s *Server) handleDiagCapture(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Interface string `json:"interface"`
		Count     int    `json:"count"`
		Proto     string `json:"proto"` // optional: tcp, udp, icmp, arp
		Port      int    `json:"port"`  // optional
	}
	if err := decodeJSON(r, &req); err != nil || !sys.ValidIface(req.Interface) {
		writeErr(w, http.StatusBadRequest, "invalid interface")
		return
	}
	if req.Count <= 0 || req.Count > 50 {
		req.Count = 20
	}
	args := []string{"-i", req.Interface, "-c", fmt.Sprintf("%d", req.Count), "-nn", "-l"}
	var expr []string
	switch req.Proto {
	case "tcp", "udp", "icmp", "arp":
		expr = append(expr, req.Proto)
	case "":
	default:
		writeErr(w, http.StatusBadRequest, "proto must be tcp, udp, icmp, arp, or empty")
		return
	}
	if req.Port > 0 {
		if !sys.ValidPort(req.Port) {
			writeErr(w, http.StatusBadRequest, "invalid port")
			return
		}
		if req.Proto == "icmp" || req.Proto == "arp" {
			writeErr(w, http.StatusBadRequest, "port filter cannot be combined with icmp or arp")
			return
		}
		if len(expr) > 0 {
			expr = append(expr, "and")
		}
		expr = append(expr, "port", fmt.Sprintf("%d", req.Port))
	}
	args = append(args, expr...)

	release, ok := s.acquireDiagSlot()
	if !ok {
		writeErr(w, http.StatusTooManyRequests, "too many diagnostic tasks running; please wait")
		return
	}
	defer release()

	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(20 * time.Second))
	res, err := sys.Run(12*time.Second, "tcpdump", args...)
	packets := []string{}
	if trimmed := strings.TrimSpace(res.Stdout); trimmed != "" {
		packets = strings.Split(trimmed, "\n")
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      err == nil || len(packets) > 0,
		"packets": packets,
		"summary": strings.TrimSpace(res.Stderr),
	})
}
