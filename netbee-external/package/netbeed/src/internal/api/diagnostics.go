package api

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/yalcer/netbee/netbeed/internal/sys"
)

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
	// Build strict whitelisted BPF expression (zero arbitrary filter injection)
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
