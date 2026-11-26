package api

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/yalcer/netbee/netbeed/internal/config"
	"github.com/yalcer/netbee/netbeed/internal/sys"
)

const (
	uiNftDropInPath     = "/etc/nftables.d/10-ui-rules.nft"
	customNftDropInPath = "/etc/nftables.d/00-custom.nft"
)

func isIPv6Addr(s string) bool {
	if ip := net.ParseIP(s); ip != nil {
		return ip.To4() == nil
	}
	if ip, _, err := net.ParseCIDR(s); err == nil {
		return ip.To4() == nil
	}
	return false
}

// RenderCustomNFT generates /etc/nftables.d/10-ui-rules.nft targeting custom_input and custom_forward
// (evaluated BEFORE default LAN->WAN accept so both custom drop/reject and accept rules take effect).
func RenderCustomNFT(fw config.FirewallState, lanIP string) string {
	if lanIP == "" {
		lanIP = "192.168.10.1"
	}
	var b strings.Builder
	b.WriteString("# Managed by NetBee OS (netbeed) - Custom Rules, DNAT & Toggles\n")

	if fw.ExposeWireGuard && sys.ValidPort(fw.WireGuardPort) {
		fmt.Fprintf(&b, "add rule inet netbee_fw custom_input iifname $WAN_IFS udp dport %d accept\n", fw.WireGuardPort)
	}

	if fw.TransparentDNS {
		fmt.Fprintf(&b, "add rule ip netbee_nat prerouting iifname $LAN_IF ip daddr != %s udp dport 53 redirect to :53\n", lanIP)
		fmt.Fprintf(&b, "add rule ip netbee_nat prerouting iifname $LAN_IF ip daddr != %s tcp dport 53 redirect to :53\n", lanIP)
	}

	for _, pf := range fw.PortForwards {
		if !pf.Enabled {
			continue
		}
		protos := []string{pf.Protocol}
		if pf.Protocol == "both" {
			protos = []string{"tcp", "udp"}
		}
		for _, proto := range protos {
			src := ""
			if pf.SourceCIDR != "" {
				src = fmt.Sprintf("ip saddr %s ", pf.SourceCIDR)
			}
			if pf.IntPort > 0 {
				fmt.Fprintf(&b, "add rule ip netbee_nat prerouting iifname $WAN_IFS %s%s dport %s dnat to %s:%d\n",
					src, proto, pf.ExtPort, pf.IntIP, pf.IntPort)
				fmt.Fprintf(&b, "add rule inet netbee_fw custom_forward iifname $WAN_IFS %sip daddr %s %s dport %d accept\n",
					src, pf.IntIP, proto, pf.IntPort)
			} else {
				fmt.Fprintf(&b, "add rule ip netbee_nat prerouting iifname $WAN_IFS %s%s dport %s dnat to %s\n",
					src, proto, pf.ExtPort, pf.IntIP)
				fmt.Fprintf(&b, "add rule inet netbee_fw custom_forward iifname $WAN_IFS %sip daddr %s %s dport %s accept\n",
					src, pf.IntIP, proto, pf.ExtPort)
			}
		}
	}

	for _, rule := range fw.CustomRules {
		if !rule.Enabled {
			continue
		}
		chain := "custom_input"
		if rule.Chain == "forward" {
			chain = "custom_forward"
		}
		var parts []string
		if rule.InIface != "" {
			parts = append(parts, fmt.Sprintf("iifname %q", rule.InIface))
		}
		if rule.OutIface != "" && rule.Chain == "forward" {
			parts = append(parts, fmt.Sprintf("oifname %q", rule.OutIface))
		}
		v6 := false
		if rule.SrcAddr != "" {
			if isIPv6Addr(rule.SrcAddr) {
				v6 = true
				parts = append(parts, fmt.Sprintf("ip6 saddr %s", rule.SrcAddr))
			} else {
				parts = append(parts, fmt.Sprintf("ip saddr %s", rule.SrcAddr))
			}
		}
		if rule.DstAddr != "" {
			if isIPv6Addr(rule.DstAddr) {
				v6 = true
				parts = append(parts, fmt.Sprintf("ip6 daddr %s", rule.DstAddr))
			} else {
				parts = append(parts, fmt.Sprintf("ip daddr %s", rule.DstAddr))
			}
		}
		switch rule.Protocol {
		case "tcp", "udp":
			if rule.DstPort != "" {
				parts = append(parts, fmt.Sprintf("%s dport %s", rule.Protocol, rule.DstPort))
			} else {
				parts = append(parts, fmt.Sprintf("meta l4proto %s", rule.Protocol))
			}
		case "icmpv6":
			parts = append(parts, "ip6 nexthdr icmpv6")
		case "icmp":
			if v6 {
				parts = append(parts, "ip6 nexthdr icmpv6")
			} else {
				parts = append(parts, "ip protocol icmp")
			}
		}
		if rule.Log {
			parts = append(parts, fmt.Sprintf(`limit rate 10/minute log prefix "netbee-%s: "`, rule.ID))
		}
		parts = append(parts, rule.Action)
		fmt.Fprintf(&b, "add rule inet netbee_fw %s %s\n", chain, strings.Join(parts, " "))
	}

	return b.String()
}

func validateFirewallRule(r config.FirewallRule) error {
	if r.ID == "" || !sys.ValidID(r.ID) {
		return fmt.Errorf("invalid rule id")
	}
	if r.Chain != "input" && r.Chain != "forward" {
		return fmt.Errorf("chain must be input or forward")
	}
	if r.Chain == "input" && r.OutIface != "" {
		return fmt.Errorf("out_iface is only valid on forward chain")
	}
	if r.Action != "accept" && r.Action != "drop" && r.Action != "reject" {
		return fmt.Errorf("action must be accept, drop, or reject")
	}
	if r.Protocol != "tcp" && r.Protocol != "udp" && r.Protocol != "icmp" && r.Protocol != "icmpv6" && r.Protocol != "any" {
		return fmt.Errorf("protocol must be tcp, udp, icmp, icmpv6, or any")
	}
	if r.InIface != "" && !sys.ValidIface(r.InIface) {
		return fmt.Errorf("invalid in_iface")
	}
	if r.OutIface != "" && !sys.ValidIface(r.OutIface) {
		return fmt.Errorf("invalid out_iface")
	}
	if r.SrcAddr != "" && !sys.ValidIPOrCIDR(r.SrcAddr) {
		return fmt.Errorf("invalid src_addr")
	}
	if r.DstAddr != "" && !sys.ValidIPOrCIDR(r.DstAddr) {
		return fmt.Errorf("invalid dst_addr")
	}
	if r.SrcAddr != "" && r.DstAddr != "" && isIPv6Addr(r.SrcAddr) != isIPv6Addr(r.DstAddr) {
		return fmt.Errorf("src_addr and dst_addr must use the same IP family")
	}
	if r.Protocol == "icmpv6" && ((r.SrcAddr != "" && !isIPv6Addr(r.SrcAddr)) || (r.DstAddr != "" && !isIPv6Addr(r.DstAddr))) {
		return fmt.Errorf("icmpv6 protocol cannot be combined with IPv4 addresses")
	}
	if r.DstPort != "" {
		if r.Protocol != "tcp" && r.Protocol != "udp" {
			return fmt.Errorf("dst_port requires protocol tcp or udp")
		}
		if !sys.ValidPortSpec(r.DstPort) {
			return fmt.Errorf("invalid dst_port")
		}
	}
	return nil
}

func validatePortForward(pf config.PortForward) error {
	if pf.ID == "" || !sys.ValidID(pf.ID) {
		return fmt.Errorf("invalid port-forward id")
	}
	if pf.Protocol != "tcp" && pf.Protocol != "udp" && pf.Protocol != "both" {
		return fmt.Errorf("protocol must be tcp, udp, or both")
	}
	if !sys.ValidPortSpec(pf.ExtPort) {
		return fmt.Errorf("invalid ext_port")
	}
	if !sys.ValidIPv4(pf.IntIP) {
		return fmt.Errorf("invalid int_ip (IPv4 required)")
	}
	if pf.IntPort != 0 && !sys.ValidPort(pf.IntPort) {
		return fmt.Errorf("invalid int_port (use 0 to preserve external port/range, or 1..65535)")
	}
	if strings.Contains(pf.ExtPort, "-") && pf.IntPort != 0 {
		return fmt.Errorf("int_port must be 0 when ext_port is a port range")
	}
	if pf.SourceCIDR != "" && (!sys.ValidIPOrCIDR(pf.SourceCIDR) || isIPv6Addr(pf.SourceCIDR)) {
		return fmt.Errorf("invalid source_cidr (IPv4 CIDR required)")
	}
	return nil
}

// mutateAndApplyFirewall snapshots state & nft drop-in BEFORE mutating Store, validates via nft -c, and reloads.
func (s *Server) mutateAndApplyFirewall(reason string, mutate func(*config.FirewallState) error) error {
	files := []string{uiNftDropInPath, s.Cfg.StatePath}
	s.Rollback.Begin(reason, time.Duration(s.Cfg.RollbackSeconds)*time.Second, files, func() {
		_ = s.Store.Reload()
		_, _ = sys.Run(10*time.Second, "/etc/init.d/S35nftables", "reload")
		if s.Store.Get().Firewall.FlowOffload {
			_, _ = sys.Run(5*time.Second, "/etc/init.d/S42nft-offload", "start")
		}
	})

	var fw config.FirewallState
	var lanIP string
	if err := s.Store.Update(func(st *config.State) error {
		if err := mutate(&st.Firewall); err != nil {
			return err
		}
		fw = st.Firewall
		lanIP = st.LAN.IP
		return nil
	}); err != nil {
		s.Rollback.RevertNow()
		return err
	}

	rendered := RenderCustomNFT(fw, lanIP)
	if err := config.AtomicWriteFile(uiNftDropInPath, []byte(rendered), 0644); err != nil {
		s.Rollback.RevertNow()
		return err
	}
	if _, err := sys.Run(5*time.Second, "nft", "-c", "-f", "/etc/nftables.conf"); err != nil {
		s.Rollback.RevertNow()
		return fmt.Errorf("nftables validation failed: %w", err)
	}
	if _, err := sys.Run(10*time.Second, "/etc/init.d/S35nftables", "reload"); err != nil {
		s.Rollback.RevertNow()
		return err
	}
	if fw.FlowOffload {
		_, _ = sys.Run(5*time.Second, "/etc/init.d/S42nft-offload", "start")
	}
	s.iperfSrv.ReapplyFirewallRules()
	return nil
}

func isFlowOffloadActive() bool {
	_, err := sys.Run(2*time.Second, "nft", "list", "flowtable", "inet", "netbee_fw", "fastpath")
	return err == nil
}

func (s *Server) handleFirewallRuleset(w http.ResponseWriter, r *http.Request) {
	res, err := sys.Run(5*time.Second, "nft", "-j", "list", "ruleset")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeValidatedRawJSON(w, http.StatusOK, []byte(res.Stdout), "{}")
}

func (s *Server) handleGetFirewallConfig(w http.ResponseWriter, r *http.Request) {
	fw := s.Store.Get().Firewall
	writeJSON(w, http.StatusOK, map[string]any{
		"config":         fw,
		"offload_active": isFlowOffloadActive(),
	})
}

func (s *Server) handleSetFirewallConfig(w http.ResponseWriter, r *http.Request) {
	var req config.FirewallState
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json body")
		return
	}
	if req.WireGuardPort == 0 {
		req.WireGuardPort = 51820
	}
	if !sys.ValidPort(req.WireGuardPort) {
		writeErr(w, http.StatusBadRequest, "invalid wireguard_port")
		return
	}
	seenRules := map[string]bool{}
	for _, rule := range req.CustomRules {
		if err := validateFirewallRule(rule); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if seenRules[rule.ID] {
			writeErr(w, http.StatusConflict, "duplicate rule id: "+rule.ID)
			return
		}
		seenRules[rule.ID] = true
	}
	seenPF := map[string]bool{}
	for _, pf := range req.PortForwards {
		if err := validatePortForward(pf); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if seenPF[pf.ID] {
			writeErr(w, http.StatusConflict, "duplicate port-forward id: "+pf.ID)
			return
		}
		seenPF[pf.ID] = true
	}

	if err := s.mutateAndApplyFirewall("Firewall configuration update", func(fw *config.FirewallState) error {
		*fw = req
		return nil
	}); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "pending_commit": s.Rollback.Status()})
}

func (s *Server) handlePatchFirewallToggles(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TransparentDNS  *bool `json:"transparent_dns"`
		ExposeWireGuard *bool `json:"expose_wireguard"`
		WireGuardPort   *int  `json:"wireguard_port"`
		FlowOffload     *bool `json:"flow_offload"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json body")
		return
	}
	if req.WireGuardPort != nil && !sys.ValidPort(*req.WireGuardPort) {
		writeErr(w, http.StatusBadRequest, "invalid wireguard_port")
		return
	}
	if err := s.mutateAndApplyFirewall("Firewall toggle update", func(fw *config.FirewallState) error {
		if req.TransparentDNS != nil {
			fw.TransparentDNS = *req.TransparentDNS
		}
		if req.ExposeWireGuard != nil {
			fw.ExposeWireGuard = *req.ExposeWireGuard
		}
		if req.WireGuardPort != nil {
			fw.WireGuardPort = *req.WireGuardPort
		}
		if req.FlowOffload != nil {
			fw.FlowOffload = *req.FlowOffload
		}
		return nil
	}); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "config": s.Store.Get().Firewall, "pending_commit": s.Rollback.Status()})
}

func (s *Server) handleAddFirewallRule(w http.ResponseWriter, r *http.Request) {
	var rule config.FirewallRule
	if err := decodeJSON(r, &rule); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json body")
		return
	}
	if rule.ID == "" {
		rule.ID = fmt.Sprintf("r%d", time.Now().UnixMilli())
	}
	if err := validateFirewallRule(rule); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	err := s.mutateAndApplyFirewall("Add firewall rule", func(fw *config.FirewallState) error {
		for _, existing := range fw.CustomRules {
			if existing.ID == rule.ID {
				return fmt.Errorf("duplicate rule id: %s", rule.ID)
			}
		}
		fw.CustomRules = append(fw.CustomRules, rule)
		return nil
	})
	if err != nil {
		status := http.StatusBadRequest
		if strings.Contains(err.Error(), "duplicate") {
			status = http.StatusConflict
		}
		writeErr(w, status, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"ok": true, "rule": rule, "pending_commit": s.Rollback.Status()})
}

func (s *Server) handleUpdateFirewallRule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var rule config.FirewallRule
	if err := decodeJSON(r, &rule); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json body")
		return
	}
	rule.ID = id
	if err := validateFirewallRule(rule); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	found := false
	err := s.mutateAndApplyFirewall("Update firewall rule", func(fw *config.FirewallState) error {
		for i, existing := range fw.CustomRules {
			if existing.ID == id {
				fw.CustomRules[i] = rule
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("rule not found")
		}
		return nil
	})
	if err != nil {
		status := http.StatusBadRequest
		if !found {
			status = http.StatusNotFound
		}
		writeErr(w, status, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "rule": rule, "pending_commit": s.Rollback.Status()})
}

func (s *Server) handleDelFirewallRule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	found := false
	err := s.mutateAndApplyFirewall("Delete firewall rule", func(fw *config.FirewallState) error {
		next := make([]config.FirewallRule, 0, len(fw.CustomRules))
		for _, item := range fw.CustomRules {
			if item.ID == id {
				found = true
				continue
			}
			next = append(next, item)
		}
		if !found {
			return fmt.Errorf("rule not found")
		}
		fw.CustomRules = next
		return nil
	})
	if err != nil {
		status := http.StatusBadRequest
		if !found {
			status = http.StatusNotFound
		}
		writeErr(w, status, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "pending_commit": s.Rollback.Status()})
}

func (s *Server) handleAddPortForward(w http.ResponseWriter, r *http.Request) {
	var pf config.PortForward
	if err := decodeJSON(r, &pf); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json body")
		return
	}
	if pf.ID == "" {
		pf.ID = fmt.Sprintf("pf%d", time.Now().UnixMilli())
	}
	if err := validatePortForward(pf); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	err := s.mutateAndApplyFirewall("Add port forward", func(fw *config.FirewallState) error {
		for _, existing := range fw.PortForwards {
			if existing.ID == pf.ID {
				return fmt.Errorf("duplicate port-forward id: %s", pf.ID)
			}
		}
		fw.PortForwards = append(fw.PortForwards, pf)
		return nil
	})
	if err != nil {
		status := http.StatusBadRequest
		if strings.Contains(err.Error(), "duplicate") {
			status = http.StatusConflict
		}
		writeErr(w, status, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"ok": true, "port_forward": pf, "pending_commit": s.Rollback.Status()})
}

func (s *Server) handleUpdatePortForward(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var pf config.PortForward
	if err := decodeJSON(r, &pf); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json body")
		return
	}
	pf.ID = id
	if err := validatePortForward(pf); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	found := false
	err := s.mutateAndApplyFirewall("Update port forward", func(fw *config.FirewallState) error {
		for i, existing := range fw.PortForwards {
			if existing.ID == id {
				fw.PortForwards[i] = pf
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("port forward not found")
		}
		return nil
	})
	if err != nil {
		status := http.StatusBadRequest
		if !found {
			status = http.StatusNotFound
		}
		writeErr(w, status, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "port_forward": pf, "pending_commit": s.Rollback.Status()})
}

func (s *Server) handleDelPortForward(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	found := false
	err := s.mutateAndApplyFirewall("Delete port forward", func(fw *config.FirewallState) error {
		next := make([]config.PortForward, 0, len(fw.PortForwards))
		for _, item := range fw.PortForwards {
			if item.ID == id {
				found = true
				continue
			}
			next = append(next, item)
		}
		if !found {
			return fmt.Errorf("port forward not found")
		}
		fw.PortForwards = next
		return nil
	})
	if err != nil {
		status := http.StatusBadRequest
		if !found {
			status = http.StatusNotFound
		}
		writeErr(w, status, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "pending_commit": s.Rollback.Status()})
}

func (s *Server) handleGetFirewallRaw(w http.ResponseWriter, r *http.Request) {
	data, _ := os.ReadFile(customNftDropInPath)
	writeJSON(w, http.StatusOK, map[string]any{
		"path":    customNftDropInPath,
		"content": string(data),
	})
}

func (s *Server) handleSetFirewallRaw(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Content string `json:"content"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json body")
		return
	}
	if len(req.Content) > 65536 || strings.ContainsRune(req.Content, '\x00') {
		writeErr(w, http.StatusBadRequest, "raw nftables snippet invalid or exceeds 64 KB")
		return
	}
	s.Rollback.Begin("Custom raw nftables update", time.Duration(s.Cfg.RollbackSeconds)*time.Second, []string{customNftDropInPath}, func() {
		_, _ = sys.Run(10*time.Second, "/etc/init.d/S35nftables", "reload")
		if s.Store.Get().Firewall.FlowOffload {
			_, _ = sys.Run(5*time.Second, "/etc/init.d/S42nft-offload", "start")
		}
	})
	if err := config.AtomicWriteFile(customNftDropInPath, []byte(req.Content), 0644); err != nil {
		s.Rollback.RevertNow()
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if _, err := sys.Run(5*time.Second, "nft", "-c", "-f", "/etc/nftables.conf"); err != nil {
		s.Rollback.RevertNow()
		writeErr(w, http.StatusBadRequest, "nftables syntax check failed: "+err.Error())
		return
	}
	if _, err := sys.Run(10*time.Second, "/etc/init.d/S35nftables", "reload"); err != nil {
		s.Rollback.RevertNow()
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if s.Store.Get().Firewall.FlowOffload {
		_, _ = sys.Run(5*time.Second, "/etc/init.d/S42nft-offload", "start")
	}
	s.iperfSrv.ReapplyFirewallRules()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "pending_commit": s.Rollback.Status()})
}

func (s *Server) handleSetFlowOffload(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json body")
		return
	}
	if err := s.Store.Update(func(st *config.State) error {
		st.Firewall.FlowOffload = req.Enabled
		return nil
	}); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	act := "stop"
	if req.Enabled {
		act = "start"
	}
	res, err := sys.Run(10*time.Second, "/etc/init.d/S42nft-offload", act)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":             true,
		"offload_active": isFlowOffloadActive(),
		"output":         strings.TrimSpace(res.Stdout),
	})
}

func (s *Server) handleReloadFirewall(w http.ResponseWriter, r *http.Request) {
	if _, err := sys.Run(10*time.Second, "/etc/init.d/S35nftables", "reload"); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if s.Store.Get().Firewall.FlowOffload {
		_, _ = sys.Run(5*time.Second, "/etc/init.d/S42nft-offload", "start")
	}
	s.iperfSrv.ReapplyFirewallRules()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleGetConntrack(w http.ResponseWriter, r *http.Request) {
	res, err := sys.Run(5*time.Second, "conntrack", "-L")
	if err != nil && res.Stdout == "" {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	flows := []map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(res.Stdout), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		entry := map[string]string{"proto": fields[0], "timeout": fields[2], "raw": line}
		for _, tok := range fields[3:] {
			if k, v, ok := strings.Cut(tok, "="); ok {
				if _, exists := entry[k]; !exists {
					entry[k] = v
				} else {
					entry["reply_"+k] = v
				}
			} else if strings.HasPrefix(tok, "[") && strings.HasSuffix(tok, "]") {
				entry["flags"] = strings.TrimSpace(entry["flags"] + " " + tok)
			} else if entry["state"] == "" {
				entry["state"] = tok
			}
		}
		flows = append(flows, entry)
	}
	ctCount, ctMax := sys.ReadConntrackCounts()
	writeJSON(w, http.StatusOK, map[string]any{
		"count":          len(flows),
		"kernel_count":   ctCount,
		"conntrack_max":  ctMax,
		"flows":          flows,
	})
}

func (s *Server) handleFlushConntrack(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	proto := strings.ToLower(strings.TrimSpace(q.Get("proto")))
	src := strings.TrimSpace(q.Get("src"))
	dst := strings.TrimSpace(q.Get("dst"))
	sport := strings.TrimSpace(q.Get("sport"))
	dport := strings.TrimSpace(q.Get("dport"))

	// Single-flow termination when 5-tuple filter parameters are supplied
	if proto != "" || src != "" || dst != "" {
		validProtos := map[string]bool{"tcp": true, "udp": true, "icmp": true, "icmpv6": true}
		if !validProtos[proto] {
			writeErr(w, http.StatusBadRequest, "invalid conntrack proto (expected tcp, udp, icmp, or icmpv6)")
			return
		}
		if net.ParseIP(src) == nil || net.ParseIP(dst) == nil {
			writeErr(w, http.StatusBadRequest, "valid src and dst IP addresses are required")
			return
		}
		args := []string{"-D", "-p", proto, "-s", src, "-d", dst}
		if (proto == "tcp" || proto == "udp") && sport != "" && dport != "" {
			var sp, dp int
			if _, err := fmt.Sscanf(sport, "%d", &sp); err != nil || !sys.ValidPort(sp) {
				writeErr(w, http.StatusBadRequest, "invalid sport")
				return
			}
			if _, err := fmt.Sscanf(dport, "%d", &dp); err != nil || !sys.ValidPort(dp) {
				writeErr(w, http.StatusBadRequest, "invalid dport")
				return
			}
			args = append(args, "--sport", fmt.Sprintf("%d", sp), "--dport", fmt.Sprintf("%d", dp))
		}
		if _, err := sys.Run(5*time.Second, "conntrack", args...); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "mode": "single"})
		return
	}

	if _, err := sys.Run(5*time.Second, "conntrack", "-F"); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "mode": "flush_all"})
}
