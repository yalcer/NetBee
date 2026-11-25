package api

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/yalcer/netbee/netbeed/internal/config"
	"github.com/yalcer/netbee/netbeed/internal/sys"
)

const uiNftDropInPath = "/etc/nftables.d/10-ui-rules.nft"

// RenderCustomNFT generates /etc/nftables.d/10-ui-rules.nft from FirewallState.
func RenderCustomNFT(fw config.FirewallState, lanIP string) string {
	if lanIP == "" {
		lanIP = "192.168.10.1"
	}
	var b strings.Builder
	b.WriteString("# Managed by NetBee OS (netbeed) - Custom Rules, DNAT & Toggles\n")

	if fw.ExposeWireGuard && sys.ValidPort(fw.WireGuardPort) {
		fmt.Fprintf(&b, "add rule inet netbee_fw input iifname $WAN_IFS udp dport %d accept\n", fw.WireGuardPort)
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
			// DNAT in prerouting + matching forward accept
			fmt.Fprintf(&b, "add rule ip netbee_nat prerouting iifname $WAN_IFS %s%s dport %s dnat to %s:%d\n",
				src, proto, pf.ExtPort, pf.IntIP, pf.IntPort)
			fmt.Fprintf(&b, "add rule inet netbee_fw forward iifname $WAN_IFS %sip daddr %s %s dport %d accept\n",
				src, pf.IntIP, proto, pf.IntPort)
		}
	}

	for _, rule := range fw.CustomRules {
		if !rule.Enabled {
			continue
		}
		var parts []string
		if rule.InIface != "" {
			parts = append(parts, fmt.Sprintf("iifname %q", rule.InIface))
		}
		if rule.OutIface != "" && rule.Chain == "forward" {
			parts = append(parts, fmt.Sprintf("oifname %q", rule.OutIface))
		}
		if rule.SrcAddr != "" {
			parts = append(parts, fmt.Sprintf("ip saddr %s", rule.SrcAddr))
		}
		if rule.DstAddr != "" {
			parts = append(parts, fmt.Sprintf("ip daddr %s", rule.DstAddr))
		}
		if rule.Protocol == "tcp" || rule.Protocol == "udp" {
			if rule.DstPort != "" {
				parts = append(parts, fmt.Sprintf("%s dport %s", rule.Protocol, rule.DstPort))
			} else {
				parts = append(parts, fmt.Sprintf("meta l4proto %s", rule.Protocol))
			}
		} else if rule.Protocol == "icmp" {
			parts = append(parts, "ip protocol icmp")
		}
		if rule.Log {
			parts = append(parts, fmt.Sprintf(`limit rate 10/minute log prefix "netbee-%s: "`, rule.ID))
		}
		parts = append(parts, rule.Action)
		fmt.Fprintf(&b, "add rule inet netbee_fw %s %s\n", rule.Chain, strings.Join(parts, " "))
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
	if r.Action != "accept" && r.Action != "drop" && r.Action != "reject" {
		return fmt.Errorf("action must be accept, drop, or reject")
	}
	if r.Protocol != "tcp" && r.Protocol != "udp" && r.Protocol != "icmp" && r.Protocol != "any" {
		return fmt.Errorf("protocol must be tcp, udp, icmp, or any")
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
	if r.DstPort != "" && !sys.ValidPortSpec(r.DstPort) {
		return fmt.Errorf("invalid dst_port")
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
		return fmt.Errorf("invalid int_ip")
	}
	if !sys.ValidPort(pf.IntPort) {
		return fmt.Errorf("invalid int_port")
	}
	if pf.SourceCIDR != "" && !sys.ValidIPOrCIDR(pf.SourceCIDR) {
		return fmt.Errorf("invalid source_cidr")
	}
	return nil
}

func (s *Server) applyFirewall(fw config.FirewallState, lanIP string) error {
	rendered := RenderCustomNFT(fw, lanIP)
	files := []string{uiNftDropInPath, s.Cfg.StatePath}
	s.Rollback.Begin("Firewall configuration update", time.Duration(s.Cfg.RollbackSeconds)*time.Second, files, func() {
		_, _ = sys.Run(10*time.Second, "/etc/init.d/S35nftables", "reload")
		_, _ = sys.Run(10*time.Second, "/etc/init.d/S42nft-offload", "start")
	})

	if err := config.AtomicWriteFile(uiNftDropInPath, []byte(rendered), 0644); err != nil {
		return err
	}
	// Syntax & dry-run check BEFORE reloading live firewall
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
	return nil
}

func (s *Server) handleFirewallRuleset(w http.ResponseWriter, r *http.Request) {
	res, err := sys.Run(5*time.Second, "nft", "-j", "list", "ruleset")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeRawJSON(w, http.StatusOK, []byte(res.Stdout))
}

func (s *Server) handleGetFirewallConfig(w http.ResponseWriter, r *http.Request) {
	fw := s.Store.Get().Firewall
	offloadActive := false
	if _, err := sys.Run(2*time.Second, "nft", "list", "flowtable", "inet", "netbee_fw", "fastpath"); err == nil {
		offloadActive = true
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"config":         fw,
		"offload_active": offloadActive,
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
	for _, rule := range req.CustomRules {
		if err := validateFirewallRule(rule); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	for _, pf := range req.PortForwards {
		if err := validatePortForward(pf); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	lanIP := s.Store.Get().LAN.IP
	if err := s.Store.Update(func(st *config.State) error {
		st.Firewall = req
		return nil
	}); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.applyFirewall(req, lanIP); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "pending_commit": s.Rollback.Status()})
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
	var fw config.FirewallState
	lanIP := s.Store.Get().LAN.IP
	if err := s.Store.Update(func(st *config.State) error {
		st.Firewall.CustomRules = append(st.Firewall.CustomRules, rule)
		fw = st.Firewall
		return nil
	}); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.applyFirewall(fw, lanIP); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"ok": true, "rule": rule, "pending_commit": s.Rollback.Status()})
}

func (s *Server) handleDelFirewallRule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var fw config.FirewallState
	found := false
	lanIP := s.Store.Get().LAN.IP
	_ = s.Store.Update(func(st *config.State) error {
		next := make([]config.FirewallRule, 0, len(st.Firewall.CustomRules))
		for _, item := range st.Firewall.CustomRules {
			if item.ID == id {
				found = true
				continue
			}
			next = append(next, item)
		}
		st.Firewall.CustomRules = next
		fw = st.Firewall
		return nil
	})
	if !found {
		writeErr(w, http.StatusNotFound, "rule not found")
		return
	}
	if err := s.applyFirewall(fw, lanIP); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
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
	var fw config.FirewallState
	lanIP := s.Store.Get().LAN.IP
	if err := s.Store.Update(func(st *config.State) error {
		st.Firewall.PortForwards = append(st.Firewall.PortForwards, pf)
		fw = st.Firewall
		return nil
	}); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.applyFirewall(fw, lanIP); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"ok": true, "port_forward": pf, "pending_commit": s.Rollback.Status()})
}

func (s *Server) handleDelPortForward(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var fw config.FirewallState
	found := false
	lanIP := s.Store.Get().LAN.IP
	_ = s.Store.Update(func(st *config.State) error {
		next := make([]config.PortForward, 0, len(st.Firewall.PortForwards))
		for _, item := range st.Firewall.PortForwards {
			if item.ID == id {
				found = true
				continue
			}
			next = append(next, item)
		}
		st.Firewall.PortForwards = next
		fw = st.Firewall
		return nil
	})
	if !found {
		writeErr(w, http.StatusNotFound, "port forward not found")
		return
	}
	if err := s.applyFirewall(fw, lanIP); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
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
	_ = s.Store.Update(func(st *config.State) error {
		st.Firewall.FlowOffload = req.Enabled
		return nil
	})
	act := "stop"
	if req.Enabled {
		act = "start"
	}
	res, err := sys.Run(10*time.Second, "/etc/init.d/S42nft-offload", act)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "output": strings.TrimSpace(res.Stdout)})
}

func (s *Server) handleReloadFirewall(w http.ResponseWriter, r *http.Request) {
	if _, err := sys.Run(10*time.Second, "/etc/init.d/S35nftables", "reload"); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if s.Store.Get().Firewall.FlowOffload {
		_, _ = sys.Run(5*time.Second, "/etc/init.d/S42nft-offload", "start")
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleGetConntrack(w http.ResponseWriter, r *http.Request) {
	res, err := sys.Run(5*time.Second, "conntrack", "-L")
	if err != nil && res.Stdout == "" {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	var flows []map[string]string
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
	if flows == nil {
		flows = []map[string]string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"count": len(flows), "flows": flows})
}

func (s *Server) handleFlushConntrack(w http.ResponseWriter, r *http.Request) {
	if _, err := sys.Run(5*time.Second, "conntrack", "-F"); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
