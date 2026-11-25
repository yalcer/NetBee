package api

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/yalcer/netbee/netbeed/internal/config"
	"github.com/yalcer/netbee/netbeed/internal/sys"
)

func lanCIDR(lan config.LANState) string {
	ip := net.ParseIP(lan.IP).To4()
	maskIP := net.ParseIP(lan.Netmask).To4()
	if ip == nil || maskIP == nil {
		return "192.168.10.0/24"
	}
	mask := net.IPv4Mask(maskIP[0], maskIP[1], maskIP[2], maskIP[3])
	ones, bits := mask.Size()
	if bits != 32 || ones < 8 {
		return "192.168.10.0/24"
	}
	return fmt.Sprintf("%s/%d", ip.Mask(mask).String(), ones)
}

// --- NTP (Chrony) ---

func (s *Server) handleGetNTP(w http.ResponseWriter, r *http.Request) {
	tracking, _ := sys.Run(3*time.Second, "chronyc", "tracking")
	sources, _ := sys.Run(3*time.Second, "chronyc", "sources")
	conf, _ := os.ReadFile("/etc/chrony.conf")
	servers := []string{}
	serveLAN := false
	for _, line := range strings.Split(string(conf), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) >= 2 && (f[0] == "server" || f[0] == "pool") {
			servers = append(servers, f[1])
		}
		if len(f) >= 2 && f[0] == "allow" {
			serveLAN = true
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"servers":   servers,
		"serve_lan": serveLAN,
		"tracking":  tracking.Stdout,
		"sources":   sources.Stdout,
	})
}

func RenderChronyConf(servers []string, serveLAN bool, lan config.LANState) (string, error) {
	if len(servers) == 0 || len(servers) > 16 {
		return "", fmt.Errorf("provide between 1 and 16 NTP servers")
	}
	var b strings.Builder
	b.WriteString("# Managed by NetBee OS (netbeed)\n")
	for _, srv := range servers {
		srv = strings.TrimSpace(srv)
		if !sys.ValidHost(srv) {
			return "", fmt.Errorf("invalid NTP server: %s", srv)
		}
		if net.ParseIP(srv) != nil {
			fmt.Fprintf(&b, "server %s iburst\n", srv)
		} else {
			fmt.Fprintf(&b, "pool %s iburst\n", srv)
		}
	}
	b.WriteString("driftfile /var/lib/chrony/drift\nmakestep 1.0 -1\nrtcsync\n")
	if serveLAN {
		fmt.Fprintf(&b, "allow %s\nlocal stratum 10\n", lanCIDR(lan))
	}
	return b.String(), nil
}

func (s *Server) handleSetNTP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Servers  []string `json:"servers"`
		ServeLAN bool     `json:"serve_lan"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json body")
		return
	}
	rendered, err := RenderChronyConf(req.Servers, req.ServeLAN, s.Store.Get().LAN)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := config.AtomicWriteFile("/etc/chrony.conf", []byte(rendered), 0644); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	_, _ = sys.Run(10*time.Second, "/etc/init.d/S49chronyd", "restart")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// --- IPv6 (radvd SLAAC + dhcpcd PD) ---

func RenderRadvdConf(lanIface string) string {
	if lanIface == "" || !sys.ValidIface(lanIface) {
		lanIface = "eth0"
	}
	return fmt.Sprintf(
		"# Managed by NetBee OS (netbeed)\n"+
			"interface %s\n{\n"+
			"    AdvSendAdvert on;\n"+
			"    IgnoreIfMissing on;\n"+
			"    MinRtrAdvInterval 30;\n"+
			"    MaxRtrAdvInterval 100;\n"+
			"    prefix ::/64\n    {\n"+
			"        AdvOnLink on;\n"+
			"        AdvAutonomous on;\n"+
			"        AdvRouterAddr off;\n"+
			"    };\n};\n",
		lanIface,
	)
}

func (s *Server) handleGetIPv6(w http.ResponseWriter, r *http.Request) {
	_, err := os.Stat("/etc/radvd.conf")
	radvdEnabled := err == nil
	radvdRunning := false
	if _, err := sys.Run(2*time.Second, "pidof", "radvd"); err == nil {
		radvdRunning = true
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"radvd_enabled": radvdEnabled,
		"radvd_running": radvdRunning,
		"ipv6_pd":       s.Store.Get().WAN.IPv6PD,
	})
}

func (s *Server) handleSetIPv6(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RadvdEnabled bool `json:"radvd_enabled"`
		IPv6PD       bool `json:"ipv6_pd"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json body")
		return
	}
	if err := s.Store.Update(func(st *config.State) error {
		st.WAN.IPv6PD = req.IPv6PD
		return nil
	}); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	st := s.Store.Get()
	if err := config.AtomicWriteFile("/etc/dhcpcd.conf", []byte(RenderDHCPCDConf(st.LAN, st.WAN)), 0644); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	_, _ = sys.Run(10*time.Second, "/etc/init.d/S41dhcpcd", "restart")

	if req.RadvdEnabled {
		if err := config.AtomicWriteFile("/etc/radvd.conf", []byte(RenderRadvdConf(st.LAN.Interface)), 0644); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		_, _ = sys.Run(10*time.Second, "/etc/init.d/S50radvd", "restart")
	} else {
		_, _ = sys.Run(5*time.Second, "/etc/init.d/S50radvd", "stop")
		_ = os.Remove("/etc/radvd.conf")
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// --- SSH (Dropbear & Authorized Keys) ---

const authorizedKeysPath = "/root/.ssh/authorized_keys"

// ParseDropbearConf extracts password_auth and idle_timeout solely from DROPBEAR_ARGS tokens (ignoring comments).
func ParseDropbearConf(raw string) (passwordAuth bool, idleTimeout int) {
	passwordAuth = true
	idleTimeout = 600
	foundLine := false
	var argsStr string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok && strings.TrimSpace(k) == "DROPBEAR_ARGS" {
			foundLine = true
			argsStr = strings.Trim(strings.TrimSpace(v), `"'`)
		}
	}
	if !foundLine {
		return true, 600
	}
	idleTimeout = 0
	fields := strings.Fields(argsStr)
	for i := 0; i < len(fields); i++ {
		tok := fields[i]
		if tok == "-s" || tok == "-sg" || tok == "-gs" {
			passwordAuth = false
		}
		if tok == "-I" && i+1 < len(fields) {
			if n, err := strconv.Atoi(fields[i+1]); err == nil && n >= 0 {
				idleTimeout = n
			}
			i++
		} else if strings.HasPrefix(tok, "-I") && len(tok) > 2 {
			if n, err := strconv.Atoi(tok[2:]); err == nil && n >= 0 {
				idleTimeout = n
			}
		}
	}
	return passwordAuth, idleTimeout
}

func RenderDropbearConf(lanIP string, passwordAuth bool, idleTimeout int) string {
	if lanIP == "" {
		lanIP = "192.168.10.1"
	}
	args := fmt.Sprintf("-p %s:22", lanIP)
	if idleTimeout > 0 {
		args += fmt.Sprintf(" -I %d", idleTimeout)
	}
	if !passwordAuth {
		args += " -s"
	}
	return fmt.Sprintf("# Managed by NetBee OS (netbeed)\nDROPBEAR_ARGS=%q\n", args)
}

func readAuthorizedKeys() []string {
	data, err := os.ReadFile(authorizedKeysPath)
	if err != nil {
		return []string{}
	}
	keys := []string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			keys = append(keys, line)
		}
	}
	return keys
}

func validSSHPublicKey(key string) bool {
	if key == "" || len(key) > 4096 || strings.ContainsAny(key, "\n\r\x00") {
		return false
	}
	prefixes := []string{
		"ssh-ed25519 ",
		"ssh-rsa ",
		"ecdsa-sha2-nistp256 ",
		"ecdsa-sha2-nistp384 ",
		"ecdsa-sha2-nistp521 ",
		"sk-ssh-ed25519@openssh.com ",
		"sk-ecdsa-sha2-nistp256@openssh.com ",
	}
	hasPrefix := false
	for _, p := range prefixes {
		if strings.HasPrefix(key, p) {
			hasPrefix = true
			break
		}
	}
	if !hasPrefix {
		return false
	}
	fields := strings.Fields(key)
	return len(fields) >= 2 && len(fields[1]) >= 32
}

func (s *Server) handleGetSSH(w http.ResponseWriter, r *http.Request) {
	def, _ := os.ReadFile("/etc/default/dropbear")
	raw := string(def)
	pwAuth, idleTimeout := ParseDropbearConf(raw)
	writeJSON(w, http.StatusOK, map[string]any{
		"dropbear_default": strings.TrimSpace(raw),
		"password_auth":    pwAuth,
		"idle_timeout":     idleTimeout,
		"authorized_keys":  readAuthorizedKeys(),
	})
}

func (s *Server) handleSetSSH(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PasswordAuth bool `json:"password_auth"`
		IdleTimeout  int  `json:"idle_timeout"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json body")
		return
	}
	if !req.PasswordAuth && len(readAuthorizedKeys()) == 0 {
		writeErr(w, http.StatusBadRequest, "add at least one SSH public key before disabling password auth")
		return
	}
	if req.IdleTimeout < 0 || req.IdleTimeout > 86400 {
		writeErr(w, http.StatusBadRequest, "idle_timeout must be 0..86400")
		return
	}
	content := RenderDropbearConf(s.Store.Get().LAN.IP, req.PasswordAuth, req.IdleTimeout)
	if err := config.AtomicWriteFile("/etc/default/dropbear", []byte(content), 0644); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	_, _ = sys.Run(5*time.Second, "/etc/init.d/S50dropbear", "restart")
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"password_auth": req.PasswordAuth,
		"idle_timeout":  req.IdleTimeout,
	})
}

func (s *Server) handleAddSSHKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PublicKey string `json:"public_key"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json body")
		return
	}
	key := strings.TrimSpace(req.PublicKey)
	if !validSSHPublicKey(key) {
		writeErr(w, http.StatusBadRequest, "invalid SSH public key format")
		return
	}
	existing := readAuthorizedKeys()
	newFields := strings.Fields(key)
	for _, k := range existing {
		kf := strings.Fields(k)
		if len(kf) >= 2 && kf[0] == newFields[0] && kf[1] == newFields[1] {
			writeErr(w, http.StatusConflict, "SSH public key already exists")
			return
		}
	}
	keys := append(existing, key)
	_ = os.MkdirAll("/root/.ssh", 0700)
	if err := config.AtomicWriteFile(authorizedKeysPath, []byte(strings.Join(keys, "\n")+"\n"), 0600); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"ok": true, "count": len(keys)})
}

func (s *Server) handleDelSSHKey(w http.ResponseWriter, r *http.Request) {
	idx, err := strconv.Atoi(r.PathValue("index"))
	keys := readAuthorizedKeys()
	if err != nil || idx < 0 || idx >= len(keys) {
		writeErr(w, http.StatusBadRequest, "invalid key index")
		return
	}
	// Prevent total SSH lockout if password auth (-s) is disabled and this is the last key
	if len(keys) == 1 {
		def, _ := os.ReadFile("/etc/default/dropbear")
		pwAuth, _ := ParseDropbearConf(string(def))
		if !pwAuth {
			writeErr(w, http.StatusBadRequest, "cannot remove last SSH key while password authentication is disabled")
			return
		}
	}
	next := make([]string, 0, len(keys)-1)
	next = append(next, keys[:idx]...)
	next = append(next, keys[idx+1:]...)
	content := ""
	if len(next) > 0 {
		content = strings.Join(next, "\n") + "\n"
	}
	if err := config.AtomicWriteFile(authorizedKeysPath, []byte(content), 0600); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "count": len(next)})
}

// --- Scheduled Tasks (BusyBox crond: /etc/cron/crontabs/root) ---

const (
	rootCrontabPath   = "/etc/cron/crontabs/root"
	systemLogrotateJob = "0 * * * * /usr/sbin/logrotate /etc/logrotate.conf >/dev/null 2>&1"
)

type CronActionSpec struct {
	Action      string `json:"action"`
	Description string `json:"description"`
	NeedsTarget bool   `json:"needs_target"`
}

var SupportedCronActions = []CronActionSpec{
	{"reboot", "Reboot the router cleanly", false},
	{"wan_reconnect", "Reconnect WAN (renew DHCP or redial PPPoE/ONT)", false},
	{"firewall_reload", "Reload nftables firewall ruleset", false},
	{"sqm_start", "Enable/restart SQM CAKE traffic shaping", false},
	{"sqm_stop", "Stop SQM CAKE and re-enable gigabit flow offload", false},
	{"logs_rotate", "Force immediate RAM syslog rotation", false},
	{"conntrack_flush", "Flush active NAT/conntrack session table", false},
	{"service_restart", "Restart a specific managed service (set target)", true},
}

var cronControllableServices = map[string]string{
	"adguardhome": "/etc/init.d/S85adguardhome",
	"chronyd":     "/etc/init.d/S49chronyd",
	"dhcpcd":      "/etc/init.d/S41dhcpcd",
	"dropbear":    "/etc/init.d/S50dropbear",
	"radvd":       "/etc/init.d/S50radvd",
	"vnstatd":     "/etc/init.d/S86vnstatd",
	"sqm":         "/etc/init.d/S45sqm",
	"nftables":    "/etc/init.d/S35nftables",
	"nft-offload": "/etc/init.d/S42nft-offload",
}

func validateCronField(tok string, minVal, maxVal int) error {
	for _, part := range strings.Split(tok, ",") {
		if part == "" {
			return fmt.Errorf("empty cron list element")
		}
		base, stepStr, hasStep := strings.Cut(part, "/")
		if hasStep {
			step, err := strconv.Atoi(stepStr)
			if err != nil || step < 1 || step > maxVal {
				return fmt.Errorf("invalid cron step %q", stepStr)
			}
		}
		if base == "*" {
			continue
		}
		if startStr, endStr, isRange := strings.Cut(base, "-"); isRange {
			a, errA := strconv.Atoi(startStr)
			b, errB := strconv.Atoi(endStr)
			if errA != nil || errB != nil || a < minVal || b > maxVal || a > b {
				return fmt.Errorf("invalid cron range %q", base)
			}
			continue
		}
		n, err := strconv.Atoi(base)
		if err != nil || n < minVal || n > maxVal {
			return fmt.Errorf("cron value %q out of bounds (%d..%d)", base, minVal, maxVal)
		}
	}
	return nil
}

// ValidateCronSchedule strictly validates a standard 5-field cron expression ("min hour dom month dow").
func ValidateCronSchedule(expr string) error {
	if strings.ContainsAny(expr, "\n\r\x00#;") {
		return fmt.Errorf("cron schedule contains forbidden characters")
	}
	fields := strings.Fields(expr)
	if len(fields) != 5 {
		return fmt.Errorf("cron schedule must have exactly 5 fields (minute hour day month weekday)")
	}
	bounds := [5][2]int{{0, 59}, {0, 23}, {1, 31}, {1, 12}, {0, 7}}
	for i, f := range fields {
		if err := validateCronField(f, bounds[i][0], bounds[i][1]); err != nil {
			return err
		}
	}
	return nil
}

// ResolveCronActionCommand maps a whitelisted router action to a fixed, injection-free command string.
func ResolveCronActionCommand(action, target string) (string, error) {
	switch action {
	case "reboot":
		return "/sbin/reboot", nil
	case "wan_reconnect":
		return `/bin/sh -c '. /etc/netbee/netif.env 2>/dev/null; if [ "$WAN_MODE" = "pppoe" ] || [ "$WAN_MODE" = "ont_vlan" ]; then killall pppd 2>/dev/null; pppd call wan-pppoe; else /etc/init.d/S41dhcpcd restart; fi'`, nil
	case "firewall_reload":
		return "/etc/init.d/S35nftables reload", nil
	case "sqm_start":
		return "/usr/sbin/netbee-sqm restart", nil
	case "sqm_stop":
		return "/bin/sh -c '/usr/sbin/netbee-sqm stop && /etc/init.d/S42nft-offload start'", nil
	case "logs_rotate":
		return "/usr/sbin/logrotate -f /etc/logrotate.conf", nil
	case "conntrack_flush":
		return "/usr/sbin/conntrack -F", nil
	case "service_restart":
		script, ok := cronControllableServices[target]
		if !ok {
			return "", fmt.Errorf("unsupported service target %q for service_restart", target)
		}
		return script + " restart", nil
	default:
		return "", fmt.Errorf("unsupported cron action %q", action)
	}
}

func validateCronJob(job *config.CronJob) error {
	if job.ID == "" || !sys.ValidID(job.ID) {
		return fmt.Errorf("invalid cron job id")
	}
	job.Name = strings.TrimSpace(job.Name)
	if job.Name == "" || len(job.Name) > 64 || !sys.ValidSafeString(job.Name) {
		return fmt.Errorf("invalid cron job name")
	}
	job.Schedule = strings.Join(strings.Fields(job.Schedule), " ")
	if err := ValidateCronSchedule(job.Schedule); err != nil {
		return err
	}
	if _, err := ResolveCronActionCommand(job.Action, job.Target); err != nil {
		return err
	}
	if job.Action != "service_restart" {
		job.Target = ""
	}
	return nil
}

// RenderRootCrontab generates /etc/cron/crontabs/root preserving the mandatory hourly RAM logrotate safeguard.
func RenderRootCrontab(jobs []config.CronJob) (string, error) {
	var b strings.Builder
	b.WriteString("# Managed by NetBee OS (netbeed) - Periodic maintenance & user schedules\n")
	b.WriteString(systemLogrotateJob + "\n")
	for _, j := range jobs {
		if err := validateCronJob(&j); err != nil {
			return "", err
		}
		if !j.Enabled {
			continue
		}
		cmd, err := ResolveCronActionCommand(j.Action, j.Target)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "# [%s] %s\n%s %s >/dev/null 2>&1\n", j.ID, j.Name, j.Schedule, cmd)
	}
	return b.String(), nil
}

func (s *Server) crontabPath() string {
	if s.Cfg.CrontabPath != "" {
		return s.Cfg.CrontabPath
	}
	return rootCrontabPath
}

func (s *Server) syncRootCrontab(jobs []config.CronJob) error {
	rendered, err := RenderRootCrontab(jobs)
	if err != nil {
		return err
	}
	if err := config.AtomicWriteFile(s.crontabPath(), []byte(rendered), 0600); err != nil {
		return err
	}
	if _, err := os.Stat("/etc/init.d/S50crond"); err == nil {
		_, _ = sys.Run(5*time.Second, "/etc/init.d/S50crond", "reload")
	}
	return nil
}

func (s *Server) handleGetCron(w http.ResponseWriter, r *http.Request) {
	crondRunning := false
	if _, err := sys.Run(2*time.Second, "pidof", "crond"); err == nil {
		crondRunning = true
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"crond_running":     crondRunning,
		"system_jobs":       []string{systemLogrotateJob},
		"jobs":              s.Store.Get().CronJobs,
		"supported_actions": SupportedCronActions,
	})
}

func (s *Server) handleAddCron(w http.ResponseWriter, r *http.Request) {
	var job config.CronJob
	if err := decodeJSON(r, &job); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json body")
		return
	}
	if job.ID == "" {
		job.ID = fmt.Sprintf("cron%d", time.Now().UnixMilli())
	}
	if err := validateCronJob(&job); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	var allJobs []config.CronJob
	if err := s.Store.Update(func(st *config.State) error {
		if len(st.CronJobs) >= 32 {
			return fmt.Errorf("maximum of 32 scheduled jobs reached")
		}
		for _, existing := range st.CronJobs {
			if existing.ID == job.ID {
				return fmt.Errorf("duplicate cron job id: %s", job.ID)
			}
		}
		st.CronJobs = append(st.CronJobs, job)
		allJobs = append([]config.CronJob{}, st.CronJobs...)
		return nil
	}); err != nil {
		status := http.StatusBadRequest
		if strings.Contains(err.Error(), "duplicate") {
			status = http.StatusConflict
		}
		writeErr(w, status, err.Error())
		return
	}
	if err := s.syncRootCrontab(allJobs); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"ok": true, "job": job})
}

func (s *Server) handleUpdateCron(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var job config.CronJob
	if err := decodeJSON(r, &job); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json body")
		return
	}
	job.ID = id
	if err := validateCronJob(&job); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	found := false
	var allJobs []config.CronJob
	if err := s.Store.Update(func(st *config.State) error {
		for i, existing := range st.CronJobs {
			if existing.ID == id {
				st.CronJobs[i] = job
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("cron job not found")
		}
		allJobs = append([]config.CronJob{}, st.CronJobs...)
		return nil
	}); err != nil {
		if !found {
			writeErr(w, http.StatusNotFound, "cron job not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.syncRootCrontab(allJobs); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "job": job})
}

func (s *Server) handleDelCron(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	found := false
	var allJobs []config.CronJob
	if err := s.Store.Update(func(st *config.State) error {
		next := make([]config.CronJob, 0, len(st.CronJobs))
		for _, item := range st.CronJobs {
			if item.ID == id {
				found = true
				continue
			}
			next = append(next, item)
		}
		if !found {
			return fmt.Errorf("cron job not found")
		}
		st.CronJobs = next
		allJobs = append([]config.CronJob{}, st.CronJobs...)
		return nil
	}); err != nil {
		if !found {
			writeErr(w, http.StatusNotFound, "cron job not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.syncRootCrontab(allJobs); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
