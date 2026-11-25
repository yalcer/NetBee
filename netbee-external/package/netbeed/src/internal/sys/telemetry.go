package sys

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type OSInfo struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	PrettyName string `json:"pretty_name"`
	Board      string `json:"board"`
	Arch       string `json:"arch"`
	Kernel     string `json:"kernel"`
}

type DiskUsage struct {
	Mount   string `json:"mount"`
	TotalMB uint64 `json:"total_mb"`
	UsedMB  uint64 `json:"used_mb"`
	FreeMB  uint64 `json:"free_mb"`
	UsedPct int    `json:"used_pct"`
}

type SystemOverview struct {
	Hostname       string      `json:"hostname"`
	BoardModel     string      `json:"board_model,omitempty"`
	OS             OSInfo      `json:"os"`
	Time           string      `json:"time"`
	Timezone       string      `json:"timezone"`
	UptimeSec      int64       `json:"uptime_seconds"`
	LoadAvg        [3]float64  `json:"load_avg"`
	CPUCores       int         `json:"cpu_cores"`
	CPUFreqMHz     *int        `json:"cpu_freq_mhz"`
	CPUGovernor    string      `json:"cpu_governor,omitempty"`
	CPUTempC       *float64    `json:"cpu_temp_c"`
	FanRPM         *int        `json:"fan_rpm"`
	CoolingState   *int        `json:"cooling_state"`
	Undervoltage   bool        `json:"undervoltage"`
	MemTotalMB     uint64      `json:"mem_total_mb"`
	MemUsedMB      uint64      `json:"mem_used_mb"`
	MemAvailMB     uint64      `json:"mem_avail_mb"`
	ConntrackCount int         `json:"conntrack_count"`
	ConntrackMax   int         `json:"conntrack_max"`
	RootfsExpanded bool        `json:"rootfs_expanded"`
	Disks          []DiskUsage `json:"disks"`
}

type ServiceStatus struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	InitScript  string   `json:"init_script,omitempty"`
	Running     bool     `json:"running"`
	PID         string   `json:"pid,omitempty"`
	Actions     []string `json:"actions"`
}

type ManagedServiceDef struct {
	Name           string
	Description    string
	ProcName       string
	InitScript     string
	SupportsReload bool
	Actions        []string
}

var ManagedServices = []ManagedServiceDef{
	{"netbeed", "NetBee Management HTTPS API", "netbeed", "/etc/init.d/S90netbeed", true, []string{"restart", "reload"}},
	{"adguardhome", "AdGuardHome DNS & DHCP Server", "AdGuardHome", "/etc/init.d/S85adguardhome", true, []string{"start", "stop", "restart", "reload"}},
	{"nftables", "Stateful Firewall & NAT", "", "/etc/init.d/S35nftables", true, []string{"start", "stop", "restart", "reload"}},
	{"nft-offload", "Software Fastpath Flow Offload", "", "/etc/init.d/S42nft-offload", true, []string{"start", "stop", "restart", "reload"}},
	{"sqm", "SQM CAKE Anti-Bufferbloat QoS", "", "/etc/init.d/S45sqm", true, []string{"start", "stop", "restart", "reload"}},
	{"dropbear", "Dropbear SSH Server", "dropbear", "/etc/init.d/S50dropbear", true, []string{"start", "stop", "restart", "reload"}},
	{"chronyd", "Chrony NTP Client & LAN Time Server", "chronyd", "/etc/init.d/S49chronyd", false, []string{"start", "stop", "restart"}},
	{"dhcpcd", "WAN DHCP & IPv6-PD Client", "dhcpcd", "/etc/init.d/S41dhcpcd", true, []string{"start", "stop", "restart", "reload"}},
	{"pppd", "PPPoE / ONT Fiber Session Daemon", "pppd", "", false, []string{"start", "stop", "restart"}},
	{"radvd", "IPv6 Router Advertisement (SLAAC)", "radvd", "/etc/init.d/S50radvd", true, []string{"start", "stop", "restart", "reload"}},
	{"vnstatd", "Persistent Bandwidth Accounting", "vnstatd", "/etc/init.d/S86vnstatd", true, []string{"start", "stop", "restart", "reload"}},
	{"watchdog", "Raspberry Pi 5 Hardware Watchdog", "watchdog", "/etc/init.d/S15watchdog", true, []string{"start", "stop", "restart", "reload"}},
	{"triggerhappy", "Physical Power Button Handler", "thd", "/etc/init.d/S10triggerhappy", false, []string{"start", "stop", "restart"}},
	{"crond", "Periodic Logrotate & Scheduled Tasks", "crond", "/etc/init.d/S50crond", true, []string{"start", "stop", "restart", "reload"}},
	{"syslogd", "System RAM Ring-Buffer Logger", "syslogd", "/etc/init.d/S01syslogd", true, []string{"start", "stop", "restart", "reload"}},
	{"klogd", "Kernel Log Daemon", "klogd", "/etc/init.d/S02klogd", true, []string{"start", "stop", "restart", "reload"}},
	{"udevd", "Dynamic Device & Hotplug Manager", "udevd", "/etc/init.d/S10udevd", false, []string{"restart"}},
}

func ReadOSInfo() OSInfo {
	info := OSInfo{Name: "NetBee OS", Arch: "aarch64", Board: "rpi5"}
	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			v = strings.Trim(v, `"`)
			switch k {
			case "NAME":
				info.Name = v
			case "VERSION":
				info.Version = v
			case "PRETTY_NAME":
				info.PrettyName = v
			case "BOARD":
				info.Board = v
			case "ARCH":
				info.Arch = v
			}
		}
	}
	if data, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		info.Kernel = strings.TrimSpace(string(data))
	}
	return info
}

func ReadDiskUsage(mount string) DiskUsage {
	var st syscall.Statfs_t
	du := DiskUsage{Mount: mount}
	if err := syscall.Statfs(mount, &st); err != nil {
		return du
	}
	total := st.Blocks * uint64(st.Bsize)
	free := st.Bavail * uint64(st.Bsize)
	used := total - (st.Bfree * uint64(st.Bsize))
	du.TotalMB = total / (1024 * 1024)
	du.UsedMB = used / (1024 * 1024)
	du.FreeMB = free / (1024 * 1024)
	if total > 0 {
		du.UsedPct = int((used * 100) / total)
	}
	return du
}

// ReadFanRPMAndPower reads Raspberry Pi 5 Active Cooler PWM fan RPM and PMIC under-voltage alarm if present.
func ReadFanRPMAndPower() (fanRPM *int, undervoltage bool) {
	matches, _ := filepath.Glob("/sys/class/hwmon/hwmon*")
	for _, dir := range matches {
		if fanRPM == nil {
			if b, err := os.ReadFile(filepath.Join(dir, "fan1_input")); err == nil {
				if v, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && v >= 0 {
					rpm := v
					fanRPM = &rpm
				}
			}
		}
		if b, err := os.ReadFile(filepath.Join(dir, "in0_lcrit_alarm")); err == nil {
			if strings.TrimSpace(string(b)) == "1" {
				undervoltage = true
			}
		}
	}
	return fanRPM, undervoltage
}

// ReadConntrackCounts reads live kernel conntrack active entries and configured maximum.
func ReadConntrackCounts() (count, max int) {
	if b, err := os.ReadFile("/proc/sys/net/netfilter/nf_conntrack_count"); err == nil {
		count, _ = strconv.Atoi(strings.TrimSpace(string(b)))
	}
	if b, err := os.ReadFile("/proc/sys/net/netfilter/nf_conntrack_max"); err == nil {
		max, _ = strconv.Atoi(strings.TrimSpace(string(b)))
	}
	return count, max
}

func ReadOverview() SystemOverview {
	host, _ := os.Hostname()
	ctCount, ctMax := ReadConntrackCounts()
	fanRPM, undervolt := ReadFanRPMAndPower()
	_, expandedErr := os.Stat("/etc/netbee/.rootfs-expanded")

	disks := []DiskUsage{ReadDiskUsage("/"), ReadDiskUsage("/var/log")}
	if _, err := os.Stat("/boot/config.txt"); err == nil {
		disks = append(disks, ReadDiskUsage("/boot"))
	}

	ov := SystemOverview{
		Hostname:       host,
		OS:             ReadOSInfo(),
		Time:           time.Now().Format(time.RFC3339),
		Timezone:       ReadTimezone(),
		CPUCores:       runtime.NumCPU(),
		FanRPM:         fanRPM,
		Undervoltage:   undervolt,
		ConntrackCount: ctCount,
		ConntrackMax:   ctMax,
		RootfsExpanded: expandedErr == nil,
		Disks:          disks,
	}

	if b, err := os.ReadFile("/sys/firmware/devicetree/base/model"); err == nil {
		ov.BoardModel = strings.TrimSpace(strings.TrimRight(string(b), "\x00"))
	}

	if data, err := os.ReadFile("/proc/uptime"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) > 0 {
			if f, err := strconv.ParseFloat(fields[0], 64); err == nil {
				ov.UptimeSec = int64(f)
			}
		}
	}

	if data, err := os.ReadFile("/proc/loadavg"); err == nil {
		fields := strings.Fields(string(data))
		for i := 0; i < 3 && i < len(fields); i++ {
			ov.LoadAvg[i], _ = strconv.ParseFloat(fields[i], 64)
		}
	}

	if b, err := os.ReadFile("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq"); err == nil {
		if khz, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && khz > 0 {
			mhz := khz / 1000
			ov.CPUFreqMHz = &mhz
		}
	}
	if b, err := os.ReadFile("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"); err == nil {
		ov.CPUGovernor = strings.TrimSpace(string(b))
	}

	if data, err := os.ReadFile("/sys/class/thermal/thermal_zone0/temp"); err == nil {
		if mili, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil {
			t := float64(mili) / 1000.0
			ov.CPUTempC = &t
		}
	}
	if b, err := os.ReadFile("/sys/class/thermal/cooling_device0/cur_state"); err == nil {
		if st, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && st >= 0 {
			cs := st
			ov.CoolingState = &cs
		}
	}

	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		var totalKB, availKB uint64
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			val, _ := strconv.ParseUint(fields[1], 10, 64)
			switch fields[0] {
			case "MemTotal:":
				totalKB = val
			case "MemAvailable:":
				availKB = val
			}
		}
		ov.MemTotalMB = totalKB / 1024
		ov.MemAvailMB = availKB / 1024
		if totalKB >= availKB {
			ov.MemUsedMB = (totalKB - availKB) / 1024
		}
	}
	return ov
}

func ReadTimezone() string {
	if target, err := os.Readlink("/etc/localtime"); err == nil {
		const prefix = "/usr/share/zoneinfo/"
		if idx := strings.Index(target, prefix); idx >= 0 {
			return target[idx+len(prefix):]
		}
	}
	if data, err := os.ReadFile("/etc/TZ"); err == nil {
		return strings.TrimSpace(string(data))
	}
	return "UTC"
}

func ListServices() []ServiceStatus {
	out := make([]ServiceStatus, 0, len(ManagedServices))
	for _, svc := range ManagedServices {
		st := ServiceStatus{
			Name:        svc.Name,
			Description: svc.Description,
			InitScript:  svc.InitScript,
			Actions:     svc.Actions,
		}
		if svc.ProcName != "" {
			if res, err := Run(3*time.Second, "pidof", svc.ProcName); err == nil {
				pid := strings.TrimSpace(res.Stdout)
				if pid != "" {
					st.Running = true
					st.PID = pid
				}
			}
		} else if svc.Name == "nftables" {
			if _, err := Run(3*time.Second, "nft", "list", "table", "inet", "netbee_fw"); err == nil {
				st.Running = true
			}
		} else if svc.Name == "nft-offload" {
			if _, err := Run(3*time.Second, "nft", "list", "flowtable", "inet", "netbee_fw", "fastpath"); err == nil {
				st.Running = true
			}
		} else if svc.Name == "sqm" {
			if res, err := Run(3*time.Second, "tc", "qdisc", "show"); err == nil && strings.Contains(res.Stdout, "qdisc cake") {
				st.Running = true
			}
		}
		out = append(out, st)
	}
	return out
}

type NetCounters struct {
	RxBytes   uint64 `json:"rx_bytes"`
	TxBytes   uint64 `json:"tx_bytes"`
	RxPackets uint64 `json:"rx_packets"`
	TxPackets uint64 `json:"tx_packets"`
}

func ReadAllNetCounters() map[string]NetCounters {
	res := make(map[string]NetCounters)
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return res
	}
	readUint := func(p string) uint64 {
		b, err := os.ReadFile(p)
		if err != nil {
			return 0
		}
		v, _ := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
		return v
	}
	for _, e := range entries {
		name := e.Name()
		base := filepath.Join("/sys/class/net", name, "statistics")
		res[name] = NetCounters{
			RxBytes:   readUint(filepath.Join(base, "rx_bytes")),
			TxBytes:   readUint(filepath.Join(base, "tx_bytes")),
			RxPackets: readUint(filepath.Join(base, "rx_packets")),
			TxPackets: readUint(filepath.Join(base, "tx_packets")),
		}
	}
	return res
}

type CPUTimes struct {
	Idle  uint64
	Total uint64
}

func ReadCPUTimes() CPUTimes {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return CPUTimes{}
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "cpu ") {
			fields := strings.Fields(line)[1:]
			var total, idle uint64
			for i, f := range fields {
				v, _ := strconv.ParseUint(f, 10, 64)
				total += v
				if i == 3 || i == 4 { // idle + iowait
					idle += v
				}
			}
			return CPUTimes{Idle: idle, Total: total}
		}
	}
	return CPUTimes{}
}
