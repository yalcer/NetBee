package sys

import (
	"os"
	"path/filepath"
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
	Mount     string `json:"mount"`
	TotalMB   uint64 `json:"total_mb"`
	UsedMB    uint64 `json:"used_mb"`
	FreeMB    uint64 `json:"free_mb"`
	UsedPct   int    `json:"used_pct"`
}

type SystemOverview struct {
	Hostname    string      `json:"hostname"`
	OS          OSInfo      `json:"os"`
	Time        string      `json:"time"`
	Timezone    string      `json:"timezone"`
	UptimeSec   int64       `json:"uptime_seconds"`
	LoadAvg     [3]float64  `json:"load_avg"`
	CPUTempC    *float64    `json:"cpu_temp_c"`
	MemTotalMB  uint64      `json:"mem_total_mb"`
	MemUsedMB   uint64      `json:"mem_used_mb"`
	MemAvailMB  uint64      `json:"mem_avail_mb"`
	Disks       []DiskUsage `json:"disks"`
}

type ServiceStatus struct {
	Name       string `json:"name"`
	InitScript string `json:"init_script"`
	Running    bool   `json:"running"`
	PID        string `json:"pid,omitempty"`
}

var ManagedServices = []struct {
	Name       string
	ProcName   string
	InitScript string
}{
	{"adguardhome", "AdGuardHome", "/etc/init.d/S85adguardhome"},
	{"dropbear", "dropbear", "/etc/init.d/S50dropbear"},
	{"chronyd", "chronyd", "/etc/init.d/S49chronyd"},
	{"dhcpcd", "dhcpcd", "/etc/init.d/S41dhcpcd"},
	{"vnstatd", "vnstatd", "/etc/init.d/S86vnstatd"},
	{"radvd", "radvd", "/etc/init.d/S50radvd"},
	{"crond", "crond", "/etc/init.d/S50crond"},
	{"watchdog", "watchdog", "/etc/init.d/S15watchdog"},
	{"triggerhappy", "thd", "/etc/init.d/S10triggerhappy"},
	{"pppd", "pppd", ""},
	{"nftables", "", "/etc/init.d/S35nftables"},
	{"nft-offload", "", "/etc/init.d/S42nft-offload"},
	{"sqm", "", "/etc/init.d/S45sqm"},
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

func ReadOverview() SystemOverview {
	host, _ := os.Hostname()
	ov := SystemOverview{
		Hostname: host,
		OS:       ReadOSInfo(),
		Time:     time.Now().Format(time.RFC3339),
		Timezone: ReadTimezone(),
		Disks:    []DiskUsage{ReadDiskUsage("/"), ReadDiskUsage("/var/log")},
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

	if data, err := os.ReadFile("/sys/class/thermal/thermal_zone0/temp"); err == nil {
		if mili, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil {
			t := float64(mili) / 1000.0
			ov.CPUTempC = &t
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
		st := ServiceStatus{Name: svc.Name, InitScript: svc.InitScript}
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
