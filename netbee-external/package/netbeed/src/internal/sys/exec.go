package sys

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	reIface    = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,15}$`)
	reHostname = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)
	reMAC      = regexp.MustCompile(`^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$`)
	rePortSpec = regexp.MustCompile(`^[0-9]{1,5}(-[0-9]{1,5})?$`)
	reTZ       = regexp.MustCompile(`^[A-Za-z0-9_+-]+(/[A-Za-z0-9_+-]+)*$`)
	reID       = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)
)

type CmdResult struct {
	ExitCode int
	Stdout   string
	Stderr   string
}

func Run(timeout time.Duration, name string, args ...string) (CmdResult, error) {
	return RunWithInput(timeout, "", name, args...)
}

func RunWithInput(timeout time.Duration, stdin string, name string, args ...string) (CmdResult, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}

	err := cmd.Run()
	res := CmdResult{
		Stdout: outBuf.String(),
		Stderr: errBuf.String(),
	}
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			res.ExitCode = exitErr.ExitCode()
		} else {
			res.ExitCode = -1
		}
		return res, fmt.Errorf("%s failed: %w (%s)", name, err, strings.TrimSpace(res.Stderr))
	}
	return res, nil
}

// --- Strict Input Validators (Zero Shell Injection) ---

func ValidIface(s string) bool {
	return reIface.MatchString(s) && !strings.HasPrefix(s, "-") && !strings.Contains(s, "..")
}

// ValidHost accepts either a valid IPv4/IPv6 literal or a strict RFC-1123 hostname/FQDN (no ports, colons, or '..').
func ValidHost(s string) bool {
	if s == "" || len(s) > 253 || strings.HasPrefix(s, "-") {
		return false
	}
	if net.ParseIP(s) != nil {
		return true
	}
	trimmed := strings.TrimSuffix(s, ".")
	if trimmed == "" {
		return false
	}
	labels := strings.Split(trimmed, ".")
	for _, lbl := range labels {
		if !reHostname.MatchString(lbl) {
			return false
		}
	}
	return true
}

func ValidHostname(s string) bool { return reHostname.MatchString(s) }
func ValidMAC(s string) bool      { return reMAC.MatchString(s) }
func ValidTimezone(s string) bool { return reTZ.MatchString(s) && !strings.Contains(s, "..") }
func ValidID(s string) bool       { return reID.MatchString(s) }

// ValidWGKey verifies a strict 32-byte base64-encoded WireGuard key (44 chars).
func ValidWGKey(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) != 44 || !strings.HasSuffix(s, "=") {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(raw) == 32
}

func ValidIPv4(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() != nil
}

// ValidIPv4Netmask checks for a valid contiguous IPv4 subnet mask between /8 and /30.
func ValidIPv4Netmask(s string) bool {
	ip := net.ParseIP(s).To4()
	if ip == nil {
		return false
	}
	mask := net.IPv4Mask(ip[0], ip[1], ip[2], ip[3])
	ones, bits := mask.Size()
	return bits == 32 && ones >= 8 && ones <= 30
}

// ValidUnicastIPv4Host ensures ipStr is a usable unicast host IPv4 address within maskStr (not loopback, multicast, network, or broadcast).
func ValidUnicastIPv4Host(ipStr, maskStr string) bool {
	ip := net.ParseIP(ipStr).To4()
	maskIP := net.ParseIP(maskStr).To4()
	if ip == nil || maskIP == nil || !ValidIPv4Netmask(maskStr) {
		return false
	}
	if ip.IsLoopback() || ip.IsMulticast() || ip.IsUnspecified() || ip[0] == 0 || ip[0] >= 224 {
		return false
	}
	mask := net.IPv4Mask(maskIP[0], maskIP[1], maskIP[2], maskIP[3])
	netIP := ip.Mask(mask)
	if ip.Equal(netIP) {
		return false // network address
	}
	bcast := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		bcast[i] = netIP[i] | ^mask[i]
	}
	if ip.Equal(bcast) {
		return false // broadcast address
	}
	return true
}

func ValidIPOrCIDR(s string) bool {
	if net.ParseIP(s) != nil {
		return true
	}
	_, _, err := net.ParseCIDR(s)
	return err == nil
}

// ValidIPList validates a comma-separated list of 1..8 valid IPv4/IPv6 addresses (e.g. WireGuard DNS).
func ValidIPList(s string) bool {
	parts := strings.Split(s, ",")
	if len(parts) == 0 || len(parts) > 8 {
		return false
	}
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" || net.ParseIP(p) == nil {
			return false
		}
	}
	return true
}

func ValidPort(p int) bool { return p >= 1 && p <= 65535 }

func ValidPortSpec(s string) bool {
	if !rePortSpec.MatchString(s) {
		return false
	}
	parts := strings.Split(s, "-")
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || !ValidPort(n) {
			return false
		}
	}
	if len(parts) == 2 {
		a, _ := strconv.Atoi(parts[0])
		b, _ := strconv.Atoi(parts[1])
		return a <= b
	}
	return true
}

func ValidSafeString(s string) bool {
	return !strings.ContainsAny(s, "\"\n\r\x00$`\\;")
}

func ValidateVLAN(id int) error {
	if id < 1 || id > 4094 {
		return errors.New("vlan_id must be between 1 and 4094")
	}
	return nil
}
