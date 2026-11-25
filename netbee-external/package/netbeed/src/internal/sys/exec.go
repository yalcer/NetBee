package sys

import (
	"bytes"
	"context"
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
	reHost     = regexp.MustCompile(`^[a-zA-Z0-9._:-]{1,253}$`)
	reHostname = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)
	reMAC      = regexp.MustCompile(`^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$`)
	rePortSpec = regexp.MustCompile(`^[0-9]{1,5}(-[0-9]{1,5})?$`)
	reWGKey    = regexp.MustCompile(`^[A-Za-z0-9+/]{42,44}=?$`)
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

func ValidIface(s string) bool    { return reIface.MatchString(s) }
func ValidHost(s string) bool     { return reHost.MatchString(s) && !strings.HasPrefix(s, "-") }
func ValidHostname(s string) bool { return reHostname.MatchString(s) }
func ValidMAC(s string) bool      { return reMAC.MatchString(s) }
func ValidWGKey(s string) bool    { return reWGKey.MatchString(strings.TrimSpace(s)) }
func ValidTimezone(s string) bool { return reTZ.MatchString(s) && !strings.Contains(s, "..") }
func ValidID(s string) bool       { return reID.MatchString(s) }

func ValidIPv4(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() != nil
}

func ValidIPOrCIDR(s string) bool {
	if net.ParseIP(s) != nil {
		return true
	}
	_, _, err := net.ParseCIDR(s)
	return err == nil
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
