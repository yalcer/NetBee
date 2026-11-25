package api

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/yalcer/netbee/netbeed/internal/config"
	"github.com/yalcer/netbee/netbeed/internal/sys"
)

var (
	passwdFilePath = "/etc/passwd"
	groupFilePath  = "/etc/group"
	shadowFilePath = "/etc/shadow"
)

type OSUserInfo struct {
	Username     string   `json:"username"`
	UID          int      `json:"uid"`
	GID          int      `json:"gid"`
	Comment      string   `json:"comment"`
	Home         string   `json:"home"`
	Shell        string   `json:"shell"`
	Role         string   `json:"role"` // "superuser", "admin", "service"
	LoginEnabled bool     `json:"login_enabled"`
	Groups       []string `json:"groups"`
	SSHKeysCount int      `json:"ssh_keys_count"`
}

func parseGroupMemberships(username string, primaryGID int) []string {
	raw, err := os.ReadFile(groupFilePath)
	if err != nil {
		return []string{}
	}
	var out []string
	seen := map[string]bool{}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 4 {
			continue
		}
		gname := parts[0]
		gid, err := strconv.Atoi(parts[2])
		if err != nil {
			continue
		}
		matched := gid == primaryGID
		if !matched && parts[3] != "" {
			for _, m := range strings.Split(parts[3], ",") {
				if strings.TrimSpace(m) == username {
					matched = true
					break
				}
			}
		}
		if matched && !seen[gname] {
			seen[gname] = true
			out = append(out, gname)
		}
	}
	if out == nil {
		out = []string{}
	}
	return out
}

func parseAllPasswdUsers() []OSUserInfo {
	raw, err := os.ReadFile(passwdFilePath)
	if err != nil {
		return nil
	}
	var users []OSUserInfo
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 7 {
			continue
		}
		uid, err1 := strconv.Atoi(parts[2])
		gid, err2 := strconv.Atoi(parts[3])
		if err1 != nil || err2 != nil {
			continue
		}
		shell := parts[6]
		loginEnabled := shell != "/bin/false" && shell != "/sbin/nologin" && shell != "/usr/sbin/nologin"
		role := "service"
		if uid == 0 {
			role = "superuser"
		} else if uid >= 1000 && uid < 65534 && loginEnabled {
			role = "admin"
		}
		u := OSUserInfo{
			Username:     parts[0],
			UID:          uid,
			GID:          gid,
			Comment:      parts[4],
			Home:         parts[5],
			Shell:        shell,
			Role:         role,
			LoginEnabled: loginEnabled,
			Groups:       parseGroupMemberships(parts[0], gid),
		}
		if u.Home != "" && u.Home != "/" {
			u.SSHKeysCount = len(readAuthorizedKeysFromPath(u.Home + "/.ssh/authorized_keys"))
		}
		users = append(users, u)
	}
	return users
}

func lookupPasswdUser(username string) (OSUserInfo, bool) {
	for _, u := range parseAllPasswdUsers() {
		if u.Username == username {
			return u, true
		}
	}
	return OSUserInfo{}, false
}

var managedDaemonUsers = map[string]bool{
	"iperf":  true,
	"chrony": true,
	"dhcpcd": true,
}

func listNetBeeOSUsers() []OSUserInfo {
	all := parseAllPasswdUsers()
	out := make([]OSUserInfo, 0, len(all))
	for _, u := range all {
		if u.UID == 0 || (u.UID >= 1000 && u.UID < 65534) || managedDaemonUsers[u.Username] {
			out = append(out, u)
		}
	}
	return out
}

func setOSUserPassword(username, newPassword string) error {
	if username != "root" && username != "netbee" {
		return errors.New("only interactive accounts ('root' or 'netbee') allow password updates")
	}
	if len(newPassword) < 8 || len(newPassword) > 128 {
		return errors.New("password must be between 8 and 128 characters")
	}
	if strings.ContainsAny(newPassword, "\n\r\x00") {
		return errors.New("password contains forbidden control characters")
	}
	if _, ok := lookupPasswdUser(username); !ok {
		return fmt.Errorf("OS account %q does not exist", username)
	}

	if _, err := sys.RunWithInput(5*time.Second, username+":"+newPassword+"\n", "chpasswd"); err == nil {
		return nil
	}

	// Fallback if chpasswd is unavailable: hash with BusyBox mkpasswd -m sha-512 and rewrite /etc/shadow atomically
	res, err := sys.Run(5*time.Second, "mkpasswd", "-m", "sha-512", newPassword)
	if err != nil || strings.TrimSpace(res.Stdout) == "" {
		return fmt.Errorf("failed to update OS password via chpasswd or mkpasswd: %w", err)
	}
	hash := strings.TrimSpace(res.Stdout)
	rawShadow, err := os.ReadFile(shadowFilePath)
	if err != nil {
		return err
	}
	days := strconv.FormatInt(time.Now().Unix()/86400, 10)
	lines := strings.Split(string(rawShadow), "\n")
	updated := false
	for i, line := range lines {
		if strings.HasPrefix(line, username+":") {
			fields := strings.Split(line, ":")
			if len(fields) >= 3 {
				fields[1] = hash
				fields[2] = days
				lines[i] = strings.Join(fields, ":")
				updated = true
			}
		}
	}
	if !updated {
		return fmt.Errorf("account %q missing from shadow file", username)
	}
	return config.AtomicWriteFile(shadowFilePath, []byte(strings.Join(lines, "\n")), 0600)
}

func (s *Server) handleGetOSUsers(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"users": listNetBeeOSUsers(),
	})
}

func (s *Server) handleSetOSUserPassword(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimSpace(r.PathValue("username"))
	if username != "root" && username != "netbee" {
		writeErr(w, http.StatusBadRequest, "password changes are only permitted for 'root' or 'netbee'")
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json body")
		return
	}
	if err := setOSUserPassword(username, req.Password); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"username": username,
	})
}
