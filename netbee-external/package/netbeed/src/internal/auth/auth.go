package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/yalcer/netbee/netbeed/internal/config"
)

const (
	SessionCookieName = "netbee_session"
	sessionTTL        = 12 * time.Hour
	pbkdf2Iterations  = 100000
)

type Credentials struct {
	Username           string `json:"username"`
	SaltHex            string `json:"salt_hex"`
	HashHex            string `json:"hash_hex"`
	Iterations         int    `json:"iterations"`
	MustChangePassword bool   `json:"must_change_password"`
}

type Session struct {
	Token     string
	Username  string
	CSRFToken string
	ExpiresAt time.Time
}

type rateEntry struct {
	attempts int
	windowAt time.Time
}

type Manager struct {
	mu       sync.RWMutex
	path     string
	creds    Credentials
	sessions map[string]Session
	rates    map[string]rateEntry
}

func NewManager(path string) (*Manager, error) {
	m := &Manager{
		path:     path,
		sessions: make(map[string]Session),
		rates:    make(map[string]rateEntry),
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		// Bootstrap default credentials (admin / netbee) on first boot
		creds, err := hashPassword("admin", "netbee", true)
		if err != nil {
			return nil, err
		}
		m.creds = creds
		_ = config.AtomicWriteJSON(path, creds, 0600)
		return m, nil
	}
	if err := json.Unmarshal(data, &m.creds); err != nil {
		return nil, err
	}
	return m, nil
}

// pbkdf2SHA256 implements RFC 2898 PBKDF2-HMAC-SHA256 using only Go stdlib.
func pbkdf2SHA256(password, salt []byte, iter, keyLen int) []byte {
	prf := func(key, data []byte) []byte {
		h := hmac.New(sha256.New, key)
		h.Write(data)
		return h.Sum(nil)
	}
	hashLen := sha256.Size
	numBlocks := (keyLen + hashLen - 1) / hashLen
	var dk []byte
	for block := 1; block <= numBlocks; block++ {
		buf := make([]byte, len(salt)+4)
		copy(buf, salt)
		buf[len(salt)] = byte(block >> 24)
		buf[len(salt)+1] = byte(block >> 16)
		buf[len(salt)+2] = byte(block >> 8)
		buf[len(salt)+3] = byte(block)
		u := prf(password, buf)
		t := make([]byte, len(u))
		copy(t, u)
		for i := 1; i < iter; i++ {
			u = prf(password, u)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		dk = append(dk, t...)
	}
	return dk[:keyLen]
}

func hashPassword(username, password string, mustChange bool) (Credentials, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return Credentials{}, err
	}
	dk := pbkdf2SHA256([]byte(password), salt, pbkdf2Iterations, 32)
	return Credentials{
		Username:           username,
		SaltHex:            hex.EncodeToString(salt),
		HashHex:            hex.EncodeToString(dk),
		Iterations:         pbkdf2Iterations,
		MustChangePassword: mustChange,
	}, nil
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (m *Manager) checkRateLimitLocked(ip string) bool {
	now := time.Now()
	// Prevent unbounded map growth under scanning/long uptime
	if len(m.rates) > 256 {
		for k, v := range m.rates {
			if now.Sub(v.windowAt) > 5*time.Minute {
				delete(m.rates, k)
			}
		}
	}
	ent, ok := m.rates[ip]
	if !ok || now.Sub(ent.windowAt) > time.Minute {
		m.rates[ip] = rateEntry{attempts: 1, windowAt: now}
		return true
	}
	if ent.attempts >= 10 {
		return false
	}
	ent.attempts++
	m.rates[ip] = ent
	return true
}

func (m *Manager) VerifyPassword(username, password string) bool {
	m.mu.RLock()
	creds := m.creds
	m.mu.RUnlock()

	if !hmac.Equal([]byte(username), []byte(creds.Username)) {
		return false
	}
	salt, err := hex.DecodeString(creds.SaltHex)
	if err != nil {
		return false
	}
	expected, err := hex.DecodeString(creds.HashHex)
	if err != nil {
		return false
	}
	iter := creds.Iterations
	if iter <= 0 {
		iter = pbkdf2Iterations
	}
	actual := pbkdf2SHA256([]byte(password), salt, iter, len(expected))
	return hmac.Equal(actual, expected)
}

func (m *Manager) Login(r *http.Request, username, password string) (Session, error) {
	ip := clientIP(r)
	m.mu.Lock()
	allowed := m.checkRateLimitLocked(ip)
	m.mu.Unlock()
	if !allowed {
		return Session{}, errors.New("too many login attempts, wait 1 minute")
	}

	if !m.VerifyPassword(username, password) {
		return Session{}, errors.New("invalid username or password")
	}

	tok, err := randomToken(32)
	if err != nil {
		return Session{}, err
	}
	csrf, err := randomToken(24)
	if err != nil {
		return Session{}, err
	}
	sess := Session{
		Token:     tok,
		Username:  username,
		CSRFToken: csrf,
		ExpiresAt: time.Now().Add(sessionTTL),
	}

	m.mu.Lock()
	// Prune expired sessions
	now := time.Now()
	for k, v := range m.sessions {
		if now.After(v.ExpiresAt) {
			delete(m.sessions, k)
		}
	}
	m.sessions[tok] = sess
	delete(m.rates, ip)
	m.mu.Unlock()
	return sess, nil
}

func (m *Manager) Logout(token string) {
	m.mu.Lock()
	delete(m.sessions, token)
	m.mu.Unlock()
}

func (m *Manager) ChangePassword(currentPassword, newPassword, keepSessionToken string) error {
	if len(newPassword) < 8 || len(newPassword) > 128 {
		return errors.New("new password must be between 8 and 128 characters")
	}
	if strings.ContainsAny(newPassword, "\n\r\x00") {
		return errors.New("new password contains forbidden control characters")
	}
	m.mu.RLock()
	username := m.creds.Username
	m.mu.RUnlock()

	if !m.VerifyPassword(username, currentPassword) {
		return errors.New("current password is incorrect")
	}
	next, err := hashPassword(username, newPassword, false)
	if err != nil {
		return err
	}
	if err := config.AtomicWriteJSON(m.path, next, 0600); err != nil {
		return err
	}
	m.mu.Lock()
	m.creds = next
	// Invalidate all other active sessions on password change
	for tok := range m.sessions {
		if tok != keepSessionToken {
			delete(m.sessions, tok)
		}
	}
	m.mu.Unlock()
	return nil
}

func (m *Manager) MustChangePassword() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.creds.MustChangePassword
}

func (m *Manager) Authenticate(r *http.Request) (Session, bool) {
	var token string
	if authHdr := r.Header.Get("Authorization"); strings.HasPrefix(authHdr, "Bearer ") {
		token = strings.TrimSpace(strings.TrimPrefix(authHdr, "Bearer "))
	} else if c, err := r.Cookie(SessionCookieName); err == nil {
		token = c.Value
	}
	if token == "" {
		return Session{}, false
	}

	m.mu.RLock()
	sess, ok := m.sessions[token]
	m.mu.RUnlock()
	if !ok || time.Now().After(sess.ExpiresAt) {
		if ok {
			m.Logout(token)
		}
		return Session{}, false
	}
	return sess, true
}

