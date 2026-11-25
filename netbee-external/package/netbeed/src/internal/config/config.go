package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

// RuntimeConfig holds daemon startup configuration from /etc/netbee/netbeed.json.
type RuntimeConfig struct {
	HTTPSAddr       string   `json:"https_addr"`
	HTTPAddr        string   `json:"http_addr"`
	TLSDIR          string   `json:"tls_dir"`
	WebDir          string   `json:"web_dir"`
	StatePath       string   `json:"state_path"`
	AuthPath        string   `json:"auth_path"`
	AdGuardURL      string   `json:"adguard_url"`
	AdGuardUser     string   `json:"adguard_user"`
	AdGuardPass     string   `json:"adguard_pass"`
	RollbackSeconds int      `json:"rollback_seconds"`
	CORSOrigins     []string `json:"cors_origins"`
}

func DefaultRuntimeConfig() RuntimeConfig {
	return RuntimeConfig{
		HTTPSAddr:       ":443",
		HTTPAddr:        ":80",
		TLSDIR:          "/etc/netbee/tls",
		WebDir:          "/usr/share/netbee/web",
		StatePath:       "/etc/netbee/state.json",
		AuthPath:        "/etc/netbee/auth.json",
		AdGuardURL:      "http://127.0.0.1:3000",
		AdGuardUser:     "admin",
		AdGuardPass:     "netbee",
		RollbackSeconds: 60,
		CORSOrigins:     []string{},
	}
}

func LoadRuntimeConfig(path string) (RuntimeConfig, error) {
	cfg := DefaultRuntimeConfig()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, err
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}
	if cfg.RollbackSeconds <= 0 {
		cfg.RollbackSeconds = 60
	}
	return cfg, nil
}

// --- Persistent Router State (/etc/netbee/state.json) ---

type FirewallRule struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Enabled  bool   `json:"enabled"`
	Chain    string `json:"chain"`    // "input" or "forward"
	Action   string `json:"action"`   // "accept", "drop", "reject"
	Protocol string `json:"protocol"` // "tcp", "udp", "icmp", "icmpv6", "any"
	InIface  string `json:"in_iface,omitempty"`
	OutIface string `json:"out_iface,omitempty"`
	SrcAddr  string `json:"src_addr,omitempty"`
	DstAddr  string `json:"dst_addr,omitempty"`
	DstPort  string `json:"dst_port,omitempty"` // e.g. "443" or "8000-8100"
	Log      bool   `json:"log"`
}

type PortForward struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Enabled    bool   `json:"enabled"`
	Protocol   string `json:"protocol"` // "tcp", "udp", "both"
	ExtPort    string `json:"ext_port"` // e.g. "443" or "8080-8090"
	IntIP      string `json:"int_ip"`   // e.g. "192.168.10.50"
	IntPort    int    `json:"int_port"` // 0 preserves external port/range 1:1
	SourceCIDR string `json:"source_cidr,omitempty"`
}

type FirewallState struct {
	TransparentDNS  bool           `json:"transparent_dns"`
	ExposeWireGuard bool           `json:"expose_wireguard"`
	WireGuardPort   int            `json:"wireguard_port"`
	FlowOffload     bool           `json:"flow_offload"`
	CustomRules     []FirewallRule `json:"custom_rules"`
	PortForwards    []PortForward  `json:"port_forwards"`
}

type StaticRoute struct {
	ID          string `json:"id"`
	Name        string `json:"name,omitempty"`
	Destination string `json:"destination"`
	Gateway     string `json:"gateway,omitempty"`
	Device      string `json:"device,omitempty"`
	Metric      int    `json:"metric,omitempty"`
	Enabled     bool   `json:"enabled"`
}

type WANState struct {
	Mode          string `json:"mode"` // "dhcp", "pppoe", "ont_vlan"
	Interface     string `json:"interface"`
	VLANID        int    `json:"vlan_id"`
	PPPoEUser     string `json:"pppoe_user"`
	PPPoEPassword string `json:"pppoe_password,omitempty"`
	MACClone      string `json:"mac_clone,omitempty"`
	MTU           int    `json:"mtu"`
	IPv6PD        bool   `json:"ipv6_pd"`
}

type LANState struct {
	Interface string `json:"interface"`
	IP        string `json:"ip"`
	Netmask   string `json:"netmask"`
}

type WireGuardPeer struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	PublicKey    string `json:"public_key"`
	PresharedKey string `json:"preshared_key,omitempty"`
	HasPSK       bool   `json:"has_psk,omitempty"`
	AllowedIPs   string `json:"allowed_ips"`
	Enabled      bool   `json:"enabled"`
}

type WireGuardState struct {
	Enabled    bool            `json:"enabled"`
	Interface  string          `json:"interface"`
	Address    string          `json:"address"` // e.g. "10.66.66.1/24"
	ListenPort int             `json:"listen_port"`
	PrivateKey string          `json:"private_key,omitempty"`
	PublicKey  string          `json:"public_key,omitempty"`
	Endpoint   string          `json:"endpoint,omitempty"` // public host/DDNS for client configs
	DNS        string          `json:"dns"`                // e.g. "192.168.10.1"
	Peers      []WireGuardPeer `json:"peers"`
}

type State struct {
	WAN          WANState       `json:"wan"`
	LAN          LANState       `json:"lan"`
	StaticRoutes []StaticRoute  `json:"static_routes"`
	Firewall     FirewallState  `json:"firewall"`
	WireGuard    WireGuardState `json:"wireguard"`
}

func DefaultState() State {
	return State{
		WAN: WANState{
			Mode:      "dhcp",
			Interface: "eth1",
			VLANID:    35,
			MTU:       1500,
			IPv6PD:    false,
		},
		LAN: LANState{
			Interface: "eth0",
			IP:        "192.168.10.1",
			Netmask:   "255.255.255.0",
		},
		StaticRoutes: []StaticRoute{},
		Firewall: FirewallState{
			TransparentDNS:  false,
			ExposeWireGuard: false,
			WireGuardPort:   51820,
			FlowOffload:     true,
			CustomRules:     []FirewallRule{},
			PortForwards:    []PortForward{},
		},
		WireGuard: WireGuardState{
			Enabled:    false,
			Interface:  "wg0",
			Address:    "10.66.66.1/24",
			ListenPort: 51820,
			DNS:        "192.168.10.1",
			Peers:      []WireGuardPeer{},
		},
	}
}

func normalizeState(st *State) {
	if st.WAN.Interface == "" {
		st.WAN.Interface = "eth1"
	}
	if st.WAN.Mode == "" {
		st.WAN.Mode = "dhcp"
	}
	if st.WAN.MTU == 0 {
		if st.WAN.Mode == "dhcp" {
			st.WAN.MTU = 1500
		} else {
			st.WAN.MTU = 1492
		}
	}
	if st.LAN.Interface == "" {
		st.LAN.Interface = "eth0"
	}
	if st.LAN.IP == "" {
		st.LAN.IP = "192.168.10.1"
	}
	if st.LAN.Netmask == "" {
		st.LAN.Netmask = "255.255.255.0"
	}
	if st.StaticRoutes == nil {
		st.StaticRoutes = []StaticRoute{}
	}
	if st.Firewall.WireGuardPort == 0 {
		st.Firewall.WireGuardPort = 51820
	}
	if st.Firewall.CustomRules == nil {
		st.Firewall.CustomRules = []FirewallRule{}
	}
	if st.Firewall.PortForwards == nil {
		st.Firewall.PortForwards = []PortForward{}
	}
	if st.WireGuard.Interface == "" {
		st.WireGuard.Interface = "wg0"
	}
	if st.WireGuard.Address == "" {
		st.WireGuard.Address = "10.66.66.1/24"
	}
	if st.WireGuard.ListenPort == 0 {
		st.WireGuard.ListenPort = 51820
	}
	if st.WireGuard.Peers == nil {
		st.WireGuard.Peers = []WireGuardPeer{}
	}
}

type Store struct {
	mu    sync.RWMutex
	path  string
	state State
}

func NewStore(path string) (*Store, error) {
	s := &Store{path: path, state: DefaultState()}
	if data, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(data, &s.state); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	normalizeState(&s.state)
	return s, nil
}

func (s *Store) Get() State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cp := s.state
	cp.StaticRoutes = append([]StaticRoute{}, s.state.StaticRoutes...)
	cp.Firewall.CustomRules = append([]FirewallRule{}, s.state.Firewall.CustomRules...)
	cp.Firewall.PortForwards = append([]PortForward{}, s.state.Firewall.PortForwards...)
	cp.WireGuard.Peers = append([]WireGuardPeer{}, s.state.WireGuard.Peers...)
	return cp
}

func (s *Store) Update(fn func(*State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.state
	next.StaticRoutes = append([]StaticRoute{}, s.state.StaticRoutes...)
	next.Firewall.CustomRules = append([]FirewallRule{}, s.state.Firewall.CustomRules...)
	next.Firewall.PortForwards = append([]PortForward{}, s.state.Firewall.PortForwards...)
	next.WireGuard.Peers = append([]WireGuardPeer{}, s.state.WireGuard.Peers...)
	if err := fn(&next); err != nil {
		return err
	}
	for i := range next.WireGuard.Peers {
		next.WireGuard.Peers[i].HasPSK = false
	}
	normalizeState(&next)
	if err := AtomicWriteJSON(s.path, next, 0600); err != nil {
		return err
	}
	s.state = next
	return nil
}

// Reload re-reads persistent state from disk (essential after a rollback reverts state.json).
func (s *Store) Reload() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := DefaultState()
	if data, err := os.ReadFile(s.path); err == nil {
		if err := json.Unmarshal(data, &next); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	normalizeState(&next)
	s.state = next
	return nil
}

// AtomicWriteFile writes data to a unique temporary file in the same directory and renames it atomically.
func AtomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if err := f.Chmod(perm); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func AtomicWriteJSON(path string, v any, perm os.FileMode) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return AtomicWriteFile(path, b, perm)
}
