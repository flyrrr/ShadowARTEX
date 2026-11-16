package opsec

import (
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
)

const (
	DefaultTorPort = 9050

	DefaultTorControlPort = 9051

	torHostNative = "127.0.0.1"
	torHostDocker = "host.docker.internal"
)

type Config struct {
	Enabled bool

	TorHost string
	TorPort int

	ControlPort int

	Bypass []string
}

type State struct {
	cfg         Config
	torHost     string
	torPort     int
	controlPort int
	inDocker    bool

	nets     []*net.IPNet
	hosts    map[string]bool
	suffixes []string
}

var defaultBypassCIDRs = []string{
	"127.0.0.0/8", "::1/128",
	"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
	"100.64.0.0/10",
	"169.254.0.0/16",
	"fc00::/7",
	"fe80::/10",
}

var defaultBypassHosts = []string{"localhost", "host.docker.internal", "postgres", "tor"}

var current atomic.Pointer[State]

func New(cfg Config) *State {
	s := &State{
		cfg:         cfg,
		torHost:     strings.TrimSpace(cfg.TorHost),
		torPort:     cfg.TorPort,
		controlPort: cfg.ControlPort,
		inDocker:    InDocker(),
		hosts:       map[string]bool{},
	}
	if s.torHost == "" {
		if s.inDocker {
			s.torHost = torHostDocker
		} else {
			s.torHost = torHostNative
		}
	}
	if s.torPort <= 0 || s.torPort > 65535 {
		s.torPort = DefaultTorPort
	}
	if s.controlPort <= 0 || s.controlPort > 65535 {
		s.controlPort = DefaultTorControlPort
	}
	for _, c := range defaultBypassCIDRs {
		if _, n, err := net.ParseCIDR(c); err == nil {
			s.nets = append(s.nets, n)
		}
	}
	for _, h := range defaultBypassHosts {
		s.hosts[strings.ToLower(h)] = true
	}

	s.addBypassEntry(s.torHost)
	for _, e := range cfg.Bypass {
		s.addBypassEntry(e)
	}
	return s
}

func (s *State) addBypassEntry(raw string) {
	e := strings.ToLower(strings.TrimSpace(raw))
	if e == "" {
		return
	}

	if strings.Contains(e, "://") {
		if u, err := url.Parse(e); err == nil && u.Host != "" {
			e = u.Hostname()
		}
	} else if h, _, err := net.SplitHostPort(e); err == nil {
		e = h
	}
	e = strings.Trim(e, "[]")
	if e == "" {
		return
	}
	if _, n, err := net.ParseCIDR(e); err == nil {
		s.nets = append(s.nets, n)
		return
	}
	if strings.HasPrefix(e, ".") {
		s.suffixes = append(s.suffixes, e)
		return
	}
	s.hosts[e] = true
}

func SetConfig(cfg Config) *State {
	s := New(cfg)
	current.Store(s)
	return s
}

func Current() *State {
	if s := current.Load(); s != nil {
		return s
	}
	s := New(Config{})
	current.CompareAndSwap(nil, s)
	return current.Load()
}

func Enabled() bool { return Current().cfg.Enabled }

func (s *State) Enabled() bool { return s.cfg.Enabled }

func (s *State) InDocker() bool { return s.inDocker }

func (s *State) TorHost() string  { return s.torHost }
func (s *State) TorPort() int     { return s.torPort }
func (s *State) ControlPort() int { return s.controlPort }

func (s *State) TorAddr() string { return net.JoinHostPort(s.torHost, strconv.Itoa(s.torPort)) }

func (s *State) TorControlAddr() string {
	return net.JoinHostPort(s.torHost, strconv.Itoa(s.controlPort))
}

func (s *State) TorProxyURL() string { return "socks5://" + s.TorAddr() }

func (s *State) TorProxyURLRemoteDNS() string { return "socks5h://" + s.TorAddr() }

func (s *State) Bypass(hostOrIP string) bool {
	h := strings.ToLower(strings.TrimSpace(hostOrIP))
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	h = strings.Trim(h, "[]")
	if h == "" {
		return false
	}
	if s.hosts[h] {
		return true
	}
	for _, suf := range s.suffixes {
		if h == strings.TrimPrefix(suf, ".") || strings.HasSuffix(h, suf) {
			return true
		}
	}
	if ip := net.ParseIP(h); ip != nil {
		for _, n := range s.nets {
			if n.Contains(ip) {
				return true
			}
		}
	}
	return false
}

func (s *State) NoProxyList() string {
	seen := map[string]bool{}
	var out []string
	add := func(v string) {
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	add("localhost")
	add("127.0.0.1")
	add("::1")
	add("10.0.0.0/8")
	add("172.16.0.0/12")
	add("192.168.0.0/16")
	add("169.254.0.0/16")
	for h := range s.hosts {
		add(h)
	}
	for _, suf := range s.suffixes {
		add(suf)
	}
	return strings.Join(out, ",")
}
