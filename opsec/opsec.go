// Package opsec enforces anonymous egress for ARTEX tool calls in code, not in
// a prompt. When Opsec is enabled every external connection must exit through
// Tor (SOCKS5); if Tor is unreachable the call is blocked and never falls back
// to clearnet (fail closed). Loopback, RFC1918/LAN, the ARTEX UI and recording
// proxy, Postgres and the configured local LLM are on a bypass allowlist and
// stay direct, so the platform keeps working.
//
// The package holds one process-wide State (Current / SetConfig, mirroring
// egress.Current / SetProfile). It owns no approval logic of its own: the guard
// PreToolUse hook and the intercept pinned dialer consult it and block through
// their existing mechanisms. The surrounding packages read the live State per
// call, so a settings change applies to the next tool call.
package opsec

import (
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
)

const (
	// DefaultTorPort is the Tor SOCKS5 port used when none is configured.
	DefaultTorPort = 9050
	// DefaultTorControlPort is the Tor control port used for NEWNYM.
	DefaultTorControlPort = 9051

	torHostNative = "127.0.0.1"
	torHostDocker = "host.docker.internal"
)

// Config is the persisted opsec configuration (db settings opsec_*). The zero
// Config is disabled: a strict no-op, so default behavior is unchanged.
type Config struct {
	Enabled bool
	// TorHost / TorPort are the Tor SOCKS5 endpoint. An empty host resolves to
	// the Docker-aware default (host.docker.internal in a container, else
	// 127.0.0.1); a zero port to DefaultTorPort.
	TorHost string
	TorPort int
	// ControlPort is the Tor control port for circuit rotation (NEWNYM); 0 =
	// DefaultTorControlPort.
	ControlPort int
	// Bypass are extra hosts / IPs / CIDRs that stay direct (never via Tor), on
	// top of the always-direct loopback + RFC1918 + infra defaults. The Manager
	// adds the local LLM host(s) here.
	Bypass []string
}

// State is the live opsec state: a Config plus the compiled bypass matcher.
// It is immutable after New; SetConfig publishes a new one.
type State struct {
	cfg         Config
	torHost     string
	torPort     int
	controlPort int
	inDocker    bool

	nets     []*net.IPNet    // bypass CIDRs
	hosts    map[string]bool // bypass exact hostnames (lowercased)
	suffixes []string        // bypass domain suffixes, e.g. ".local"
}

// defaultBypassCIDRs are always direct: loopback, RFC1918, CGNAT, link-local
// and IPv6 ULA/loopback/link-local. External targets are everything else.
var defaultBypassCIDRs = []string{
	"127.0.0.0/8", "::1/128",
	"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
	"100.64.0.0/10",  // CGNAT
	"169.254.0.0/16", // IPv4 link-local
	"fc00::/7",       // IPv6 ULA
	"fe80::/10",      // IPv6 link-local
}

// defaultBypassHosts are infra hostnames that must stay direct: the loopback
// name, the Docker host gateway, and the compose service names for Postgres and
// Tor itself (Tor must be reachable directly, never through Tor).
var defaultBypassHosts = []string{"localhost", "host.docker.internal", "postgres", "tor"}

var current atomic.Pointer[State]

// New builds a State for cfg and compiles its bypass matcher.
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
	// The Tor host itself is always direct.
	s.addBypassEntry(s.torHost)
	for _, e := range cfg.Bypass {
		s.addBypassEntry(e)
	}
	return s
}

// addBypassEntry records one user/derived bypass token: a CIDR, an IP, a
// ".suffix", or an exact hostname. A host:port is reduced to its host.
func (s *State) addBypassEntry(raw string) {
	e := strings.ToLower(strings.TrimSpace(raw))
	if e == "" {
		return
	}
	// Allow a full URL (e.g. an LLM base_url) and keep only its host.
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

// SetConfig publishes a new live State for cfg and returns it.
func SetConfig(cfg Config) *State {
	s := New(cfg)
	current.Store(s)
	return s
}

// Current returns the live State; before any SetConfig it is a disabled State.
func Current() *State {
	if s := current.Load(); s != nil {
		return s
	}
	s := New(Config{})
	current.CompareAndSwap(nil, s)
	return current.Load()
}

// Enabled reports whether opsec enforcement is on (package-level shortcut).
func Enabled() bool { return Current().cfg.Enabled }

// Enabled reports whether opsec enforcement is on.
func (s *State) Enabled() bool { return s.cfg.Enabled }

// InDocker reports whether this process runs inside a container. It is used for
// the Tor host default and shown in the UI.
func (s *State) InDocker() bool { return s.inDocker }

// TorHost / TorPort / ControlPort are the resolved Tor endpoint values.
func (s *State) TorHost() string  { return s.torHost }
func (s *State) TorPort() int     { return s.torPort }
func (s *State) ControlPort() int { return s.controlPort }

// TorAddr is host:port of the Tor SOCKS5 endpoint.
func (s *State) TorAddr() string { return net.JoinHostPort(s.torHost, strconv.Itoa(s.torPort)) }

// TorControlAddr is host:port of the Tor control endpoint.
func (s *State) TorControlAddr() string {
	return net.JoinHostPort(s.torHost, strconv.Itoa(s.controlPort))
}

// TorProxyURL is socks5://host:port, for Go HTTP clients and the recording
// proxy upstream (x/net SOCKS5 resolves names remotely, so no clearnet DNS).
func (s *State) TorProxyURL() string { return "socks5://" + s.TorAddr() }

// TorProxyURLRemoteDNS is socks5h://host:port, for the Bash env (curl/wget read
// ALL_PROXY): the h forces remote DNS so target names never resolve on the host.
func (s *State) TorProxyURLRemoteDNS() string { return "socks5h://" + s.TorAddr() }

// Bypass reports whether a host or IP (optionally host:port) stays direct,
// never through Tor. A name that is not on the allowlist is external: it is
// resolved remotely by Tor, never here.
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

// NoProxyList is a comma-separated NO_PROXY value for the Bash env so LAN/infra
// traffic stays direct even under Tor. It lists the infra hostnames, the Tor
// host, the RFC1918/loopback prefixes (the forms curl understands), and the
// user/derived bypass hosts. External targets are absent, so they go to Tor.
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
