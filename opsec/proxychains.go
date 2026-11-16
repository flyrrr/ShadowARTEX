package opsec

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// Tooling reports which egress helpers are installed on the host. proxychains4
// and torsocks wrap dynamically-linked programs; a statically-linked or
// Go/raw-socket binary bypasses LD_PRELOAD and is NOT covered — the dialer-level
// enforcement and the Bash argv block are what fail closed for those.
type Tooling struct {
	Proxychains     bool   `json:"proxychains"`
	ProxychainsPath string `json:"proxychains_path,omitempty"`
	Torsocks        bool   `json:"torsocks"`
	TorsocksPath    string `json:"torsocks_path,omitempty"`
	Tor             bool   `json:"tor"`
	TorPath         string `json:"tor_path,omitempty"`
}

// proxychainsBinaries are the names proxychains ships under across distros.
var proxychainsBinaries = []string{"proxychains4", "proxychains"}

// CheckTooling looks up the egress helpers on PATH.
func CheckTooling() Tooling {
	var t Tooling
	for _, b := range proxychainsBinaries {
		if p, err := exec.LookPath(b); err == nil {
			t.Proxychains, t.ProxychainsPath = true, p
			break
		}
	}
	if p, err := exec.LookPath("torsocks"); err == nil {
		t.Torsocks, t.TorsocksPath = true, p
	}
	if p, err := exec.LookPath("tor"); err == nil {
		t.Tor, t.TorPath = true, p
	}
	return t
}

// ProxychainsBin returns the proxychains program to prefix Bash with, or "" when
// none is installed.
func ProxychainsBin() string {
	for _, b := range proxychainsBinaries {
		if p, err := exec.LookPath(b); err == nil {
			return p
		}
	}
	return ""
}

// ProxychainsConf renders /etc/proxychains4.conf for this State: a strict chain
// of exactly one SOCKS5 hop (Tor) with remote DNS (proxy_dns). strict_chain +
// a single proxy means a failed Tor hop fails the connection — no direct
// fallback.
func (s *State) ProxychainsConf() string {
	var b strings.Builder
	b.WriteString("# Managed by ARTEX Opsec. Do not edit by hand.\n")
	b.WriteString("strict_chain\n")
	b.WriteString("proxy_dns\n")
	b.WriteString("remote_dns_subnet 224\n")
	b.WriteString("tcp_read_time_out 15000\n")
	b.WriteString("tcp_connect_time_out 10000\n")
	b.WriteString("quiet_mode\n")
	b.WriteString("[ProxyList]\n")
	// proxychains4 requires a numeric IP for the first (only) proxy, even with
	// strict_chain + proxy_dns, so the Tor host is resolved here; the literal is
	// a best-effort fallback when resolution fails.
	fmt.Fprintf(&b, "socks5 %s %d\n", resolveHostIP(s.torHost), s.torPort)
	return b.String()
}

// resolveHostIP returns host unchanged when it is already an IP literal, else
// its first resolved address, else host (best effort).
func resolveHostIP(host string) string {
	if net.ParseIP(host) != nil {
		return host
	}
	if addrs, err := net.LookupHost(host); err == nil {
		for _, a := range addrs {
			if ip := net.ParseIP(a); ip != nil && ip.To4() != nil {
				return a // prefer IPv4 for proxychains
			}
		}
		if len(addrs) > 0 {
			return addrs[0]
		}
	}
	return host
}

// TorsocksConf renders /etc/torsocks.conf for this State.
func (s *State) TorsocksConf() string {
	var b strings.Builder
	b.WriteString("# Managed by ARTEX Opsec. Do not edit by hand.\n")
	fmt.Fprintf(&b, "TorAddress %s\n", s.torHost)
	fmt.Fprintf(&b, "TorPort %s\n", strconv.Itoa(s.torPort))
	b.WriteString("OnionAddrRange 127.42.42.0/24\n")
	b.WriteString("AllowInbound 0\n")
	return b.String()
}

// ConfigPaths are the files WriteConfigs manages.
const (
	ProxychainsConfPath = "/etc/proxychains4.conf"
	TorsocksConfPath    = "/etc/torsocks.conf"
)

// WriteResult is the outcome of writing one managed config file.
type WriteResult struct {
	Path    string `json:"path"`
	Written bool   `json:"written"`
	Err     string `json:"error,omitempty"`
}

// WriteConfigs writes the proxychains4 and torsocks configs for this State. It
// is best effort: on a non-Linux host or without write permission it records
// the error per file and does not fail the toggle (the dialer-level enforcement
// does not depend on these files). It never writes when Opsec is disabled.
func (s *State) WriteConfigs() []WriteResult {
	out := []WriteResult{
		writeFileResult(ProxychainsConfPath, s.ProxychainsConf()),
		writeFileResult(TorsocksConfPath, s.TorsocksConf()),
	}
	return out
}

func writeFileResult(path, content string) WriteResult {
	r := WriteResult{Path: path}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		r.Err = err.Error()
		return r
	}
	r.Written = true
	return r
}
