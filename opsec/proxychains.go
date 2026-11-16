package opsec

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

type Tooling struct {
	Proxychains     bool   `json:"proxychains"`
	ProxychainsPath string `json:"proxychains_path,omitempty"`
	Torsocks        bool   `json:"torsocks"`
	TorsocksPath    string `json:"torsocks_path,omitempty"`
	Tor             bool   `json:"tor"`
	TorPath         string `json:"tor_path,omitempty"`
}

var proxychainsBinaries = []string{"proxychains4", "proxychains"}

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

func ProxychainsBin() string {
	for _, b := range proxychainsBinaries {
		if p, err := exec.LookPath(b); err == nil {
			return p
		}
	}
	return ""
}

func (s *State) ProxychainsConf() string {
	var b strings.Builder
	b.WriteString("# Managed by ShadowARTEX Opsec. Do not edit by hand.\n")
	b.WriteString("strict_chain\n")
	b.WriteString("proxy_dns\n")
	b.WriteString("remote_dns_subnet 224\n")
	b.WriteString("tcp_read_time_out 15000\n")
	b.WriteString("tcp_connect_time_out 10000\n")
	b.WriteString("quiet_mode\n")
	b.WriteString("[ProxyList]\n")

	fmt.Fprintf(&b, "socks5 %s %d\n", resolveHostIP(s.torHost), s.torPort)
	return b.String()
}

func resolveHostIP(host string) string {
	if net.ParseIP(host) != nil {
		return host
	}
	if addrs, err := net.LookupHost(host); err == nil {
		for _, a := range addrs {
			if ip := net.ParseIP(a); ip != nil && ip.To4() != nil {
				return a
			}
		}
		if len(addrs) > 0 {
			return addrs[0]
		}
	}
	return host
}

func (s *State) TorsocksConf() string {
	var b strings.Builder
	b.WriteString("# Managed by ShadowARTEX Opsec. Do not edit by hand.\n")
	fmt.Fprintf(&b, "TorAddress %s\n", s.torHost)
	fmt.Fprintf(&b, "TorPort %s\n", strconv.Itoa(s.torPort))
	b.WriteString("OnionAddrRange 127.42.42.0/24\n")
	b.WriteString("AllowInbound 0\n")
	return b.String()
}

const (
	ProxychainsConfPath = "/etc/proxychains4.conf"
	TorsocksConfPath    = "/etc/torsocks.conf"
)

type WriteResult struct {
	Path    string `json:"path"`
	Written bool   `json:"written"`
	Err     string `json:"error,omitempty"`
}

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
