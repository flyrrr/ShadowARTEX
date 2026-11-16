package opsec

import (
	"strings"
	"testing"
)

func TestBypassMatcher(t *testing.T) {
	s := New(Config{Enabled: true, Bypass: []string{
		"http://my-ollama.local:11434",
		"192.168.50.0/24",
		".corp.internal",
		"llama.lan:8000",
	}})
	direct := []string{
		"127.0.0.1", "127.0.0.1:8787", "localhost", "::1", "[::1]:5432",
		"10.1.2.3", "172.16.9.9", "192.168.1.1", "169.254.1.1",
		"host.docker.internal", "postgres:5432", "tor:9050",
		"my-ollama.local", "192.168.50.42", "api.corp.internal", "llama.lan",
	}
	for _, d := range direct {
		if !s.Bypass(d) {
			t.Errorf("Bypass(%q) = false, want true (should stay direct)", d)
		}
	}
	external := []string{
		"example.com", "scanme.example.com:443", "8.8.8.8", "203.0.113.5",
		"evil.corp.internal.attacker.com", "11.0.0.1",
	}
	for _, e := range external {
		if s.Bypass(e) {
			t.Errorf("Bypass(%q) = true, want false (should go via Tor)", e)
		}
	}
}

func TestTorURLsAndDefaults(t *testing.T) {
	s := New(Config{TorHost: "127.0.0.1", TorPort: 9050})
	if got, want := s.TorProxyURL(), "socks5://127.0.0.1:9050"; got != want {
		t.Errorf("TorProxyURL = %q, want %q", got, want)
	}
	if got, want := s.TorProxyURLRemoteDNS(), "socks5h://127.0.0.1:9050"; got != want {
		t.Errorf("TorProxyURLRemoteDNS = %q, want %q", got, want)
	}

	s2 := New(Config{TorHost: "tor"})
	if s2.TorPort() != DefaultTorPort {
		t.Errorf("default port = %d, want %d", s2.TorPort(), DefaultTorPort)
	}
	if s2.TorAddr() != "tor:9050" {
		t.Errorf("TorAddr = %q, want tor:9050", s2.TorAddr())
	}
}

func TestDisabledIsNoop(t *testing.T) {
	if New(Config{}).Enabled() {
		t.Fatal("zero Config must be disabled")
	}
}

func TestNoProxyListHasInfra(t *testing.T) {
	s := New(Config{Enabled: true, Bypass: []string{"192.168.5.5"}})
	np := s.NoProxyList()
	for _, want := range []string{"localhost", "127.0.0.1", "192.168.0.0/16", "192.168.5.5"} {
		if !strings.Contains(np, want) {
			t.Errorf("NoProxyList = %q, missing %q", np, want)
		}
	}
}

func TestProxychainsConf(t *testing.T) {

	s := New(Config{TorHost: "127.0.0.1", TorPort: 9050})
	conf := s.ProxychainsConf()
	for _, want := range []string{"strict_chain", "proxy_dns", "socks5 127.0.0.1 9050"} {
		if !strings.Contains(conf, want) {
			t.Errorf("ProxychainsConf missing %q:\n%s", want, conf)
		}
	}
}

func TestClearnetBlockDecision(t *testing.T) {
	on := New(Config{Enabled: true})
	if r := on.TestClearnetBlock("example.com:443"); !r.Blocked {
		t.Errorf("external target should be blocked when Opsec on: %+v", r)
	}
	if r := on.TestClearnetBlock("127.0.0.1:5432"); r.Blocked {
		t.Errorf("loopback should not be blocked: %+v", r)
	}
	off := New(Config{Enabled: false})
	if r := off.TestClearnetBlock("example.com:443"); r.Blocked {
		t.Errorf("Opsec off must never block: %+v", r)
	}
}
