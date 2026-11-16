package opsec

import "testing"

func TestClassifyBashBlocks(t *testing.T) {
	blocked := []string{
		"nmap -sS 10.0.0.1",
		"nmap -sU -p53 target",
		"nmap -O scanme.example.com",
		"nmap -sn 192.168.1.0/24",
		"nmap scanme.example.com",     // no -sT -Pn
		"nmap -sT scanme.example.com", // missing -Pn
		"ping -c1 example.com",
		"traceroute example.com",
		"hping3 -S -p80 target",
		"masscan -p80 10.0.0.0/8",
		"curl example.com | nmap -sS -iL -", // dangerous program in a pipe
		"nmap --traceroute -sT -Pn target",
		"sudo nmap -sS target",            // raw scan behind a wrapper
		"proxychains4 -q nmap -sU target", // udp scan behind proxychains
	}
	for _, cmd := range blocked {
		if b, reason := ClassifyBash(cmd); !b {
			t.Errorf("ClassifyBash(%q) = allowed, want blocked", cmd)
		} else if reason == "" {
			t.Errorf("ClassifyBash(%q) blocked but gave no reason", cmd)
		}
	}
}

func TestClassifyBashAllows(t *testing.T) {
	allowed := []string{
		"nmap -sT -Pn -p80,443 scanme.example.com",
		"proxychains4 -q nmap -sT -Pn target",
		"curl -s https://example.com",
		"httpx -l hosts.txt",
		"echo hello && ls -la",
		"ffuf -u https://x/FUZZ -w list.txt",
		"",
	}
	for _, cmd := range allowed {
		if b, reason := ClassifyBash(cmd); b {
			t.Errorf("ClassifyBash(%q) = blocked (%s), want allowed", cmd, reason)
		}
	}
}
