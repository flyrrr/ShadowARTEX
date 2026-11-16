package opsec

import (
	"path"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

func ClassifyBash(command string) (blocked bool, reason string) {
	f, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(command), "")
	if err != nil {

		return false, ""
	}
	syntax.Walk(f, func(n syntax.Node) bool {
		if blocked {
			return false
		}
		call, ok := n.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		args := make([]string, 0, len(call.Args))
		for _, w := range call.Args {
			args = append(args, litWord(w))
		}
		if b, why := classifyArgv(args); b {
			blocked, reason = true, why
			return false
		}
		return true
	})
	return blocked, reason
}

func litWord(w *syntax.Word) string {
	var sb strings.Builder
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			sb.WriteString(p.Value)
		case *syntax.SglQuoted:
			sb.WriteString(p.Value)
		case *syntax.DblQuoted:
			for _, q := range p.Parts {
				if lit, ok := q.(*syntax.Lit); ok {
					sb.WriteString(lit.Value)
				}
			}
		}
	}
	return sb.String()
}

var icmpRawTools = map[string]bool{
	"ping": true, "ping6": true, "traceroute": true, "traceroute6": true,
	"tracepath": true, "mtr": true, "hping3": true, "fping": true, "fping6": true,
	"arping": true, "masscan": true, "zmap": true,
}

var argvWrappers = map[string]bool{
	"proxychains": true, "proxychains4": true, "torsocks": true,
	"sudo": true, "env": true, "nice": true, "ionice": true,
	"stdbuf": true, "setsid": true, "nohup": true, "command": true,
}

func unwrap(args []string) []string {
	for len(args) > 0 && argvWrappers[path.Base(args[0])] {
		i := 1
		for i < len(args) && strings.HasPrefix(args[i], "-") {
			i++
		}
		if i >= len(args) {
			return nil
		}
		args = args[i:]
	}
	return args
}

func classifyArgv(args []string) (blocked bool, reason string) {
	args = unwrap(args)
	if len(args) == 0 {
		return false, ""
	}
	prog := path.Base(args[0])
	rest := args[1:]

	if icmpRawTools[prog] {
		return true, prog + " uses ICMP or raw sockets, which cannot be carried through Tor/SOCKS5. Opsec blocks it to prevent a direct leak. Use a TCP-based check (e.g. nmap -sT -Pn, or curl) through proxychains instead."
	}

	if prog == "nmap" {
		return classifyNmap(rest)
	}
	return false, ""
}

var forbiddenNmapScan = map[string]string{
	"-sS": "SYN scan", "-sU": "UDP scan", "-sO": "IP-protocol scan",
	"-sN": "NULL scan", "-sF": "FIN scan", "-sX": "Xmas scan",
	"-sA": "ACK scan", "-sW": "Window scan", "-sM": "Maimon scan",
	"-sY": "SCTP INIT scan", "-sZ": "SCTP COOKIE-ECHO scan",
	"-O": "OS detection", "-sn": "ping/host-discovery scan",
}

func classifyNmap(rest []string) (blocked bool, reason string) {
	hasConnect, hasPn := false, false
	for _, a := range rest {
		if why, bad := forbiddenNmapScan[a]; bad {
			return true, "nmap " + a + " (" + why + ") sends raw packets that bypass Tor/SOCKS5. Under Opsec only a TCP connect scan is allowed: run `proxychains4 -q nmap -sT -Pn ...`."
		}
		switch a {
		case "-sT":
			hasConnect = true
		case "-Pn":
			hasPn = true
		case "--traceroute":
			return true, "nmap --traceroute sends raw packets that bypass Tor/SOCKS5. Remove it under Opsec."
		default:

			if strings.HasPrefix(a, "-PE") || strings.HasPrefix(a, "-PP") ||
				strings.HasPrefix(a, "-PM") || a == "-PR" {
				return true, "nmap " + a + " is ICMP/ARP host discovery that bypasses Tor/SOCKS5. Use -Pn under Opsec."
			}
		}
	}
	if !hasConnect || !hasPn {
		return true, "under Opsec nmap must be a TCP connect scan with host discovery off, carried by proxychains: `proxychains4 -q nmap -sT -Pn ...`. Add -sT and -Pn (raw SYN/UDP scans and ping probes leak around Tor)."
	}
	return false, ""
}
