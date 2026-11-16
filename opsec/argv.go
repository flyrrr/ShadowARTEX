package opsec

import (
	"path"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// ClassifyBash inspects a Bash command line and reports whether, under Opsec,
// it must be blocked because it uses an egress mode that cannot be carried by a
// SOCKS5 proxy / Tor and would therefore leak the real source or exit directly:
//
//   - raw-packet nmap scans (-sS/-sU/-sO SYN/UDP/IP, FIN/NULL/Xmas/ACK/Window/
//     Maimon), OS detection (-O), and ICMP/ARP host discovery (-sn, -PE/-PP/-PM,
//     --traceroute). Only a TCP connect scan with -Pn (nmap -sT -Pn) is allowed,
//     since proxychains can carry its connect() calls.
//   - ICMP / raw-socket tools: ping, traceroute, mtr, hping3, fping, arping,
//     masscan, zmap — none of which use connect() and so bypass LD_PRELOAD and
//     the SOCKS proxy entirely.
//
// It walks every simple command in the line (across pipes, lists and
// substitutions), so a dangerous program hidden in a pipeline is still caught.
// reason is empty when nothing is blocked. ClassifyBash never inspects targets;
// it classifies the command shape only.
func ClassifyBash(command string) (blocked bool, reason string) {
	f, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(command), "")
	if err != nil {
		// Unparseable here is not a block: the real Bash gate and the guard
		// evaluate the command; opsec only adds the egress-mode check.
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

// litWord extracts the literal text of a word, best effort: an expansion or
// substitution contributes nothing, which is fine for matching program names
// and flags.
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

// icmpRawTools are programs that use ICMP or raw sockets and cannot be proxied
// through SOCKS5 / Tor at all.
var icmpRawTools = map[string]bool{
	"ping": true, "ping6": true, "traceroute": true, "traceroute6": true,
	"tracepath": true, "mtr": true, "hping3": true, "fping": true, "fping6": true,
	"arping": true, "masscan": true, "zmap": true,
}

// argvWrappers run another program given as their arguments; the real program
// follows the wrapper and its own flags. Opsec unwraps them so a raw scan
// hidden behind proxychains/sudo is still classified.
var argvWrappers = map[string]bool{
	"proxychains": true, "proxychains4": true, "torsocks": true,
	"sudo": true, "env": true, "nice": true, "ionice": true,
	"stdbuf": true, "setsid": true, "nohup": true, "command": true,
}

// unwrap advances past leading wrapper programs and their flags, returning the
// argv of the real program.
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

// classifyArgv classifies one simple command's argv.
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

// forbiddenNmapScan lists the scan-type flags that send raw packets and bypass
// any SOCKS proxy. -O is OS detection; -sn is ping/host discovery.
var forbiddenNmapScan = map[string]string{
	"-sS": "SYN scan", "-sU": "UDP scan", "-sO": "IP-protocol scan",
	"-sN": "NULL scan", "-sF": "FIN scan", "-sX": "Xmas scan",
	"-sA": "ACK scan", "-sW": "Window scan", "-sM": "Maimon scan",
	"-sY": "SCTP INIT scan", "-sZ": "SCTP COOKIE-ECHO scan",
	"-O": "OS detection", "-sn": "ping/host-discovery scan",
}

// classifyNmap allows only a TCP connect scan with -Pn (nmap -sT -Pn), which
// proxychains can carry; every other scan mode sends raw packets and is blocked.
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
			// -PE/-PP/-PM and -PR are ICMP/ARP host discovery.
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
