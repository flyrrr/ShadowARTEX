package agent

import "github.com/Autumn-27/artex/opsec"

// opsecPromptHeader starts the code-owned opsec block, appended to every agent
// prompt that can launch Bash. It is empty when Opsec is off, so prompts stay
// byte-for-byte unchanged by default. The block only instructs; the actual
// enforcement is in code (the dialer, the Bash env, and the guard argv block)
// and does not depend on the model obeying this text.
const opsecPromptHeader = "[Opsec: anonymous egress ENFORCED."

// opsecPromptBlock returns the operator-facing opsec guidance when Opsec is on,
// or "" when off. Read at each prompt build, so a toggle shows in the next prompt.
func opsecPromptBlock() string {
	if !opsec.Enabled() {
		return ""
	}
	return opsecPromptHeader + " Operator control, not a target fact.]\n" +
		"All external traffic is forced through Tor; there is no clearnet fallback and direct connections to external hosts are blocked in code.\n" +
		"- For network tools in Bash, go through Tor: prefix with `proxychains4 -q` (e.g. `proxychains4 -q curl ...`, `proxychains4 -q nmap -sT -Pn ...`). HTTP_PROXY/HTTPS_PROXY/ALL_PROXY already point at Tor, so curl/wget/python are covered without a flag.\n" +
		"- Only a TCP connect scan is possible: use `nmap -sT -Pn`. Raw-packet scans (-sS/-sU/-sO), OS detection (-O), ICMP/host discovery (-sn, -PE/-PP/-PM, --traceroute) and ICMP/raw-socket tools (ping, traceroute, hping3, masscan, zmap) CANNOT be carried through Tor and are blocked by the platform — do not attempt them.\n" +
		"- Loopback, LAN/RFC1918, the local LLM, Postgres, the ARTEX UI and the recording proxy stay direct (bypass allowlist); everything else exits via Tor.\n" +
		"- Do not try to defeat this (no raw sockets, no setting a different proxy, no direct IP connections to external hosts): such attempts fail closed and are logged.\n"
}
