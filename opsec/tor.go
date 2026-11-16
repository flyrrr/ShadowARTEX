package opsec

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

// TorCheckURL is the service queried through Tor to learn the exit IP and
// whether the traffic really left via the Tor network.
const TorCheckURL = "https://check.torproject.org/api/ip"

// TorStatus is the result of a Tor reachability + exit check.
type TorStatus struct {
	Reachable bool      `json:"reachable"`         // the SOCKS5 port accepted a connection and the probe completed
	IsTor     bool      `json:"is_tor"`            // check.torproject.org confirmed a Tor exit
	ExitIP    string    `json:"exit_ip,omitempty"` // the exit IP as seen by the check service
	Addr      string    `json:"addr"`              // the SOCKS5 host:port probed
	InDocker  bool      `json:"in_docker"`         // whether ARTEX runs in a container
	CheckedAt time.Time `json:"checked_at"`        // when the probe ran
	Err       string    `json:"error,omitempty"`   // failure detail when not reachable
}

// socksDialer returns a context dialer for this State's Tor SOCKS5 endpoint.
// Names are resolved by the proxy (remote DNS), so a target name never resolves
// on the host.
func (s *State) socksDialer() (proxy.ContextDialer, error) {
	d, err := proxy.SOCKS5("tcp", s.TorAddr(), nil, &net.Dialer{Timeout: 15 * time.Second})
	if err != nil {
		return nil, err
	}
	cd, ok := d.(proxy.ContextDialer)
	if !ok {
		return nil, errors.New("socks5 dialer is not context-aware")
	}
	return cd, nil
}

// torHTTPClient is an HTTP client whose every connection goes through Tor.
func (s *State) torHTTPClient(timeout time.Duration) (*http.Client, error) {
	cd, err := s.socksDialer()
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{
		DialContext:           cd.DialContext,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		DisableKeepAlives:     true,
		Proxy:                 nil, // never read HTTP_PROXY etc.: Tor is the only path
	}
	return &http.Client{Transport: tr, Timeout: timeout}, nil
}

// TestTor probes the Tor SOCKS5 endpoint and checks the exit via TorCheckURL.
// It never falls back to a direct connection: a failure means Tor is the only
// path and it is down.
func (s *State) TestTor(ctx context.Context) TorStatus {
	st := TorStatus{Addr: s.TorAddr(), InDocker: s.inDocker, CheckedAt: time.Now()}
	client, err := s.torHTTPClient(20 * time.Second)
	if err != nil {
		st.Err = "tor socks5 dialer: " + err.Error()
		return st
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, TorCheckURL, nil)
	if err != nil {
		st.Err = err.Error()
		return st
	}
	req.Header.Set("User-Agent", "curl/8.0")
	resp, err := client.Do(req)
	if err != nil {
		st.Err = "tor unreachable at " + s.TorAddr() + ": " + err.Error()
		return st
	}
	defer resp.Body.Close()
	st.Reachable = true
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	var parsed struct {
		IsTor bool   `json:"IsTor"`
		IP    string `json:"IP"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		st.Err = "unexpected response from " + TorCheckURL + ": " + strings.TrimSpace(string(body))
		return st
	}
	st.IsTor, st.ExitIP = parsed.IsTor, parsed.IP
	if !st.IsTor {
		st.Err = "connection succeeded but the exit is not a Tor node — check the SOCKS5 endpoint"
	}
	return st
}

// DNSLeakResult reports whether target names are resolved remotely by Tor
// rather than on the host.
type DNSLeakResult struct {
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
	ExitIP string `json:"exit_ip,omitempty"`
}

// TestDNSLeak connects to the check host through Tor using the proxy's own
// (remote) name resolution. A success with a Tor exit proves the name was
// resolved by Tor, not by the host resolver, so there is no DNS leak for
// external targets.
func (s *State) TestDNSLeak(ctx context.Context) DNSLeakResult {
	cd, err := s.socksDialer()
	if err != nil {
		return DNSLeakResult{Detail: "tor socks5 dialer: " + err.Error()}
	}
	// Dial by NAME (not a pre-resolved IP): x/net SOCKS5 sends the name to Tor,
	// which resolves it at the exit. If this works, host DNS was not used.
	dialCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	conn, err := cd.DialContext(dialCtx, "tcp", "check.torproject.org:443")
	if err != nil {
		return DNSLeakResult{Detail: "remote resolution/connect via Tor failed: " + err.Error()}
	}
	_ = conn.Close()
	st := s.TestTor(ctx)
	if !st.IsTor {
		return DNSLeakResult{Detail: "name resolved remotely but exit is not Tor: " + st.Err}
	}
	return DNSLeakResult{OK: true, ExitIP: st.ExitIP,
		Detail: "target names are resolved remotely by Tor (socks5h); no clearnet DNS for external targets. Exit IP " + st.ExitIP + "."}
}

// ClearnetBlockResult reports whether a direct (non-Tor) connection to an
// external target is blocked by policy.
type ClearnetBlockResult struct {
	Blocked bool   `json:"blocked"`
	Target  string `json:"target"`
	Reason  string `json:"reason"`
}

// TestClearnetBlock reports the enforcement decision for a direct connection to
// target when Opsec is on: an external target is blocked (fail closed), a
// bypass-listed one is allowed direct. It changes nothing; it reflects exactly
// what the dialer and the Bash env enforce.
func (s *State) TestClearnetBlock(target string) ClearnetBlockResult {
	if strings.TrimSpace(target) == "" {
		target = "example.com:443"
	}
	host := target
	if h, _, err := net.SplitHostPort(target); err == nil {
		host = h
	}
	res := ClearnetBlockResult{Target: target}
	switch {
	case !s.cfg.Enabled:
		res.Reason = "Opsec is off: direct egress is allowed. Enable Opsec to force external traffic through Tor."
	case s.Bypass(host):
		res.Blocked = false
		res.Reason = host + " is on the bypass allowlist (loopback/LAN/infra), so it is reached directly, never through Tor."
	default:
		res.Blocked = true
		res.Reason = "Opsec is on: a direct connection to external target " + host +
			" is blocked. All external egress must go through Tor; there is no clearnet fallback."
	}
	return res
}

// NewNym asks Tor to build fresh circuits (SIGNAL NEWNYM) over the control
// port. password is the control-port password (empty for an open/NULL control
// port). It is best effort: a clear error is returned when the control port is
// unreachable or auth fails.
func (s *State) NewNym(ctx context.Context, password string) error {
	d := net.Dialer{Timeout: 10 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", s.TorControlAddr())
	if err != nil {
		return fmt.Errorf("tor control port %s unreachable: %w (enable ControlPort in torrc)", s.TorControlAddr(), err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(conn)

	auth := "AUTHENTICATE\r\n"
	if password != "" {
		auth = fmt.Sprintf("AUTHENTICATE \"%s\"\r\n", strings.ReplaceAll(password, `"`, `\"`))
	}
	if err := ctrlCmd(conn, br, auth); err != nil {
		return fmt.Errorf("tor control authenticate: %w", err)
	}
	if err := ctrlCmd(conn, br, "SIGNAL NEWNYM\r\n"); err != nil {
		return fmt.Errorf("tor NEWNYM: %w", err)
	}
	return nil
}

// ctrlCmd writes one control-port command and checks for a 250 reply.
func ctrlCmd(w io.Writer, br *bufio.Reader, cmd string) error {
	if _, err := io.WriteString(w, cmd); err != nil {
		return err
	}
	line, err := br.ReadString('\n')
	if err != nil {
		return err
	}
	if !strings.HasPrefix(strings.TrimSpace(line), "250") {
		return errors.New(strings.TrimSpace(line))
	}
	return nil
}
