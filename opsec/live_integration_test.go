package opsec

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"
)

func TestLiveTor(t *testing.T) {
	if os.Getenv("ARTEX_OPSEC_LIVE") == "" {
		t.Skip("set ARTEX_OPSEC_LIVE=1 with a reachable Tor to run")
	}
	host := os.Getenv("ARTEX_OPSEC_TOR_HOST")
	if host == "" {
		host = "tor"
	}
	port, _ := strconv.Atoi(os.Getenv("ARTEX_OPSEC_TOR_PORT"))
	st := New(Config{Enabled: true, TorHost: host, TorPort: port})

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	tor := st.TestTor(ctx)
	t.Logf("TestTor: reachable=%v is_tor=%v exit_ip=%s addr=%s err=%s", tor.Reachable, tor.IsTor, tor.ExitIP, tor.Addr, tor.Err)
	if !tor.Reachable {
		t.Fatalf("Tor unreachable at %s: %s", tor.Addr, tor.Err)
	}
	if !tor.IsTor {
		t.Fatalf("exit is not Tor: %s", tor.Err)
	}
	if tor.ExitIP == "" {
		t.Fatal("no exit IP reported")
	}

	dns := st.TestDNSLeak(ctx)
	t.Logf("TestDNSLeak: ok=%v detail=%s", dns.OK, dns.Detail)
	if !dns.OK {
		t.Fatalf("DNS-leak check failed: %s", dns.Detail)
	}

	cb := st.TestClearnetBlock("example.com:443")
	t.Logf("TestClearnetBlock(external): blocked=%v reason=%s", cb.Blocked, cb.Reason)
	if !cb.Blocked {
		t.Fatal("external clearnet target must be blocked when Opsec is on")
	}
	if lb := st.TestClearnetBlock("127.0.0.1:5432"); lb.Blocked {
		t.Fatalf("loopback must stay direct, got blocked: %s", lb.Reason)
	}
}

func TestLiveTorDown(t *testing.T) {
	if os.Getenv("ARTEX_OPSEC_LIVE_DOWN") == "" {
		t.Skip("set ARTEX_OPSEC_LIVE_DOWN=1 with a dead Tor endpoint to run")
	}
	host := os.Getenv("ARTEX_OPSEC_TOR_HOST")
	port, _ := strconv.Atoi(os.Getenv("ARTEX_OPSEC_TOR_PORT"))
	st := New(Config{Enabled: true, TorHost: host, TorPort: port})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	tor := st.TestTor(ctx)
	t.Logf("TestTor (down): reachable=%v err=%s", tor.Reachable, tor.Err)
	if tor.IsTor {
		t.Fatal("expected Tor to be down, but IsTor=true")
	}
}
