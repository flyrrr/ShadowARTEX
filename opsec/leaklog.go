package opsec

import (
	"sync"
	"time"
)

// Leak is one recorded opsec event: a blocked clearnet attempt, a Tor failure
// that blocked a call, a blocked un-proxyable scan mode, or a DNS-leak risk.
// It carries no secret, only the shape of the attempt.
type Leak struct {
	TS     time.Time `json:"ts"`
	Worker string    `json:"worker"` // agent / worker identity, best effort
	Tool   string    `json:"tool"`   // Bash, WebFetch, http, enrich, dial, test, …
	Target string    `json:"target"` // host / address / URL involved
	Reason string    `json:"reason"` // why it was blocked / flagged
}

// leakRingCap bounds the in-memory ring kept as a fallback for when no DB sink
// is wired (startup, tests). The durable record is the DB sink.
const leakRingCap = 500

var (
	leakMu   sync.Mutex
	leakRing []Leak
	leakSink func(Leak)
)

// SetLeakSink installs the durable sink (the server persists to Postgres). It
// may be nil to clear. Called once at startup.
func SetLeakSink(fn func(Leak)) {
	leakMu.Lock()
	leakSink = fn
	leakMu.Unlock()
}

// LogLeak records one event: it appends to the in-memory ring and, if a sink is
// installed, hands it a copy. The sink runs under the lock, so it must be quick
// (the server's sink does a single INSERT).
func LogLeak(l Leak) {
	if l.TS.IsZero() {
		l.TS = time.Now()
	}
	leakMu.Lock()
	defer leakMu.Unlock()
	leakRing = append(leakRing, l)
	if len(leakRing) > leakRingCap {
		leakRing = leakRing[len(leakRing)-leakRingCap:]
	}
	if leakSink != nil {
		leakSink(l)
	}
}

// Leaks returns the most recent in-memory events, newest first, up to limit
// (<=0 means all kept). It is the fallback view; the Opsec page reads the DB.
func Leaks(limit int) []Leak {
	leakMu.Lock()
	defer leakMu.Unlock()
	n := len(leakRing)
	if limit > 0 && limit < n {
		n = limit
	}
	out := make([]Leak, 0, n)
	for i := len(leakRing) - 1; i >= 0 && len(out) < n; i-- {
		out = append(out, leakRing[i])
	}
	return out
}
