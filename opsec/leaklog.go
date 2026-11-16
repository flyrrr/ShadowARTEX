package opsec

import (
	"sync"
	"time"
)

type Leak struct {
	TS     time.Time `json:"ts"`
	Worker string    `json:"worker"`
	Tool   string    `json:"tool"`
	Target string    `json:"target"`
	Reason string    `json:"reason"`
}

const leakRingCap = 500

var (
	leakMu   sync.Mutex
	leakRing []Leak
	leakSink func(Leak)
)

func SetLeakSink(fn func(Leak)) {
	leakMu.Lock()
	leakSink = fn
	leakMu.Unlock()
}

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
