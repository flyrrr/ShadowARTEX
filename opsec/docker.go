package opsec

import (
	"os"
	"strings"
	"sync"
)

var (
	dockerOnce sync.Once
	dockerIn   bool
)

func InDocker() bool {
	dockerOnce.Do(func() {
		if _, err := os.Stat("/.dockerenv"); err == nil {
			dockerIn = true
			return
		}
		for _, p := range []string{"/proc/1/cgroup", "/proc/self/mountinfo"} {
			if b, err := os.ReadFile(p); err == nil {
				s := string(b)
				if strings.Contains(s, "docker") || strings.Contains(s, "containerd") ||
					strings.Contains(s, "kubepods") || strings.Contains(s, "/lxc/") {
					dockerIn = true
					return
				}
			}
		}
	})
	return dockerIn
}
