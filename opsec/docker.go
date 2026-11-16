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

// InDocker reports whether this process runs inside a container, used to choose
// the Tor host default (host.docker.internal vs 127.0.0.1). The result is
// detected once: /.dockerenv (Docker), or a container hint in /proc/1/cgroup or
// /proc/self/mountinfo (Docker, Podman, Kubernetes). It is cheap and safe to
// call off the hot path.
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
