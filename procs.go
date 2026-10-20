package main

import (
	"os/exec"
	"strings"
)

// procPaths returns unique executable paths of running processes (macOS: ps).
func procPaths() []string {
	out, err := exec.Command("ps", "-axo", "comm=").Output()
	if err != nil {
		return nil
	}
	var paths []string
	for _, line := range strings.Split(string(out), "\n") {
		p := strings.TrimSpace(line)
		if strings.HasPrefix(p, "/") {
			paths = append(paths, p)
		}
	}
	return paths
}
