//go:build windows

package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

func alive(pid int) bool {
	out, _ := exec.Command(filepath.Join(os.Getenv("SystemRoot"), "System32", "tasklist.exe"), "/FI", "PID eq "+strconv.Itoa(pid), "/NH").Output()
	return strings.Contains(string(out), " "+strconv.Itoa(pid)+" ")
}
