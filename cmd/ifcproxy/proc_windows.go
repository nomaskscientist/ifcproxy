//go:build windows

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
)

func setProcGroup(*exec.Cmd) {}

// termTree: Windows has no SIGTERM for console processes; callers fall back
// to killTree.
func termTree(*os.Process) error {
	return errors.New("graceful termination is not supported on Windows")
}

// killTree kills the server and its descendants (wrapper launchers such as
// npx.cmd start the real server as a child). taskkill must run before the
// parent dies, since /T walks the tree from the parent's PID.
func killTree(p *os.Process) {
	taskkill := filepath.Join(os.Getenv("SystemRoot"), "System32", "taskkill.exe")
	_ = exec.Command(taskkill, "/T", "/F", "/PID", strconv.Itoa(p.Pid)).Run()
	_ = p.Kill()
}
