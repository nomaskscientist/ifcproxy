//go:build !windows

package main

import (
	"os"
	"os/exec"
	"syscall"
)

// setProcGroup starts the server in its own process group so that wrapper
// launchers (npx, uvx, sh -c) and their children can be signalled together.
func setProcGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// termTree asks the server's whole process group to stop.
func termTree(p *os.Process) error {
	return syscall.Kill(-p.Pid, syscall.SIGTERM)
}

// killTree kills the server's whole process group.
func killTree(p *os.Process) {
	_ = syscall.Kill(-p.Pid, syscall.SIGKILL)
	_ = p.Kill()
}
