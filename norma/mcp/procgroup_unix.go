//go:build !windows

package mcp

import (
	"os/exec"
	"syscall"
)

// prepareProcessGroup puts the MCP server in its own process group so the whole
// tree can be signalled at once. Without it, killing "npx" leaves the node/npm
// children it forked running: they get reparented to init but stay in ARTEX's
// cgroup, piling up until the service is starved of memory. That leak is what
// took the backend down.
func prepareProcessGroup(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
}

// killProcessGroup SIGKILLs the server and everything it spawned.
func killProcessGroup(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	pid := cmd.Process.Pid
	// Negative pid addresses the whole group; the leader's own pgid is its pid
	// because Setpgid was set above.
	if err := syscall.Kill(-pid, syscall.SIGKILL); err != nil {
		// Group already gone (or never created): fall back to the single process.
		_ = cmd.Process.Kill()
	}
}
