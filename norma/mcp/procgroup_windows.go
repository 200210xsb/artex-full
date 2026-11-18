//go:build windows

package mcp

import "os/exec"

// prepareProcessGroup is a no-op on Windows: there are no POSIX process groups.
// Killing the direct child is the best stdlib-only option here; the platform's
// job objects would be needed to reap grandchildren.
func prepareProcessGroup(cmd *exec.Cmd) {}

// killProcessGroup terminates the server process.
func killProcessGroup(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
}
