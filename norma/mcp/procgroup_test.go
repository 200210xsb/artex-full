//go:build !windows

package mcp

import (
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

// 关掉一个 stdio MCP 服务器时必须连带它派生的子进程一起收掉。只杀直接子进程
// 的话，npx → npm → node 这条链上后面的进程会变成孤儿，继续留在 ARTEX 的
// cgroup 里吃内存——曾经因此攒到上百个进程，把后端拖到无法响应。
func TestKillProcessGroupReapsGrandchildren(t *testing.T) {
	// sh 起一个后台子进程再自己等着：杀掉进程组应让两者都消失。
	cmd := exec.Command("sh", "-c", "sleep 60 & sleep 60")
	prepareProcessGroup(cmd)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	pgid, err := syscall.Getpgid(cmd.Process.Pid)
	if err != nil {
		t.Fatalf("getpgid: %v", err)
	}
	if pgid != cmd.Process.Pid {
		t.Fatalf("process not in its own group: pgid=%d pid=%d", pgid, cmd.Process.Pid)
	}

	// 找到那个孙进程（sleep 60 的另一个实例）。
	deadline := time.Now().Add(3 * time.Second)
	var grandchild int
	for time.Now().Before(deadline) {
		if pids := groupMembers(t, pgid); len(pids) >= 2 {
			for _, p := range pids {
				if p != cmd.Process.Pid {
					grandchild = p
				}
			}
			if grandchild != 0 {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if grandchild == 0 {
		t.Skip("could not observe a grandchild in this environment")
	}

	killProcessGroup(cmd)
	_ = cmd.Wait()

	// 组内所有进程都该消失（给内核一点回收时间）。
	for i := 0; i < 40; i++ {
		alive := 0
		for _, p := range groupMembers(t, pgid) {
			if isAlive(p) {
				alive++
			}
		}
		if alive == 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("processes still alive in group %d after kill", pgid)
}

// groupMembers lists the pids currently in pgid.
func groupMembers(t *testing.T, pgid int) []int {
	t.Helper()
	entries, err := os.ReadDir("/proc")
	if err != nil {
		t.Skipf("no /proc: %v", err)
	}
	var out []int
	for _, e := range entries {
		pid := 0
		for _, c := range e.Name() {
			if c < '0' || c > '9' {
				pid = 0
				break
			}
			pid = pid*10 + int(c-'0')
		}
		if pid == 0 {
			continue
		}
		if g, err := syscall.Getpgid(pid); err == nil && g == pgid {
			out = append(out, pid)
		}
	}
	return out
}

func isAlive(pid int) bool {
	// 僵尸进程算已退出：它不再占内存，等父进程回收即可。
	data, err := os.ReadFile("/proc/" + itoa(pid) + "/stat")
	if err != nil {
		return false
	}
	for i := len(data) - 1; i >= 0; i-- {
		if data[i] == ')' && i+2 < len(data) {
			return data[i+2] != 'Z'
		}
	}
	return true
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
