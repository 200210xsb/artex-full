package server

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// fakeSingBox 假扮一个 sing-box 进程：Go 允许改 cmd.Args[0]，
// 于是 /proc/<pid>/cmdline 里就是 "sing-box run -c <cfg> 30"。
func fakeSingBox(t *testing.T, cfg string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command("sleep", "30")
	cmd.Args[0] = "sing-box run -c " + cfg
	if err := cmd.Start(); err != nil {
		t.Skipf("无法启动假进程: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	// cmdline 落盘前有一小段窗口，轮询等它就位。
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(cmd.Process.Pid), "cmdline")); err == nil && len(b) > 0 {
			return cmd
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("假进程的 cmdline 一直没有就绪")
	return nil
}

// killSingBoxByConfig 只能杀命令行里引用该配置的 sing-box；
// 别的配置、以及不是 sing-box 的进程都得放过。
func TestKillSingBoxByConfig(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "sing-box.json")
	other := filepath.Join(dir, "sb_7891.json")

	// 1) 没有匹配 → 0 个
	if n := killSingBoxByConfig(target); n != 0 {
		t.Fatalf("空场景应杀 0 个，实际杀了 %d 个", n)
	}

	// 2) 目标配置的进程：应被杀掉
	victim := fakeSingBox(t, target)
	n := killSingBoxByConfig(target)
	if n != 1 {
		t.Fatalf("应杀掉 1 个，实际 %d 个", n)
	}
	// 被 SIGKILL 的进程由父进程回收后，Wait 返回 signal: killed。
	waitErr := make(chan error, 1)
	go func() { waitErr <- victim.Wait() }()
	select {
	case err := <-waitErr:
		if err == nil {
			t.Fatal("目标进程是正常退出的，不是被杀掉的")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("目标进程没被杀掉")
	}

	// 3) 别的配置的 sing-box：不能被误杀
	bystander := fakeSingBox(t, other)
	if n := killSingBoxByConfig(target); n != 0 {
		t.Fatalf("不应杀到别的配置的进程，实际杀了 %d 个", n)
	}
	if _, err := os.Stat(filepath.Join("/proc", strconv.Itoa(bystander.Process.Pid))); err != nil {
		t.Fatal("别的配置的 sing-box 被误杀了")
	}
}
