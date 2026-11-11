package server

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// fakeSingBox 造一个 argv 形如 "sing-box run -c <cfg>" 的常驻进程：
//   - argv[0] 指向一个名为 sing-box 的假可执行文件（实际是 /bin/sh）
//   - argv[1] == "-c"，argv[2] == cfg，cfg 本身是一段可执行的 shell 脚本
//
// 这样既复刻了真实 sing-box 的 argv 形状（匹配逻辑只看这个），
// 又不依赖机器上是否装了 sing-box。
func fakeSingBox(t *testing.T, cfg string) *exec.Cmd {
	t.Helper()
	dir := filepath.Dir(cfg)
	shim := filepath.Join(dir, "sing-box")
	// 注意不能用 exec：exec 会连 argv[0] 一起换成 /bin/sh，外层就不再像 sing-box 了。
	if err := os.WriteFile(shim, []byte("#!/bin/sh\n/bin/sh \"$@\"\n"), 0o755); err != nil {
		t.Skipf("无法写假可执行文件: %v", err)
	}
	if err := os.WriteFile(cfg, []byte("sleep 30\n"), 0o755); err != nil {
		t.Skipf("无法写假配置: %v", err)
	}
	cmd := exec.Command(shim, "-c", cfg)
	if err := cmd.Start(); err != nil {
		t.Skipf("无法启动假进程: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })
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

// fakeMentionOnly 造一个「只是命令行里提到配置路径」的普通进程。
// 早先的匹配逻辑按子串找，会把这种进程一起 SIGKILL 掉（连运维的 ssh 命令都被误杀）。
func fakeMentionOnly(t *testing.T, cfg string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command("/bin/sh", "-c", "sleep 30 "+cfg)
	if err := cmd.Start(); err != nil {
		t.Skipf("无法启动假进程: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	time.Sleep(150 * time.Millisecond)
	return cmd
}

func alive(t *testing.T, pid int) bool {
	t.Helper()
	_, err := os.Stat(filepath.Join("/proc", strconv.Itoa(pid)))
	return err == nil
}

// killSingBoxByConfig 只能杀「用该配置启动的 sing-box」；
// 别的配置、仅仅提到该路径的进程，都得放过。
func TestKillSingBoxByConfig(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "sing-box.json")
	other := filepath.Join(dir, "sb_7891.json")

	// 1) 没有匹配 → 0 个
	if n := killSingBoxByConfig(target); n != 0 {
		t.Fatalf("空场景应杀 0 个，实际杀了 %d 个", n)
	}

	// 2) 只提到路径的普通进程：绝不能被杀
	mention := fakeMentionOnly(t, target)
	if n := killSingBoxByConfig(target); n != 0 {
		t.Fatalf("不应杀到只是提到路径的进程，实际杀了 %d 个", n)
	}
	if !alive(t, mention.Process.Pid) {
		t.Fatal("只是提到配置路径的进程被误杀了")
	}

	// 3) 目标配置的 sing-box：应被杀掉
	victim := fakeSingBox(t, target)
	if n := killSingBoxByConfig(target); n != 1 {
		t.Fatalf("应杀掉 1 个，实际 %d 个", n)
	}
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

	// 4) 别的配置的 sing-box：不能被误杀
	bystander := fakeSingBox(t, other)
	if n := killSingBoxByConfig(target); n != 0 {
		t.Fatalf("不应杀到别的配置的进程，实际杀了 %d 个", n)
	}
	if !alive(t, bystander.Process.Pid) {
		t.Fatal("别的配置的 sing-box 被误杀了")
	}
}
