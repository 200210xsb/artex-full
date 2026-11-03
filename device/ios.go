package device

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// IOS 通过 libimobiledevice 命令行工具访问 iOS 设备。
//
// 为什么是命令行而不是 Go 协议栈：usbmux/lockdown/AFC 协议栈在 Linux 上要自己实现
// 一整套（含配对、开发者镜像、AFC 权限），而 libimobiledevice-utils 是现成的稳定件，
// Docker 里 `apt install libimobiledevice-utils` 即可；ARTEX 只做编排与留痕。
//
// 能力边界（未越狱设备）：
//   - 设备枚举、机型/系统版本/电量等信息；
//   - 截屏、应用列表、安装/卸载 IPA（需开发者镜像或企业签）；
//   - syslog 采集；
//   - iproxy 端口转发（把手机的 22 端口映射到本机，即可走越狱 SSH 做 deeper 操作）。
type IOS struct {
	binDir string // libimobiledevice 工具所在目录（空 = 用 PATH）
}

// NewIOS 构造 iOS 客户端；binDir 为空表示从 PATH 查找工具。
func NewIOS(binDir string) *IOS { return &IOS{binDir: strings.TrimSpace(binDir)} }

func (i *IOS) tool(name string) string {
	if i.binDir == "" {
		return name
	}
	return filepath.Join(i.binDir, name)
}

// Available 报告 libimobiledevice 工具是否可用。
func (i *IOS) Available() bool {
	_, err := exec.LookPath(i.tool("idevice_id"))
	return err == nil
}

// Devices 枚举当前主机 usbmux 能看到的 iOS 设备。
func (i *IOS) Devices(ctx context.Context) ([]Device, error) {
	if !i.Available() {
		return nil, nil // 工具没装：不是错误，只是没有 iOS 直连能力
	}
	out, err := i.run(ctx, 20*time.Second, "idevice_id", "-l")
	if err != nil {
		return nil, err
	}
	devs := []Device{}
	for _, line := range strings.Split(out, "\n") {
		udid := strings.TrimSpace(line)
		if udid == "" {
			continue
		}
		devs = append(devs, Device{
			ID:        udid,
			Platform:  PlatformIOS,
			UDID:      udid,
			Serial:    udid,
			State:     "connected",
			Transport: "usbmux",
			OSVersion: i.quickInfo(ctx, udid, "ProductVersion"),
			Model:     i.quickInfo(ctx, udid, "ProductType"),
		})
	}
	return devs, nil
}

func (i *IOS) quickInfo(ctx context.Context, udid, key string) string {
	out, err := i.run(ctx, 15*time.Second, "ideviceinfo", "-u", udid, "-k", key)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// Info 返回设备信息字典。
func (i *IOS) Info(ctx context.Context, udid string) (map[string]any, error) {
	if !i.Available() {
		return nil, errors.New("未安装 libimobiledevice 工具（容器内：apt install libimobiledevice-utils）")
	}
	out, err := i.run(ctx, 30*time.Second, "ideviceinfo", "-u", udid)
	if err != nil {
		return nil, err
	}
	info := map[string]any{}
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		info[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return info, nil
}

// Screenshot 截屏并返回 PNG 字节。
func (i *IOS) Screenshot(ctx context.Context, udid string) ([]byte, error) {
	if !i.Available() {
		return nil, errors.New("未安装 libimobiledevice 工具")
	}
	tmp, err := os.CreateTemp("", "artex-ios-*.png")
	if err != nil {
		return nil, err
	}
	path := tmp.Name()
	_ = tmp.Close()
	defer os.Remove(path)
	if _, err := i.run(ctx, 40*time.Second, "idevicescreenshot", "-u", udid, path); err != nil {
		return nil, err
	}
	return os.ReadFile(path)
}

// Apps 列出设备上安装的应用（bundle id）。
func (i *IOS) Apps(ctx context.Context, udid string) ([]string, error) {
	if !i.Available() {
		return nil, errors.New("未安装 libimobiledevice 工具")
	}
	out, err := i.run(ctx, 40*time.Second, "ideviceinstaller", "-u", udid, "-l")
	if err != nil {
		return nil, err
	}
	apps := []string{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Listing") {
			continue
		}
		apps = append(apps, line)
	}
	return apps, nil
}

// Install 安装一个 IPA。
func (i *IOS) Install(ctx context.Context, udid, ipaPath string) (string, error) {
	if !i.Available() {
		return "", errors.New("未安装 libimobiledevice 工具")
	}
	out, err := i.run(ctx, 180*time.Second, "ideviceinstaller", "-u", udid, "-i", ipaPath)
	if err != nil {
		return out, err
	}
	return out, nil
}

// Uninstall 卸载应用。
func (i *IOS) Uninstall(ctx context.Context, udid, bundleID string) (string, error) {
	if !i.Available() {
		return "", errors.New("未安装 libimobiledevice 工具")
	}
	return i.run(ctx, 60*time.Second, "ideviceinstaller", "-u", udid, "-U", bundleID)
}

// Syslog 采集一段系统日志（按行数截断）。
func (i *IOS) Syslog(ctx context.Context, udid, filter string, lines int) (string, error) {
	if !i.Available() {
		return "", errors.New("未安装 libimobiledevice 工具")
	}
	if lines <= 0 {
		lines = 200
	}
	args := []string{"-u", udid}
	if strings.TrimSpace(filter) != "" {
		args = append(args, "-m", filter)
	}
	// 用 timeout 限制采集窗口，再按行数裁剪。
	cmd := exec.CommandContext(ctx, i.tool("timeout"), append([]string{"15", i.tool("idevicesyslog")}, args...)...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	_ = cmd.Run()
	all := strings.Split(buf.String(), "\n")
	if len(all) > lines {
		all = all[len(all)-lines:]
	}
	return strings.Join(all, "\n"), nil
}

// Shell 在 iOS 上执行命令：需要越狱设备，并通过 iproxy + ssh 走。
// keyPath/passphrase 可为空（默认用当前用户的 ssh key）。
func (i *IOS) Shell(ctx context.Context, udid, cmd, user, keyPath string) (string, error) {
	if user == "" {
		user = "root"
	}
	port, err := i.freePort(ctx, udid)
	if err != nil {
		return "", err
	}
	sshArgs := []string{"-p", strconv.Itoa(port), "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null"}
	if keyPath != "" {
		sshArgs = append(sshArgs, "-i", keyPath)
	}
	sshArgs = append(sshArgs, fmt.Sprintf("%s@127.0.0.1", user), cmd)
	return i.run(ctx, 60*time.Second, "ssh", sshArgs...)
}

// netListenAny 监听一个随机端口（用于 iproxy 端口分配）。
func netListenAny() (net.Listener, error) {
	return net.Listen("tcp", "127.0.0.1:0")
}

// freePort 起一个 iproxy（手机端口 → 本机端口），返回本机端口；调用方需自行结束进程。
func (i *IOS) freePort(ctx context.Context, udid string) (int, error) {
	// 找一个空闲的本机端口
	l, err := netListenAny()
	if err != nil {
		return 0, err
	}
	port := 0
	if addr, ok := l.Addr().(*net.TCPAddr); ok {
		port = addr.Port
	}
	_ = l.Close()
	if port == 0 {
		return 0, errors.New("无法分配本机端口")
	}
	proc := exec.Command(i.tool("iproxy"), strconv.Itoa(port), "22", "-u", udid)
	if err := proc.Start(); err != nil {
		return 0, fmt.Errorf("启动 iproxy 失败: %w", err)
	}
	// 交给调用方生命周期管理：这里只保证进程已在跑，退出由 run 结束后自杀。
	go func() {
		<-ctx.Done()
		_ = proc.Process.Kill()
	}()
	time.Sleep(700 * time.Millisecond)
	return port, nil
}

// run 执行一个 libimobiledevice 工具并返回合并输出。
func (i *IOS) run(ctx context.Context, timeout time.Duration, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, i.tool(name), args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	out := buf.String()
	if err != nil {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		return out, fmt.Errorf("%s 执行失败: %w: %s", name, err, strings.TrimSpace(out))
	}
	return out, nil
}
