package device

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// ADB 是一个纯 Go 的 ADB 客户端：直接讲 adb server 协议（TCP），不依赖 adb 可执行文件。
//
// 为什么不用 adb 命令行：
//   - 容器里不用再装 android-tools，ARTEX 单二进制 + 一个 adb server 就能跑；
//   - 每一步都能拿到原始退出码与原始字节（screencap / pull 都是二进制流）。
//
// 连接的 adb server 地址来自 ARTEX_ADB_SERVER（默认 127.0.0.1:5037）。典型部署是：
//   - 宿主机跑 `adb -a nodaemon server`（监听 0.0.0.0:5037），容器用
//     ARTEX_ADB_SERVER=host.docker.internal:5037 连过去，USB 直连的手机也能用；
//   - 或手机开「无线调试」，宿主机 `adb connect 192.168.x.x:5555` 之后同样走这条通道。
type ADB struct {
	addr        string
	dialTimeout time.Duration
	ioTimeout   time.Duration
}

// DefaultADBAddr 返回默认的 adb server 地址：环境变量 ARTEX_ADB_SERVER 优先。
func DefaultADBAddr() string {
	if v := strings.TrimSpace(os.Getenv("ARTEX_ADB_SERVER")); v != "" {
		return v
	}
	return "127.0.0.1:5037"
}

// NewADB 建立一个 ADB 客户端；addr 为空时用 DefaultADBAddr。
func NewADB(addr string) *ADB {
	if strings.TrimSpace(addr) == "" {
		addr = DefaultADBAddr()
	}
	return &ADB{addr: addr, dialTimeout: 8 * time.Second, ioTimeout: 120 * time.Second}
}

// Addr 返回当前配置的 adb server 地址。
func (a *ADB) Addr() string { return a.addr }

// Available 探测 adb server 是否可达（用于 UI 上显示「未接入」而不是报错）。
func (a *ADB) Available(ctx context.Context) bool {
	conn, err := a.dial(ctx)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func (a *ADB) dial(ctx context.Context) (net.Conn, error) {
	d := net.Dialer{Timeout: a.dialTimeout}
	conn, err := d.DialContext(ctx, "tcp", a.addr)
	if err != nil {
		return nil, fmt.Errorf("连接 adb server %s 失败: %w", a.addr, err)
	}
	return conn, nil
}

// --- adb server 协议底层 ---

// writeRequest 发送一条长度前缀的请求（4 位十六进制长度 + 负载）。
func writeRequest(conn net.Conn, payload string) error {
	if len(payload) > 0xffff {
		return errors.New("adb 请求过长")
	}
	if _, err := conn.Write([]byte(fmt.Sprintf("%04x%s", len(payload), payload))); err != nil {
		return err
	}
	return nil
}

// readOKAY 读取 4 字节状态字；OKAY 之外的一律视为失败。
func readOKAY(conn net.Conn) error {
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return fmt.Errorf("读取 adb 应答失败: %w", err)
	}
	if string(buf) != "OKAY" {
		return fmt.Errorf("adb 应答异常: %q", string(buf))
	}
	return nil
}

// readStatus 读取 4 字节状态字并返回其内容（OKAY / FAIL）。
func readStatus(conn net.Conn) (string, error) {
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return "", fmt.Errorf("读取 adb 应答失败: %w", err)
	}
	return string(buf), nil
}

// readLengthPrefixed 读取「4 位十六进制长度 + 负载」的应答。
func readLengthPrefixed(conn net.Conn) (string, error) {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return "", fmt.Errorf("读取 adb 应答长度失败: %w", err)
	}
	n, err := strconv.ParseUint(string(lenBuf), 16, 32)
	if err != nil {
		return "", fmt.Errorf("adb 应答长度非法 %q: %w", string(lenBuf), err)
	}
	if n == 0 {
		return "", nil
	}
	if n > 64<<20 {
		return "", fmt.Errorf("adb 应答过大: %d 字节", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return "", fmt.Errorf("读取 adb 应答失败: %w", err)
	}
	return string(buf), nil
}

// host 发一条 host 级请求（host:devices-l / host:connect:… 等）。
func (a *ADB) host(ctx context.Context, service string) (string, error) {
	conn, err := a.dial(ctx)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if err := writeRequest(conn, service); err != nil {
		return "", err
	}
	return readLengthPrefixed(conn)
}

// transport 选中目标设备并返回后续可读写原始流的连接。
func (a *ADB) transport(ctx context.Context, serial string) (net.Conn, error) {
	conn, err := a.dial(ctx)
	if err != nil {
		return nil, err
	}
	if err := writeRequest(conn, "host:transport:"+serial); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := readOKAY(conn); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("设备 %s 不可用（offline/unauthorized?）: %w", serial, err)
	}
	return conn, nil
}

// --- 设备枚举 ---

// Devices 返回 adb server 已知的所有设备（包含 offline/unauthorized 状态）。
func (a *ADB) Devices(ctx context.Context) ([]Device, error) {
	raw, err := a.host(ctx, "host:devices-l")
	if err != nil {
		return nil, err
	}
	out := []Device{}
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		d := Device{
			ID:       parts[0],
			Serial:   parts[0],
			Platform: PlatformAndroid,
			State:    parts[1],
			Transport: "usb",
		}
		if strings.Contains(parts[0], ":") {
			d.Transport = "tcp"
		}
		for _, kv := range parts[2:] {
			k, v, ok := strings.Cut(kv, ":")
			if !ok {
				continue
			}
			switch k {
			case "model":
				d.Model = v
			case "product":
				d.Product = v
			case "device":
				d.Codename = v
			case "transport_id":
				d.TransportID = v
			}
		}
		if d.Model == "" {
			d.Model = d.Codename
		}
		out = append(out, d)
	}
	return out, nil
}

// Connect 让 adb server 连接一个网络设备（无线调试 / adb over TCP）。
func (a *ADB) Connect(ctx context.Context, addr string) (string, error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", errors.New("地址为空")
	}
	if !strings.Contains(addr, ":") {
		addr += ":5555"
	}
	raw, err := a.host(ctx, "host:connect:"+addr)
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(raw, "failed") {
		return raw, fmt.Errorf("连接 %s 失败: %s", addr, raw)
	}
	return raw, nil
}

// Disconnect 断开一个网络设备。
func (a *ADB) Disconnect(ctx context.Context, addr string) (string, error) {
	return a.host(ctx, "host:disconnect:"+strings.TrimSpace(addr))
}

// --- 命令执行 ---

// Shell 在设备上执行一条命令，返回合并后的 stdout/stderr 文本。
func (a *ADB) Shell(ctx context.Context, serial, cmd string) (string, error) {
	out, _, err := a.shellWithExit(ctx, serial, cmd, false)
	return out, err
}

// ShellExit 在设备上执行一条命令并返回退出码（用尾部标记解析，兼容老版本 adbd）。
func (a *ADB) ShellExit(ctx context.Context, serial, cmd string) (int, error) {
	_, code, err := a.shellWithExit(ctx, serial, cmd, true)
	return code, err
}

const exitMarker = "__ARTEX_EXIT__"

// shellWithExit 执行命令；wantExit 为真时在命令尾部追加一个标记以取回退出码。
func (a *ADB) shellWithExit(ctx context.Context, serial, cmd string, wantExit bool) (string, int, error) {
	conn, err := a.transport(ctx, serial)
	if err != nil {
		return "", 0, err
	}
	defer conn.Close()
	if wantExit {
		cmd = fmt.Sprintf("(%s); echo %s$?", cmd, exitMarker)
	}
	if err := writeRequest(conn, "shell:"+cmd); err != nil {
		return "", 0, err
	}
	if err := readOKAY(conn); err != nil {
		return "", 0, err
	}
	data, err := readAllWithContext(ctx, conn, a.ioTimeout)
	if err != nil {
		return "", 0, err
	}
	out := string(data)
	code := 0
	if wantExit {
		if idx := strings.LastIndex(out, exitMarker); idx >= 0 {
			rest := out[idx+len(exitMarker):]
			out = out[:idx]
			num := strings.TrimSpace(strings.SplitN(rest, "\n", 2)[0])
			if v, perr := strconv.Atoi(num); perr == nil {
				code = v
			}
		}
	}
	return out, code, nil
}

// ExecOut 执行命令并返回原始字节（stderr 被丢弃），用于 screencap 这类二进制输出。
func (a *ADB) ExecOut(ctx context.Context, serial, cmd string) ([]byte, error) {
	conn, err := a.transport(ctx, serial)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := writeRequest(conn, "exec-out:"+cmd); err != nil {
		return nil, err
	}
	return readAllWithContext(ctx, conn, a.ioTimeout)
}

// --- 文件传输（sync 协议） ---

// Pull 从设备拉取一个文件到本地路径。
func (a *ADB) Pull(ctx context.Context, serial, remote, local string) error {
	conn, err := a.transport(ctx, serial)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := writeRequest(conn, "sync:"); err != nil {
		return err
	}
	if err := readOKAY(conn); err != nil {
		return err
	}
	if err := writeSyncRequest(conn, "RECV", remote); err != nil {
		return err
	}
	f, err := os.Create(local)
	if err != nil {
		return err
	}
	defer f.Close()
	for {
		id, size, err := readSyncHeader(conn)
		if err != nil {
			return err
		}
		switch id {
		case "DATA":
			if _, err := io.CopyN(f, conn, int64(size)); err != nil {
				return err
			}
		case "DONE":
			if size > 0 {
				_, _ = io.CopyN(io.Discard, conn, int64(size))
			}
			return nil
		case "FAIL":
			msg, _ := readSyncPayload(conn, size)
			return fmt.Errorf("拉取 %s 失败: %s", remote, msg)
		default:
			return fmt.Errorf("未知的 sync 应答 %q", id)
		}
	}
}

// Push 把本地文件推到设备路径。
func (a *ADB) Push(ctx context.Context, serial, local, remote string) error {
	data, err := os.ReadFile(local)
	if err != nil {
		return err
	}
	conn, err := a.transport(ctx, serial)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := writeRequest(conn, "sync:"); err != nil {
		return err
	}
	if err := readOKAY(conn); err != nil {
		return err
	}
	const chunk = 64 << 10
	for off := 0; off < len(data); off += chunk {
		end := off + chunk
		if end > len(data) {
			end = len(data)
		}
		if err := writeSyncRequest(conn, "DATA", string(data[off:end])); err != nil {
			return err
		}
	}
	// DONE + mtime + size
	if err := writeRequest(conn, "sync:"); err == nil { // 占位避免误用
		_ = err
	}
	var done [12]byte
	copy(done[0:4], "DONE")
	binary.LittleEndian.PutUint32(done[4:8], 0)
	binary.LittleEndian.PutUint32(done[8:12], uint32(len(data)))
	if _, err := conn.Write(done[:]); err != nil {
		return err
	}
	id, size, err := readSyncHeader(conn)
	if err != nil {
		return err
	}
	if id == "FAIL" {
		msg, _ := readSyncPayload(conn, size)
		return fmt.Errorf("推送 %s 失败: %s", remote, msg)
	}
	if id != "OKAY" {
		return fmt.Errorf("未知的 sync 应答 %q", id)
	}
	return nil
}

func writeSyncRequest(conn net.Conn, id, payload string) error {
	buf := make([]byte, 8, 8+len(payload))
	copy(buf[0:4], id)
	binary.LittleEndian.PutUint32(buf[4:8], uint32(len(payload)))
	buf = append(buf, payload...)
	_, err := conn.Write(buf)
	return err
}

func readSyncHeader(conn net.Conn) (string, uint32, error) {
	buf := make([]byte, 8)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return "", 0, fmt.Errorf("读取 sync 头失败: %w", err)
	}
	return string(buf[0:4]), binary.LittleEndian.Uint32(buf[4:8]), nil
}

func readSyncPayload(conn net.Conn, size uint32) (string, error) {
	if size == 0 || size > 1<<20 {
		return "", nil
	}
	buf := make([]byte, size)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

// --- 端口转发（设备流量接入代理的关键） ---

// Forward 建立 host→device 的端口转发：设备的 local 端口流量会从 host 的 remote 端口进出。
// 手机侧把系统代理指向 127.0.0.1:<local> 即可把流量送到 ARTEX 的记录代理。
func (a *ADB) Forward(ctx context.Context, serial, local, remote string) error {
	return a.forwardLike(ctx, serial, "forward", local, remote)
}

// Reverse 建立 device→host 的反向转发：设备的 remote 端口流量从 host 的 local 端口进来。
// 手机侧把代理指向 127.0.0.1:<remote>，即可把流量送到宿主上的 ARTEX 代理。
func (a *ADB) Reverse(ctx context.Context, serial, remote, local string) error {
	return a.forwardLike(ctx, serial, "reverse", remote, local)
}

// forwardLike 发送一条 host:forward / host-serial:<serial>:forward 请求。
// ADB 的 service 串用冒号分隔：host-serial:<serial>:forward:<local>:<remote>；
// serial 为空时退化为 host:forward:<local>:<remote>。
func (a *ADB) forwardLike(ctx context.Context, serial, kind, first, second string) error {
	first = strings.TrimSpace(first)
	second = strings.TrimSpace(second)
	if first == "" || second == "" {
		return errors.New("端口转发参数为空")
	}
	conn, err := a.dial(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	var service string
	if host := serialOrEmpty(serial); host != "" {
		service = fmt.Sprintf("host-serial:%s:%s:%s:%s", host, kind, first, second)
	} else {
		service = fmt.Sprintf("host:%s:%s:%s", kind, first, second)
	}
	if err := writeRequest(conn, service); err != nil {
		return err
	}
	status, err := readStatus(conn)
	if err != nil {
		return err
	}
	if status != "OKAY" {
		msg, _ := readLengthPrefixed(conn)
		return fmt.Errorf("%s %s %s 失败: %s", kind, first, second, strings.TrimSpace(msg))
	}
	return nil
}

func serialOrEmpty(s string) string { return strings.TrimSpace(s) }

// --- 常用设备查询 ---

// GetProp 读取一个系统属性（ro.product.model 等）。
func (a *ADB) GetProp(ctx context.Context, serial, key string) (string, error) {
	out, err := a.Shell(ctx, serial, "getprop "+key)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

// Packages 列出设备上安装的第三方应用包名。
func (a *ADB) Packages(ctx context.Context, serial string, thirdPartyOnly bool) ([]string, error) {
	cmd := "pm list packages"
	if thirdPartyOnly {
		cmd += " -3"
	}
	out, err := a.Shell(ctx, serial, cmd)
	if err != nil {
		return nil, err
	}
	pkgs := []string{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		line = strings.TrimPrefix(line, "package:")
		pkgs = append(pkgs, line)
	}
	return pkgs, nil
}

// Install 安装一个 APK（先推到 /data/local/tmp 再 pm install）。
func (a *ADB) Install(ctx context.Context, serial, apkPath string) (string, error) {
	remote := "/data/local/tmp/artex-install.apk"
	if err := a.Push(ctx, serial, apkPath, remote); err != nil {
		return "", fmt.Errorf("推送 APK 失败: %w", err)
	}
	out, err := a.Shell(ctx, serial, "pm install -r "+remote)
	if err != nil {
		return "", err
	}
	out = strings.TrimSpace(out)
	if strings.Contains(out, "Success") {
		return out, nil
	}
	return out, fmt.Errorf("安装失败: %s", out)
}

// Uninstall 卸载一个应用。
func (a *ADB) Uninstall(ctx context.Context, serial, pkg string) (string, error) {
	return a.Shell(ctx, serial, "pm uninstall "+pkg)
}

// Screenshot 截屏并返回 PNG 字节。
func (a *ADB) Screenshot(ctx context.Context, serial string) ([]byte, error) {
	data, err := a.ExecOut(ctx, serial, "screencap -p")
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, errors.New("截屏返回空数据")
	}
	return data, nil
}

// Logcat 拉取一段 logcat。
func (a *ADB) Logcat(ctx context.Context, serial, filter string, lines int) (string, error) {
	if lines <= 0 {
		lines = 200
	}
	cmd := fmt.Sprintf("logcat -d -t %d", lines)
	if strings.TrimSpace(filter) != "" {
		cmd += " " + strings.TrimSpace(filter)
	}
	return a.Shell(ctx, serial, cmd)
}

// UIDump 用 uiautomator 导出当前界面结构（XML）。
func (a *ADB) UIDump(ctx context.Context, serial string) (string, error) {
	const remote = "/sdcard/artex_window_dump.xml"
	if _, err := a.Shell(ctx, serial, "uiautomator dump "+remote); err != nil {
		return "", err
	}
	out, err := a.Shell(ctx, serial, "cat "+remote)
	if err != nil {
		return "", err
	}
	return out, nil
}

// StartActivity 用 am start 拉起一个组件（包名/Activity 或 scheme URI）。
func (a *ADB) StartActivity(ctx context.Context, serial, target string) (string, error) {
	cmd := "am start -n " + target
	if strings.Contains(target, "://") {
		cmd = "am start -a android.intent.action.VIEW -d '" + target + "'"
	}
	return a.Shell(ctx, serial, cmd)
}

// SetProxy 设置设备的系统代理（接入 ARTEX 记录代理时用）。
func (a *ADB) SetProxy(ctx context.Context, serial, host string, port int) (string, error) {
	return a.Shell(ctx, serial, fmt.Sprintf("settings put global http_proxy %s:%d", host, port))
}

// ClearProxy 清除设备系统代理。
func (a *ADB) ClearProxy(ctx context.Context, serial string) (string, error) {
	return a.Shell(ctx, serial, "settings put global http_proxy :0")
}

// readAllWithContext 读取连接剩余数据，超时或 ctx 取消时中止。
func readAllWithContext(ctx context.Context, conn net.Conn, timeout time.Duration) ([]byte, error) {
	if timeout > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(timeout))
	}
	done := make(chan struct{})
	var out []byte
	var err error
	go func() {
		defer close(done)
		out, err = io.ReadAll(conn)
	}()
	select {
	case <-ctx.Done():
		_ = conn.Close()
		<-done
		return nil, ctx.Err()
	case <-done:
		return out, err
	}
}
