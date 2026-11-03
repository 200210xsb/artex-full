// Command artex-device-agent 是 ARTEX「接入代理」的设备端。
//
// 它跑在手机（Termux / adb push 到 /data/local/tmp）或任意内网机器上，主动回连
// ARTEX 的 /device-bridge（WebSocket），于是设备不需要开放任何端口、跨网段也能被
// 纳管——和全链哨兵的 DroidBridge / SentinelBridge 同一思路。
//
// 线上协议对齐哨兵的 droid-protocol（见 device/bridge.go）：
//
//	→ {"t":"hello","token":"...","device_id":"...","model":"...","os_version":"...","sdk":34,"rooted":true}
//	← {"t":"welcome","device_id":"..."}
//	← {"t":"exec","req_id":"d...","cmd":"id","as_root":false,"timeout_ms":60000}
//	→ {"t":"result","req_id":"d...","ok":true,"stdout":"...","stderr":"...","code":0}
//	← {"t":"pull","req_id":"...","path":"/sdcard/a","max_bytes":1048576}
//	→ {"t":"data","req_id":"...","seq":0,"b64":"...","done":true}
//	→ {"t":"result","req_id":"...","ok":true}
//	→ {"t":"hb"}                                  每 15s 一次
//
// 用法：
//
//	artex-device-agent --server ws://192.168.1.10:8080/device-bridge --token <令牌> --name 测试机
package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// 与 device/bridge.go 保持一致。
const (
	maxFrameBytes  = 8 * 1024 * 1024
	pushChunkBytes = 512 * 1024
	pullChunkBytes = 512 * 1024
	heartbeat      = 15 * time.Second
	deviceIDFile   = "artex-device-id"
)

// frame 是线上 JSON 帧，字段与 device/bridge.go 的 bridgeFrame 一一对应
// （camelCase，和官方 sentinel-droidbridge APK 的协议逐字一致）。
type frame struct {
	T string `json:"t"`

	Token     string `json:"token,omitempty"`
	DeviceID  string `json:"deviceId,omitempty"`
	Model     string `json:"model,omitempty"`
	OSVersion string `json:"androidVersion,omitempty"`
	SDK       int    `json:"sdkInt,omitempty"`
	Rooted    bool   `json:"rooted,omitempty"`

	ReqID          string `json:"reqId,omitempty"`
	Cmd            string `json:"cmd,omitempty"`
	AsRoot         bool   `json:"asRoot,omitempty"`
	TimeoutMs      int    `json:"timeoutMs,omitempty"`
	Path           string `json:"path,omitempty"`
	MaxBytes       int64  `json:"maxBytes,omitempty"`
	Seq            int    `json:"seq,omitempty"`
	Done           bool   `json:"done,omitempty"`
	B64            string `json:"b64,omitempty"`
	Mode           string `json:"mode,omitempty"`
	Lines          int    `json:"lines,omitempty"`
	Filter         string `json:"filter,omitempty"`
	ThirdPartyOnly bool   `json:"thirdPartyOnly,omitempty"`

	OK     bool   `json:"ok,omitempty"`
	Code   int    `json:"code,omitempty"`
	Stdout string `json:"stdout,omitempty"`
	Stderr string `json:"stderr,omitempty"`
	Error  string `json:"error,omitempty"`
}

// client 维护一条连接与写锁（心跳、结果、分片可能并发写）。
type client struct {
	conn   *websocket.Conn
	mu     sync.Mutex
	device string
}

func (c *client) send(v frame) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(raw) > maxFrameBytes {
		return fmt.Errorf("单帧 %d 字节超过上限", len(raw))
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	_ = c.conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
	return c.conn.WriteMessage(websocket.TextMessage, raw)
}

// sendStream 把一段字节切成 data 帧按 seq 递增发出去。
func (c *client) sendStream(reqID string, data []byte) error {
	if len(data) == 0 {
		return c.send(frame{T: "data", ReqID: reqID, Seq: 0, Done: true})
	}
	seq := 0
	for off := 0; off < len(data); off += pullChunkBytes {
		end := off + pullChunkBytes
		if end > len(data) {
			end = len(data)
		}
		f := frame{
			T:     "data",
			ReqID: reqID,
			Seq:   seq,
			B64:   base64.StdEncoding.EncodeToString(data[off:end]),
			Done:  end >= len(data),
		}
		if err := c.send(f); err != nil {
			return err
		}
		seq++
	}
	return nil
}

func main() {
	server := flag.String("server", "", "ARTEX 地址，如 ws://192.168.1.10:8080/device-bridge")
	pair := flag.String("pair", "", "扫码得到的配对地址（等价于 --server，token 就写在查询串里）")
	token := flag.String("token", "", "接入令牌（ARTEX「设备」页生成；用 --pair 时可省略）")
	name := flag.String("name", "", "设备显示名（默认取机型/主机名）")
	id := flag.String("id", "", "设备 id（默认持久化在数据目录，删掉等于换一台新设备）")
	insecure := flag.Bool("insecure", false, "跳过 TLS 证书校验（自签证书时用）")
	flag.Parse()

	if *server == "" {
		*server = *pair
	}
	// 允许直接把整条 pair_url 当 --server 用：token 从查询串里取出来。
	if u, err := url.Parse(*server); err == nil && *token == "" {
		*token = u.Query().Get("token")
	}
	if strings.TrimSpace(*server) == "" || strings.TrimSpace(*token) == "" {
		log.Fatal("必须提供 --server（或 --pair）和 --token；参数在 ARTEX 前端「设备」页获取")
	}
	if *name == "" {
		*name = deviceModel()
	}
	if *id == "" {
		*id = loadOrCreateDeviceID()
	}

	dialer := websocket.Dialer{
		HandshakeTimeout: 15 * time.Second,
		TLSClientConfig:  &tls.Config{InsecureSkipVerify: *insecure}, //nolint:gosec // 自签证书是本地部署常态，由 --insecure 显式开启
	}
	backoff := time.Second
	for {
		if err := run(dialer, *server, *token, *name, *id); err != nil {
			log.Printf("[agent] 连接断开: %v（%s 后重连）", err, backoff)
		}
		time.Sleep(backoff)
		if backoff < 30*time.Second {
			backoff *= 2
		}
		if backoff > 30*time.Second {
			backoff = 30 * time.Second
		}
	}
}

// run 建立一条连接并跑到断开为止。
func run(dialer websocket.Dialer, server, token, name, id string) error {
	u, err := url.Parse(server)
	if err != nil {
		return fmt.Errorf("地址不合法: %w", err)
	}
	q := u.Query()
	q.Set("token", token)
	u.RawQuery = q.Encode()

	conn, _, err := dialer.Dial(u.String(), http.Header{})
	if err != nil {
		return fmt.Errorf("握手失败: %w", err)
	}
	defer conn.Close()

	c := &client{conn: conn, device: id}
	if err := c.send(frame{
		T:         "hello",
		Token:     token,
		DeviceID:  id,
		Model:     name,
		OSVersion: deviceOSVersion(),
		SDK:       androidSDK(),
		Rooted:    isRooted(),
	}); err != nil {
		return fmt.Errorf("发送 hello 失败: %w", err)
	}

	// 等服务端 welcome；超时说明 token 被拒。
	_ = conn.SetReadDeadline(time.Now().Add(20 * time.Second))
	var welcome frame
	_, raw, err := conn.ReadMessage()
	if err != nil {
		return fmt.Errorf("等待 welcome 失败（多半是令牌不对）: %w", err)
	}
	if err := json.Unmarshal(raw, &welcome); err != nil || welcome.T != "welcome" {
		return fmt.Errorf("服务端没有回 welcome: %s", raw)
	}
	log.Printf("[agent] 已接线 %s，设备 id=%s", server, id)
	_ = conn.SetReadDeadline(time.Time{})

	// 心跳：让服务端知道设备还活着（45s 收不到就标 stale）。
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		t := time.NewTicker(heartbeat)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				_ = c.send(frame{T: "hb"})
			}
		}
	}()

	for {
		_, raw, err := conn.ReadMessage()
		if err != nil {
			return fmt.Errorf("读取指令失败: %w", err)
		}
		var f frame
		if err := json.Unmarshal(raw, &f); err != nil {
			continue
		}
		switch f.T {
		case "exec", "pull", "screencap", "logcat", "packages", "push":
			go c.handle(f)
		}
	}
}

// handle 执行一条下发指令并回 result（流式操作先回 data 分片）。
func (c *client) handle(f frame) {
	res := frame{T: "result", ReqID: f.ReqID, OK: true}
	defer func() {
		if r := recover(); r != nil {
			res.OK, res.Error = false, fmt.Sprintf("agent panic: %v", r)
		}
		_ = c.send(res)
	}()

	switch f.T {
	case "exec":
		out, errOut, code := runShell(f.Cmd, f.AsRoot, time.Duration(f.TimeoutMs)*time.Millisecond)
		res.Stdout, res.Stderr, res.Code = out, errOut, code
		if code != 0 && errOut == "" {
			res.OK = false
		}
	case "pull":
		data, err := os.ReadFile(f.Path)
		if err != nil {
			res.OK, res.Error = false, err.Error()
			return
		}
		if f.MaxBytes > 0 && int64(len(data)) > f.MaxBytes {
			res.OK, res.Error = false, fmt.Sprintf("文件 %d 字节超过上限 %d", len(data), f.MaxBytes)
			return
		}
		if err := c.sendStream(f.ReqID, data); err != nil {
			res.OK, res.Error = false, err.Error()
		}
	case "screencap":
		data, err := screencap()
		if err != nil {
			res.OK, res.Error = false, err.Error()
			return
		}
		if err := c.sendStream(f.ReqID, data); err != nil {
			res.OK, res.Error = false, err.Error()
		}
	case "logcat":
		res.Stdout = logcat(f.Lines, f.Filter)
	case "packages":
		res.Stdout = packages(f.ThirdPartyOnly)
	case "push":
		if err := appendChunk(f.Path, f.B64, f.Seq, f.Done, f.Mode); err != nil {
			res.OK, res.Error = false, err.Error()
		}
	case "tcp_open", "tcp_send", "tcp_close":
		res.OK, res.Error = false, "TCP 隧道暂未实现（用于 frida 等本机端口透传）"
	default:
		res.OK, res.Error = false, "不支持的指令: "+f.T
	}
}

// runShell 在本机执行一条命令；asRoot 时走 su。
func runShell(cmdText string, asRoot bool, timeout time.Duration) (string, string, int) {
	if strings.TrimSpace(cmdText) == "" {
		return "", "命令为空", 1
	}
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	var cmd *exec.Cmd
	switch {
	case runtime.GOOS == "windows":
		cmd = exec.Command("cmd", "/C", cmdText)
	case asRoot && runtime.GOOS == "android":
		cmd = exec.Command("/system/bin/su", "-c", cmdText)
	case runtime.GOOS == "android":
		cmd = exec.Command("/system/bin/sh", "-c", cmdText)
	default:
		cmd = exec.Command("sh", "-c", cmdText)
	}
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	if err := cmd.Start(); err != nil {
		return "", err.Error(), 1
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		code := 0
		if err != nil {
			code = 1
			if ee, ok := err.(*exec.ExitError); ok {
				code = ee.ExitCode()
			}
		}
		return out.String(), errBuf.String(), code
	case <-time.After(timeout):
		_ = cmd.Process.Kill()
		return out.String(), errBuf.String() + "\n[timeout]", 124
	}
}

// appendChunk 处理 push 的一个分片：seq 0 覆盖写，其后追加，done 时落权限。
func appendChunk(path, b64 string, seq int, done bool, mode string) error {
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return fmt.Errorf("分片不是合法 base64: %w", err)
	}
	flag := os.O_CREATE | os.O_WRONLY
	if seq == 0 {
		flag |= os.O_TRUNC
	} else {
		flag |= os.O_APPEND
	}
	fh, err := os.OpenFile(path, flag, 0o600)
	if err != nil {
		return err
	}
	if _, err := fh.Write(data); err != nil {
		_ = fh.Close()
		return err
	}
	if err := fh.Close(); err != nil {
		return err
	}
	if done {
		perm := os.FileMode(0o700)
		if mode != "" {
			if v, err := strconv.ParseUint(mode, 8, 32); err == nil {
				perm = os.FileMode(v)
			}
		}
		return os.Chmod(path, perm)
	}
	return nil
}

// screencap 截屏：Android 用 screencap，其它平台不支持。
func screencap() ([]byte, error) {
	if runtime.GOOS != "android" {
		return nil, fmt.Errorf("当前平台 %s 不支持截屏（仅 Android 的 screencap）", runtime.GOOS)
	}
	var buf bytes.Buffer
	cmd := exec.Command("/system/bin/screencap", "-p")
	cmd.Stdout = &buf
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	if buf.Len() == 0 {
		return nil, fmt.Errorf("screencap 没有输出")
	}
	return buf.Bytes(), nil
}

// logcat 取最近 N 行日志。
func logcat(lines int, filter string) string {
	if lines <= 0 {
		lines = 300
	}
	args := []string{"-d", "-t", strconv.Itoa(lines)}
	if strings.TrimSpace(filter) != "" {
		args = append(args, "-s", filter)
	}
	out, err := exec.Command("logcat", args...).Output()
	if err != nil {
		return "logcat 执行失败: " + err.Error()
	}
	return string(out)
}

// packages 列出已安装应用。
func packages(thirdPartyOnly bool) string {
	args := []string{"pm", "list", "packages"}
	if thirdPartyOnly {
		args = append(args, "-3")
	}
	out, err := exec.Command("/system/bin/"+args[0], args[1:]...).Output()
	if err != nil {
		return "pm 执行失败: " + err.Error()
	}
	return string(out)
}

// isRooted 报告当前进程是否 root。
func isRooted() bool {
	if runtime.GOOS != "android" {
		return os.Geteuid() == 0
	}
	out, err := exec.Command("/system/bin/id", "-u").Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "0"
}

// deviceOSVersion 返回系统版本。
func deviceOSVersion() string {
	if runtime.GOOS == "android" {
		return prop("ro.build.version.release")
	}
	if b, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				return strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), `"`)
			}
		}
	}
	return runtime.GOOS
}

// androidSDK 返回 SDK 版本号。
func androidSDK() int {
	if runtime.GOOS != "android" {
		return 0
	}
	n, _ := strconv.Atoi(prop("ro.build.version.sdk"))
	return n
}

func prop(key string) string {
	if runtime.GOOS != "android" {
		return ""
	}
	out, err := exec.Command("/system/bin/getprop", key).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// deviceModel 尽量给出一个人能认的机型。
func deviceModel() string {
	if runtime.GOOS == "android" {
		if m := prop("ro.product.model"); m != "" {
			return m
		}
	}
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "unknown-device"
}

// loadOrCreateDeviceID 让设备 id 稳定：删掉这个文件就等于换一台新设备。
func loadOrCreateDeviceID() string {
	dir := dataDir()
	path := filepath.Join(dir, deviceIDFile)
	if b, err := os.ReadFile(path); err == nil {
		if id := strings.TrimSpace(string(b)); id != "" {
			return id
		}
	}
	id := fmt.Sprintf("%s-%d", strings.ToLower(deviceModel()), time.Now().UnixNano()%1e6)
	_ = os.MkdirAll(dir, 0o700)
	_ = os.WriteFile(path, []byte(id), 0o600)
	return strings.ReplaceAll(id, " ", "-")
}

func dataDir() string {
	if runtime.GOOS == "android" {
		return "/data/local/tmp"
	}
	if d, err := os.UserConfigDir(); err == nil {
		return filepath.Join(d, "artex-device-agent")
	}
	return "."
}
