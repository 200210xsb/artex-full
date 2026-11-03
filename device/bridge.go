package device

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// 接入代理（bridge）：设备上跑一个 agent，主动回连 ARTEX 的 /device-bridge。
// 手机不用开放任何端口，跨网段也能接入——与全链哨兵的 DroidBridge / SentinelBridge 同一思路。
//
// 线上的帧格式刻意对齐全链哨兵的 droid-protocol：
//   - 设备 → 服务端：hello / hb / data(分片) / result
//   - 服务端 → 设备：exec / pull / push(分片) / screencap / logcat / packages
//
// 为什么要分片：一条 20MB 截图或 100MB 文件塞进单个 JSON 帧，设备上会同时持有
// 消息缓冲、JSON 文本、base64 串、解码后字节四份，直接把进程撑死（哨兵在 59MB
// frida-server 上踩过）。所以二进制一律走 `data` 帧，按 seq 递增、done 收尾。
const (
	// BridgeMaxFrameBytes 单帧（一个 base64 分片）上限。
	BridgeMaxFrameBytes = 8 * 1024 * 1024
	// BridgeMaxStreamBytes 单次流式载荷（pull / screencap）上限。
	BridgeMaxStreamBytes = 256 * 1024 * 1024
	// BridgePushChunkBytes push 每片原始字节数。
	BridgePushChunkBytes = 512 * 1024
	// BridgeStaleAfter 超过这个时间没收到任何帧就标记 stale（设备进程被挂起）。
	BridgeStaleAfter = 45 * time.Second
	// BridgeHeartbeat 设备端心跳间隔（写进 hello 的回执里给文档用）。
	BridgeHeartbeat = 15 * time.Second
)

// BridgeOp 是接入代理支持的操作。
const (
	BridgeOpShell      = "exec"
	BridgeOpPull       = "pull"
	BridgeOpPush       = "push"
	BridgeOpScreencap  = "screencap"
	BridgeOpLogcat     = "logcat"
	BridgeOpPackages   = "packages"
	bridgeOpHello      = "hello"
	bridgeOpHeartbeat  = "hb"
	bridgeOpData       = "data"
	bridgeOpResult     = "result"
	bridgeOpWelcome    = "welcome"

	// 设备侧抓包（APK 用 tcpdump 写固定路径，跑完由 BridgePull 拉回来）。
	bridgeOpCaptureStart  = "capture_start"
	bridgeOpCaptureStop   = "capture_stop"
	bridgeOpCaptureStatus = "capture_status"

	// 应用/界面操作（APK 侧走 PackageManager / ACTION_VIEW，不需要 shell）。
	bridgeOpApps     = "apps"
	bridgeOpAppStart = "app_start"
	bridgeOpAppInfo  = "app_info"
	bridgeOpURLOpen  = "url_open"
)

// BridgeCapturePath 是官方 APK 约定写 pcap 的位置（Handlers.CAPTURE_PATH）。
const BridgeCapturePath = "/data/local/tmp/droid-capture.pcap"

// bridgeFrame 是线上的 JSON 帧。字段名逐字对齐全链哨兵的 droid-protocol（camelCase），
// 这样官方那个 sentinel-droidbridge APK 不用改一行代码就能连 ARTEX。
type bridgeFrame struct {
	T string `json:"t"`

	// hello（设备 → 服务端）
	Token     string `json:"token,omitempty"`
	DeviceID  string `json:"deviceId,omitempty"`
	Model     string `json:"model,omitempty"`
	OSVersion string `json:"androidVersion,omitempty"`
	SDK       int    `json:"sdkInt,omitempty"`
	Rooted    bool   `json:"rooted,omitempty"`

	// 请求（服务端 → 设备）
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
	Iface          string `json:"iface,omitempty"`
	Seconds        int    `json:"seconds,omitempty"`
	Pkg            string `json:"pkg,omitempty"`
	URL            string `json:"url,omitempty"`

	// 结果（设备 → 服务端）
	OK     bool   `json:"ok,omitempty"`
	Code   int    `json:"code,omitempty"`
	Stdout string `json:"stdout,omitempty"`
	Stderr string `json:"stderr,omitempty"`
	Error  string `json:"error,omitempty"`
}

// BridgeResult 是一次接入代理调用的结果。
type BridgeResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Bytes    []byte // pull / screencap 的分片汇聚结果
}

// bridgeCall 是一次在途请求：结果帧、分片装配、超时都挂在这里。
type bridgeCall struct {
	res     chan bridgeFrame
	buf     bytes.Buffer
	nextSeq int
	limit   int64
}

// BridgeAgent 是一台已接线的接入代理设备。
type BridgeAgent struct {
	Device Device
	conn   *websocket.Conn

	writeMu sync.Mutex
	mu      sync.Mutex
	pending map[string]*bridgeCall
	counter uint64
	lastAt  time.Time
	stale   bool
}

// BridgeRegistry 保存所有在线的接入代理。
type BridgeRegistry struct {
	mu    sync.RWMutex
	items map[string]*BridgeAgent
}

// NewBridgeRegistry 构造一个空的接入代理注册表。
func NewBridgeRegistry() *BridgeRegistry {
	return &BridgeRegistry{items: map[string]*BridgeAgent{}}
}

// List 返回所有在线的接入代理设备。
func (r *BridgeRegistry) List() []Device {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Device, 0, len(r.items))
	for _, a := range r.items {
		out = append(out, a.Device)
	}
	return out
}

// Get 返回指定 id 的接入代理。
func (r *BridgeRegistry) Get(id string) (*BridgeAgent, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	a, ok := r.items[id]
	return a, ok
}

func (r *BridgeRegistry) add(a *BridgeAgent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.items[a.Device.ID] = a
}

func (r *BridgeRegistry) remove(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.items, id)
}

// HandleWS 处理一条接入代理连接：首帧必须是 hello（令牌校验）→ 注册 → 收发循环。
// 同一 deviceId 重复接入时新连接顶掉旧连接（与哨兵一致：设备重装/重启后不该留两条）。
func (r *BridgeRegistry) HandleWS(ctx context.Context, conn *websocket.Conn, token string) error {
	defer conn.Close()

	// hello 可能来得晚：APK 要先跑 su 探 root，Magisk 第一次会弹授权框。
	_ = conn.SetReadDeadline(time.Now().Add(90 * time.Second))
	_, data, err := conn.ReadMessage()
	if err != nil {
		return fmt.Errorf("读取接入代理首帧失败: %w", err)
	}
	var hello bridgeFrame
	if err := json.Unmarshal(data, &hello); err != nil {
		return fmt.Errorf("接入代理首帧不是合法 JSON: %w", err)
	}
	if hello.T != bridgeOpHello {
		return errors.New("接入代理首帧必须是 hello")
	}
	if token == "" || hello.Token != token {
		return errors.New("接入令牌无效")
	}
	if strings.TrimSpace(hello.DeviceID) == "" {
		return errors.New("hello 缺少 device_id")
	}

	dev := Device{
		ID:        strings.TrimSpace(hello.DeviceID),
		Platform:  PlatformAndroid,
		Serial:    strings.TrimSpace(hello.DeviceID),
		Name:      strings.TrimSpace(hello.Model),
		Model:     strings.TrimSpace(hello.Model),
		OSVersion: strings.TrimSpace(hello.OSVersion),
		State:     "online",
		Transport: "bridge",
		LastSeen:  time.Now(),
		Extra: map[string]any{
			"rooted": hello.Rooted,
			"sdk":    hello.SDK,
		},
	}
	agent := &BridgeAgent{Device: dev, conn: conn, pending: map[string]*bridgeCall{}, lastAt: time.Now()}

	if prev, ok := r.Get(dev.ID); ok && prev != agent {
		_ = prev.conn.Close() // 旧连接作废：同一设备只保留最新一条
		r.remove(dev.ID)
	}
	r.add(agent)
	defer r.remove(dev.ID)

	if err := agent.write(bridgeFrame{T: bridgeOpWelcome, DeviceID: dev.ID}); err != nil {
		return err
	}

	_ = conn.SetReadDeadline(time.Now().Add(BridgeStaleAfter * 2))
	for {
		_, raw, err := conn.ReadMessage()
		if err != nil {
			break
		}
		var f bridgeFrame
		if err := json.Unmarshal(raw, &f); err != nil {
			continue
		}
		agent.touch()
		switch f.T {
		case bridgeOpHeartbeat:
			// touch 已经更新了 lastAt
		case bridgeOpData:
			agent.onData(f)
		case bridgeOpResult:
			agent.settle(f)
		}
	}
	agent.failAll(err)
	return nil
}

func (a *BridgeAgent) touch() {
	a.mu.Lock()
	a.lastAt = time.Now()
	a.stale = false
	a.mu.Unlock()
}

// staleNow 报告设备是否已经超过 BridgeStaleAfter 没有任何帧。
func (a *BridgeAgent) staleNow() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.stale = time.Since(a.lastAt) > BridgeStaleAfter
	return a.stale
}

func (a *BridgeAgent) write(f bridgeFrame) error {
	raw, err := json.Marshal(f)
	if err != nil {
		return err
	}
	if len(raw) > BridgeMaxFrameBytes {
		return fmt.Errorf("单帧 %d 字节超过上限 %d", len(raw), BridgeMaxFrameBytes)
	}
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	_ = a.conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
	return a.conn.WriteMessage(websocket.TextMessage, raw)
}

// call 下发一次请求并等待 result。流式操作（pull / screencap）由 onData 消费 data 帧。
func (a *BridgeAgent) call(ctx context.Context, req bridgeFrame, timeout time.Duration, limit int64) (BridgeResult, error) {
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	if a.staleNow() {
		return BridgeResult{}, errors.New("设备无响应：超过 45s 没有心跳，可能被系统挂起了")
	}

	a.mu.Lock()
	a.counter++
	id := fmt.Sprintf("d%d%x%s", time.Now().UnixNano(), a.counter, randHex(4))
	c := &bridgeCall{res: make(chan bridgeFrame, 1), limit: limit}
	a.pending[id] = c
	a.mu.Unlock()

	req.T = requestTypeForOp(req)
	req.ReqID = id
	if req.TimeoutMs == 0 {
		req.TimeoutMs = int(timeout / time.Millisecond)
	}
	if err := a.write(req); err != nil {
		a.mu.Lock()
		delete(a.pending, id)
		a.mu.Unlock()
		return BridgeResult{}, fmt.Errorf("下发指令失败: %w", err)
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		a.mu.Lock()
		delete(a.pending, id)
		a.mu.Unlock()
		return BridgeResult{}, ctx.Err()
	case <-timer.C:
		a.mu.Lock()
		delete(a.pending, id)
		a.mu.Unlock()
		return BridgeResult{}, fmt.Errorf("接入代理执行超时（%s）", timeout)
	case res := <-c.res:
		out := BridgeResult{Stdout: res.Stdout, Stderr: res.Stderr, ExitCode: res.Code}
		if !res.OK && res.Error != "" {
			return out, errors.New(res.Error)
		}
		if limit > 0 {
			out.Bytes = c.buf.Bytes()
		}
		return out, nil
	}
}

// requestTypeForOp 在调用方没指定 t 时按业务字段推断（兼容老的调用方式）。
func requestTypeForOp(req bridgeFrame) string {
	if req.T != "" {
		return req.T
	}
	switch {
	case req.Cmd != "":
		return BridgeOpShell
	case req.Path != "" && req.MaxBytes > 0:
		return BridgeOpPull
	case req.Path != "":
		return BridgeOpPush
	case req.ThirdPartyOnly:
		return BridgeOpPackages
	default:
		return ""
	}
}

// onData 处理设备回传的分片：seq 必须严格递增，否则整条流作废。
func (a *BridgeAgent) onData(f bridgeFrame) {
	a.mu.Lock()
	c, ok := a.pending[f.ReqID]
	if ok {
		if f.Seq != c.nextSeq {
			delete(a.pending, f.ReqID)
			c.res <- bridgeFrame{OK: false, Error: fmt.Sprintf("流分片乱序：期望 %d，收到 %d", c.nextSeq, f.Seq)}
		} else {
			chunk, err := base64.StdEncoding.DecodeString(f.B64)
			if err != nil {
				delete(a.pending, f.ReqID)
				c.res <- bridgeFrame{OK: false, Error: "分片不是合法 base64"}
			} else if c.limit > 0 && int64(c.buf.Len()+len(chunk)) > c.limit {
				delete(a.pending, f.ReqID)
				c.res <- bridgeFrame{OK: false, Error: fmt.Sprintf("流超过上限 %d 字节", c.limit)}
			} else {
				c.nextSeq++
				if c.limit > 0 {
					c.buf.Write(chunk)
				}
			}
		}
	}
	a.mu.Unlock()
}

func (a *BridgeAgent) settle(f bridgeFrame) {
	a.mu.Lock()
	c, ok := a.pending[f.ReqID]
	if ok {
		delete(a.pending, f.ReqID)
	}
	a.mu.Unlock()
	if ok {
		c.res <- f
	}
}

// failAll 在连接断开时把所有在途请求一次性叫醒，而不是让每个请求各自等到超时。
func (a *BridgeAgent) failAll(cause error) {
	msg := "接入代理连接已断开"
	if cause != nil {
		msg += ": " + cause.Error()
	}
	a.mu.Lock()
	for id, c := range a.pending {
		delete(a.pending, id)
		c.res <- bridgeFrame{OK: false, Error: msg}
	}
	a.mu.Unlock()
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "deadbeef"
	}
	return hex.EncodeToString(b)
}

// --- 对外操作 ---

// BridgeShell 通过接入代理在设备上执行 shell 命令。
func (r *BridgeRegistry) BridgeShell(ctx context.Context, deviceID, cmd string, asRoot bool, timeout time.Duration) (string, error) {
	a, ok := r.Get(deviceID)
	if !ok {
		return "", fmt.Errorf("接入代理设备 %s 不在线", deviceID)
	}
	res, err := a.call(ctx, bridgeFrame{Cmd: cmd, AsRoot: asRoot}, timeout, 0)
	if err != nil {
		return "", err
	}
	out := res.Stdout
	if res.Stderr != "" {
		out += "\n[stderr] " + res.Stderr
	}
	if res.ExitCode != 0 {
		out += fmt.Sprintf("\n[exit_code] %d", res.ExitCode)
	}
	return out, nil
}

// BridgeScreencap 取一张全屏截图（PNG）。
func (r *BridgeRegistry) BridgeScreencap(ctx context.Context, deviceID string) ([]byte, error) {
	a, ok := r.Get(deviceID)
	if !ok {
		return nil, fmt.Errorf("接入代理设备 %s 不在线", deviceID)
	}
	res, err := a.call(ctx, bridgeFrame{T: BridgeOpScreencap}, 60*time.Second, BridgeMaxStreamBytes)
	if err != nil {
		return nil, err
	}
	return res.Bytes, nil
}

// BridgePull 把设备上的文件拉回来。
func (r *BridgeRegistry) BridgePull(ctx context.Context, deviceID, path string, maxBytes int64) ([]byte, error) {
	a, ok := r.Get(deviceID)
	if !ok {
		return nil, fmt.Errorf("接入代理设备 %s 不在线", deviceID)
	}
	if maxBytes <= 0 || maxBytes > BridgeMaxStreamBytes {
		maxBytes = BridgeMaxStreamBytes
	}
	res, err := a.call(ctx, bridgeFrame{Path: path, MaxBytes: maxBytes}, 5*time.Minute, maxBytes)
	if err != nil {
		return nil, err
	}
	return res.Bytes, nil
}

// BridgePush 把本地文件分片推到设备上。
func (r *BridgeRegistry) BridgePush(ctx context.Context, deviceID, path string, data []byte, mode string) error {
	a, ok := r.Get(deviceID)
	if !ok {
		return fmt.Errorf("接入代理设备 %s 不在线", deviceID)
	}
	if mode == "" {
		mode = "0700"
	}
	total := len(data)
	for off, seq := 0, 0; off < total || seq == 0; seq++ {
		end := off + BridgePushChunkBytes
		if end > total {
			end = total
		}
		chunk := data[off:end]
		done := end >= total
		f := bridgeFrame{
			T:     BridgeOpPush,
			Path:  path,
			Seq:   seq,
			Done:  done,
			B64:   base64.StdEncoding.EncodeToString(chunk),
			Mode:  mode,
		}
		if !done {
			// 中间分片不等 result：只写帧，最后一片才等回执。
			if err := a.write(f); err != nil {
				return err
			}
			off = end
			continue
		}
		res, err := a.call(ctx, f, 2*time.Minute, 0)
		if err != nil {
			return err
		}
		if res.ExitCode != 0 {
			return fmt.Errorf("push 失败: %s", res.Stderr)
		}
		off = end
	}
	return nil
}

// BridgeLogcat 取最近 N 行日志。
func (r *BridgeRegistry) BridgeLogcat(ctx context.Context, deviceID, filter string, lines int) (string, error) {
	a, ok := r.Get(deviceID)
	if !ok {
		return "", fmt.Errorf("接入代理设备 %s 不在线", deviceID)
	}
	if lines <= 0 {
		lines = 300
	}
	res, err := a.call(ctx, bridgeFrame{T: BridgeOpLogcat, Lines: lines, Filter: filter}, 60*time.Second, 0)
	if err != nil {
		return "", err
	}
	return res.Stdout, nil
}

// BridgePackages 列出已安装应用包名。
func (r *BridgeRegistry) BridgePackages(ctx context.Context, deviceID string, thirdPartyOnly bool) (string, error) {
	a, ok := r.Get(deviceID)
	if !ok {
		return "", fmt.Errorf("接入代理设备 %s 不在线", deviceID)
	}
	res, err := a.call(ctx, bridgeFrame{T: BridgeOpPackages, ThirdPartyOnly: thirdPartyOnly}, 60*time.Second, 0)
	if err != nil {
		return "", err
	}
	return res.Stdout, nil
}

// BridgeCaptureStart 在设备上开 tcpdump（APK 侧写 BridgeCapturePath）。
// 抓包进程由设备端 nohup 拉起，这里只负责下发与确认。
func (r *BridgeRegistry) BridgeCaptureStart(ctx context.Context, deviceID, iface string, seconds int) (string, error) {
	a, ok := r.Get(deviceID)
	if !ok {
		return "", fmt.Errorf("接入代理设备 %s 不在线", deviceID)
	}
	if strings.TrimSpace(iface) == "" {
		iface = "any"
	}
	res, err := a.call(ctx, bridgeFrame{T: bridgeOpCaptureStart, Iface: iface, Seconds: seconds}, 30*time.Second, 0)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(res.Stdout), nil
}

// BridgeCaptureStatus 报告设备上 tcpdump 是否在跑、pcap 有多大。
func (r *BridgeRegistry) BridgeCaptureStatus(ctx context.Context, deviceID string) (string, error) {
	a, ok := r.Get(deviceID)
	if !ok {
		return "", fmt.Errorf("接入代理设备 %s 不在线", deviceID)
	}
	res, err := a.call(ctx, bridgeFrame{T: bridgeOpCaptureStatus}, 30*time.Second, 0)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(res.Stdout), nil
}

// BridgeCaptureStop 停掉设备上的 tcpdump（pcap 留在设备上，随后用 BridgePull 取）。
func (r *BridgeRegistry) BridgeCaptureStop(ctx context.Context, deviceID string) (string, error) {
	a, ok := r.Get(deviceID)
	if !ok {
		return "", fmt.Errorf("接入代理设备 %s 不在线", deviceID)
	}
	res, err := a.call(ctx, bridgeFrame{T: bridgeOpCaptureStop}, 30*time.Second, 0)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(res.Stdout), nil
}

// BridgeCall 下发一个自定义帧并返回 stdout。应用管理、拉起 URL 这类低带宽请求共用。
func (r *BridgeRegistry) BridgeCall(ctx context.Context, deviceID string, f bridgeFrame, timeout time.Duration) (string, error) {
	a, ok := r.Get(deviceID)
	if !ok {
		return "", fmt.Errorf("接入代理设备 %s 不在线", deviceID)
	}
	res, err := a.call(ctx, f, timeout, 0)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(res.Stdout), nil
}

// BridgeApps 列出设备上的应用（PackageManager，不需要 root）。
func (r *BridgeRegistry) BridgeApps(ctx context.Context, deviceID string, thirdParty bool) (string, error) {
	return r.BridgeCall(ctx, deviceID, bridgeFrame{T: bridgeOpApps, ThirdPartyOnly: thirdParty}, 60*time.Second)
}

// BridgeAppStart 按包名启动应用。
func (r *BridgeRegistry) BridgeAppStart(ctx context.Context, deviceID, pkg string) (string, error) {
	return r.BridgeCall(ctx, deviceID, bridgeFrame{T: bridgeOpAppStart, Pkg: pkg}, 30*time.Second)
}

// BridgeAppInfo 返回单个应用的信息。
func (r *BridgeRegistry) BridgeAppInfo(ctx context.Context, deviceID, pkg string) (string, error) {
	return r.BridgeCall(ctx, deviceID, bridgeFrame{T: bridgeOpAppInfo, Pkg: pkg}, 30*time.Second)
}

// BridgeURLOpen 用 ACTION_VIEW 打开 URL / scheme。
func (r *BridgeRegistry) BridgeURLOpen(ctx context.Context, deviceID, url string) (string, error) {
	return r.BridgeCall(ctx, deviceID, bridgeFrame{T: bridgeOpURLOpen, URL: url}, 30*time.Second)
}

// BridgeTokenFile 是接入令牌在数据目录里的默认文件名。
const BridgeTokenFile = "device-bridge-token"

// LoadOrCreateBridgeToken 读取接入令牌；不存在则生成一个新的（32 字节 hex）。
func LoadOrCreateBridgeToken(dir string) (string, error) {
	path := dir + string(os.PathSeparator) + BridgeTokenFile
	if b, err := os.ReadFile(path); err == nil {
		tok := strings.TrimSpace(string(b))
		if tok != "" {
			return tok, nil
		}
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	tok := hex.EncodeToString(buf)
	if err := os.WriteFile(path, []byte(tok), 0o600); err != nil {
		return "", err
	}
	return tok, nil
}
