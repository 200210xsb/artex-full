package device

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Platform 表示设备平台。
type Platform string

const (
	// PlatformAndroid 是 Android 真机 / 模拟器（走 ADB）。
	PlatformAndroid Platform = "android"
	// PlatformIOS 是 iOS 设备（走 libimobiledevice / 越狱 SSH / 接入代理）。
	PlatformIOS Platform = "ios"
)

// Device 是一个被 ARTEX 纳管的移动设备。
//
// 三种接入方式共用同一个结构：
//   - ADB：宿主机或局域网里的 Android，通过 adb server 连（Serial 形如 192.168.1.7:5555）；
//   - iOS 直连：宿主机上能访问 usbmuxd 时，用 libimobiledevice 命令行；
//   - 接入代理（bridge）：设备上跑 artex-device-agent，主动回连 ARTEX（手机不用开端口）。
type Device struct {
	ID          string         `json:"id"`
	Platform    Platform       `json:"platform"`
	State       string         `json:"state"` // online / offline / unauthorized / connected
	Transport   string         `json:"transport"`
	Serial      string         `json:"serial"`
	UDID        string         `json:"udid"`
	Name        string         `json:"name"`
	Model       string         `json:"model"`
	Product     string         `json:"product"`
	Codename    string         `json:"codename"`
	OSVersion   string         `json:"os_version"`
	Address     string         `json:"address"`
	ProductID   string         `json:"product_id"`
	TransportID string         `json:"transport_id"`
	Note        string         `json:"note"`
	Tags        []string       `json:"tags"`
	Extra       map[string]any `json:"extra"`
	LastSeen    time.Time      `json:"last_seen"`
	CreatedAt   time.Time      `json:"created_at"`
}

// Display 返回一个给人看的名字。
func (d Device) Display() string {
	if d.Name != "" {
		return d.Name
	}
	if d.Model != "" {
		return d.Model
	}
	return d.ID
}

// Store 是设备登记表的持久化接口（由 db.DeviceStore 实现）。
// 用接口而不是直接依赖 db 包，避免 device → db 的反向依赖。
type Store interface {
	UpsertDevice(d Device) error
	DeleteDevice(id string) error
	ListStoredDevices() ([]Device, error)
}

// Hub 是移动端设备接入的中心：聚合 ADB / iOS / 接入代理三类来源，
// 并把「设备引用（id 或 serial）」解析成具体驱动。
type Hub struct {
	adb     *ADB
	ios     *IOS
	bridges *BridgeRegistry
	store   Store

	mu       sync.Mutex
	lastSync map[string]time.Time
}

// NewHub 构造设备中心；store 可为 nil（不落库，只用实时枚举）。
func NewHub(store Store) *Hub {
	return &Hub{
		adb:     NewADB(DefaultADBAddr()),
		ios:     NewIOS(""),
		bridges: NewBridgeRegistry(),
		store:   store,
		lastSync: map[string]time.Time{},
	}
}

// ADB 暴露 adb 客户端（UI 上显示连接状态用）。
func (h *Hub) ADB() *ADB { return h.adb }

// IOS 暴露 iOS 客户端。
func (h *Hub) IOS() *IOS { return h.ios }

// Bridges 暴露接入代理注册表。
func (h *Hub) Bridges() *BridgeRegistry { return h.bridges }

// List 汇总所有来源的设备：登记表里的（离线设备也保留）+ 当前 ADB/iOS 枚举到的 + 接入代理连着的。
func (h *Hub) List(ctx context.Context) []Device {
	seen := map[string]Device{}
	order := []string{}

	add := func(d Device) {
		if d.ID == "" {
			return
		}
		if _, ok := seen[d.ID]; !ok {
			order = append(order, d.ID)
		}
		seen[d.ID] = d
	}

	if h.store != nil {
		if stored, err := h.store.ListStoredDevices(); err == nil {
			for _, d := range stored {
				add(d)
			}
		}
	}
	if devs, err := h.adb.Devices(ctx); err == nil {
		for _, d := range devs {
			if prev, ok := seen[d.ID]; ok {
				d.Name = prev.Name
				d.Note = prev.Note
				d.Tags = prev.Tags
				d.Extra = prev.Extra
				d.CreatedAt = prev.CreatedAt
			}
			d.LastSeen = time.Now()
			add(d)
		}
	}
	if devs, err := h.ios.Devices(ctx); err == nil {
		for _, d := range devs {
			if prev, ok := seen[d.ID]; ok {
				d.Name = prev.Name
				d.Note = prev.Note
				d.Tags = prev.Tags
				d.Extra = prev.Extra
				d.CreatedAt = prev.CreatedAt
			}
			d.LastSeen = time.Now()
			add(d)
		}
	}
	for _, d := range h.bridges.List() {
		if prev, ok := seen[d.ID]; ok {
			d.Name = prev.Name
			d.Note = prev.Note
			d.Tags = prev.Tags
			d.Extra = prev.Extra
			d.CreatedAt = prev.CreatedAt
		}
		d.LastSeen = time.Now()
		add(d)
	}

	out := make([]Device, 0, len(order))
	for _, id := range order {
		out = append(out, seen[id])
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Platform != out[j].Platform {
			return out[i].Platform < out[j].Platform
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Get 按 id / serial / udid 查一台设备。
func (h *Hub) Get(ctx context.Context, ref string) (Device, bool) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return Device{}, false
	}
	for _, d := range h.List(ctx) {
		if d.ID == ref || d.Serial == ref || d.UDID == ref {
			return d, true
		}
	}
	return Device{}, false
}

// Connect 把一台设备登记进资产表（并可选地立刻建立 adb 连接）。
func (h *Hub) Connect(ctx context.Context, platform Platform, addr, name, note string) (Device, error) {
	var d Device
	switch platform {
	case PlatformAndroid:
		raw, err := h.adb.Connect(ctx, addr)
		if err != nil {
			return Device{}, err
		}
		d = Device{
			ID:        strings.TrimSpace(addr),
			Platform:  PlatformAndroid,
			Serial:    strings.TrimSpace(addr),
			State:     "online",
			Transport: "tcp",
			Address:   strings.TrimSpace(addr),
			Extra:     map[string]any{"connect_result": raw},
		}
	case PlatformIOS:
		d = Device{
			ID:       strings.TrimSpace(addr),
			Platform: PlatformIOS,
			UDID:     strings.TrimSpace(addr),
			Serial:   strings.TrimSpace(addr),
			State:    "registered",
			Transport: "usbmux",
		}
	default:
		return Device{}, fmt.Errorf("不支持的平台 %q（当前支持 android / ios）", platform)
	}
	if name != "" {
		d.Name = name
	}
	d.Note = note
	d.LastSeen = time.Now()
	d.CreatedAt = time.Now()
	if h.store != nil {
		if err := h.store.UpsertDevice(d); err != nil {
			return d, err
		}
	}
	return d, nil
}

// Disconnect 从登记表中移除一台设备。
func (h *Hub) Disconnect(ref string) error {
	ref = strings.TrimSpace(ref)
	if h.store != nil {
		return h.store.DeleteDevice(ref)
	}
	return nil
}

// Info 汇总设备信息（属性、屏幕、已装应用等）。
func (h *Hub) Info(ctx context.Context, ref string) (map[string]any, error) {
	d, ok := h.Get(ctx, ref)
	if !ok {
		return nil, fmt.Errorf("设备 %s 未接入", ref)
	}
	if _, ok := h.bridges.Get(d.ID); ok {
		return map[string]any{
			"id":         d.ID,
			"platform":   string(d.Platform),
			"transport":  "bridge",
			"model":      d.Model,
			"os_version": d.OSVersion,
			"state":      d.State,
			"extra":      d.Extra,
		}, nil
	}
	switch d.Platform {
	case PlatformAndroid:
		return h.androidInfo(ctx, d)
	case PlatformIOS:
		return h.ios.Info(ctx, d.UDID)
	}
	return nil, fmt.Errorf("设备 %s 的平台不受支持", ref)
}

func (h *Hub) androidInfo(ctx context.Context, d Device) (map[string]any, error) {
	out := map[string]any{"id": d.ID, "platform": string(d.Platform), "state": d.State}
	props := map[string]any{}
	for _, k := range []string{
		"ro.product.model", "ro.product.brand", "ro.product.device",
		"ro.build.version.release", "ro.build.version.sdk", "ro.product.cpu.abi",
	} {
		if v, err := h.adb.GetProp(ctx, d.Serial, k); err == nil && v != "" {
			props[k] = v
		}
	}
	out["props"] = props
	if v, err := h.adb.Shell(ctx, d.Serial, "wm size"); err == nil {
		out["screen"] = strings.TrimSpace(v)
	}
	if pkgs, err := h.adb.Packages(ctx, d.Serial, true); err == nil {
		out["third_party_packages"] = pkgs
		out["third_party_count"] = len(pkgs)
	}
	return out, nil
}

// Shell 在设备上执行命令。
func (h *Hub) Shell(ctx context.Context, ref, cmd string) (string, error) {
	d, ok := h.Get(ctx, ref)
	if !ok {
		return "", fmt.Errorf("设备 %s 未接入", ref)
	}
	// 接入代理设备：指令经 WebSocket 下发到设备端 agent 执行。
	if _, ok := h.bridges.Get(d.ID); ok {
		return h.bridges.BridgeShell(ctx, d.ID, cmd, false, 60*time.Second)
	}
	switch d.Platform {
	case PlatformAndroid:
		return h.adb.Shell(ctx, d.Serial, cmd)
	case PlatformIOS:
		return h.ios.Shell(ctx, d.UDID, cmd, "", "")
	}
	return "", fmt.Errorf("设备 %s 的平台不受支持", ref)
}

// Screenshot 截屏（PNG 字节）。
func (h *Hub) Screenshot(ctx context.Context, ref string) ([]byte, error) {
	d, ok := h.Get(ctx, ref)
	if !ok {
		return nil, fmt.Errorf("设备 %s 未接入", ref)
	}
	if _, ok := h.bridges.Get(d.ID); ok {
		return h.bridges.BridgeScreencap(ctx, d.ID)
	}
	switch d.Platform {
	case PlatformAndroid:
		return h.adb.Screenshot(ctx, d.Serial)
	case PlatformIOS:
		return h.ios.Screenshot(ctx, d.UDID)
	}
	return nil, fmt.Errorf("设备 %s 的平台不受支持", ref)
}

// Install 安装应用包（APK / IPA）。
func (h *Hub) Install(ctx context.Context, ref, path string) (string, error) {
	d, ok := h.Get(ctx, ref)
	if !ok {
		return "", fmt.Errorf("设备 %s 未接入", ref)
	}
	if _, err := os.Stat(path); err != nil {
		return "", fmt.Errorf("安装包不存在: %s", path)
	}
	switch d.Platform {
	case PlatformAndroid:
		return h.adb.Install(ctx, d.Serial, path)
	case PlatformIOS:
		return h.ios.Install(ctx, d.UDID, path)
	}
	return "", fmt.Errorf("设备 %s 的平台不受支持", ref)
}

// Uninstall 卸载应用。
func (h *Hub) Uninstall(ctx context.Context, ref, pkg string) (string, error) {
	d, ok := h.Get(ctx, ref)
	if !ok {
		return "", fmt.Errorf("设备 %s 未接入", ref)
	}
	switch d.Platform {
	case PlatformAndroid:
		return h.adb.Uninstall(ctx, d.Serial, pkg)
	case PlatformIOS:
		return h.ios.Uninstall(ctx, d.UDID, pkg)
	}
	return "", fmt.Errorf("设备 %s 的平台不受支持", ref)
}

// Pull 从设备拉取文件到本地目录，返回落盘路径。
func (h *Hub) Pull(ctx context.Context, ref, remote, destDir string) (string, error) {
	d, ok := h.Get(ctx, ref)
	if !ok {
		return "", fmt.Errorf("设备 %s 未接入", ref)
	}
	if d.Platform != PlatformAndroid {
		return "", errors.New("当前仅 Android(ADB) 支持 pull/push")
	}
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return "", err
	}
	local := filepath.Join(destDir, filepath.Base(remote))
	if err := h.adb.Pull(ctx, d.Serial, remote, local); err != nil {
		return "", err
	}
	return local, nil
}

// Push 把本地文件推到设备。
func (h *Hub) Push(ctx context.Context, ref, local, remote string) (string, error) {
	d, ok := h.Get(ctx, ref)
	if !ok {
		return "", fmt.Errorf("设备 %s 未接入", ref)
	}
	if d.Platform != PlatformAndroid {
		return "", errors.New("当前仅 Android(ADB) 支持 pull/push")
	}
	if err := h.adb.Push(ctx, d.Serial, local, remote); err != nil {
		return "", err
	}
	return remote, nil
}

// Logs 拉取设备日志（Android: logcat；iOS: syslog）。
func (h *Hub) Logs(ctx context.Context, ref, filter string, lines int) (string, error) {
	d, ok := h.Get(ctx, ref)
	if !ok {
		return "", fmt.Errorf("设备 %s 未接入", ref)
	}
	switch d.Platform {
	case PlatformAndroid:
		return h.adb.Logcat(ctx, d.Serial, filter, lines)
	case PlatformIOS:
		return h.ios.Syslog(ctx, d.UDID, filter, lines)
	}
	return "", fmt.Errorf("设备 %s 的平台不受支持", ref)
}

// UIDump 导出当前界面结构（Android: uiautomator）。
func (h *Hub) UIDump(ctx context.Context, ref string) (string, error) {
	d, ok := h.Get(ctx, ref)
	if !ok {
		return "", fmt.Errorf("设备 %s 未接入", ref)
	}
	if d.Platform != PlatformAndroid {
		return "", errors.New("当前仅 Android(ADB) 支持界面结构导出")
	}
	return h.adb.UIDump(ctx, d.Serial)
}

// Forward 建立端口转发。direction 取 "forward"（host→device）或 "reverse"（device→host）。
// 手机抓包走 "reverse"：手机把代理指向 127.0.0.1:<devicePort>，宿主机上的 ARTEX
// 记录代理就能收到手机的流量。
func (h *Hub) Forward(ctx context.Context, ref, direction, local, remote string) error {
	d, ok := h.Get(ctx, ref)
	if !ok {
		return fmt.Errorf("设备 %s 未接入", ref)
	}
	if d.Platform != PlatformAndroid {
		return errors.New("当前仅 Android(ADB) 支持端口转发")
	}
	switch strings.ToLower(strings.TrimSpace(direction)) {
	case "", "forward", "tcp":
		return h.adb.Forward(ctx, d.Serial, local, remote)
	case "reverse":
		return h.adb.Reverse(ctx, d.Serial, remote, local)
	default:
		return fmt.Errorf("未知的转发方向 %q（支持 forward / reverse）", direction)
	}
}

// SetProxy 把设备系统代理指向 ARTEX 的记录代理（接入代理）。
// proxyAddr 形如 "192.168.1.10:8788"（宿主机可达地址）；返回给操作者的提示里
// 包含 CA 证书路径——手机上需安装该 CA 才能解出 HTTPS 明文。
func (h *Hub) SetProxy(ctx context.Context, ref, proxyAddr string, caPath string) (string, error) {
	d, ok := h.Get(ctx, ref)
	if !ok {
		return "", fmt.Errorf("设备 %s 未接入", ref)
	}
	if d.Platform != PlatformAndroid {
		return "", errors.New("当前仅 Android 支持设置系统代理")
	}
	host, port, err := splitHostPort(proxyAddr)
	if err != nil {
		return "", err
	}
	var out string
	if _, ok := h.bridges.Get(d.ID); ok {
		// 接入代理设备：经 root shell 改系统代理（需要 root 才能写 secure 表）。
		out, err = h.bridges.BridgeShell(ctx, d.ID,
			fmt.Sprintf("settings put global http_proxy %s:%d", host, port), true, 20*time.Second)
	} else {
		out, err = h.adb.SetProxy(ctx, d.Serial, host, port)
	}
	if err != nil {
		return "", err
	}
	msg := strings.TrimSpace(out)
	if caPath != "" {
		msg += fmt.Sprintf("\nCA 证书: %s（推送到设备并安装后，HTTPS 才能解出明文）", caPath)
	}
	return msg, nil
}

// ClearProxy 清除设备系统代理。
func (h *Hub) ClearProxy(ctx context.Context, ref string) (string, error) {
	d, ok := h.Get(ctx, ref)
	if !ok {
		return "", fmt.Errorf("设备 %s 未接入", ref)
	}
	if d.Platform != PlatformAndroid {
		return "", errors.New("当前仅 Android 支持清除系统代理")
	}
	if _, ok := h.bridges.Get(d.ID); ok {
		return h.bridges.BridgeShell(ctx, d.ID, "settings put global http_proxy :0", true, 20*time.Second)
	}
	return h.adb.ClearProxy(ctx, d.Serial)
}

// StartActivity 在设备上拉起一个组件或 URI（小程序用 weixin:// scheme）。
func (h *Hub) StartActivity(ctx context.Context, ref, target string) (string, error) {
	d, ok := h.Get(ctx, ref)
	if !ok {
		return "", fmt.Errorf("设备 %s 未接入", ref)
	}
	if d.Platform != PlatformAndroid {
		return "", errors.New("当前仅 Android(ADB) 支持拉起组件")
	}
	return h.adb.StartActivity(ctx, d.Serial, target)
}

// --- 设备抓包（接入代理 APK 侧的 tcpdump） ---

// bridgeOrErr 取一台接入代理设备；非 bridge 设备给出可操作的替代方案。
func (h *Hub) bridgeOrErr(ctx context.Context, ref string) (Device, error) {
	d, ok := h.Get(ctx, ref)
	if !ok {
		return Device{}, fmt.Errorf("设备 %s 未接入", ref)
	}
	if _, ok := h.bridges.Get(d.ID); !ok {
		return Device{}, errors.New("设备抓包目前只支持接入代理（APK / agent）；ADB 设备请改用 device_proxy 把流量送进 ARTEX 记录代理")
	}
	return d, nil
}

// CaptureStart 在设备上开始抓包（tcpdump → BridgeCapturePath）。
func (h *Hub) CaptureStart(ctx context.Context, ref, iface string, seconds int) (string, error) {
	d, err := h.bridgeOrErr(ctx, ref)
	if err != nil {
		return "", err
	}
	return h.bridges.BridgeCaptureStart(ctx, d.ID, iface, seconds)
}

// CaptureStatus 查看设备上的抓包状态。
func (h *Hub) CaptureStatus(ctx context.Context, ref string) (string, error) {
	d, err := h.bridgeOrErr(ctx, ref)
	if err != nil {
		return "", err
	}
	return h.bridges.BridgeCaptureStatus(ctx, d.ID)
}

// CapturePull 停抓包 → 拉 pcap → 落盘，返回本地路径与字节数。
func (h *Hub) CapturePull(ctx context.Context, ref, destDir string) (string, int64, error) {
	d, err := h.bridgeOrErr(ctx, ref)
	if err != nil {
		return "", 0, err
	}
	if _, err := h.bridges.BridgeCaptureStop(ctx, d.ID); err != nil {
		return "", 0, fmt.Errorf("停止抓包失败: %w", err)
	}
	data, err := h.bridges.BridgePull(ctx, d.ID, BridgeCapturePath, 128<<20)
	if err != nil {
		return "", 0, err
	}
	if len(data) == 0 {
		return "", 0, errors.New("pcap 为空：抓包期间可能没有流量，或设备上没有 tcpdump")
	}
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return "", 0, err
	}
	path := filepath.Join(destDir, "capture-"+time.Now().Format("20060102-150405")+".pcap")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", 0, err
	}
	return path, int64(len(data)), nil
}

// --- 应用管理（PackageManager，接入代理免 root） ---

// Apps 列出设备上的应用（每行：包名 \t 名称 \t 版本 \t system/user）。
func (h *Hub) Apps(ctx context.Context, ref string, thirdParty bool) (string, error) {
	d, ok := h.Get(ctx, ref)
	if !ok {
		return "", fmt.Errorf("设备 %s 未接入", ref)
	}
	if _, ok := h.bridges.Get(d.ID); ok {
		return h.bridges.BridgeApps(ctx, d.ID, thirdParty)
	}
	if d.Platform != PlatformAndroid {
		return "", errors.New("应用管理目前仅支持 Android")
	}
	cmd := "pm list packages"
	if thirdParty {
		cmd += " -3"
	}
	return h.adb.Shell(ctx, d.Serial, cmd)
}

// AppStart 启动一个应用。
func (h *Hub) AppStart(ctx context.Context, ref, pkg string) (string, error) {
	d, ok := h.Get(ctx, ref)
	if !ok {
		return "", fmt.Errorf("设备 %s 未接入", ref)
	}
	if pkg = strings.TrimSpace(pkg); pkg == "" {
		return "", errors.New("pkg 必填")
	}
	if _, ok := h.bridges.Get(d.ID); ok {
		return h.bridges.BridgeAppStart(ctx, d.ID, pkg)
	}
	if d.Platform != PlatformAndroid {
		return "", errors.New("应用管理目前仅支持 Android")
	}
	return h.adb.Shell(ctx, d.Serial, fmt.Sprintf("monkey -p %s -c android.intent.category.LAUNCHER 1", pkg))
}

// AppInfo 返回单个应用的信息。
func (h *Hub) AppInfo(ctx context.Context, ref, pkg string) (string, error) {
	d, ok := h.Get(ctx, ref)
	if !ok {
		return "", fmt.Errorf("设备 %s 未接入", ref)
	}
	if pkg = strings.TrimSpace(pkg); pkg == "" {
		return "", errors.New("pkg 必填")
	}
	if _, ok := h.bridges.Get(d.ID); ok {
		return h.bridges.BridgeAppInfo(ctx, d.ID, pkg)
	}
	if d.Platform != PlatformAndroid {
		return "", errors.New("应用管理目前仅支持 Android")
	}
	return h.adb.Shell(ctx, d.Serial, "dumpsys package "+pkg)
}

// URLOpen 用 ACTION_VIEW 打开 URL / scheme（小程序、deep link）。
func (h *Hub) URLOpen(ctx context.Context, ref, target string) (string, error) {
	d, ok := h.Get(ctx, ref)
	if !ok {
		return "", fmt.Errorf("设备 %s 未接入", ref)
	}
	if target = strings.TrimSpace(target); target == "" {
		return "", errors.New("target 必填")
	}
	if _, ok := h.bridges.Get(d.ID); ok {
		return h.bridges.BridgeURLOpen(ctx, d.ID, target)
	}
	if d.Platform != PlatformAndroid {
		return "", errors.New("拉起 URL 目前仅支持 Android")
	}
	return h.adb.StartActivity(ctx, d.Serial, fmt.Sprintf("-a android.intent.action.VIEW -d '%s'", target))
}

// splitHostPort 把 "host:port"（也接受带 http:// 前缀）拆开。
func splitHostPort(addr string) (string, int, error) {
	addr = strings.TrimSpace(addr)
	addr = strings.TrimPrefix(strings.TrimPrefix(addr, "http://"), "https://")
	addr = strings.TrimSuffix(addr, "/")
	if addr == "" {
		return "", 0, errors.New("代理地址为空")
	}
	idx := strings.LastIndex(addr, ":")
	if idx <= 0 {
		return "", 0, fmt.Errorf("代理地址格式错误（应为 host:port）: %s", addr)
	}
	var port int
	if _, err := fmt.Sscanf(addr[idx+1:], "%d", &port); err != nil || port <= 0 || port > 65535 {
		return "", 0, fmt.Errorf("代理端口非法: %s", addr)
	}
	return addr[:idx], port, nil
}
