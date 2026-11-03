package server

import (
	"context"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/device"
	"github.com/gorilla/websocket"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/skip2/go-qrcode"
)

// 移动端设备接入（Device Lab）的服务端：
//   - REST：设备列表 / 接入 / 移除 / 备注 / shell / 截图；
//   - WebSocket：接入代理（设备端 artex-device-agent 主动回连）；
//   - host 工具：device_* / mini_* 工具注入 agent 工具集。

// deviceHub 返回设备中心（惰性初始化，保证 PG 就绪后仍可用）。
func (s *Server) deviceHub() *device.Hub {
	s.deviceMu.Lock()
	defer s.deviceMu.Unlock()
	if s.devices == nil {
		var store device.Store
		if s.m != nil && s.m.pg != nil {
			store = s.m.pg.Devices()
		}
		s.devices = device.NewHub(store)
	}
	return s.devices
}

// deviceBridgeToken 返回接入代理令牌（不存在则生成并落盘到数据目录）。
func (s *Server) deviceBridgeToken() string {
	s.deviceMu.Lock()
	defer s.deviceMu.Unlock()
	if s.bridgeToken != "" {
		return s.bridgeToken
	}
	dir := "."
	if s.m != nil && s.m.dir != "" {
		dir = s.m.dir
	}
	tok, err := device.LoadOrCreateBridgeToken(dir)
	if err != nil {
		log.Printf("[device] 生成接入代理令牌失败: %v", err)
		return ""
	}
	s.bridgeToken = tok
	return tok
}

// pgListDevices 返回已接入设备（含实时枚举）。
func (s *Server) pgListDevices(w http.ResponseWriter, _ *http.Request) {
	hub := s.deviceHub()
	devs := hub.List(context.Background())
	writeJSON(w, http.StatusOK, map[string]any{
		"devices":       devs,
		"total":         len(devs),
		"adb_server":    hub.ADB().Addr(),
		"adb_available": hub.ADB().Available(context.Background()),
		"ios_available": hub.IOS().Available(),
	})
}

// pgCreateDevice 接入一台设备（Android: adb connect；iOS: 登记 UDID）。
func (s *Server) pgCreateDevice(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Platform string `json:"platform"`
		Address  string `json:"address"`
		Name     string `json:"name"`
		Note     string `json:"note"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	platform := device.Platform(strings.TrimSpace(req.Platform))
	if platform != device.PlatformAndroid && platform != device.PlatformIOS {
		writeErr(w, http.StatusBadRequest, "platform 必须是 android 或 ios")
		return
	}
	if strings.TrimSpace(req.Address) == "" {
		writeErr(w, http.StatusBadRequest, "address 必填")
		return
	}
	d, err := s.deviceHub().Connect(context.Background(), platform, req.Address, req.Name, req.Note)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, d)
}

// pgDeleteDevice 把设备移出登记表。
func (s *Server) pgDeleteDevice(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeErr(w, http.StatusBadRequest, "设备 id 为空")
		return
	}
	if err := s.deviceHub().Disconnect(id); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
}

// pgUpdateDevice 更新设备备注/标签。
func (s *Server) pgUpdateDevice(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	var req struct {
		Note string   `json:"note"`
		Tags []string `json:"tags"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	if err := pg.Devices().UpdateDeviceNote(id, req.Note, req.Tags); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"updated": id})
}

// pgDeviceShell 在设备上执行一条命令（前端「设备调试」用）。
func (s *Server) pgDeviceShell(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	var req struct {
		Cmd     string `json:"cmd"`
		Timeout int    `json:"timeout"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if strings.TrimSpace(req.Cmd) == "" {
		writeErr(w, http.StatusBadRequest, "cmd 必填")
		return
	}
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = 60
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(timeout)*time.Second)
	defer cancel()
	out, err := s.deviceHub().Shell(ctx, id, req.Cmd)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"output": out})
}

// deviceAPKDir 是放接入代理 APK 的目录（数据目录下的 apk/）。
func (s *Server) deviceAPKDir() string {
	dir := "."
	if s.m != nil && s.m.dir != "" {
		dir = s.m.dir
	}
	return filepath.Join(dir, "apk")
}

// deviceAgentAPK 下发接入代理 APK：手机浏览器直接下载，不需要登录态
// （设备此时还没有 ARTEX 会话，和 /ws/droid 同理）。
func (s *Server) deviceAgentAPK(w http.ResponseWriter, r *http.Request) {
	matches, _ := filepath.Glob(filepath.Join(s.deviceAPKDir(), "*.apk"))
	if len(matches) == 0 {
		writeErr(w, http.StatusNotFound, "APK 未上传：把 sentinel-droidbridge-*.apk 放到 "+s.deviceAPKDir())
		return
	}
	best := ""
	var bestTime time.Time
	for _, m := range matches {
		st, err := os.Stat(m)
		if err != nil {
			continue
		}
		if st.ModTime().After(bestTime) {
			best, bestTime = m, st.ModTime()
		}
	}
	if best == "" {
		writeErr(w, http.StatusNotFound, "APK 目录为空")
		return
	}
	w.Header().Set("Content-Type", "application/vnd.android.package-archive")
	w.Header().Set("Content-Disposition", `attachment; filename="artex-device-agent.apk"`)
	http.ServeFile(w, r, best)
}

// pgDeviceScreenshot 设备截屏（返回 PNG 字节流）。
func (s *Server) pgDeviceScreenshot(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	data, err := s.deviceHub().Screenshot(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	_, _ = w.Write(data)
}

// bridgePairURL 拼接设备配对用的反连地址：ws(s)://<当前访问的主机>/ws/droid?token=…
// 用请求里的 Host 而不是写死端口——反向代理/域名/端口映射的情况都能对上。
// 路径用 /ws/droid：官方 sentinel-droidbridge APK 就是按这个约定连的。
func (s *Server) bridgePairURL(r *http.Request) (endpoint, pair string) {
	scheme := "ws"
	if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		scheme = "wss"
	}
	endpoint = scheme + "://" + r.Host + "/ws/droid"
	return endpoint, endpoint + "?token=" + s.deviceBridgeToken()
}

// pgDeviceBridgeInfo 返回接入代理（bridge）的接入信息：令牌 + 端点 + 配对地址 + 示例命令。
func (s *Server) pgDeviceBridgeInfo(w http.ResponseWriter, r *http.Request) {
	tok := s.deviceBridgeToken()
	endpoint, pair := s.bridgePairURL(r)
	writeJSON(w, http.StatusOK, map[string]any{
		"token":    tok,
		"endpoint": endpoint,
		"pair_url": pair,
		"example":  "artex-device-agent --server '" + pair + "' --name <设备名>",
		"hint": "设备端主动回连，手机无需开放端口；扫码拿到同一条 pair_url，agent 会把查询串里的 token 取出来用。",
	})
}

// pgDevicePairQR 把配对地址渲染成二维码 PNG（前端直接展示，手机扫码即得反连地址 + token）。
func (s *Server) pgDevicePairQR(w http.ResponseWriter, r *http.Request) {
	_, pair := s.bridgePairURL(r)
	png, err := qrcode.Encode(pair, qrcode.Medium, 360)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", strconv.Itoa(len(png)))
	_, _ = w.Write(png)
}

// pgDeviceCaptureStart 在设备上开 tcpdump。
func (s *Server) pgDeviceCaptureStart(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	var req struct {
		Iface   string `json:"iface"`
		Seconds int    `json:"seconds"`
	}
	_ = decode(r, &req)
	out, err := s.deviceHub().CaptureStart(r.Context(), id, req.Iface, req.Seconds)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"output": out})
}

// pgDeviceCaptureStatus 报告设备上的抓包状态。
func (s *Server) pgDeviceCaptureStatus(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	out, err := s.deviceHub().CaptureStatus(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"output": out})
}

// pgDeviceCapturePull 停止抓包、把 pcap 拉回数据目录，返回落盘路径。
func (s *Server) pgDeviceCapturePull(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	dir := filepath.Join(s.m.dir, "captures")
	path, size, err := s.deviceHub().CapturePull(r.Context(), id, dir)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"path": path, "bytes": size})
}

var bridgeUpgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	// 接入代理来自内网设备，允许任意来源（令牌校验才是真正的门）。
	CheckOrigin: func(r *http.Request) bool { return true },
}

// deviceBridgeWS 是接入代理的 WebSocket 入口。刻意挂在 /device-bridge（不在 /api/ 下），
// 因为设备端 agent 没有 ARTEX 的登录态——它用独立令牌鉴权。
func (s *Server) deviceBridgeWS(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSpace(r.URL.Query().Get("token"))
	if token == "" {
		token = strings.TrimSpace(s.deviceBridgeToken())
	}
	if token == "" || r.URL.Query().Get("token") != token {
		writeErr(w, http.StatusUnauthorized, "接入令牌无效")
		return
	}
	conn, err := bridgeUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[device] 接入代理握手失败: %v", err)
		return
	}
	if err := s.deviceHub().Bridges().HandleWS(r.Context(), conn, token); err != nil {
		log.Printf("[device] 接入代理断开: %v", err)
	}
}

// deviceTools 返回移动端设备接入的 host 工具。
func (s *Server) deviceTools() []actool.CoreTool {
	return s.deviceHub().Tools()
}

// deviceProxyConfig 返回给前端的接入参数：记录代理地址 + 手机可达的局域网地址 + CA 路径。
func (s *Server) deviceProxyConfig(r *http.Request) map[string]any {
	addr, ca := "", ""
	if s.m != nil {
		addr = s.m.ProxyAddr()
		ca = s.m.ProxyCACert()
	}
	// 手机要的是「宿主在局域网里的地址 + 代理端口」，不是容器内的 127.0.0.1。
	lan := ""
	if addr != "" {
		if u, err := url.Parse(addr); err == nil && u.Port() != "" {
			host := r.Host
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}
			if host == "" {
				host = "127.0.0.1"
			}
			lan = host + ":" + u.Port()
		}
	}
	return map[string]any{
		"proxy_addr":     addr,
		"proxy_addr_lan": lan,
		"ca_path":        ca,
		"capture_on":     ca != "",
	}
}

// pgDeviceProxyConfig 是 deviceProxyConfig 的 HTTP 入口。
func (s *Server) pgDeviceProxyConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.deviceProxyConfig(r))
}

// pgDeviceProxy 给一台设备设置/清除系统代理（Android；ADB 与接入代理都支持）。
func (s *Server) pgDeviceProxy(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	var req struct {
		Action string `json:"action"`
		Addr   string `json:"addr"`
	}
	_ = decode(r, &req)

	if strings.EqualFold(strings.TrimSpace(req.Action), "clear") {
		out, err := s.deviceHub().ClearProxy(r.Context(), id)
		if err != nil {
			writeErr(w, http.StatusBadGateway, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"output": out})
		return
	}

	addr := strings.TrimSpace(req.Addr)
	ca := ""
	if s.m != nil {
		ca = s.m.ProxyCACert()
	}
	if addr == "" {
		if v, ok := s.deviceProxyConfig(r)["proxy_addr_lan"].(string); ok {
			addr = v
		}
	}
	if addr == "" {
		writeErr(w, http.StatusBadRequest, "代理地址为空：先打开流量录制，或显式传 addr")
		return
	}
	out, err := s.deviceHub().SetProxy(r.Context(), id, addr, ca)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"output": out, "addr": addr})
}

// deviceCA 下发记录代理的 CA 证书：手机装了它才能解 HTTPS 明文。
func (s *Server) deviceCA(w http.ResponseWriter, r *http.Request) {
	path := ""
	if s.m != nil {
		path = s.m.ProxyCACert()
	}
	if path == "" {
		writeErr(w, http.StatusNotFound, "流量录制未开启，CA 还没生成")
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="artex-ca.pem"`)
	http.ServeFile(w, r, path)
}
