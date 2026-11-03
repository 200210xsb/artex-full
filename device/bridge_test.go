package device

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// startBridgeServer 起一个只处理一条接入代理连接的测试服务端。
func startBridgeServer(t *testing.T, reg *BridgeRegistry, token string) *httptest.Server {
	t.Helper()
	up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		_ = reg.HandleWS(context.Background(), conn, token)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// dialAgent 模拟设备端：连上后发 hello（字段名与官方 APK 一致）。
func dialAgent(t *testing.T, srv *httptest.Server, token, deviceID string) *websocket.Conn {
	t.Helper()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/?token=" + token
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	hello, _ := json.Marshal(map[string]any{
		"t": "hello", "token": token, "deviceId": deviceID,
		"model": "Pixel 8", "androidVersion": "14", "sdkInt": 34, "rooted": true,
	})
	if err := conn.WriteMessage(websocket.TextMessage, hello); err != nil {
		t.Fatalf("hello: %v", err)
	}
	var welcome bridgeFrame
	_, raw, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read welcome: %v", err)
	}
	if err := json.Unmarshal(raw, &welcome); err != nil || welcome.T != bridgeOpWelcome {
		t.Fatalf("welcome frame = %s", raw)
	}
	return conn
}

func waitRegistered(t *testing.T, reg *BridgeRegistry, id string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, ok := reg.Get(id); ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("接入代理 %s 未在超时内注册", id)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestBridgeHelloAndExec 覆盖 hello 握手 + exec 往返，并锁住 reqId 必须原样回传。
func TestBridgeHelloAndExec(t *testing.T) {
	reg := NewBridgeRegistry()
	srv := startBridgeServer(t, reg, "tok")
	conn := dialAgent(t, srv, "tok", "pixel-1")
	waitRegistered(t, reg, "pixel-1")

	go func() {
		for {
			_, raw, err := conn.ReadMessage()
			if err != nil {
				return
			}
			var f bridgeFrame
			if json.Unmarshal(raw, &f) != nil || f.T != BridgeOpShell {
				continue
			}
			if f.ReqID == "" {
				t.Errorf("exec 缺少 reqId: %s", raw)
			}
			out, _ := json.Marshal(map[string]any{
				"t": "result", "reqId": f.ReqID, "ok": true, "stdout": "pong", "code": 0,
			})
			_ = conn.WriteMessage(websocket.TextMessage, out)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := reg.BridgeShell(ctx, "pixel-1", "echo hi", false, 2*time.Second)
	if err != nil {
		t.Fatalf("BridgeShell: %v", err)
	}
	if !strings.Contains(out, "pong") {
		t.Fatalf("BridgeShell out = %q", out)
	}
}

// TestBridgePullChunked 覆盖分片回流：seq 必须递增，字节要按序拼回去。
func TestBridgePullChunked(t *testing.T) {
	reg := NewBridgeRegistry()
	srv := startBridgeServer(t, reg, "tok")
	conn := dialAgent(t, srv, "tok", "pixel-2")
	waitRegistered(t, reg, "pixel-2")

	go func() {
		for {
			_, raw, err := conn.ReadMessage()
			if err != nil {
				return
			}
			var f bridgeFrame
			if json.Unmarshal(raw, &f) != nil || f.T != BridgeOpPull {
				continue
			}
			for seq, part := range []string{"hello", " world"} {
				data, _ := json.Marshal(map[string]any{
					"t": "data", "reqId": f.ReqID, "seq": seq,
					"b64": base64.StdEncoding.EncodeToString([]byte(part)), "done": seq == 1,
				})
				_ = conn.WriteMessage(websocket.TextMessage, data)
			}
			res, _ := json.Marshal(map[string]any{"t": "result", "reqId": f.ReqID, "ok": true})
			_ = conn.WriteMessage(websocket.TextMessage, res)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	data, err := reg.BridgePull(ctx, "pixel-2", "/sdcard/a.txt", 1<<20)
	if err != nil {
		t.Fatalf("BridgePull: %v", err)
	}
	if string(data) != "hello world" {
		t.Fatalf("pull = %q", string(data))
	}
}

// TestBridgeCaptureFrames 覆盖设备抓包的三帧：capture_start / capture_status / capture_stop。
func TestBridgeCaptureFrames(t *testing.T) {
	reg := NewBridgeRegistry()
	srv := startBridgeServer(t, reg, "tok")
	conn := dialAgent(t, srv, "tok", "pixel-3")
	waitRegistered(t, reg, "pixel-3")

	got := make(chan bridgeFrame, 8)
	go func() {
		for {
			_, raw, err := conn.ReadMessage()
			if err != nil {
				return
			}
			var f bridgeFrame
			if json.Unmarshal(raw, &f) != nil {
				continue
			}
			got <- f
			out, _ := json.Marshal(map[string]any{"t": "result", "reqId": f.ReqID, "ok": true, "stdout": "RUNNING"})
			_ = conn.WriteMessage(websocket.TextMessage, out)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if _, err := reg.BridgeCaptureStart(ctx, "pixel-3", "wlan0", 120); err != nil {
		t.Fatalf("BridgeCaptureStart: %v", err)
	}
	start := <-got
	if start.T != "capture_start" || start.Iface != "wlan0" || start.Seconds != 120 {
		t.Fatalf("capture_start frame = %+v", start)
	}

	if _, err := reg.BridgeCaptureStatus(ctx, "pixel-3"); err != nil {
		t.Fatalf("BridgeCaptureStatus: %v", err)
	}
	if f := <-got; f.T != "capture_status" {
		t.Fatalf("capture_status frame = %+v", f)
	}

	if _, err := reg.BridgeCaptureStop(ctx, "pixel-3"); err != nil {
		t.Fatalf("BridgeCaptureStop: %v", err)
	}
	if f := <-got; f.T != "capture_stop" {
		t.Fatalf("capture_stop frame = %+v", f)
	}
}

// TestBridgeTokenMismatch 校验令牌不对时连接被拒、设备不入表。
func TestBridgeTokenMismatch(t *testing.T) {
	reg := NewBridgeRegistry()
	srv := startBridgeServer(t, reg, "right")

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/?token=wrong"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	hello, _ := json.Marshal(map[string]any{"t": "hello", "token": "wrong", "deviceId": "x"})
	_ = conn.WriteMessage(websocket.TextMessage, hello)

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := conn.ReadMessage(); err == nil {
		t.Fatal("令牌错误时连接应被关闭")
	}
	if _, ok := reg.Get("x"); ok {
		t.Fatal("令牌错误的设备不应入表")
	}
}
