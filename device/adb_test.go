package device

import (
	"context"
	"io"
	"net"
	"strconv"
	"testing"
	"time"
)

// fakeADBServer 起一个只回 OKAY 的假 adb server，把收到的 service 串丢进 channel。
func fakeADBServer(t *testing.T) (string, chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	got := make(chan string, 8)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				hdr := make([]byte, 4)
				if _, err := io.ReadFull(c, hdr); err != nil {
					return
				}
				n, err := strconv.ParseUint(string(hdr), 16, 32)
				if err != nil {
					return
				}
				body := make([]byte, n)
				if _, err := io.ReadFull(c, body); err != nil {
					return
				}
				got <- string(body)
				_, _ = c.Write([]byte("OKAY"))
			}(conn)
		}
	}()
	return ln.Addr().String(), got
}

// TestADBForwardServiceString 锁住 adb 端口转发的 service 串格式：
// 有 serial 时是 host-serial:<serial>:<kind>:<first>:<second>，没有时是 host:<kind>:<first>:<second>。
// 之前这里把分隔符写成了 ";"，adb server 会直接回 FAIL。
func TestADBForwardServiceString(t *testing.T) {
	addr, got := fakeADBServer(t)
	a := NewADB(addr)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := a.Forward(ctx, "emulator-5554", "8080", "8788"); err != nil {
		t.Fatalf("Forward: %v", err)
	}
	if s := <-got; s != "host-serial:emulator-5554:forward:8080:8788" {
		t.Fatalf("forward service = %q", s)
	}

	if err := a.Reverse(ctx, "", "8788", "8080"); err != nil {
		t.Fatalf("Reverse: %v", err)
	}
	if s := <-got; s != "host:reverse:8788:8080" {
		t.Fatalf("reverse service = %q", s)
	}
}

// TestSplitHostPort 覆盖 device_proxy 用到的 host:port 解析。
func TestSplitHostPort(t *testing.T) {
	host, port, err := splitHostPort("192.168.1.10:8788")
	if err != nil || host != "192.168.1.10" || port != 8788 {
		t.Fatalf("splitHostPort = %q %d %v", host, port, err)
	}
	for _, bad := range []string{"", "no-port", ":0", "host:70000"} {
		if _, _, err := splitHostPort(bad); err == nil {
			t.Fatalf("splitHostPort(%q) 应当报错", bad)
		}
	}
}
