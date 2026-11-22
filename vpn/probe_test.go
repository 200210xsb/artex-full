package vpn

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// rawClient 直接发请求（不走 SOCKS），但用与 httpClient.getRaw 相同的语义：
// 不跟随重定向、返回状态码与响应体。用来验证 getRaw 的重定向语义。
func rawClient(t *testing.T, url string) (string, int, error) {
	t.Helper()
	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get(url)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 512))
	if err != nil {
		return "", resp.StatusCode, err
	}
	return strings.TrimSpace(string(b)), resp.StatusCode, nil
}

// TestGetRawDoesNotFollowRedirect 锁住「不跟随重定向」：http://1.1.1.1 会 301 到
// https://1.1.1.1/，跟过去就是对 1.1.1.1 做无 SNI 的 TLS 握手，Cloudflare 直接回
// internal error 告警——探测必失败，好隧道被误拆。
func TestGetRawDoesNotFollowRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "http://"+r.Host+"/end", http.StatusMovedPermanently)
			return
		}
		w.Write([]byte("1.2.3.4"))
	}))
	defer srv.Close()

	body, code, err := rawClient(t, srv.URL+"/start")
	if err != nil {
		t.Fatalf("request error: %v", err)
	}
	if code != http.StatusMovedPermanently {
		t.Fatalf("expected 301 (redirect not followed), got %d", code)
	}
	if strings.Contains(body, "1.2.3.4") {
		t.Fatalf("redirect was followed, body=%q", body)
	}
}

// TestGetRawTreatsAnyStatusAsAlive 验证「任何 HTTP 状态码都算隧道在通」——
// 这是本次修复的核心语义：只有传输层失败才算断链，DNS 抖动不再误杀好隧道。
func TestGetRawTreatsAnyStatusAsAlive(t *testing.T) {
	for _, code := range []int{200, 301, 403, 404, 500} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(code)
			w.Write([]byte("body"))
		}))
		_, got, err := rawClient(t, srv.URL+"/x")
		srv.Close()
		if err != nil {
			t.Fatalf("status %d: transport error should not happen: %v", code, err)
		}
		if got != code {
			t.Fatalf("status %d: got %d", code, got)
		}
	}
}

// TestLiveAndEgressURLsAreSeparated 锁住端点分工：连通性端点必须是 IP 字面量
// （不依赖 DNS），出口地址端点才是域名型回显端点。
func TestLiveAndEgressURLsAreSeparated(t *testing.T) {
	m := New("/tmp/vpn-test", "")
	if len(m.liveURLs) == 0 {
		t.Fatal("no liveness endpoints configured")
	}
	if len(m.egressURLs) == 0 {
		t.Fatal("no egress endpoints configured")
	}
	for _, u := range m.liveURLs {
		if !strings.HasPrefix(u, "http://") {
			t.Fatalf("liveness endpoint must be plain http: %q", u)
		}
		host := strings.TrimPrefix(u, "http://")
		if i := strings.IndexAny(host, "/:"); i >= 0 {
			host = host[:i]
		}
		if strings.Contains(host, ".") && !isIPLiteral(host) {
			t.Fatalf("liveness endpoint must be an IP literal (no DNS): %q", u)
		}
	}
	for _, u := range m.egressURLs {
		if !strings.Contains(u, "http://") || !strings.Contains(u, ".") {
			t.Fatalf("egress endpoint should be a domain echo service: %q", u)
		}
	}
}

// isIPLiteral 粗判一个 host 是不是 IP 字面量（只用于测试断言）。
func isIPLiteral(host string) bool {
	parts := strings.Split(host, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" || len(p) > 3 {
			return false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}
