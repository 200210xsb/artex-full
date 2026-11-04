package server

// webshell_egress_test.go —— 出口隔离（A 层）的回归。
//
// A 层的目的是让目标侧只看到代理/节点 IP，而不是平台地址。所以这里不只测
// 字符串解析，还要真的跑一次请求，确认请求确实从代理出去了。

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// 测试进程一律不跟随平台代理：跑测试的机器上 7890 很可能真有 sing-box 边车，
// 那样连 httptest 起的 127.0.0.1 目标也会被代理出去，白白失败一片。
// 需要验证跟随行为的用例自己用 t.Setenv 覆盖。
func init() {
	if strings.TrimSpace(os.Getenv("ARTEX_PLATFORM_PROXY")) == "" {
		_ = os.Setenv("ARTEX_PLATFORM_PROXY", "off")
	}
}

func TestWebshellProxyPool(t *testing.T) {
	got := webshellProxyPool("socks5h://a:1080, http://b:8080\nsocks5://c:9050;")
	want := []string{"socks5h://a:1080", "http://b:8080", "socks5://c:9050"}
	if len(got) != len(want) {
		t.Fatalf("拆池结果 = %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("拆池结果 = %v，期望 %v", got, want)
		}
	}
	if len(webshellProxyPool("   ")) != 0 {
		t.Fatal("空白串不应拆出元素")
	}
	// 同一会话必须稳定挑同一个（出口 IP 会变，老换来源 IP 反而更显眼）
	pool := webshellProxyPool("http://a:1,http://b:2")
	first := webshellPickProxy("http://a:1,http://b:2", "http://target/x.php", false)
	if first != pool[0] && first != pool[1] {
		t.Fatalf("挑出了池外的代理: %s", first)
	}
	for i := 0; i < 20; i++ {
		if got := webshellPickProxy("http://a:1,http://b:2", "http://target/x.php", false); got != first {
			t.Fatalf("同一会话的出口应在池内固定，%s != %s", got, first)
		}
	}
	// 显式开启轮换后才允许变
	seen := map[string]bool{}
	for i := 0; i < 60; i++ {
		seen[webshellPickProxy("http://a:1,http://b:2", "http://target/x.php", true)] = true
	}
	if len(seen) < 2 {
		t.Fatalf("开了轮换却始终同一出口: %v", seen)
	}
}

func TestWebshellValidateProxy(t *testing.T) {
	ok := []string{
		"",
		"direct", // 强制直连
		"off",
		"直连",
		"socks5h://127.0.0.1:1080",
		"socks5://user:pa%40ss@proxy.local:1080",
		"http://127.0.0.1:7890",
		"https://u:p@h:8443",
		"http://a:1,http://b:2",
	}
	for _, p := range ok {
		if err := webshellValidateProxy(p); err != nil {
			t.Fatalf("%q 应当通过校验: %v", p, err)
		}
	}
	bad := []string{
		"socks4://h:1080",  // 协议不支持
		"127.0.0.1:1080",   // 缺协议
		"http://",          // 缺主机
		"http://h:8080, ::",
	}
	for _, p := range bad {
		if err := webshellValidateProxy(p); err == nil {
			t.Fatalf("%q 应当被拒", p)
		}
	}
}

func TestWebshellRedactProxy(t *testing.T) {
	got := webshellRedactProxy("socks5h://alice:s3cret@1.2.3.4:1080")
	if strings.Contains(got, "s3cret") || strings.Contains(got, "alice") {
		t.Fatalf("账密没打码: %s", got)
	}
	if !strings.Contains(got, "1.2.3.4:1080") {
		t.Fatalf("主机端口应保留: %s", got)
	}
	if got := webshellRedactProxy(""); got != "" {
		t.Fatalf("空代理应返回空: %q", got)
	}
}

func TestWebshellProxyEnvFallback(t *testing.T) {
	t.Setenv("ARTEX_PLATFORM_PROXY", "off") // 关掉平台代理探测，测试要确定性
	t.Setenv(webshellProxyEnv, "socks5h://127.0.0.1:1080")
	sess := webshellSession{}
	if got := webshellProxyOf(sess); got != "socks5h://127.0.0.1:1080" {
		t.Fatalf("没配会话代理时应回落到环境变量: %s", got)
	}
	if got := webshellEgressLabel(sess); !strings.HasPrefix(got, "平台代理") {
		t.Fatalf("没有会话代理时应标成平台代理: %s", got)
	}
	// 会话配置优先
	sess.Proxy = "http://u:p@1.2.3.4:8080"
	if got := webshellProxyOf(sess); got != sess.Proxy {
		t.Fatalf("会话代理应优先: %s", got)
	}
	if got := webshellEgressLabel(sess); strings.HasPrefix(got, "平台代理") {
		t.Fatalf("会话自己配了代理解析时不该标平台: %s", got)
	}

	t.Setenv(webshellProxyEnv, "")
	if got := webshellEgressLabel(webshellSession{}); !strings.HasPrefix(got, "直连") {
		t.Fatalf("都没配时应显示直连: %s", got)
	}
	// 会话强制直连：即使平台代理在跑也不走
	if got := webshellProxyOf(webshellSession{Proxy: "direct"}); got != "" {
		t.Fatalf("direct 应强制直连: %s", got)
	}
	if got := webshellEgressLabel(webshellSession{Proxy: "direct"}); !strings.HasPrefix(got, "直连") {
		t.Fatalf("强制直连的标签不对: %s", got)
	}
}

// TestWebshellPlatformEgressFollowsSubscription 平台代理在跑时，默认出口就该是它；
// 换节点时地址不变（边车端口固定），变的是背后的节点与出口 IP。
func TestWebshellPlatformEgressFollowsSubscription(t *testing.T) {
	t.Setenv("ARTEX_PLATFORM_PROXY", "")
	t.Setenv(webshellProxyEnv, "")
	sess := webshellSession{URL: "http://t/a.php"}

	// 假边车：本地起一个监听，冒充 mixed 端口不现实（端口固定），所以直接断言
	// 「探测得到 proxyEgressURL 时出口就是它」这条映射，用显式环境变量模拟。
	t.Setenv("ARTEX_PLATFORM_PROXY", proxyEgressURL)
	if got := webshellProxyOf(sess); got != proxyEgressURL {
		t.Fatalf("默认出口应跟随平台代理: %s", got)
	}
	if got := webshellEgressLabel(sess); !strings.Contains(got, "平台代理") {
		t.Fatalf("标签应说明走平台代理: %s", got)
	}
}

// TestWebshellPostViaHTTPProxy 真跑一发：目标域名不可解析，只有代理接得住。
// 代理收到的是绝对 URI（http 代理的转发形态），说明请求确实走了出口。
func TestWebshellPostViaHTTPProxy(t *testing.T) {
	var hits int32
	fp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		if !strings.HasPrefix(r.RequestURI, "http://") {
			t.Errorf("代理收到的不是绝对 URI: %s", r.RequestURI)
		}
		if ua := r.Header.Get("User-Agent"); strings.Contains(strings.ToLower(ua), "artex") {
			t.Errorf("UA 泄露了工具名: %s", ua)
		}
		_, _ = w.Write([]byte("via-proxy"))
	}))
	defer fp.Close()

	sess := webshellSession{
		URL:      "http://target.invalid/a.php", // 故意不可解析：只有走代理才能通
		Type:     "php",
		Password: "pass",
		Method:   "POST",
		Proxy:    fp.URL,
	}
	_, text, err := webshellPost(context.Background(), sess, "x", 5*time.Second)
	if err != nil {
		t.Fatalf("经代理请求失败: %v", err)
	}
	if text != "via-proxy" {
		t.Fatalf("响应 = %q", text)
	}
	if atomic.LoadInt32(&hits) == 0 {
		t.Fatal("代理没收到请求，说明没走出口")
	}
}

// TestWebshellPostDirectByDefault 没配代理时不该被环境变量意外带走：
// 这里显式把全局变量清空，确认走的是直连分支。
func TestWebshellPostDirectByDefault(t *testing.T) {
	t.Setenv(webshellProxyEnv, "")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("direct"))
	}))
	defer ts.Close()

	sess := webshellSession{URL: ts.URL, Type: "php", Password: "pass", Method: "POST"}
	_, text, err := webshellPost(context.Background(), sess, "x", 5*time.Second)
	if err != nil {
		t.Fatalf("直连请求失败: %v", err)
	}
	if text != "direct" {
		t.Fatalf("响应 = %q", text)
	}
	client, label, err := webshellClientFor(sess, time.Second)
	if err != nil || client == nil || label != "直连" {
		t.Fatalf("直连分支不对: label=%q err=%v", label, err)
	}
}

// TestWebshellClientForBadProxy 配错的代理要在发请求前就报出来，不能静默直连。
func TestWebshellClientForBadProxy(t *testing.T) {
	sess := webshellSession{Proxy: "socks4://1.2.3.4:1080"}
	if _, _, err := webshellClientFor(sess, time.Second); err == nil {
		t.Fatal("不支持的协议应当报错")
	}
}
