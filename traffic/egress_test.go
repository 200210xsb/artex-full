package traffic

import (
	"net/http"
	"net/url"
	"testing"
)

func reqFor(t *testing.T, raw string) *http.Request {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("解析 %q: %v", raw, err)
	}
	return &http.Request{URL: u, Host: u.Host}
}

// CONNECT 请求的 URL 只有 Host（"example.com:443"），普通请求才带 Scheme。
// 端口补错会让探测打错端口，进而把「能直连」判成「要代理」。
func TestEgressAddr(t *testing.T) {
	cases := []struct{ raw, want string }{
		{"https://open.ys7.com/upload", "open.ys7.com:443"},
		{"http://example.com/a/b", "example.com:80"},
		{"https://fs.ys7.com:8443/x", "fs.ys7.com:8443"},
		{"https://1.2.3.4/", "1.2.3.4:443"},
	}
	for _, c := range cases {
		if got := egressAddr(reqFor(t, c.raw)); got != c.want {
			t.Errorf("egressAddr(%q) = %q, 期望 %q", c.raw, got, c.want)
		}
	}
	// CONNECT 形态：URL 只有 Host，没有 Scheme/Path。
	r := &http.Request{URL: &url.URL{Host: "example.com:443"}, Host: "example.com:443"}
	if got := egressAddr(r); got != "example.com:443" {
		t.Errorf("CONNECT 形态 egressAddr = %q, 期望 example.com:443", got)
	}
}

// 后缀匹配必须按标签边界：notys7.com 不能被 ys7.com 命中，否则会把不相干的
// 站点也一起改道。
func TestMatchHostSuffix(t *testing.T) {
	suffixes := []string{"ys7.com", "10.0.0.5"}
	yes := []string{"ys7.com", "open.ys7.com", "a.b.ys7.com", "10.0.0.5"}
	no := []string{"notys7.com", "ys7.com.cn", "ys7com", "10.0.0.55", "example.com"}
	for _, h := range yes {
		if !matchHostSuffix(h, suffixes) {
			t.Errorf("%q 应命中", h)
		}
	}
	for _, h := range no {
		if matchHostSuffix(h, suffixes) {
			t.Errorf("%q 不应命中", h)
		}
	}
	if matchHostSuffix("ys7.com", nil) {
		t.Error("空名单不应命中任何主机")
	}
}

func TestSetEgressRulesParsing(t *testing.T) {
	tf := &Traffic{}
	tf.SetEgressRules(" YS7.com , .Lenovo.com.cn;\nexample.org ", "")
	direct, proxy := tf.EgressRules()
	want := []string{"ys7.com", "lenovo.com.cn", "example.org"}
	if len(direct) != len(want) {
		t.Fatalf("解析结果 %v，期望 %v", direct, want)
	}
	for i := range want {
		if direct[i] != want[i] {
			t.Errorf("第 %d 项 = %q，期望 %q", i, direct[i], want[i])
		}
	}
	if len(proxy) != 0 {
		t.Errorf("空的代理名单应为空，实际 %v", proxy)
	}
}

// 这条覆盖的正是当初的事故路径：配了全局出口代理，国内目标被无脑送去海外
// 节点，同一请求从 0.08s 变成 7.6s，Agent 于是 --noproxy 直连、证据丢失。
// 现在显式规则必须能决定方向，且不需要任何网络探测就能判定。
func TestPreferDirectHonorsRules(t *testing.T) {
	tf := &Traffic{}
	tf.SetUpstreamProxy("socks5://127.0.0.1:7890") // 有全局出口才需要分流
	tf.SetEgressRules("ys7.com", "must-proxy.example.cn")

	cases := []struct {
		url  string
		want bool
	}{
		{"https://fs.ys7.com/upload.php", true},        // 显式直连
		{"https://open.ys7.com/upload", true},          // 子域按后缀命中
		{"https://must-proxy.example.cn/api", false},   // 显式走出口
		{"https://sub.must-proxy.example.cn/api", false},
		{"http://127.0.0.1:8080/x", true},              // 回环：出口到不了
		{"https://10.1.2.3/x", true},                   // 私网：出口到不了
		{"https://192.168.1.1/x", true},
		{"https://[::1]/x", true},                      // IPv6 回环
	}
	for _, c := range cases {
		if got := tf.preferDirect(reqFor(t, c.url)); got != c.want {
			t.Errorf("preferDirect(%q) = %v，期望 %v", c.url, got, c.want)
		}
	}
}

// 显式「走出口」优先于「直连」：安全/合规上要求隐藏源 IP 的目标，不能因为
// 探测通了就被改成直连。
func TestProxyRuleBeatsDirectRule(t *testing.T) {
	tf := &Traffic{}
	tf.SetUpstreamProxy("socks5://127.0.0.1:7890")
	tf.SetEgressRules("example.com", "example.com")
	if tf.preferDirect(reqFor(t, "https://example.com/")) {
		t.Error("两条规则同时命中时应走出口")
	}
}

// 规则热更新必须立刻生效：改完不必重启，否则运维还得为一次名单调整重启服务。
func TestEgressRulesHotReload(t *testing.T) {
	tf := &Traffic{}
	tf.SetUpstreamProxy("socks5://127.0.0.1:7890")
	tf.SetEgressRules("ys7.com", "")
	if !tf.preferDirect(reqFor(t, "https://fs.ys7.com/")) {
		t.Fatal("设为直连后应直连")
	}
	tf.SetEgressRules("", "ys7.com")
	if tf.preferDirect(reqFor(t, "https://fs.ys7.com/")) {
		t.Error("改成走出口后应立即不再直连")
	}
}
