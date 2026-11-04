package server

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
)

const webuiFixTestHTML = `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">` +
	`<title>ARTEX</title></head><body><div id="__next"></div></body></html>`

// webuiBaseURIUserinfoRE 是脚本里那个正则的 Go 镜像。两边必须一致，否则测试在
// 自欺——所以 TestWebuiInjectBaseURIFixProbe 会断言注入的脚本里逐字含有这个模式。
const webuiBaseURIUserinfoRE = `^[a-z][a-z0-9+.-]*:\/\/[^\/@]*@`

// 脚本必须落在 <head> 之后、正文之前：要赶在 Next 的 module 脚本和 hydration 之前跑。
func TestWebuiInjectBaseURIFixPlacement(t *testing.T) {
	out := webuiInjectBaseURIFix([]byte(webuiFixTestHTML))
	s := string(out)
	if !strings.Contains(s, "artex:cleanurl") {
		t.Fatalf("脚本没插进去: %s", s)
	}
	headEnd := strings.Index(s, "<head>") + len("<head>")
	scriptAt := strings.Index(s, "artex:cleanurl")
	bodyAt := strings.Index(s, "<body>")
	if scriptAt <= headEnd {
		t.Fatalf("脚本位置不对：scriptAt=%d headEnd=%d", scriptAt, headEnd)
	}
	if scriptAt >= bodyAt {
		t.Fatalf("脚本插到 body 之后了：scriptAt=%d bodyAt=%d", scriptAt, bodyAt)
	}
	// 原始内容必须一字不差地保留下来（只多不少）
	if !strings.Contains(s, `<meta charset="utf-8">`) || !strings.Contains(s, `id="__next"`) {
		t.Fatalf("原 HTML 被破坏: %s", s)
	}
}

// 判断依据必须是 document.baseURI 上的 userinfo 正则，而且不能用 location.href：
// 浏览器会把 href 里的凭据剥掉，拿它判断永远探不出来。
func TestWebuiInjectBaseURIFixProbe(t *testing.T) {
	s := string(webuiInjectBaseURIFix([]byte(webuiFixTestHTML)))
	if !strings.Contains(s, "document.baseURI") {
		t.Fatalf("没用 document.baseURI 判断: %s", s)
	}
	if !strings.Contains(s, webuiBaseURIUserinfoRE) {
		t.Fatalf("正则与 Go 侧镜像不一致（改了两边要同步）: %s", s)
	}
	if strings.Contains(s, "location.href") {
		t.Fatalf("不应依赖 location.href（凭据已被浏览器剥离）: %s", s)
	}
	if !strings.Contains(s, "location.replace(location.origin+location.pathname") {
		t.Fatalf("没有换到干净 URL 的逻辑: %s", s)
	}
	if !strings.Contains(s, "sessionStorage") {
		t.Fatalf("缺少重载次数兜底")
	}
}

// 每个标签页只修一次是不够的：用户在同一标签页点书签又进带凭据的地址时，自愈会被
// 一次性标记挡掉（线上实测复现过）。所以判断必须与「修没修过」无关，只与当前
// baseURI 有关——baseURI 干净就什么都不做。这里用 Go 镜像正则跑一遍语义。
func TestWebuiBaseURIUserinfoRegex(t *testing.T) {
	re := regexp.MustCompile(webuiBaseURIUserinfoRE)
	cases := []struct {
		baseURI string
		dirty   bool
	}{
		// 真实的病态输入：地址栏是 http://artex:200210xsb%40XSB@106.54.218.129:8787/...
		{"http://artex:200210xsb%40XSB@106.54.218.129:8787/function/webshell/", true},
		{"http://user@host:8787/", true},
		{"https://u:p@host/", true},
		// 正常输入必须判为干净，否则会无限重载
		{"http://106.54.218.129:8787/function/webshell/", false},
		{"http://106.54.218.129:8787/", false},
		{"https://host:8787/a/b?x=1@2", false}, // @ 在路径里，不是 userinfo
		{"https://host/", false},
		{"", false},
	}
	for _, c := range cases {
		if got := re.MatchString(c.baseURI); got != c.dirty {
			t.Errorf("baseURI=%q 判定=%v，期望 %v", c.baseURI, got, c.dirty)
		}
	}
}

// 重复调用不能插两遍，否则每次导航都会多一个脚本。
func TestWebuiInjectBaseURIFixIdempotent(t *testing.T) {
	once := webuiInjectBaseURIFix([]byte(webuiFixTestHTML))
	twice := webuiInjectBaseURIFix(once)
	if !bytes.Equal(once, twice) {
		t.Fatalf("重复注入改变了内容")
	}
	if n := strings.Count(string(twice), "artex:cleanurl"); n < 1 {
		t.Fatalf("脚本丢了")
	}
	if n := strings.Count(string(twice), "<script>"); n != 1 {
		t.Fatalf("脚本被插了 %d 次", n)
	}
}

// 没有 <head> 的片段原样返回，不要往 <html> 外面乱插。
func TestWebuiInjectBaseURIFixNoHead(t *testing.T) {
	raw := []byte(`<div>plain</div>`)
	if got := webuiInjectBaseURIFix(raw); !bytes.Equal(got, raw) {
		t.Fatalf("无 head 时应原样返回，得到: %s", got)
	}
}

// 带属性的 head（Next 有时会输出 <head data-xxx>）也要能定位。
func TestWebuiInjectBaseURIFixHeadWithAttrs(t *testing.T) {
	s := string(webuiInjectBaseURIFix([]byte(`<html><head data-x="1"><title>a</title></head></html>`)))
	if !strings.Contains(s, `data-x="1"><script>`) {
		t.Fatalf("insert point wrong: %s", s)
	}
}
