package server

import (
	"bytes"
	"testing"
)

// 回归守护：HTML 里的静态资源引用不许带 ?v= 版本号。
//
// 带版本号是 0.3.30 的做法，但它把客户端路由搞坏了：HTML 引的是 xxx.js?v=1.2.3，
// flight 载荷引的是 xxx.js，浏览器于是维护两份缓存，运行时按载荷里的地址拿到的
// 往往是用户机器上那份 immutable 的旧 chunk，transition 提交不了——侧边栏点不动。
// 线上 A/B 实测：关掉版本号注入后点击立刻恢复。
func TestWebuiStripAssetVersion(t *testing.T) {
	in := []byte(`<script src="/_next/static/chunks/abc.js?v=0.3.34"></script>` +
		`<link href="/_next/static/css/x.css?v=0.3.34" rel="stylesheet">`)
	out := webuiStripAssetVersion(in)
	if bytes.Contains(out, []byte("?v=")) {
		t.Fatalf("版本号没被剥掉: %s", out)
	}
	for _, want := range []string{"/_next/static/chunks/abc.js", "/_next/static/css/x.css"} {
		if !bytes.Contains(out, []byte(want)) {
			t.Fatalf("资源地址被改坏了，缺 %s: %s", want, out)
		}
	}
}

// 别的查询参数不能被误伤。
func TestWebuiStripAssetVersionKeepsOtherQuery(t *testing.T) {
	in := []byte(`<script src="/_next/static/chunks/abc.js?d=123"></script>`)
	out := webuiStripAssetVersion(in)
	if !bytes.Contains(out, []byte("?d=123")) {
		t.Fatalf("不该动别的查询参数: %s", out)
	}
}

// 干净的 HTML 保持原样。
func TestWebuiStripAssetVersionNoop(t *testing.T) {
	in := []byte(`<script src="/_next/static/chunks/abc.js"></script>`)
	if !bytes.Equal(webuiStripAssetVersion(in), in) {
		t.Fatalf("干净 HTML 被改了")
	}
	if webuiAssetHasVersionTag(in) {
		t.Fatalf("误报有版本号")
	}
}
