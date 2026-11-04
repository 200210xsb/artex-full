package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// bulkPost 调批量改接口，返回响应码与解析后的 JSON。
func bulkPost(t *testing.T, s *Server, body string) (int, map[string]any) {
	t.Helper()
	rec := httptest.NewRecorder()
	s.webshellBulkUpdateSessions(rec, httptest.NewRequest(http.MethodPost,
		"/api/webshell/sessions/bulk", strings.NewReader(body)))
	out := map[string]any{}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

// 批量改只能动那四个字段：参数名（password）、header、url、method 必须原样保留。
//
// 这是最要紧的一条：agent 落的马用随机参数名，页面列表里这个值是打码的，前端拿不到。
// 如果批量改走「整条覆盖」的保存接口，参数名会被重置成 pass，马当场失效。
func TestWebshellBulkUpdateKeepsSensitiveFields(t *testing.T) {
	t.Setenv("ARTEX_WEBSHELL_DIR", t.TempDir())
	s := &Server{}

	// 造一条带随机参数名和自定义头的会话
	rec := httptest.NewRecorder()
	s.webshellSaveSession(rec, httptest.NewRequest(http.MethodPost, "/api/webshell/sessions",
		strings.NewReader(`{"name":"m1","url":"http://x/a.php","type":"php","password":"pusp2jt1",`+
			`"method":"POST","header":{"X-Token":"abc"},"note":"原备注","remote_path":"/var/www/a.php"}`)))
	if rec.Code != 200 {
		t.Fatalf("准备会话失败: %d %s", rec.Code, rec.Body.String())
	}

	code, out := bulkPost(t, s, `{"names":["m1"],"note":"新备注","proxy":"direct","user_agent":"UA-X"}`)
	if code != 200 {
		t.Fatalf("批量改失败: %d %v", code, out)
	}
	store, err := webshellLoadStore(filepath.Join(os.Getenv("ARTEX_WEBSHELL_DIR"), webshellStoreName))
	if err != nil {
		t.Fatal(err)
	}
	sess := store["m1"]
	if sess.Note != "新备注" {
		t.Errorf("备注没改: %q", sess.Note)
	}
	if sess.Proxy != "direct" {
		t.Errorf("出口代理没改: %q", sess.Proxy)
	}
	if sess.UserAgent != "UA-X" {
		t.Errorf("UA 没改: %q", sess.UserAgent)
	}
	// 这几个必须没动
	if sess.Password != "pusp2jt1" {
		t.Errorf("参数名被改了（马会失效）: %q", sess.Password)
	}
	if sess.Header["X-Token"] != "abc" {
		t.Errorf("自定义头被改了: %#v", sess.Header)
	}
	if sess.URL != "http://x/a.php" || sess.Method != "POST" {
		t.Errorf("url/method 被改了: %q %q", sess.URL, sess.Method)
	}
	// 没填的字段保持原值
	if sess.RemotePath != "/var/www/a.php" {
		t.Errorf("没填的落地路径被清空了: %q", sess.RemotePath)
	}
}

// 留空 = 不改；不存在的会话名进 missing，不算错。
func TestWebshellBulkUpdatePartialAndMissing(t *testing.T) {
	t.Setenv("ARTEX_WEBSHELL_DIR", t.TempDir())
	s := &Server{}
	rec := httptest.NewRecorder()
	s.webshellSaveSession(rec, httptest.NewRequest(http.MethodPost, "/api/webshell/sessions",
		strings.NewReader(`{"name":"m1","url":"http://x/a.php","type":"php","note":"n1","proxy":"socks5://1.2.3.4:1080"}`)))
	if rec.Code != 200 {
		t.Fatalf("准备会话失败: %d", rec.Code)
	}

	code, out := bulkPost(t, s, `{"names":["m1","ghost"],"note":"n2"}`)
	if code != 200 {
		t.Fatalf("批量改失败: %d %v", code, out)
	}
	missing, _ := out["missing"].([]any)
	if len(missing) != 1 || missing[0] != "ghost" {
		t.Fatalf("missing 不对: %v", out["missing"])
	}
	store, err := webshellLoadStore(filepath.Join(os.Getenv("ARTEX_WEBSHELL_DIR"), webshellStoreName))
	if err != nil {
		t.Fatal(err)
	}
	if store["m1"].Note != "n2" {
		t.Errorf("备注没改: %q", store["m1"].Note)
	}
	if store["m1"].Proxy != "socks5://1.2.3.4:1080" {
		t.Errorf("留空的出口代理被清了: %q", store["m1"].Proxy)
	}
}

// 参数校验：空名单、没填字段、非法路径、非法代理都要挡下来。
func TestWebshellBulkUpdateValidation(t *testing.T) {
	t.Setenv("ARTEX_WEBSHELL_DIR", t.TempDir())
	s := &Server{}
	cases := []struct{ name, body string }{
		{"名单为空", `{"names":[],"note":"x"}`},
		{"没填字段", `{"names":["a"]}`},
		{"落地路径不是绝对路径", `{"names":["a"],"remote_path":"a.php"}`},
		{"出口代理格式非法", `{"names":["a"],"proxy":"不是代理"}`},
		{"UA 超长", `{"names":["a"],"user_agent":"` + strings.Repeat("u", 600) + `"}`},
	}
	for _, c := range cases {
		code, _ := bulkPost(t, s, c.body)
		if code != 400 {
			t.Errorf("%s: 期望 400，实际 %d", c.name, code)
		}
	}
}
