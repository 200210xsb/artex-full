package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// 前置 Basic 认证的行为契约：未配置不启用、白名单放行、无凭据 401、错误凭据 401、
// 正确凭据放行并把用户名放进 context。任何一条走偏都意味着站点要么敞开要么全挂。
func TestBasicAuth(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u := basicAuthUser(r); u != "" {
			w.Header().Set("X-Basic-User", u)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("page"))
	})
	// s 只用于 JWT 旁路判断；这里给一把 key，方便断言「无 token 不放行」。
	s := &Server{jwtKey: []byte("0123456789abcdef0123456789abcdef")}

	cases := []struct {
		name       string
		env        string
		method     string
		path       string
		user, pass string // Basic 凭据；空 = 不带 Authorization
		bearer     string
		wantCode   int
		wantUser   string
	}{
		{name: "未配置时完全不启用（无凭据 200）", env: "", path: "/", wantCode: 200},
		{name: "未配置时 API 也不拦", env: "", path: "/api/devices", wantCode: 200},
		{name: "配置后页面无凭据 401", env: "artex:200210xsb@XSB", path: "/", wantCode: 401},
		{name: "配置后 API 无凭据 401", env: "artex:200210xsb@XSB", path: "/api/devices", wantCode: 401},
		{name: "密码错误 401", env: "artex:200210xsb@XSB", path: "/", user: "artex", pass: "wrong", wantCode: 401},
		{name: "用户名错误 401", env: "artex:200210xsb@XSB", path: "/", user: "admin", pass: "200210xsb@XSB", wantCode: 401},
		{name: "正确凭据页面 200", env: "artex:200210xsb@XSB", path: "/", user: "artex", pass: "200210xsb@XSB", wantCode: 200, wantUser: "artex"},
		{name: "正确凭据 API 200", env: "artex:200210xsb@XSB", path: "/api/devices", user: "artex", pass: "200210xsb@XSB", wantCode: 200, wantUser: "artex"},
		{name: "白名单 health 无凭据 200", env: "artex:200210xsb@XSB", path: "/api/health", wantCode: 200},
		{name: "白名单 apk 无凭据 200", env: "artex:200210xsb@XSB", path: "/device-agent.apk", wantCode: 200},
		{name: "白名单 ca 无凭据 200", env: "artex:200210xsb@XSB", path: "/device-ca.pem", wantCode: 200},
		{name: "白名单 device-bridge 无凭据 200", env: "artex:200210xsb@XSB", path: "/device-bridge", wantCode: 200},
		{name: "白名单 ws/droid 无凭据 200", env: "artex:200210xsb@XSB", path: "/ws/droid", wantCode: 200},
		{name: "白名单之外的前缀不放行", env: "artex:200210xsb@XSB", path: "/api/healthz", wantCode: 401},
		{name: "非法配置不启用", env: "artex", path: "/", wantCode: 200},
		{name: "保留空密码", env: "artex:", path: "/", user: "artex", pass: "", wantCode: 200, wantUser: "artex"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(basicAuthEnv, tc.env)
			req := httptest.NewRequest(tc.method, tc.path, nil)
			if tc.user != "" || tc.pass != "" {
				req.SetBasicAuth(tc.user, tc.pass)
			}
			if tc.bearer != "" {
				req.Header.Set("Authorization", "Bearer "+tc.bearer)
			}
			w := httptest.NewRecorder()
			s.basicAuth(ok).ServeHTTP(w, req)

			if w.Code != tc.wantCode {
				t.Fatalf("status=%d want %d; body=%s", w.Code, tc.wantCode, w.Body.String())
			}
			if tc.wantCode == 401 {
				if got := w.Header().Get("WWW-Authenticate"); got != `Basic realm="ARTEX"` {
					t.Fatalf("WWW-Authenticate=%q", got)
				}
			}
			if got := w.Header().Get("X-Basic-User"); got != tc.wantUser {
				t.Fatalf("context 用户名=%q want %q", got, tc.wantUser)
			}
		})
	}
}

// 前端对 /api/* 显式带 Bearer JWT，该头会覆盖浏览器缓存的 Basic 凭据。若只认
// Basic，登录之后每个 API 调用都会 401 —— 因此 /api/* 上接受有效 JWT，且仅限
// /api/ 前缀（页面不接受 JWT 旁路）。
func TestBasicAuthAllowsExistingJWTSessionOnAPIOnly(t *testing.T) {
	t.Setenv(basicAuthEnv, "artex:200210xsb@XSB")
	key := []byte("0123456789abcdef0123456789abcdef")
	s := &Server{jwtKey: key}
	tok, err := signJWT(key)
	if err != nil {
		t.Fatal(err)
	}
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	h := s.basicAuth(ok)

	req := httptest.NewRequest("GET", "/api/devices", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("带有效 JWT 的 API 请求 status=%d want 200（否则登录后前端全部掉线）", w.Code)
	}

	// 页面不接受 JWT 旁路：浏览器访问页面时没有 Bearer，只有 Basic。
	req = httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 401 {
		t.Fatalf("页面带 JWT status=%d want 401", w.Code)
	}

	// 伪造/过期令牌不放行。
	req = httptest.NewRequest("GET", "/api/devices", nil)
	req.Header.Set("Authorization", "Bearer not-a-token")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 401 {
		t.Fatalf("无效 JWT status=%d want 401", w.Code)
	}
}
