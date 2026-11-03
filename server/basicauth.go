package server

import (
	"context"
	"crypto/subtle"
	"log"
	"net/http"
	"os"
	"strings"
)

// HTTP Basic 前置认证：在 ARTEX 自己的登录态之外，再加一层由反向代理/站点级
// 凭据控制的通道。它在 Handler() 里包住整个 root mux，所以页面、静态资源、
// /api/* 一视同仁——浏览器必须先把凭据交上来，才看得到登录页。
//
// 凭据只来自环境变量 ARTEX_BASIC_AUTH=用户名:密码（部署时由 /opt/artex/artex.env
// 注入，权限 600）。未设置时中间件整体不启用，保持旧部署的向后兼容；格式非法时
// 同样不启用并打日志，绝不能因为拼错而悄悄把站点敞开或把所有请求打死。
const (
	basicAuthEnv   = "ARTEX_BASIC_AUTH"
	basicAuthRealm = "ARTEX"
)

// basicAuthExemptPaths 是明确不要求 Basic 的路径。
//   - /device-bridge、/ws/droid：设备端 APK 反连的 WebSocket，自带接入令牌鉴权
//   - /device-agent.apk、/device-ca.pem：手机浏览器直接下载，不该弹登录框
//   - /api/health：监控探活
//
// 这几条都挂在 /api/ 之外（health 除外），因此它们不经过 JWT 中间件。
var basicAuthExemptPaths = map[string]bool{
	"/device-bridge":    true,
	"/ws/droid":         true,
	"/device-agent.apk": true,
	"/device-ca.pem":    true,
	"/api/health":       true,
}

// basicAuthUserKey 是认证成功后写入请求 context 的用户名键。
type basicAuthUserKey struct{}

// basicAuthUser 返回前置认证成功时写入 context 的用户名（未启用/未认证时为空）。
func basicAuthUser(r *http.Request) string {
	u, _ := r.Context().Value(basicAuthUserKey{}).(string)
	return u
}

// basicAuthCredsFromEnv 解析 ARTEX_BASIC_AUTH。ok=false 表示未配置或格式非法，
// 调用方应原样放行（不启用中间件）。
func basicAuthCredsFromEnv() (user, pass string, ok bool) {
	raw := strings.TrimSpace(os.Getenv(basicAuthEnv))
	if raw == "" {
		return "", "", false
	}
	// 密码里允许出现冒号，所以只按第一个冒号切分。
	u, p, found := strings.Cut(raw, ":")
	u = strings.TrimSpace(u)
	if !found || u == "" {
		log.Printf("[basicauth] %s 格式非法（应为 用户名:密码），HTTP Basic 前置认证未启用", basicAuthEnv)
		return "", "", false
	}
	return u, p, true
}

// basicAuth 在 next 外面加一层 HTTP Basic 认证。未配置凭据时直接返回 next，
// 不做任何改动（向后兼容）。
//
// 关于「已持有 ARTEX 登录态」的请求：前端对 /api/* 的请求会显式带上
// `Authorization: Bearer <jwt>`，这个头会覆盖浏览器缓存的 Basic 凭据，所以
// 只认 Basic 会把登录之后的每一个 API 调用都打成 401。因此 /api/* 上还接受
// 一个有效的 ARTEX JWT（Bearer、artex_token cookie 或 ?token=，即登录接口本身
// 签发的令牌）——它只能通过已通过 Basic 的登录页拿到，不会削弱前置认证。
// 页面与静态资源不接受 JWT 旁路，仍然必须交 Basic 凭据。
func (s *Server) basicAuth(next http.Handler) http.Handler {
	user, pass, ok := basicAuthCredsFromEnv()
	if !ok {
		return next
	}
	// 启动日志：运维要能一眼确认闸门到底开没开（不打印密码）。
	log.Printf("[basicauth] HTTP Basic 前置认证已启用: realm=%q 用户名=%q 白名单=%d 条",
		basicAuthRealm, user, len(basicAuthExemptPaths))
	userB, passB := []byte(user), []byte(pass)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if basicAuthExemptPaths[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}
		if u, p, hasBasic := r.BasicAuth(); hasBasic {
			// ConstantTimeCompare 而不是 ==：让比较耗时与凭据内容无关。
			// 长度不同会立即返回 0，这一点对固定用户名的场景没有信息价值。
			userOK := subtle.ConstantTimeCompare([]byte(u), userB) == 1
			passOK := subtle.ConstantTimeCompare([]byte(p), passB) == 1
			if userOK && passOK {
				ctx := context.WithValue(r.Context(), basicAuthUserKey{}, u)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
		} else if strings.HasPrefix(r.URL.Path, "/api/") && s.hasJWTSession(r) {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="`+basicAuthRealm+`"`)
		http.Error(w, "401 Unauthorized: ARTEX Basic authentication required", http.StatusUnauthorized)
	})
}

// hasJWTSession 报告请求是否已带有效的 ARTEX 登录令牌。单独成函数以便测试与
// 明确「这不是绕过，而是已认证的等价证明」的语义。
func (s *Server) hasJWTSession(r *http.Request) bool {
	tok := extractToken(r)
	if tok == "" || len(s.jwtKey) == 0 {
		return false
	}
	return verifyJWT(tok, s.jwtKey)
}
