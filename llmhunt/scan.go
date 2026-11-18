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
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/db"
)

const (
	perHostGap     = 1200 * time.Millisecond
	perHostMaxReqs = 8
	globalHosts    = 4
	bodyLimit      = 256 * 1024
	keyBodyLimit   = 64 * 1024
	reqTimeout     = 12 * time.Second
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
	Note          string
}

// Discoverer 执行一次搜索并返回结果 URL。由上层注入（复用 ARTEX 已有的
// web_search 后端），llmhunt 自己不关心是 ddgs/brave/tavily。
type Discoverer func(ctx context.Context, query string, limit int) ([]string, error)

// Scanner 串行化整个进程内的扫描（同时只允许一次）。
type Scanner struct {
	pg       *db.DB
	client   *http.Client
	discover Discoverer

	mu      sync.Mutex
	running bool
	cancel  context.CancelFunc
	scanID  int64
	done    int
	assets  int
	keys    int
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
	if len(opts.Targets) == 0 && len(opts.Dorks) == 0 {
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
	s.mu.Unlock()

	go s.run(ctx, id, opts)
	return id, nil
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

	// 搜索发现：放在后台做，别把 HTTP 请求拖成长连接。
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
	return true
}

// harvestKeys 在授权目标自身的响应里识别密钥。
func (s *Scanner) harvestKeys(ctx context.Context, base string, assetID int64, budget *int, vendor string) {
	candidates := append([]string{"/"}, keyPaths...)
	// 组件自带的工作流接口常常直接回工作流 JSON（里面有 key）。
	switch vendor {
	case "flowise":
		candidates = append([]string{"/api/v1/chatflows"}, candidates...)
	case "langflow":
		candidates = append([]string{"/api/v1/flows/"}, candidates...)
	case "n8n":
		candidates = append([]string{"/rest/workflows"}, candidates...)
	}

	found := 0
	for _, p := range candidates {
		if *budget <= 0 || found >= 20 || ctx.Err() != nil {
			return
		}
		*budget--
		time.Sleep(perHostGap)
		status, body, _ := s.get(ctx, base+p, keyBodyLimit)
		if status != 200 || body == "" {
			continue
		}
		found += s.extractKeys(base+p, assetID, body)
	}
}

// extractKeys 用正则扫响应体，命中即落库（只存原文+掩码，原文不外传）。
func (s *Scanner) extractKeys(srcURL string, assetID int64, body string) int {
	n := 0
	for _, kp := range keyPatterns {
		for _, m := range kp.re.FindAllString(body, 5) {
			if len(m) < 12 {
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
	resp, err := s.client.Do(req)
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
