package llmhunt

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/db"
)

// GitHub 密钥狩猎：在**公开仓库**里找泄漏的模型 key。
//
// 这条线与"打目标"完全分开：只调用 GitHub 自己的搜索/raw API，不接触任何被测站点，
// 因此既不存在"搞崩别人"，也不涉及未授权访问 —— 公开代码里的明文密钥本来就是
// GitHub 自己也在扫的东西（secret scanning）。我们只**登记**，不验证、不使用。
//
// 配额约束（GitHub 代码搜索 10 次/分钟）：每轮最多 8 条 dork、间隔 7 秒；
// raw 文件最多抓 30 个、间隔 1 秒。

const (
	ghSearchGap = 7 * time.Second
	ghFetchGap  = time.Second
	ghMaxFetch  = 30
)

// GitHubKeyHunter 跑一轮 GitHub 密钥狩猎。
type GitHubKeyHunter struct {
	pg           *db.DB
	token        string
	mu           sync.Mutex
	busy         bool
	found        int
	cancel       context.CancelFunc
	dorksDone    int
	filesFetched int
	lastErr      string
}

// NewGitHubKeyHunter 构造。token 为空时从环境或 /root/.artex-gh-token 读。
func NewGitHubKeyHunter(pg *db.DB, token string) *GitHubKeyHunter {
	if strings.TrimSpace(token) == "" {
		token = strings.TrimSpace(os.Getenv("ARTEX_GH_TOKEN"))
	}
	if token == "" {
		if b, err := os.ReadFile("/root/.artex-gh-token"); err == nil {
			token = strings.TrimSpace(string(b))
		}
	}
	return &GitHubKeyHunter{pg: pg, token: token}
}

// Ready 报告 token 是否可用。
func (h *GitHubKeyHunter) Ready() bool { return h.token != "" }

// Found 返回本轮已登记的新 key 数。
func (h *GitHubKeyHunter) Found() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.found
}

// Running 报告是否在跑。
func (h *GitHubKeyHunter) Running() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.busy
}

// githubDorks 是搜索词：按"泄漏最常见"排序。extension/filename 限定能把噪声压下去。
// 搜索词按"实测有结果"来选：GitHub 的代码搜索**不索引 .env 这类文件**，
// 带 path:.env 的查询一律返回 0，所以只用前缀/赋值式。
// 搜索词：GitHub 不索引 .env，`path:.env` 类查询一律返回 0。
// 改用"赋值式 + 扩展名限定"，把范围从文档收到代码/配置里。
var githubDorks = []string{
	`"OPENAI_API_KEY=sk-" extension:py`,
	`"OPENAI_API_KEY=sk-" extension:js`,
	`"sk-proj-" extension:json`,
	`"sk-ant-api03-" extension:py`,
	`"ANTHROPIC_API_KEY=sk-ant" extension:js`,
	`"DEEPSEEK_API_KEY=sk-" extension:py`,
	`"ZHIPUAI_API_KEY=" extension:py`,
	`"LTAI4" extension:py`,
}

// docFileRE 命中这些文件名/扩展的一律跳过：GitHub 搜索 "sk-proj-" 命中的绝大多数是
// README / SETUP / CLAUDE.md 这类文档，里面只有示例占位串。
var docFileRE = regexp.MustCompile(`(?i)(^|/)(readme|setup|claude|promo|changelog|contributing|license|docs?/)|\.(md|mdx|txt|pdf)$`)

// assignmentContext 要求密钥出现在"赋值/JSON 字段"上下文里，
// 进一步排除文档里的裸举例。
func assignmentContext(body, key string) bool {
	i := strings.Index(body, key)
	if i < 0 {
		return false
	}
	start := i - 40
	if start < 0 {
		start = 0
	}
	return strings.ContainsAny(body[start:i], `="': `)
}

// ghSearchResult 是代码搜索返回的一条。
type ghSearchResult struct {
	Repo string
	Path string
	URL  string
}

// Start 异步跑一轮。
//
// ctx 只用于"立刻取消"（比如服务关停），**不能**传 HTTP 请求的 context：
// 请求返回后它会被取消，狩猎循环会立刻退出，表现为"点了按钮什么都没发生"。
func (h *GitHubKeyHunter) Start(ctx context.Context) error {
	if !h.Ready() {
		return fmt.Errorf("没有可用的 GitHub token")
	}
	h.mu.Lock()
	if h.busy {
		h.mu.Unlock()
		return fmt.Errorf("密钥狩猎已在运行")
	}
	runCtx, cancel := context.WithCancel(context.Background())
	h.busy, h.found, h.cancel = true, 0, cancel
	h.dorksDone, h.filesFetched, h.lastErr = 0, 0, ""
	h.mu.Unlock()

	go func() {
		defer func() {
			cancel()
			h.mu.Lock()
			h.busy, h.cancel = false, nil
			h.mu.Unlock()
		}()
		// 刻意**不**监听传入的 ctx：那通常是 HTTP 请求的 context，请求一返回就被取消，
		// 会把整轮狩猎在第一个请求处打断。停止请用 Stop()/服务关停。
		_ = ctx
		h.run(runCtx)
	}()
	return nil
}

// Progress 返回本轮进度，供界面显示"到底做了什么"。
func (h *GitHubKeyHunter) Progress() (dorks, files, found int, lastErr string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.dorksDone, h.filesFetched, h.found, h.lastErr
}

// Stop 取消本轮。
func (h *GitHubKeyHunter) Stop() {
	h.mu.Lock()
	c := h.cancel
	h.mu.Unlock()
	if c != nil {
		c()
	}
}

func (h *GitHubKeyHunter) run(ctx context.Context) {
	client := &http.Client{Timeout: 25 * time.Second}
	fetched := 0
	seenRepo := map[string]bool{}

	for _, dork := range githubDorks {
		if ctx.Err() != nil || fetched >= ghMaxFetch {
			return
		}
		results, err := h.search(ctx, client, dork, 10)
		h.mu.Lock()
		h.dorksDone++
		if err != nil {
			h.lastErr = err.Error()
		}
		h.mu.Unlock()
		if err != nil {
			log.Printf("[keyhunt] 搜索 %q 失败: %v", dork, err)
		}
		time.Sleep(ghSearchGap)
		for _, r := range results {
			if ctx.Err() != nil || fetched >= ghMaxFetch {
				return
			}
			if seenRepo[r.URL] || docFileRE.MatchString(r.Path) {
				continue
			}
			seenRepo[r.URL] = true
			fetched++
			h.mu.Lock()
			h.filesFetched++
			h.mu.Unlock()
			body := h.fetchRaw(ctx, client, r)
			time.Sleep(ghFetchGap)
			if body == "" {
				continue
			}
			h.store(r, body)
		}
	}
}

// search 调一次代码搜索。
func (h *GitHubKeyHunter) search(ctx context.Context, client *http.Client, q string, perPage int) ([]ghSearchResult, error) {
	u := fmt.Sprintf("https://api.github.com/search/code?q=%s&per_page=%d", url.QueryEscape(q), perPage)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+h.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
		return nil, fmt.Errorf("GitHub 返回 %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	var v struct {
		Items []struct {
			Name       string `json:"name"`
			Path       string `json:"path"`
			HTMLURL    string `json:"html_url"`
			Repository struct {
				FullName string `json:"full_name"`
			} `json:"repository"`
		} `json:"items"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&v) != nil {
		return nil, fmt.Errorf("解析搜索结果失败")
	}
	out := make([]ghSearchResult, 0, len(v.Items))
	for _, it := range v.Items {
		out = append(out, ghSearchResult{
			Repo: it.Repository.FullName,
			Path: it.Path,
			URL:  it.HTMLURL,
		})
	}
	return out, nil
}

// fetchRaw 取仓库里的原始文件（公开只读）。
func (h *GitHubKeyHunter) fetchRaw(ctx context.Context, client *http.Client, r ghSearchResult) string {
	if r.Repo == "" || r.Path == "" {
		return ""
	}
	// 用 Contents API 而不是 raw.githubusercontent.com：后者在国内直连超时、
	// 走代理也常 503；api.github.com 是通的（搜索就走它），配额 5000/小时够用。
	u := fmt.Sprintf("https://api.github.com/repos/%s/contents/%s", r.Repo, strings.TrimPrefix(r.Path, "/"))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Authorization", "Bearer "+h.token)
	// raw 直接返回文件内容，不用解 base64
	req.Header.Set("Accept", "application/vnd.github.raw")
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return ""
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, keyBodyLimit))
	return string(b)
}

// store 抽取并落库。
func (h *GitHubKeyHunter) store(r ghSearchResult, body string) {
	for _, kp := range keyPatterns {
		for _, m := range kp.re.FindAllString(body, 20) {
			if !looksLikeRealKey(m) || !assignmentContext(body, m) {
				continue
			}
			sum := sha256.Sum256([]byte(m))
			fp := hex.EncodeToString(sum[:8])
			ok, err := h.pg.InsertLLMKey(&db.LLMKey{
				URL:         r.URL,
				KeyType:     kp.name,
				Raw:         m,
				Masked:      mask(m),
				Fingerprint: fp,
				Context:     "公开仓库 " + r.Repo + " 的 " + r.Path,
				SourceKind:  "github",
				Repo:        r.Repo,
			})
			if err == nil && ok {
				h.mu.Lock()
				h.found++
				h.mu.Unlock()
			}
		}
	}
}

// placeholderRE 命中这些词的多半是示例/文档占位符，不是真 key。
var placeholderRE = regexp.MustCompile(`(?i)(example|sample|dummy|placeholder|changeme|your[-_]|xxxx|\.\.\.|redacted|<[a-z]+>)`)

// looksLikeRealKey 过滤明显不是真 key 的串：占位符、重复字符、过短。
func looksLikeRealKey(k string) bool {
	if len(k) < 20 {
		return false
	}
	if placeholderRE.MatchString(k) {
		return false
	}
	// 同一字符连续出现 6 次以上，基本是填充串
	if regexp.MustCompile(`(.)\1{5,}`).MatchString(k) {
		return false
	}
	return true
}
