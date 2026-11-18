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
	pg    *db.DB
	token string
	mu    sync.Mutex
	busy  bool
	found int
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
var githubDorks = []string{
	`"sk-proj-"`,           // OpenAI 新式 key
	`"OPENAI_API_KEY=sk-"`, // 赋值式，噪声比裸前缀小
	`"sk-ant-api03-"`,      // Anthropic
	`"ANTHROPIC_API_KEY=sk-ant"`,
	`"DEEPSEEK_API_KEY=sk-"`, // DeepSeek
	`"LTAI4"`,                // 阿里云 AccessKey
	`"AKID"`,                 // 腾讯云 SecretId
	`"AIza"`,                 // Google API Key
}

// ghSearchResult 是代码搜索返回的一条。
type ghSearchResult struct {
	Repo string
	Path string
	URL  string
}

// Start 异步跑一轮，返回本轮登记到的新 key 数（通过回调/轮询读取）。
func (h *GitHubKeyHunter) Start(ctx context.Context) error {
	if !h.Ready() {
		return fmt.Errorf("没有可用的 GitHub token")
	}
	h.mu.Lock()
	if h.busy {
		h.mu.Unlock()
		return fmt.Errorf("密钥狩猎已在运行")
	}
	h.busy, h.found = true, 0
	h.mu.Unlock()
	go func() {
		defer func() {
			h.mu.Lock()
			h.busy = false
			h.mu.Unlock()
		}()
		h.run(ctx)
	}()
	return nil
}

func (h *GitHubKeyHunter) run(ctx context.Context) {
	client := &http.Client{Timeout: 25 * time.Second}
	fetched := 0
	seenRepo := map[string]bool{}

	for _, dork := range githubDorks {
		if ctx.Err() != nil || fetched >= ghMaxFetch {
			return
		}
		results := h.search(ctx, client, dork, 10)
		time.Sleep(ghSearchGap)
		for _, r := range results {
			if ctx.Err() != nil || fetched >= ghMaxFetch {
				return
			}
			if seenRepo[r.URL] {
				continue
			}
			seenRepo[r.URL] = true
			fetched++
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
func (h *GitHubKeyHunter) search(ctx context.Context, client *http.Client, q string, perPage int) []ghSearchResult {
	u := fmt.Sprintf("https://api.github.com/search/code?q=%s&per_page=%d", url.QueryEscape(q), perPage)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+h.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil
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
		return nil
	}
	out := make([]ghSearchResult, 0, len(v.Items))
	for _, it := range v.Items {
		out = append(out, ghSearchResult{
			Repo: it.Repository.FullName,
			Path: it.Path,
			URL:  it.HTMLURL,
		})
	}
	return out
}

// fetchRaw 取仓库里的原始文件（公开只读）。
func (h *GitHubKeyHunter) fetchRaw(ctx context.Context, client *http.Client, r ghSearchResult) string {
	if r.Repo == "" || r.Path == "" {
		return ""
	}
	u := fmt.Sprintf("https://raw.githubusercontent.com/%s/HEAD/%s", r.Repo, strings.TrimPrefix(r.Path, "/"))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return ""
	}
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
			if !looksLikeRealKey(m) {
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
