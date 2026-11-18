package llmhunt

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// BingDork 用 Bing 的网页搜索做 dork 发现。
//
// 为什么内置这一条：ARTEX 的 web_search 后端（ddgs）在很多国内网络里完全不可达
// （实测 duckduckgo 直连与走代理都超时），而 cn.bing.com 是国内可达的。这里只做
// **少量查询**（每次扫描 ≤8 条 dork），只取结果页里的外链，不抓取、不跟随。
var bingLink = regexp.MustCompile(`<a[^>]+href="(https?://[^"]+)"`)

// bingSkip 是搜索引擎自己的域名，结果页里必然出现。
var bingSkip = []string{"bing.com", "microsoft.com", "msn.com", "go.microsoft.com"}

// BingSearch 返回结果页里的外链（去重、限量）。
func BingSearch(ctx context.Context, query string, limit int) ([]string, error) {
	if limit <= 0 || limit > 30 {
		limit = 15
	}
	u := "https://cn.bing.com/search?q=" + url.QueryEscape(query) + "&count=20&setlang=zh-CN&ensearch=0"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	// 用普通 UA：Bing 对明显的脚本 UA 会返回反爬页。
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.6")
	client := &http.Client{Timeout: 12 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))

	seen := map[string]bool{}
	var out []string
	for _, m := range bingLink.FindAllStringSubmatch(string(body), -1) {
		link := strings.TrimSpace(m[1])
		// Bing 会把结果包成 /ck/a?u=... 的跳转，取不到真实域名就跳过。
		if strings.Contains(link, "bing.com/ck/") || strings.Contains(link, "microsoft.com") {
			continue
		}
		lower := strings.ToLower(link)
		skip := false
		for _, s := range bingSkip {
			if strings.Contains(lower, s) {
				skip = true
				break
			}
		}
		if skip || seen[link] {
			continue
		}
		seen[link] = true
		out = append(out, link)
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}
