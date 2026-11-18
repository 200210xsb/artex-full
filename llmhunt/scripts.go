package llmhunt

import (
	"net/url"
	"regexp"
	"strings"
)

// scriptSrc 抓 <script src="...">：前端 bundle 是 GET-only 场景下密钥最集中的地方
// —— Webpack/Vite 会在构建期把 process.env.XXX 直接内联成字符串字面量。
var scriptSrc = regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+)["']`)

// scriptSources 从首页 HTML 里取出前 limit 个**同源**脚本的绝对 URL。
// 只取同源：跨域的 CDN 资源与被测目标无关，也没必要替第三方发请求。
func scriptSources(html, base string, limit int) []string {
	bu, err := url.Parse(base)
	if err != nil {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, m := range scriptSrc.FindAllStringSubmatch(html, -1) {
		ref := strings.TrimSpace(m[1])
		if ref == "" || strings.HasPrefix(ref, "data:") {
			continue
		}
		u, err := bu.Parse(ref)
		if err != nil || u.Host != bu.Host {
			continue
		}
		// 跳过明显不是 bundle 的资源
		lower := strings.ToLower(u.Path)
		if strings.HasSuffix(lower, ".css") || strings.HasSuffix(lower, ".png") ||
			strings.HasSuffix(lower, ".jpg") || strings.HasSuffix(lower, ".svg") {
			continue
		}
		if !strings.Contains(lower, ".js") {
			continue
		}
		s := u.String()
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
		if len(out) >= limit {
			break
		}
	}
	return out
}

// sourceMapRE 匹配 bundle 末尾的 sourceMappingURL。
var sourceMapRE = regexp.MustCompile(`(?i)sourceMappingURL=([^\s*]+)`)

// sourceMapRef 返回 bundle 里声明的 sourcemap 引用（没有则空串）。
func sourceMapRef(body string) string {
	m := sourceMapRE.FindStringSubmatch(body)
	if m == nil {
		return ""
	}
	return strings.TrimSpace(m[1])
}

// resolveRef 把 sourcemap 的相对引用解析成绝对 URL（同源才返回）。
func resolveRef(base, ref string) (string, error) {
	bu, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	u, err := bu.Parse(strings.TrimSpace(ref))
	if err != nil {
		return "", err
	}
	if u.Host != bu.Host {
		return "", errCrossOrigin
	}
	return u.String(), nil
}

var errCrossOrigin = fmtError("cross-origin ref skipped")

type fmtError string

func (e fmtError) Error() string { return string(e) }
