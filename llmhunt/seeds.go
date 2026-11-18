package llmhunt

import (
	"fmt"
	"net/url"
	"strings"
)

// ParseSeeds 把用户粘贴的清单转成目标：每行可以是
//
//	host / host:port / https://host[:port][/path] / 逗号或空格分隔
//
// 只保留主机与端口，路径丢弃（我们只探固定路径）。
func ParseSeeds(raw string, max int) ([]Target, error) {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ',' || r == ' ' || r == '\t' || r == ';'
	})
	var out []Target
	seen := map[string]bool{}
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f == "" || strings.HasPrefix(f, "#") {
			continue
		}
		t, ok := parseOne(f)
		if !ok {
			continue
		}
		key := fmt.Sprintf("%s:%d", t.Host, t.Port)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, t)
		if max > 0 && len(out) >= max {
			break
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("没有解析出可用目标（每行一个 host、host:port 或 URL）")
	}
	return out, nil
}

func parseOne(f string) (Target, bool) {
	scheme := ""
	if strings.HasPrefix(f, "http://") || strings.HasPrefix(f, "https://") {
		u, err := url.Parse(f)
		if err != nil || u.Hostname() == "" {
			return Target{}, false
		}
		scheme = u.Scheme
		port := 0
		if p := u.Port(); p != "" {
			fmt.Sscanf(p, "%d", &port)
		}
		return Target{Host: u.Hostname(), Port: port, Scheme: scheme, Source: "seed"}, true
	}
	// host:port
	if i := strings.LastIndexByte(f, ':'); i > 0 && !strings.Contains(f, "::") {
		port := 0
		if _, err := fmt.Sscanf(f[i+1:], "%d", &port); err == nil && port > 0 && port <= 65535 {
			return Target{Host: f[:i], Port: port, Source: "seed"}, true
		}
	}
	if strings.ContainsAny(f, "/ ") {
		return Target{}, false
	}
	return Target{Host: f, Source: "seed"}, true
}
