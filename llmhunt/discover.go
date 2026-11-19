package llmhunt

import (
	"context"
	"fmt"
	"net/url"
	"strings"
)

// 搜索式发现：用搜索引擎找"大模型实例"的候选站点，再对少量候选做只读指纹。
//
// 为什么用搜索而不是扫网段：扫网段既吵又越界（未授权探测），而且几分钟就会让出口
// IP 进各种黑名单。搜索是"公开面"的聚合，只拿到少量候选，再逐个轻量确认。

// DefaultDorks 是内置的搜索词：一个组件一条，命中即可判定组件类型。
var DefaultDorks = []string{
	`"Ollama" "api/tags"`,        // Ollama 默认 API
	`intitle:"Open WebUI"`,       // Open WebUI 登录页
	`intitle:"ComfyUI"`,          // ComfyUI 控制台
	`"Dify" "console/api/setup"`, // Dify 初始化接口
	`intitle:"Langflow"`,         // Langflow
	`intitle:"Flowise"`,          // Flowise
	`"vLLM" "v1/models"`,         // OpenAI 兼容推理服务
}

// dorkVendor 把搜索词映射到组件名，供后续"只探一个路径"用。
func dorkVendor(dork string) string {
	d := strings.ToLower(dork)
	switch {
	case strings.Contains(d, "ollama"):
		return "ollama"
	case strings.Contains(d, "open webui"), strings.Contains(d, "openwebui"):
		return "open-webui"
	case strings.Contains(d, "comfyui"):
		return "comfyui"
	case strings.Contains(d, "dify"):
		return "dify"
	case strings.Contains(d, "langflow"):
		return "langflow"
	case strings.Contains(d, "flowise"):
		return "flowise"
	case strings.Contains(d, "vllm"), strings.Contains(d, "v1/models"):
		return "openai-compatible"
	case strings.Contains(d, "one api"), strings.Contains(d, "one-api"):
		return "one-api"
	case strings.Contains(d, "new-api"):
		return "new-api"
	}
	return ""
}

// skipHosts 是文档/代码托管站：搜索结果里大量是教程和仓库，不是实例本身。
var skipHosts = []string{
	"github.com", "gitlab.com", "gitee.com", "medium.com", "csdn.net", "juejin.cn",
	"zhihu.com", "stackoverflow.com", "readthedocs.io", "wikipedia.org",
	"youtube.com", "bilibili.com", "x.com", "twitter.com", "reddit.com",
	"npmjs.com", "pypi.org", "docker.com", "hub.docker.com", "arxiv.org",
	// 组件官方站/云服务商：它们本来就提供公开 API，不是"暴露实例"，命中只会污染结果。
	"ollama.com", "ollama.ai", "dify.ai", "langflow.org", "langflow.ai",
	"comfy.org", "comfyui.com", "flowiseai.com", "openwebui.com",
	"openai.com", "anthropic.com", "huggingface.co", "cloudflare.com",
	"amazonaws.com", "aliyuncs.com", "tencentcloudapi.com", "azure.com",
}

func skipResult(href string) (string, bool) {
	u, err := url.Parse(href)
	if err != nil || u.Hostname() == "" {
		return "", false
	}
	host := strings.ToLower(u.Hostname())
	for _, s := range skipHosts {
		if host == s || strings.HasSuffix(host, "."+s) {
			return "", false
		}
	}
	return host, true
}

// discoverTargets 跑完所有搜索词，返回带组件提示的目标。
func (s *Scanner) discoverTargets(ctx context.Context, dorks []string, max int) []Target {
	s.mu.Lock()
	d := s.discover
	s.mu.Unlock()
	if d == nil {
		return nil
	}
	if max <= 0 || max > 200 {
		max = 30
	}
	seen := map[string]bool{}
	var out []Target

	// 1) 空间测绘优先：FOFA/Quake/Shodan 的 key 若已填在 Subfinder 的
	//    provider-config.yaml 里，这里直接查"暴露实例"，命中率远高于搜索引擎。
	if spatial, err := SpatialTargets(ctx, 8); err != nil {
		s.logf("空间测绘查询失败: %v", err)
	} else if len(spatial) > 0 {
		s.logf("空间测绘发现 %d 个候选", len(spatial))
		for _, t := range spatial {
			if len(out) >= max {
				break
			}
			key := t.Host + ":" + fmt.Sprint(t.Port)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, t)
		}
	}

	for _, dork := range dorks {
		if len(out) >= max || ctx.Err() != nil {
			break
		}
		urls, err := d(ctx, dork, 10)
		if err != nil {
			s.logf("搜索 %q 失败: %v", dork, err)
			continue
		}
		vendor := dorkVendor(dork)
		for _, u := range urls {
			if len(out) >= max {
				break
			}
			host, ok := skipResult(u)
			if !ok || seen[host] || seen[host+":443"] || seen[host+":80"] {
				continue
			}
			seen[host] = true
			out = append(out, Target{Host: host, Source: "search", Vendor: vendor})
		}
	}
	return out
}

// logf 简单日志（无外部依赖）。
func (s *Scanner) logf(format string, args ...any) {
	fmt.Printf("[llmhunt] "+format+"\n", args...)
}
