package agent

import (
	"strings"
	"testing"
)

// TestGoalsPromptSplitsEnumeratedVulnClasses 锁住 prompt 里的关键规则：描述里
// 枚举了多类漏洞时，拆解器必须逐类拆成独立目标并标注 vulnclass。
//
// 线上实际发生过：任务描述写「仅对以下高危漏洞开展无损验证：SQL 注入、核心三要素
// 敏感信息未授权访问、任意文件读取、可执行文件上传（非云存储桶）、SSRF、可利用型
// XSS、云存储桶高危配置漏洞」，结果只拆出**一条**泛泛的目标
// 「完成对目标的高危漏洞无损验证…」，7 个独立交付物被压成 1 个 —— 规划者只当
// 一件事做，界面上的"任务目标"也只有一条。
func TestGoalsPromptSplitsEnumeratedVulnClasses(t *testing.T) {
	body := goalsDefaultTmpl
	for _, must := range []string{
		"枚举型漏洞范围必须逐类拆开",
		"必须逐类拆成独立目标",
		"vulnclass",
		"相互独立",
	} {
		if !strings.Contains(body, must) {
			t.Fatalf("goals prompt must mention %q", must)
		}
	}
}
