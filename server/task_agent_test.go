package server

import (
	"strings"
	"testing"
)

func TestTaskAgentGuideBlock(t *testing.T) {
	// agent 没有可用提示词 => 不追加任何内容(任务行为与未绑定时一致)。
	if got := taskAgentGuideBlock("mobile", "移动端", "   "); got != "" {
		t.Fatalf("empty prompt must produce no guide, got %q", got)
	}
	guide := taskAgentGuideBlock("mobile", "移动端 APP 测试", "先脱壳，再看接口。")
	if !strings.Contains(guide, "=== 本次任务专项指引（来自 agent: mobile）===") {
		t.Fatalf("guide missing separator marker:\n%s", guide)
	}
	if !strings.Contains(guide, "先脱壳，再看接口。") {
		t.Fatalf("guide missing agent prompt body:\n%s", guide)
	}
	if !strings.Contains(guide, "移动端 APP 测试") {
		t.Fatalf("guide missing agent name:\n%s", guide)
	}
}

func TestTaskAgentGuideBlockTruncates(t *testing.T) {
	long := strings.Repeat("测", maxTaskAgentGuideRunes+500)
	guide := taskAgentGuideBlock("mobile", "移动端", long)
	if !strings.Contains(guide, "已截断") {
		t.Fatalf("over-long prompt must be reported as truncated:\n%s", guide[:200])
	}
	// 截断后正文长度应受限(加上标记/说明仍远小于原文)。
	body := strings.Count(guide, "测")
	if body > maxTaskAgentGuideRunes {
		t.Fatalf("truncated guide still too long: %d runes of body", body)
	}
}

func TestOptionalAgentKey(t *testing.T) {
	if got := optionalAgentKey(""); got != nil {
		t.Fatalf("optionalAgentKey(\"\") = %v, want nil", got)
	}
	got := optionalAgentKey("mobile")
	if got == nil || *got != "mobile" {
		t.Fatalf("optionalAgentKey(\"mobile\") = %v, want pointer to mobile", got)
	}
}
