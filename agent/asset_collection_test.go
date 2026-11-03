package agent

import (
	"strings"
	"testing"
)

// TestAssetCollectionRulePinsCollectThenTestContract keeps the code-owned rule
// from silently losing the parts that made it work: the exact deferred-tool
// recipe (the model never used Subfinder without it) and the read-only scope
// statement.
func TestAssetCollectionRulePinsCollectThenTestContract(t *testing.T) {
	body := assetCollectionPrompts("BASE")
	if !strings.HasPrefix(body, "BASE") {
		t.Fatal("rule must be appended after the role prompt, not replace it")
	}
	for _, want := range []string{
		"mcp__Subfinder__subfinder_enum",
		"SearchExtraTools",
		"ExecuteExtraTool",
		"insert_assets",
		"范围是只读的",
		"不要新增根域名",
		"JS 逆向",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("asset collection rule missing %q", want)
		}
	}
}

// TestPentestDefaultPromptIncludesStagedExpansion pins the pentest agent's own
// prompt (not just the code-owned task rule): it must describe the three stages —
// expand assets first, then per-asset recon (JS reverse), then vulnerability
// validation — otherwise a solo run goes straight to hand-rolled probing.
func TestPentestDefaultPromptIncludesStagedExpansion(t *testing.T) {
	for _, want := range []string{
		"第一阶段 · 资产扩散",
		"第二阶段 · 逐资产专项测绘",
		"第三阶段 · 验证与利用",
		"JS 逆向",
		"mcp__Subfinder__subfinder_enum",
		"范围只读",
	} {
		if !strings.Contains(pentestDefaultTmpl, want) {
			t.Errorf("pentest default prompt missing %q", want)
		}
	}
}
