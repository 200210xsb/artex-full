package agent

import (
	"strings"
	"testing"

	actool "github.com/Autumn-27/norma/tool"
)

// TestRedteamPromptIsAChainAgent pins the 攻防 agent's contract: it exists as a
// built-in prompt, it must build ONE attack chain (not a list of scattered
// findings), and — per the operator's scoring rule — it may only report RCE and
// "三要素" data disclosure.
func TestRedteamPromptIsAChainAgent(t *testing.T) {
	tmpl, ok := BuiltinPromptSeeds()["redteam"]
	if !ok || tmpl == "" {
		t.Fatal("redteam must be a seeded built-in prompt")
	}
	for _, want := range []string{
		"链路五段",
		"资产扩散",
		"JS 逆向",
		"mcp__Subfinder__subfinder_enum",
		"链路拼装",
		"RCE",
		"三要素",
		"身份证号",
		"只作为链路中间步骤使用，不单独上报",
		"范围是只读的",
	} {
		if !strings.Contains(tmpl, want) {
			t.Errorf("redteam prompt missing %q", want)
		}
	}
}

// TestRedteamUsesTheStrictReportingBar guards the wiring: the red-team role must
// receive its own RCE/三要素 bar, not the general one (which allows XSS/SSRF).
func TestRedteamUsesTheStrictReportingBar(t *testing.T) {
	old := FindingTrafficBindingEnabled
	t.Cleanup(func() { FindingTrafficBindingEnabled = old })
	FindingTrafficBindingEnabled = func() bool { return false }

	ts := NewToolSet(nil, "")
	_, red := findingWorkflowTools("redteam", []actool.CoreTool{ts.addFinding()})
	if !strings.Contains(red, "只报 RCE 与三要素泄露") {
		t.Fatalf("redteam guidance missing the strict bar: %q", red)
	}
	if strings.Contains(red, "反射型") {
		t.Fatal("redteam must not inherit the general bar that allows XSS")
	}
	_, general := findingWorkflowTools("worker", []actool.CoreTool{ts.addFinding()})
	if !strings.Contains(general, "反射型") {
		t.Fatal("worker should keep the general bar")
	}
}
