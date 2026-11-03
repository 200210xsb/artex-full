package agent

import (
	"strings"
	"testing"

	actool "github.com/Autumn-27/norma/tool"
)

// TestFindingQualityGuidanceOnlyForReporters pins the low-value-finding bar: it
// must reach every role that can call report_finding, and must NOT leak into a role
// whose reporting tool was filtered out (the guidance would describe a tool the
// agent cannot call).
func TestFindingQualityGuidanceOnlyForReporters(t *testing.T) {
	old := FindingTrafficBindingEnabled
	t.Cleanup(func() { FindingTrafficBindingEnabled = old })
	FindingTrafficBindingEnabled = func() bool { return false }

	ts := NewToolSet(nil, "")
	_, guidance := findingWorkflowTools("worker", []actool.CoreTool{ts.addFinding()})
	for _, want := range []string{
		"漏洞上报门槛",
		"别刷垃圾",
		"反射型",
		"盲 SSRF",
		"没有实质影响的未授权访问",
		"未授权的低价值信息泄露",
		"组合拳",
		"链条没有真正跑通",
	} {
		if !strings.Contains(guidance, want) {
			t.Errorf("reporter guidance missing %q", want)
		}
	}

	_, silent := findingWorkflowTools("worker", nil)
	if silent != "" {
		t.Fatalf("no report_finding → no guidance, got %q", silent)
	}
}
