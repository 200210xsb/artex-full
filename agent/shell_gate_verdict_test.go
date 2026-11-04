package agent

import (
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// shell 目标的判定要能区分三路证据：活动里有 shell 调用 / 任务资产上有落地会话 /
// 证据里如实写了未取得。缺一路就拒绝，任一条命中就放行。
func TestShellGoalVerdict(t *testing.T) {
	landedYes := func(int64) bool { return true }
	landedNo := func(int64) bool { return false }

	cases := []struct {
		name     string
		usage    int
		expID    int64
		landed   func(int64) bool
		evidence string
		block    bool
	}{
		{"活动里有 shell_add", 1, 17, nil, "", false},
		{"会话落在任务资产上", 0, 17, landedYes, "", false},
		{"两者都没有", 0, 17, landedNo, "", true},
		{"没有 session hook（未接线）", 0, 17, nil, "", true},
		{"证据如实写了未取得", 0, 17, landedNo, "三条路都不通，未取得 shell", false},
		{"expID 为 0 时不能靠 hook 放行", 0, 0, landedYes, "", true},
	}
	for _, c := range cases {
		got := shellGoalVerdict(c.usage, c.expID, c.landed, c.evidence)
		if c.block && got == "" {
			t.Fatalf("%s: 应拒绝，实际放行", c.name)
		}
		if !c.block && got != "" {
			t.Fatalf("%s: 应放行，实际拒绝: %s", c.name, got)
		}
	}
}

// 节点文本抽取：goal 用 text、fact 用 detail，两个字段都要能读出来。
func TestNodeTextFields(t *testing.T) {
	n := &db.Node{Payload: []byte(`{"text":"shell 目标","detail":"细节","summary":"s"}`)}
	txt := nodeText(n)
	for _, want := range []string{"shell 目标", "细节", "s"} {
		if !strings.Contains(txt, want) {
			t.Fatalf("nodeText 缺字段 %q: %q", want, txt)
		}
	}
}
