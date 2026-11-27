package agent

import (
	"encoding/json"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestGuardVulnGoalRejectsFactEvidence(t *testing.T) {
	goal := &db.Node{ID: 1, Kind: db.KindGoal, Payload: json.RawMessage(`{"text":"产出可复现的 SQL 注入漏洞条目","vulnclass":"SQLi"}`)}
	fact := &db.Node{ID: 2, Kind: db.KindFact, Payload: json.RawMessage(`{"summary":"已确认不存在 SQL 注入"}`)}
	if msg := guardVulnGoal(goal, fact); msg == "" {
		t.Fatal("fact evidence must be rejected for a vulnclass goal")
	}
	finding := &db.Node{ID: 3, Kind: db.KindFinding, Payload: json.RawMessage(`{"name":"SQL 注入"}`)}
	if msg := guardVulnGoal(goal, finding); msg != "" {
		t.Fatalf("finding evidence must pass, got: %s", msg)
	}
	noClass := &db.Node{ID: 4, Kind: db.KindGoal, Payload: json.RawMessage(`{"text":"获取 shell"}`)}
	if msg := guardVulnGoal(noClass, fact); msg != "" {
		t.Fatalf("goal without vulnclass must not be gated, got: %s", msg)
	}
}
