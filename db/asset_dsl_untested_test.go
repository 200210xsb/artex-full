package db

import (
	"strings"
	"testing"
)

// untested 是派生 DSL 字段：true = 未被事实锚点覆盖，false = 已覆盖。
func TestDSLUntestedFieldBuildsCoverageClause(t *testing.T) {
	node, err := ParseDSL("untested=true")
	if err != nil {
		t.Fatalf("parse untested=true: %v", err)
	}
	where, args, err := buildDSLWhere(node)
	if err != nil {
		t.Fatalf("build untested=true: %v", err)
	}
	if len(args) != 0 {
		t.Fatalf("untested clause should not bind args, got %d", len(args))
	}
	if !strings.Contains(where, "NOT EXISTS") {
		t.Fatalf("untested=true should exclude fact-anchored assets, got %q", where)
	}
	if !strings.Contains(where, "exploration_anchors") || !strings.Contains(where, "'fact'") {
		t.Fatalf("untested clause must use fact anchors, got %q", where)
	}

	node, err = ParseDSL("untested=false")
	if err != nil {
		t.Fatalf("parse untested=false: %v", err)
	}
	where, _, err = buildDSLWhere(node)
	if err != nil {
		t.Fatalf("build untested=false: %v", err)
	}
	if strings.Contains(where, "NOT EXISTS") {
		t.Fatalf("untested=false should keep only fact-anchored assets, got %q", where)
	}

	node, err = ParseDSL("untested!=true")
	if err != nil {
		t.Fatalf("parse untested!=true: %v", err)
	}
	where, _, err = buildDSLWhere(node)
	if err != nil {
		t.Fatalf("build untested!=true: %v", err)
	}
	if strings.Contains(where, "NOT EXISTS") {
		t.Fatalf("untested!=true should invert to fact-anchored assets, got %q", where)
	}
}

func TestDSLUntestedFieldRejectsNonBoolean(t *testing.T) {
	if err := ValidateDSL("untested=maybe"); err == nil {
		t.Fatal("untested=maybe should be rejected")
	}
}

// 未测过滤要和用户自己的 DSL 组合使用，AND/OR 优先级不能被破坏。
func TestDSLUntestedCombinesWithUserQuery(t *testing.T) {
	if err := ValidateDSL("(domain=example.com OR ip=203.0.113.10) AND untested=true"); err != nil {
		t.Fatalf("combined DSL rejected: %v", err)
	}
	where, _, err := buildDSLWhere(mustParseTestDSL("(domain=example.com OR ip=203.0.113.10) AND untested=true"))
	if err != nil {
		t.Fatalf("build combined DSL: %v", err)
	}
	if !strings.Contains(where, "NOT EXISTS") {
		t.Fatalf("combined DSL lost the untested filter: %q", where)
	}
}

func mustParseTestDSL(dsl string) *astNode {
	node, err := ParseDSL(dsl)
	if err != nil {
		panic(err)
	}
	return node
}
