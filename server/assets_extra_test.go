package server

import (
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestParseAssetIDList(t *testing.T) {
	ids, err := parseAssetIDList(" 3,1,3,,2 ")
	if err != nil {
		t.Fatalf("parse ids: %v", err)
	}
	if len(ids) != 3 || ids[0] != 3 || ids[1] != 1 || ids[2] != 2 {
		t.Fatalf("unexpected ids: %v", ids)
	}
	if _, err := parseAssetIDList("1,abc"); err == nil {
		t.Fatal("non-numeric id should be rejected")
	}
	if ids, err := parseAssetIDList(""); err != nil || len(ids) != 0 {
		t.Fatalf("empty list: ids=%v err=%v", ids, err)
	}
}

func TestPocSeverityAndCategoryGate(t *testing.T) {
	for _, sev := range []string{"critical", "high", "medium"} {
		if !pocSeverityAllowed(sev) {
			t.Fatalf("severity %s should be allowed", sev)
		}
	}
	for _, sev := range []string{"low", "info", "unknown", ""} {
		if pocSeverityAllowed(sev) {
			t.Fatalf("severity %s should be rejected", sev)
		}
	}

	if !pocDangerousCategory(pocTemplate{Tags: "cve,rce", Name: "x"}) {
		t.Fatal("rce template should be eligible")
	}
	if !pocDangerousCategory(pocTemplate{Tags: "file-upload", Name: "x"}) {
		t.Fatal("file-upload template should be eligible")
	}
	if !pocDangerousCategory(pocTemplate{Tags: "misc", Name: "x", Description: "Arbitrary File Write in foo"}) {
		t.Fatal("description keyword should make a template eligible")
	}
	if pocDangerousCategory(pocTemplate{Tags: "misconfig,cve", Name: "x", Description: "信息泄露"}) {
		t.Fatal("non-dangerous template should be rejected")
	}
}

func TestPocClassifyDangerTiers(t *testing.T) {
	score, tier, label, advice := pocClassifyDanger(pocTemplate{Tags: "cve,rce"})
	if score != 100 || tier != "A" || label == "" || advice == "" {
		t.Fatalf("rce template classified as score=%d tier=%s label=%q", score, tier, label)
	}
	score, tier, _, _ = pocClassifyDanger(pocTemplate{Tags: "file-upload"})
	if score != 88 || tier != "B" {
		t.Fatalf("file-upload template classified as score=%d tier=%s", score, tier)
	}
	score, tier, _, _ = pocClassifyDanger(pocTemplate{Tags: "deserialization"})
	if score != 72 || tier != "C" {
		t.Fatalf("deserialization template classified as score=%d tier=%s", score, tier)
	}
	score, tier, _, _ = pocClassifyDanger(pocTemplate{Tags: "sqli"})
	if score != 48 || tier != "D" {
		t.Fatalf("sqli template classified as score=%d tier=%s", score, tier)
	}
}

func TestPocFingerprintTokensAndMatch(t *testing.T) {
	fp := db.AssetFingerprint{
		ID:           7,
		Type:         "service",
		Label:        "https://example.com",
		URL:          "https://example.com",
		PageTitle:    "Apache Tomcat/9.0 管理后台",
		Technologies: []string{"Apache Tomcat", "Java", "HTTP Server"},
	}
	tokens := pocFingerprintTokens(fp)
	joined := ""
	for _, token := range tokens {
		joined += token + " "
	}
	for _, want := range []string{"apache", "tomcat", "java"} {
		found := false
		for _, token := range tokens {
			if token == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("token %q missing from %q", want, joined)
		}
	}
	for _, unwanted := range []string{"http", "server", "com"} {
		for _, token := range tokens {
			if token == unwanted {
				t.Fatalf("generic token %q should be filtered out (%q)", unwanted, joined)
			}
		}
	}

	tpl := pocTemplate{ID: "CVE-2020-1938", Name: "Ghostcat AJP", Tags: "tomcat,rce,ghostcat", Path: "http/cves/2020/CVE-2020-1938.yaml"}
	tpl.words = pocTemplateWords(tpl)
	matched := pocMatchTokens(tpl, tokens)
	if len(matched) == 0 {
		t.Fatalf("tomcat template did not match tokens %q", joined)
	}
}

// 倒排索引取到的关键词必须与直接匹配一致。
func TestPocMatchedTokensKeepsOnlyAssetOwnTokens(t *testing.T) {
	globalTokens := []string{"tomcat", "java", "php"}
	hit := []int{0, 2}
	got := matchedTokens(hit, globalTokens, []string{"java", "tomcat"})
	if len(got) != 1 || got[0] != "tomcat" {
		t.Fatalf("unexpected matched tokens: %v", got)
	}
	if extra := matchedTokens(hit, globalTokens, []string{"nginx"}); len(extra) != 0 {
		t.Fatalf("unrelated asset should not inherit matches: %v", extra)
	}
}
