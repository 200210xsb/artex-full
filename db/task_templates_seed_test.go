package db

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// TestTaskTemplateSeedV2KeysResolvable 守住 v2 增量门最容易犯的错：
// taskTemplatesSeedV2Keys 里写的 nkey 在种子文件里不存在（拼错、改名后忘同步），
// 结果老部署升级后静默地什么都不补，只有用户发现模版没出现时才暴露。
func TestTaskTemplateSeedV2KeysResolvable(t *testing.T) {
	all, err := loadTaskTemplateSeed()
	if err != nil {
		t.Fatalf("loadTaskTemplateSeed: %v", err)
	}
	if len(all) == 0 {
		t.Fatal("种子文件里没有模版")
	}
	byKey := make(map[string]taskTemplateSeed, len(all))
	for _, t := range all {
		byKey[t.NKey] = t
	}
	for _, k := range taskTemplatesSeedV2Keys {
		if _, ok := byKey[k]; !ok {
			t.Fatalf("taskTemplatesSeedV2Keys 里的 %q 在种子文件里不存在", k)
		}
	}
	sub := seedTemplateSubset(all, taskTemplatesSeedV2Keys)
	if len(sub) != len(taskTemplatesSeedV2Keys) {
		t.Fatalf("挑出 %d 个，期望 %d 个", len(sub), len(taskTemplatesSeedV2Keys))
	}
}

// TestTaskTemplateSeedShape 校验每条种子都满足建表的长度约束，
// 否则播种时会被 API 校验挡下（或写进一条空模版）。
func TestTaskTemplateSeedShape(t *testing.T) {
	all, err := loadTaskTemplateSeed()
	if err != nil {
		t.Fatalf("loadTaskTemplateSeed: %v", err)
	}
	seen := map[string]bool{}
	for _, tpl := range all {
		if tpl.NKey == "" || tpl.Name == "" || tpl.Description == "" || tpl.Goal == "" {
			t.Fatalf("模版 %q 有空字段（name/description/goal/nkey 都必填）", tpl.NKey)
		}
		if seen[tpl.NKey] {
			t.Fatalf("nkey 重复: %s", tpl.NKey)
		}
		seen[tpl.NKey] = true
		if n := utf8.RuneCountInString(tpl.Name); n > MaxTaskTemplateNameRunes {
			t.Fatalf("模版 %q 的 name 有 %d 字，超过 %d", tpl.NKey, n, MaxTaskTemplateNameRunes)
		}
		if n := utf8.RuneCountInString(tpl.Goal); n > MaxTaskTemplateTextRunes {
			t.Fatalf("模版 %q 的 goal 有 %d 字，超过 %d", tpl.NKey, n, MaxTaskTemplateTextRunes)
		}
		if n := utf8.RuneCountInString(tpl.Description); n > MaxTaskTemplateTextRunes {
			t.Fatalf("模版 %q 的 description 超长", tpl.NKey)
		}
	}
	// SRC 模版是这一版新增的，必须带可执行的红线与预算，不能是空壳。
	if !seen["src_authorized"] {
		t.Fatal("缺少 src_authorized 模版")
	}
	var src taskTemplateSeed
	for _, x := range all {
		if x.NKey == "src_authorized" {
			src = x
		}
	}
	for _, must := range []string{"一票否决", "接口语义分级", "预算", "RULES_LOADED"} {
		if !strings.Contains(src.Goal, must) {
			t.Fatalf("src_authorized 的 goal 缺少关键段落 %q", must)
		}
	}
}
