package agent

import "testing"

func TestAppendPromptAppendix(t *testing.T) {
	// 未设置钩子:提示词逐字不变(未绑定专项 agent 的任务必须保持原行为)。
	base := "系统提示词正文"
	if got := appendPromptAppendix(base, nil); got != base {
		t.Fatalf("nil appendix changed prompt: %q", got)
	}
	// 返回空串 / 纯空白:同样不改提示词。
	if got := appendPromptAppendix(base, func() string { return "" }); got != base {
		t.Fatalf("empty appendix changed prompt: %q", got)
	}
	if got := appendPromptAppendix(base, func() string { return "  \n\t " }); got != base {
		t.Fatalf("blank appendix changed prompt: %q", got)
	}
	// 有内容:追加在末尾,且不改动原正文。
	got := appendPromptAppendix(base, func() string { return "=== 专项指引 ===" })
	want := base + "\n\n=== 专项指引 ==="
	if got != want {
		t.Fatalf("appendix appended wrongly:\n got: %q\nwant: %q", got, want)
	}
}

func TestAppendPromptAppendixOnlyAppends(t *testing.T) {
	base := "AAAA"
	got := appendPromptAppendix(base, func() string { return "BBBB" })
	if len(got) <= len(base) || got[:len(base)] != base {
		t.Fatalf("appendix must not replace the original prompt: %q", got)
	}
}
