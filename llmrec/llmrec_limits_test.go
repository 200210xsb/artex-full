package llmrec

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestClipBodyKeepsShortBodyUntouched(t *testing.T) {
	const body = "short prompt"
	if got := clipBody(body, 1024); got != body {
		t.Errorf("clipBody rewrote a body under the cap: %q", got)
	}
}

func TestClipBodyTruncatesAndMarks(t *testing.T) {
	body := strings.Repeat("a", 5000)
	got := clipBody(body, 1024)
	if len(got) >= len(body) {
		t.Fatalf("body was not truncated: %d bytes", len(got))
	}
	if !strings.Contains(got, "已截断") {
		t.Errorf("truncated body does not say it was truncated: %q", got[:80])
	}
	if !strings.Contains(got, "5000") {
		t.Errorf("truncated body does not report the original size: %q", got[:120])
	}
}

func TestClipBodyZeroCapMeansUnlimited(t *testing.T) {
	body := strings.Repeat("a", 10000)
	if got := clipBody(body, 0); got != body {
		t.Errorf("cap 0 should keep the whole body, got %d bytes", len(got))
	}
}

func TestClipBodyKeepsValidUTF8(t *testing.T) {
	// A cap that lands in the middle of a multi-byte rune must not leave a
	// broken rune in the stored text — the UI renders it as-is.
	body := strings.Repeat("中", 100)
	got := clipBody(body, 5)
	if !utf8.ValidString(got) {
		t.Errorf("truncated body is not valid UTF-8: %q", got)
	}
}

func TestDefaultLimitsAreBounded(t *testing.T) {
	lim := DefaultLimits()
	if lim.MaxRequestBytes <= 0 || lim.MaxResponseBytes <= 0 {
		t.Fatalf("default limits are unbounded: %+v", lim)
	}
	if lim.StoreRaw {
		t.Error("default limits should not store the raw wire bodies")
	}
}

func TestLimitsOrDefaultFallsBackWhenUnset(t *testing.T) {
	r := &Recorder{}
	if got := r.limitsOrDefault(); got != DefaultLimits() {
		t.Errorf("limitsOrDefault() = %+v, want defaults", got)
	}
	custom := Limits{MaxRequestBytes: 7, MaxResponseBytes: 9, StoreRaw: true}
	r2 := &Recorder{limits: func() Limits { return custom }}
	if got := r2.limitsOrDefault(); got != custom {
		t.Errorf("limitsOrDefault() = %+v, want %+v", got, custom)
	}
}
