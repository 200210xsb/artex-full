package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/llmrec"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/transcript"
)

// 录制的正文必须受上限约束：整段 prompt 进库，一天就能写满数据盘（曾经
// 45GB TOAST 把 PostgreSQL 拖垮）。原文默认不存，需要时显式打开。
func TestRecorderCapsStoredBodies(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer m.Close()
	pg := m.PG()
	if err := pg.EnsureLLMRecordsTable(); err != nil {
		t.Fatalf("ensure table: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "text/event-stream")
		_, _ = io.WriteString(w, "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"m\",\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}}\n\nevent: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"ok\"}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
	}))
	defer srv.Close()

	cfg := agent.Config{Format: llm.FormatAnthropic, BaseURL: srv.URL, APIKey: "k", Model: "caps-test"}
	inner, err := cfg.NewProvider()
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	const session = "exp999998-caps"
	const reqCap = 512
	const respCap = 1024
	rec := llmrec.Wrap(inner, pg, cfg.Model, "caps-test-profile", "", "", func() bool { return true },
		func() llmrec.Limits {
			return llmrec.Limits{MaxRequestBytes: reqCap, MaxResponseBytes: respCap, StoreRaw: false}
		})
	defer func() {
		if _, err := pg.Exec(`DELETE FROM llm_records WHERE session_id = $1`, session); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	big := strings.Repeat("p", 20000)
	ctx := transcript.WithSessionID(context.Background(), session)
	for _, err := range rec.Stream(ctx, llm.CompletionRequest{
		System:    []string{big},
		Messages:  []llm.Message{{Role: "user", Content: []llm.ContentBlock{{Type: "text", Text: big}}}},
		MaxTokens: 64,
	}) {
		if err != nil {
			t.Fatalf("stream: %v", err)
		}
	}

	var id int64
	if err := pg.QueryRow(`SELECT id FROM llm_records WHERE session_id=$1 ORDER BY id DESC LIMIT 1`, session).Scan(&id); err != nil {
		t.Fatalf("no record written: %v", err)
	}
	got, err := pg.GetLLMRecord(id)
	if err != nil {
		t.Fatalf("GetLLMRecord: %v", err)
	}
	if len(got.RequestBody) > reqCap+200 {
		t.Errorf("request_body is %d bytes, cap was %d", len(got.RequestBody), reqCap)
	}
	if !strings.Contains(got.RequestBody, "已截断") {
		t.Error("request_body does not say it was truncated")
	}
	if len(got.ResponseBody) > respCap+200 {
		t.Errorf("response_body is %d bytes, cap was %d", len(got.ResponseBody), respCap)
	}
	if got.RawRequest != "" || got.RawResponse != "" {
		t.Error("raw bodies were stored even though StoreRaw is off")
	}
}
