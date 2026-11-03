package llm

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// anthropicReplayRejection is the exact 400 an Anthropic-compatible gateway
// returns when the request ran in thinking mode but the replayed history carried
// no thinking block (seen in production with a thinking-by-default model whose
// profile left thinking_type unset).
const anthropicReplayRejection = `{"type":"error","error":{"type":"invalid_request_error",` +
	`"message":"The ` + "`content[].thinking`" + ` in the thinking mode must be passed back to the API."}}`

// replayStub answers the first failStatuses requests with the replay rejection,
// then a valid (empty) message_stop stream. It records every request body.
func replayStub(t *testing.T, failCount int) (*httptest.Server, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(body))
		attempt := len(bodies)
		mu.Unlock()
		if attempt <= failCount {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(anthropicReplayRejection))
			return
		}
		_, _ = w.Write([]byte(sse(`data: {"type":"message_stop"}`, ``)))
	}))
	t.Cleanup(srv.Close)
	return srv, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), bodies...)
	}
}

func replayRequest() CompletionRequest {
	return CompletionRequest{Messages: []Message{
		UserText("hi"),
		{Role: RoleAssistant, Content: []ContentBlock{
			{Type: BlockThinking, Thinking: "REPLAYED_THOUGHT", Signature: "sig"},
			TextBlock("answer"),
		}},
	}}
}

// The provider must rebuild the request with the thinking blocks replayed instead
// of failing the intent: that is the only way a thinking-by-default gateway (which
// demands the block even though the client never asked for thinking) can continue.
func TestAnthropicRetriesWithReplayedThinking(t *testing.T) {
	srv, bodies := replayStub(t, 1)
	p, err := NewProvider(Config{Format: FormatAnthropic, BaseURL: srv.URL, APIKey: "k", Model: "m"})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	collect(t, p, replayRequest())

	sent := bodies()
	if len(sent) != 2 {
		t.Fatalf("requests=%d, want 2 (original + thinking replay retry)", len(sent))
	}
	if strings.Contains(sent[0], "REPLAYED_THOUGHT") || strings.Contains(sent[0], `"thinking"`) {
		t.Fatalf("first request should carry no thinking, got %s", sent[0])
	}
	if !strings.Contains(sent[1], "REPLAYED_THOUGHT") {
		t.Fatalf("retry must replay the thinking block, got %s", sent[1])
	}
	if !strings.Contains(sent[1], `"thinking":{"type":"enabled"}`) {
		t.Fatalf("retry must declare thinking enabled, got %s", sent[1])
	}
}

// If replaying is not enough (the block is gone from history), declaring thinking
// explicitly disabled is the last resort: nothing needs to be passed back then.
func TestAnthropicFallsBackToExplicitDisabledThinking(t *testing.T) {
	srv, bodies := replayStub(t, 2)
	p, err := NewProvider(Config{Format: FormatAnthropic, BaseURL: srv.URL, APIKey: "k", Model: "m"})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	collect(t, p, replayRequest())

	sent := bodies()
	if len(sent) != 3 {
		t.Fatalf("requests=%d, want 3 (original + replay retry + disabled retry)", len(sent))
	}
	if !strings.Contains(sent[2], `"thinking":{"type":"disabled"}`) {
		t.Fatalf("final retry must declare thinking disabled, got %s", sent[2])
	}
	if strings.Contains(sent[2], "REPLAYED_THOUGHT") {
		t.Fatalf("final retry must strip thinking blocks, got %s", sent[2])
	}
}

// After one successful replay fallback the provider remembers that this endpoint
// needs the blocks, so the next call goes straight out in thinking mode instead of
// paying another rejected round-trip.
func TestAnthropicRemembersThinkingReplayAfterFallback(t *testing.T) {
	srv, bodies := replayStub(t, 1)
	p, err := NewProvider(Config{Format: FormatAnthropic, BaseURL: srv.URL, APIKey: "k", Model: "m"})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	collect(t, p, replayRequest()) // 400 → replay retry → ok
	collect(t, p, replayRequest()) // must be a single request now

	sent := bodies()
	if len(sent) != 3 {
		t.Fatalf("requests=%d, want 3 (two attempts + one sticky request)", len(sent))
	}
	last := sent[2]
	if !strings.Contains(last, `"thinking":{"type":"enabled"}`) {
		t.Fatalf("sticky request must declare thinking enabled up front, got %s", last)
	}
	if !strings.Contains(last, "REPLAYED_THOUGHT") {
		t.Fatalf("sticky request must replay the thinking block, got %s", last)
	}
}

// A per-request override stays authoritative: a caller that demanded a
// non-thinking request must not be silently flipped into thinking mode.
func TestAnthropicPerRequestDisabledDoesNotFallBack(t *testing.T) {
	srv, bodies := replayStub(t, 1)
	p, err := NewProvider(Config{Format: FormatAnthropic, BaseURL: srv.URL, APIKey: "k", Model: "m"})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	req := replayRequest()
	req.Thinking = "disabled"
	if _, _, _, err := p.Complete(t.Context(), req); err == nil {
		t.Fatal("a deliberate disabled override must surface the provider error, not retry in thinking mode")
	}
	if got := len(bodies()); got != 1 {
		t.Fatalf("requests=%d, want 1 (no fallback for an explicit disabled override)", got)
	}
}

// Config-level "disabled" is a real switch: it must strip thinking blocks. The
// old code treated any non-empty value as enabled, replaying blocks while telling
// the provider thinking was off — which the provider rejects.
func TestAnthropicConfigDisabledStripsThinkingBlocks(t *testing.T) {
	stub := sse(`data: {"type":"message_stop"}`, ``)
	raw, m := captureReq(t, Config{Format: FormatAnthropic, ThinkingType: "disabled"}, replayRequest(), stub)
	if thinkingType(m) != "disabled" {
		t.Fatalf("thinking type = %q, want disabled", thinkingType(m))
	}
	if strings.Contains(raw, "REPLAYED_THOUGHT") {
		t.Fatalf("thinking block must be stripped when thinking is disabled, got %s", raw)
	}
}
