package mcphttp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- fake legacy-SSE MCP server (Burp Suite / SDK style) ---

type fakeSession struct {
	msgs chan []byte
	drop chan struct{}
	// dropAfterWrite closes the stream right after the next frame is flushed,
	// simulating a server-side disconnect between two calls.
	dropAfterWrite bool
}

type fakeLegacyMCP struct {
	mu       sync.Mutex
	sessions map[string]*fakeSession
	conns    map[string]bool
	seq      int
	// endpointPath prefixes the announced endpoint. "" reproduces Burp Suite
	// (a bare "?sessionId=…" on the same path), "/message" the SDK default.
	endpointPath       string
	initializeCalls    int
	dropAfterToolsList bool
}

func newFakeLegacyMCP(endpointPath string) (*fakeLegacyMCP, *httptest.Server) {
	f := &fakeLegacyMCP{
		sessions:     make(map[string]*fakeSession),
		conns:        make(map[string]bool),
		endpointPath: endpointPath,
	}
	return f, httptest.NewServer(f)
}

func (f *fakeLegacyMCP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Burp Suite answers 403 to any request that reuses a connection which already
	// served one, so the fake enforces the same rule: a client must never rely on
	// HTTP keep-alive here.
	f.mu.Lock()
	served := f.conns[r.RemoteAddr]
	f.conns[r.RemoteAddr] = true
	f.mu.Unlock()
	if served {
		http.Error(w, "", http.StatusForbidden)
		return
	}
	switch r.Method {
	case http.MethodGet:
		f.serveStream(w, r)
	case http.MethodPost:
		f.servePost(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (f *fakeLegacyMCP) serveStream(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.seq++
	id := fmt.Sprintf("sess-%d", f.seq)
	sess := &fakeSession{msgs: make(chan []byte, 32), drop: make(chan struct{})}
	f.sessions[id] = sess
	f.mu.Unlock()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	fmt.Fprintf(w, "event: endpoint\ndata: %s\n\n", f.endpointPath+"?sessionId="+id)
	if flusher != nil {
		flusher.Flush()
	}
	for {
		select {
		case payload := <-sess.msgs:
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", payload)
			if flusher != nil {
				flusher.Flush()
			}
			f.mu.Lock()
			drop := sess.dropAfterWrite
			sess.dropAfterWrite = false
			f.mu.Unlock()
			if drop {
				return
			}
		case <-sess.drop:
			return
		case <-r.Context().Done():
			return
		}
	}
}

func (f *fakeLegacyMCP) servePost(w http.ResponseWriter, r *http.Request) {
	sid := r.URL.Query().Get("sessionId")
	if sid == "" {
		// Burp Suite's exact reply to a session-less Streamable HTTP POST.
		http.Error(w, "sessionId query parameter is not provided", http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	sess := f.sessions[sid]
	f.mu.Unlock()
	if sess == nil {
		http.Error(w, "unknown session", http.StatusBadRequest)
		return
	}
	var req rpcRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusAccepted) // like Burp: only acknowledges receipt
	_, _ = io.WriteString(w, "Accepted")
	if req.ID == 0 {
		return
	}
	result, _ := json.Marshal(fakeResult(req.Method))
	payload, _ := json.Marshal(rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: result})
	f.mu.Lock()
	if req.Method == "initialize" {
		f.initializeCalls++
	}
	if req.Method == "tools/list" && f.dropAfterToolsList {
		sess.dropAfterWrite = true
	}
	f.mu.Unlock()
	select {
	case sess.msgs <- payload:
	case <-time.After(2 * time.Second):
	}
}

func (f *fakeLegacyMCP) handshakes() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.initializeCalls
}

func fakeResult(method string) any {
	switch method {
	case "initialize":
		return map[string]any{
			"protocolVersion": legacySSEProtocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "burp-suite", "version": "test"},
		}
	case "tools/list":
		return map[string]any{"tools": []any{
			map[string]any{"name": "get_proxy_history", "description": "proxy history", "inputSchema": map[string]any{"type": "object"}},
			map[string]any{"name": "send_to_repeater", "description": "repeater", "inputSchema": map[string]any{"type": "object"}},
		}}
	case "tools/call":
		return map[string]any{"content": []any{map[string]any{"type": "text", "text": "ok"}}}
	}
	return map[string]any{}
}

func waitForStreamDeath(t *testing.T, c *Client) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c.legacyMu.Lock()
		dead := c.sse == nil || !c.sse.alive()
		c.legacyMu.Unlock()
		if dead {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("SSE stream did not close")
}

// TestLegacySSEClientDiscoverAndCall covers the SDK-style server: GET /sse
// announces an absolute POST URL, replies arrive as message events.
func TestLegacySSEClientDiscoverAndCall(t *testing.T) {
	var mu sync.Mutex
	var stream http.ResponseWriter
	var flusher http.Flusher
	sessions := make(map[string]bool)
	messages := make(chan []byte, 8)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sse":
			id := "test-session"
			mu.Lock()
			sessions[id] = true
			stream, flusher = w, w.(http.Flusher)
			mu.Unlock()
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
			fmt.Fprintf(w, "event: endpoint\ndata: %s/message?sessionId=%s\n\n", "http://"+r.Host, id)
			flusher.Flush()
			for {
				select {
				case payload := <-messages:
					fmt.Fprintf(w, "event: message\ndata: %s\n\n", payload)
					flusher.Flush()
				case <-r.Context().Done():
					return
				}
			}
		case "/message":
			mu.Lock()
			knownSession := sessions["test-session"]
			mu.Unlock()
			if r.URL.Query().Get("sessionId") != "test-session" || !knownSession {
				http.Error(w, "unknown session", http.StatusBadRequest)
				return
			}
			var req rpcRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusAccepted)
			if req.ID == 0 {
				return
			}
			resultJSON, err := json.Marshal(fakeResult(req.Method))
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			payload, _ := json.Marshal(rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: json.RawMessage(resultJSON)})
			mu.Lock()
			streamReady := stream != nil
			mu.Unlock()
			if streamReady {
				messages <- payload
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := NewSSE(ctx, "test", srv.URL+"/sse", map[string]string{"Authorization ": "Bearer test"}, false)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	tools, err := c.Tools(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(tools) != 2 || !strings.Contains(tools[0].Name(), "get_proxy_history") {
		t.Fatalf("unexpected tools: %#v", tools)
	}
	got, err := c.Call(ctx, "get_proxy_history", map[string]any{"value": "x"})
	if err != nil || got != "ok" {
		t.Fatalf("Call() = %q, %v", got, err)
	}
}

// TestLegacySSEBurpStyleEndpoint reproduces Burp Suite: the endpoint event carries
// only "?sessionId=…", so it must resolve against the base URL, and the POST goes
// back to the same path with that session id.
func TestLegacySSEBurpStyleEndpoint(t *testing.T) {
	f, srv := newFakeLegacyMCP("")
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := NewSSE(ctx, "burp", srv.URL, map[string]string{"X-Test": "1"}, false)
	if err != nil {
		t.Fatalf("NewSSE: %v", err)
	}
	defer c.Close()

	c.legacyMu.Lock()
	messageURL := c.sse.messageURL
	c.legacyMu.Unlock()
	resolved, err := url.Parse(messageURL)
	if err != nil {
		t.Fatalf("bad endpoint %q: %v", messageURL, err)
	}
	if resolved.Scheme+"://"+resolved.Host != srv.URL || !strings.HasPrefix(resolved.Query().Get("sessionId"), "sess-") {
		t.Fatalf("endpoint not resolved against base: %q (base %q)", messageURL, srv.URL)
	}

	tools, err := c.Tools(ctx)
	if err != nil {
		t.Fatalf("Tools: %v", err)
	}
	if len(tools) != 2 {
		t.Fatalf("want 2 tools, got %d", len(tools))
	}
	if tools[0].Name() != "mcp__burp__get_proxy_history" {
		t.Fatalf("unexpected tool name %q", tools[0].Name())
	}
	if got, err := c.Call(ctx, "send_to_repeater", map[string]any{}); err != nil || got != "ok" {
		t.Fatalf("Call() = %q, %v", got, err)
	}
	if f.handshakes() != 1 {
		t.Fatalf("want one handshake, got %d", f.handshakes())
	}
}

// TestNewAutoFallsBackToLegacySSE is the Burp Suite regression: Streamable HTTP is
// tried first and rejected with "400 sessionId query parameter is not provided",
// which must transparently switch to the SSE transport — no user configuration.
func TestNewAutoFallsBackToLegacySSE(t *testing.T) {
	f, srv := newFakeLegacyMCP("")
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := NewAuto(ctx, "burp", srv.URL, nil, false)
	if err != nil {
		t.Fatalf("NewAuto: %v", err)
	}
	defer c.Close()
	if !c.legacySSE {
		t.Fatal("NewAuto did not fall back to the legacy SSE transport")
	}
	tools, err := c.Tools(ctx)
	if err != nil {
		t.Fatalf("Tools: %v", err)
	}
	if len(tools) != 2 {
		t.Fatalf("want 2 tools, got %d", len(tools))
	}
	if f.handshakes() != 1 {
		t.Fatalf("want one handshake, got %d", f.handshakes())
	}
}

// TestNewAutoKeepsStreamableHTTP makes sure the ScopeSentry path (a working
// Streamable HTTP server) is untouched by the automatic fallback.
func TestNewAutoKeepsStreamableHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "use POST", http.StatusMethodNotAllowed)
			return
		}
		var req rpcRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.ID == 0 {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(rpcResponse{JSONRPC: "2.0", ID: req.ID, Result: json.RawMessage(`{"tools":[{"name":"assets"}]}`)})
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := NewAuto(ctx, "ScopeSentry", srv.URL+"/mcp", nil, false)
	if err != nil {
		t.Fatalf("NewAuto: %v", err)
	}
	defer c.Close()
	if c.legacySSE {
		t.Fatal("working Streamable HTTP server must not be downgraded to SSE")
	}
	if _, err := c.Tools(ctx); err != nil {
		t.Fatalf("Tools: %v", err)
	}
}

// TestLegacySSEReconnectsAndRehandshakes drops the stream between two calls and
// expects the client to dial again and replay the initialize handshake.
func TestLegacySSEReconnectsAndRehandshakes(t *testing.T) {
	f, srv := newFakeLegacyMCP("")
	f.dropAfterToolsList = true
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := NewSSE(ctx, "burp", srv.URL, nil, false)
	if err != nil {
		t.Fatalf("NewSSE: %v", err)
	}
	defer c.Close()

	if _, err := c.Tools(ctx); err != nil {
		t.Fatalf("first Tools: %v", err)
	}
	waitForStreamDeath(t, c) // the server closed the stream after replying

	tools, err := c.Tools(ctx)
	if err != nil {
		t.Fatalf("second Tools after reconnect: %v", err)
	}
	if len(tools) != 2 {
		t.Fatalf("want 2 tools, got %d", len(tools))
	}
	if got := f.handshakes(); got != 2 {
		t.Fatalf("want re-handshake after reconnect, handshakes = %d", got)
	}
}
