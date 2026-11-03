// Package mcphttp contains remote Streamable HTTP and legacy SSE MCP clients.
//
// The core mcp package only speaks stdio; this adapts an HTTP/JSON-RPC MCP server
// to the same tool.CoreTool shape (mcp__server__tool) WITHOUT touching the SDK.
// Two transports are implemented:
//
//   - Streamable HTTP: JSON-RPC over POST, the server answering with
//     application/json or with a text/event-stream carrying the response.
//   - Legacy SSE (pre-2025): one long-lived GET stream announces a per-session POST
//     endpoint; every response comes back as a "message" event on that stream.
//
// NewAuto picks between them: Streamable HTTP first, legacy SSE only when the
// server rejects the POST as a session-less request (Burp Suite), answers
// 405/406, or answers with an event stream. NewSSE forces the legacy transport.
// Custom headers (e.g. Authorization) come from the MCP row's env map, so a bearer
// token is configured as {"Authorization":"Bearer …"}.
package mcphttp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

const protocolVersion = "2025-06-18"
const legacySSEProtocolVersion = "2024-11-05"

// callTimeout bounds one JSON-RPC call, including the wait for a reply delivered on
// the SSE stream. The long-lived SSE GET stream itself is deliberately unbounded.
const callTimeout = 120 * time.Second

// handshakeTimeout bounds the opening GET: connection, response headers and the
// endpoint event. Kept short so a silent endpoint cannot stall a discovery run.
const handshakeTimeout = 30 * time.Second

// ToolName mirrors mcp.ToolName so remote tools share the mcp__server__tool scheme.
func ToolName(server, name string) string { return "mcp__" + server + "__" + name }

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id,omitempty"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int             `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *rpcError       `json:"error"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *rpcError) Error() string { return fmt.Sprintf("mcp rpc error %d: %s", e.Code, e.Message) }

// Client is a connection to one remote MCP server. New uses Streamable HTTP;
// NewSSE forces the legacy GET + POST endpoint transport; NewAuto tries Streamable
// HTTP first and falls back to the legacy transport for servers that only speak it.
type Client struct {
	server  string
	url     string
	headers map[string]string
	http    *http.Client // bounded requests: POST, DELETE
	stream  *http.Client // unbounded request: the long-lived SSE GET

	mu        sync.Mutex
	nextID    int
	sessionID string

	// legacySSE is the pre-2025 MCP SSE transport used by servers such as Burp Suite
	// and GSL5: one long-lived GET stream announces a per-session POST endpoint and
	// carries every JSON-RPC reply as a "message" event.
	legacySSE bool
	legacyMu  sync.Mutex // serialises SSE calls, (re)dial and close
	sse       *sseSession
	pendingMu sync.Mutex
	pending   map[int]chan *rpcResponse
	protocol  string
}

// sseSession is one live legacy-SSE connection: the open GET stream plus the POST
// endpoint it announced. A dropped stream is replaced by a fresh session (and a
// replayed initialize handshake) on the next call.
type sseSession struct {
	messageURL string
	cancel     context.CancelFunc
	body       io.ReadCloser
	done       chan struct{}
	failOnce   sync.Once
	errMu      sync.Mutex
	err        error
}

func (s *sseSession) fail(err error) {
	s.errMu.Lock()
	if s.err == nil {
		s.err = err
	}
	s.errMu.Unlock()
	s.failOnce.Do(func() { close(s.done) })
}

func (s *sseSession) failure() error {
	s.errMu.Lock()
	defer s.errMu.Unlock()
	if s.err == nil {
		return errors.New("connection closed")
	}
	return s.err
}

func (s *sseSession) alive() bool {
	select {
	case <-s.done:
		return false
	default:
		return true
	}
}

func (s *sseSession) close() {
	s.cancel()
	if s.body != nil {
		_ = s.body.Close()
	}
	select {
	case <-s.done:
	case <-time.After(time.Second):
	}
}

func normalizeHeaders(headers map[string]string) (map[string]string, error) {
	out := make(map[string]string, len(headers))
	for key, value := range headers {
		clean := strings.TrimSpace(key)
		if clean == "" || strings.ContainsAny(clean, "\r\n") {
			return nil, fmt.Errorf("invalid HTTP header name %q", key)
		}
		out[clean] = value
	}
	return out, nil
}

// newHTTPClient clones the default transport so proxy/dial settings stay intact.
// timeout bounds a whole request (0 = unbounded, used for the SSE GET stream) while
// headerTimeout bounds only the wait for response headers.
func newHTTPClient(insecure bool, timeout, headerTimeout time.Duration) *http.Client {
	return &http.Client{Transport: newHTTPTransport(insecure, headerTimeout, false), Timeout: timeout}
}

// newHTTPTransport builds one dedicated transport. freshConnection disables keep-alive
// so every request gets its own TCP connection.
func newHTTPTransport(insecure bool, headerTimeout time.Duration, freshConnection bool) *http.Transport {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.ResponseHeaderTimeout = headerTimeout
	if insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	if freshConnection {
		tr.DisableKeepAlives = true
	}
	return tr
}

// HTTPError is a non-2xx reply from an MCP HTTP endpoint. The status, content type
// and body are kept so the caller can tell which transport the server expects.
type HTTPError struct {
	StatusCode  int
	ContentType string
	Body        string
}

func (e *HTTPError) Error() string { return fmt.Sprintf("mcp http %d: %s", e.StatusCode, e.Body) }

// New connects to a remote MCP endpoint and performs the initialize handshake.
// headers are sent on every request (Authorization, custom API keys, …).
// When insecure is true, TLS certificate verification is skipped so servers that
// present a self-signed certificate can still be reached (issue #108).
func New(ctx context.Context, server, url string, headers map[string]string, insecure bool) (*Client, error) {
	cleanHeaders, err := normalizeHeaders(headers)
	if err != nil {
		return nil, err
	}
	c := &Client{
		server:   server,
		url:      url,
		headers:  cleanHeaders,
		http:     newHTTPClient(insecure, callTimeout, callTimeout),
		stream:   newHTTPClient(insecure, 0, handshakeTimeout),
		protocol: protocolVersion,
	}
	if err := c.initialize(ctx); err != nil {
		return nil, err
	}
	return c, nil
}

// NewAuto connects with the transport the server actually speaks: Streamable HTTP
// is attempted first (the same behaviour as before), and only when that server
// rejects HTTP POST as a session-less request (Burp: "400 sessionId query parameter
// is not provided"), answers 405/406, or answers with an event stream, is the legacy
// SSE transport used instead. "http" in the mcp_servers table therefore means
// "auto", so no extra configuration is needed.
func NewAuto(ctx context.Context, server, endpoint string, headers map[string]string, insecure bool) (*Client, error) {
	c, httpErr := New(ctx, server, endpoint, headers, insecure)
	if httpErr == nil {
		return c, nil
	}
	if !speaksLegacySSE(ctx, endpoint, headers, insecure, httpErr) {
		return nil, httpErr
	}
	sse, sseErr := NewSSE(ctx, server, endpoint, headers, insecure)
	if sseErr != nil {
		return nil, fmt.Errorf("%w; legacy SSE fallback failed: %v", httpErr, sseErr)
	}
	return sse, nil
}

// speaksLegacySSE decides whether a failed Streamable HTTP attempt is worth retrying
// as legacy SSE. Classified rejections are trusted directly; ambiguous 400/404
// replies are confirmed with a cheap probe for an event stream.
func speaksLegacySSE(ctx context.Context, endpoint string, headers map[string]string, insecure bool, err error) bool {
	var he *HTTPError
	if !errors.As(err, &he) {
		return false // network/DNS/TLS failure: a different transport will not help
	}
	body := strings.ToLower(he.Body)
	switch {
	case he.StatusCode == http.StatusMethodNotAllowed, he.StatusCode == http.StatusNotAcceptable:
		return true
	case he.StatusCode == http.StatusBadRequest && strings.Contains(body, "sessionid"):
		return true
	case strings.Contains(body, "text/event-stream"):
		return true
	case strings.HasPrefix(strings.ToLower(he.ContentType), "text/event-stream"):
		return true
	case he.StatusCode == http.StatusBadRequest, he.StatusCode == http.StatusNotFound:
		return probeEventStream(ctx, endpoint, headers, insecure)
	}
	return false
}

// probeEventStream opens GET <endpoint> with Accept: text/event-stream and reports
// whether the server starts an SSE stream. The body is dropped immediately: this is
// only a transport probe, the real session is opened by NewSSE.
func probeEventStream(ctx context.Context, endpoint string, headers map[string]string, insecure bool) bool {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return false
	}
	req.Header.Set("Accept", "text/event-stream")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := newHTTPClient(insecure, 0, 5*time.Second).Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false
	}
	if strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/event-stream") {
		return true
	}
	line, err := bufio.NewReader(resp.Body).ReadString('\n')
	if err != nil {
		return false
	}
	line = strings.TrimSpace(line)
	return strings.HasPrefix(line, "event:") || strings.HasPrefix(line, "data:")
}

// NewSSE connects to the legacy MCP SSE transport: a long-lived GET announces a
// per-session POST endpoint, while JSON-RPC responses are delivered asynchronously
// as SSE message events. A dropped stream is re-established, with a fresh
// handshake, on the next call.
func NewSSE(ctx context.Context, server, sseURL string, headers map[string]string, insecure bool) (*Client, error) {
	cleanHeaders, err := normalizeHeaders(headers)
	if err != nil {
		return nil, err
	}
	c := &Client{
		server:    server,
		url:       sseURL,
		headers:   cleanHeaders,
		legacySSE: true,
		pending:   make(map[int]chan *rpcResponse),
		protocol:  legacySSEProtocolVersion,
	}
	// Every request on this transport gets its own connection: Burp Suite answers
	// 403 to a second request reusing a keep-alive connection, which would break the
	// handshake (initialize) and every later call. A fresh connection also makes the
	// reconnect GET immune to a stale pooled socket.
	c.http = &http.Client{Transport: newHTTPTransport(insecure, callTimeout, true), Timeout: callTimeout}
	c.stream = &http.Client{Transport: newHTTPTransport(insecure, handshakeTimeout, true)}
	if err := c.connectSSE(ctx); err != nil {
		_ = c.Close()
		return nil, err
	}
	return c, nil
}

// connectSSE opens the GET stream, learns the POST endpoint and replays the
// initialize handshake. Callers hold legacyMu (or own the client exclusively).
func (c *Client) connectSSE(ctx context.Context) error {
	c.closeSSE() // never reuse a half-dead stream
	streamCtx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(streamCtx, http.MethodGet, c.url, nil)
	if err != nil {
		cancel()
		return err
	}
	req.Header.Set("Accept", "text/event-stream")
	for k, v := range c.headers {
		req.Header.Set(k, v)
	}
	resp, err := c.stream.Do(req)
	if err != nil {
		cancel()
		return fmt.Errorf("mcp sse %s: %w", safeURL(c.url), err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet := readSnippet(resp.Body)
		resp.Body.Close()
		cancel()
		return fmt.Errorf("mcp sse %s: http %d: %s", safeURL(c.url), resp.StatusCode, snippet)
	}
	reader := bufio.NewReader(resp.Body)
	watchdog := time.AfterFunc(handshakeTimeout, cancel)
	endpoint, err := readSSEEndpoint(reader, c.url)
	watchdog.Stop()
	if err != nil {
		resp.Body.Close()
		cancel()
		return err
	}
	sess := &sseSession{messageURL: endpoint, cancel: cancel, body: resp.Body, done: make(chan struct{})}
	c.sse = sess
	go c.readSSE(reader, sess)
	if err := c.handshakeSSE(ctx); err != nil {
		c.closeSSE()
		return err
	}
	return nil
}

// readSSEEndpoint consumes the opening SSE frame and returns the absolute POST
// endpoint announced by the "endpoint" event. Legacy servers send an absolute URL, a
// path ("/message?sessionId=…") or only a query ("?sessionId=…", Burp Suite), so
// relative values are resolved against base.
func readSSEEndpoint(r *bufio.Reader, base string) (string, error) {
	var event string
	var data strings.Builder
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return "", fmt.Errorf("mcp sse endpoint: %w", err)
		}
		line = strings.TrimRight(line, "\r\n")
		switch {
		case line == "": // end of frame
			candidate := strings.TrimSpace(data.String())
			if candidate != "" && (event == "" || event == "endpoint") {
				return resolveEndpoint(candidate, base)
			}
			// First frame was not the endpoint event: keep reading until it shows up.
			event = ""
			data.Reset()
		case strings.HasPrefix(line, "event:"):
			event = strings.TrimSpace(line[len("event:"):])
		case strings.HasPrefix(line, "data:"):
			if data.Len() > 0 {
				data.WriteString("\n")
			}
			data.WriteString(strings.TrimSpace(line[len("data:"):]))
		}
	}
}

func resolveEndpoint(candidate, base string) (string, error) {
	u, err := url.Parse(candidate)
	if err != nil {
		return "", fmt.Errorf("mcp sse endpoint URL: %w", err)
	}
	if u.IsAbs() {
		return u.String(), nil
	}
	b, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("mcp sse base URL: %w", err)
	}
	// Note: a bare "?sessionId=…" keeps the base path and only replaces the query,
	// which is exactly what Burp Suite announces.
	return b.ResolveReference(u).String(), nil
}

// readSSE dispatches JSON-RPC replies from the open stream to the waiting call.
func (c *Client) readSSE(r *bufio.Reader, sess *sseSession) {
	var event string
	var data strings.Builder
	flush := func() {
		payload := strings.TrimSpace(data.String())
		data.Reset()
		ev := event
		event = ""
		if payload == "" || ev == "endpoint" {
			return
		}
		if ev != "" && ev != "message" {
			return
		}
		var response rpcResponse
		if json.Unmarshal([]byte(payload), &response) != nil || response.ID == 0 {
			return
		}
		c.pendingMu.Lock()
		ch := c.pending[response.ID]
		delete(c.pending, response.ID)
		c.pendingMu.Unlock()
		if ch != nil {
			ch <- &response // buffered: never blocks if the caller already timed out
		}
	}
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			flush()
			sess.fail(err)
			return
		}
		line = strings.TrimRight(line, "\r\n")
		switch {
		case line == "":
			flush()
		case strings.HasPrefix(line, "event:"):
			event = strings.TrimSpace(line[len("event:"):])
		case strings.HasPrefix(line, "data:"):
			if data.Len() > 0 {
				data.WriteString("\n")
			}
			data.WriteString(strings.TrimSpace(line[len("data:"):]))
		}
	}
}

func (c *Client) initialize(ctx context.Context) error {
	if c.legacySSE {
		return c.handshakeSSE(ctx)
	}
	version := c.protocol
	if version == "" {
		version = protocolVersion
	}
	if _, err := c.call(ctx, "initialize", map[string]any{
		"protocolVersion": version,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "artex", "version": "0.2"},
	}); err != nil {
		return err
	}
	return c.notify(ctx, "notifications/initialized", map[string]any{})
}

// handshakeSSE replays initialize + notifications/initialized over the open stream.
// It talks to exchangeSSE directly because connectSSE already holds legacyMu.
func (c *Client) handshakeSSE(ctx context.Context) error {
	version := c.protocol
	if version == "" {
		version = legacySSEProtocolVersion
	}
	resp, err := c.exchangeSSE(ctx, rpcRequest{
		JSONRPC: "2.0",
		ID:      c.takeID(),
		Method:  "initialize",
		Params: map[string]any{
			"protocolVersion": version,
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": "artex", "version": "0.2"},
		},
	}, true)
	if err != nil {
		return err
	}
	if resp != nil && resp.Error != nil {
		return resp.Error
	}
	_, err = c.exchangeSSE(ctx, rpcRequest{
		JSONRPC: "2.0",
		Method:  "notifications/initialized",
		Params:  map[string]any{},
	}, false)
	return err
}

func (c *Client) takeID() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nextID++
	return c.nextID
}

// Tools lists the server's tools and adapts them to CoreTools.
func (c *Client) Tools(ctx context.Context) ([]actool.CoreTool, error) {
	raw, err := c.call(ctx, "tools/list", map[string]any{})
	if err != nil {
		return nil, err
	}
	var res struct {
		Tools []remoteTool `json:"tools"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, err
	}
	out := make([]actool.CoreTool, 0, len(res.Tools))
	for _, rt := range res.Tools {
		out = append(out, c.wrap(rt))
	}
	return out, nil
}

type remoteTool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

func (c *Client) wrap(rt remoteTool) actool.CoreTool {
	schema := rt.InputSchema
	if schema == nil {
		schema = map[string]any{"type": "object"}
	}
	full := ToolName(c.server, rt.Name)
	return actool.Build(actool.Spec{
		Name:        full,
		Description: rt.Description,
		Schema:      schema,
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.AskUser("call MCP tool " + full + "?")
		},
		Run: func(ctx context.Context, in json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
			var args any
			if len(in) > 0 {
				_ = json.Unmarshal(in, &args)
			}
			raw, err := c.call(ctx, "tools/call", map[string]any{"name": rt.Name, "arguments": args})
			if err != nil {
				return actool.Errorf("Error: " + err.Error()), nil
			}
			var res struct {
				Content []struct {
					Type string `json:"type"`
					Text string `json:"text"`
				} `json:"content"`
				IsError bool `json:"isError"`
			}
			if err := json.Unmarshal(raw, &res); err != nil {
				return actool.Errorf("Error: bad MCP response: " + err.Error()), nil
			}
			var text string
			for _, blk := range res.Content {
				text += blk.Text
			}
			// 与内置/自定义工具一致：超长输出走 Capture——按会话 MaxOutputChars（默认
			// 30000）截断，配了 ToolOutputDir 时全量溢写到磁盘只留 head + 指针，避免大
			// MCP 结果整段灌爆上下文。
			return actool.Result{Content: []llm.ContentBlock{llm.TextBlock(actool.Capture(tc, text))}, IsError: res.IsError}, nil
		},
	})
}

// Call invokes one tool and returns the concatenated text of its content blocks
// (ScopeSentry answers with a single JSON text block). Unlike the CoreTool wrapper
// from Tools(), this bypasses the agent permission (AskUser) layer — it is meant
// for backend batch jobs (e.g. asset sync) that call MCP tools programmatically.
func (c *Client) Call(ctx context.Context, tool string, args any) (string, error) {
	raw, err := c.call(ctx, "tools/call", map[string]any{"name": tool, "arguments": args})
	if err != nil {
		return "", err
	}
	var res struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return "", fmt.Errorf("bad MCP response: %w", err)
	}
	var text strings.Builder
	for _, blk := range res.Content {
		text.WriteString(blk.Text)
	}
	if res.IsError {
		return text.String(), fmt.Errorf("mcp tool %q error: %s", tool, text.String())
	}
	return text.String(), nil
}

// Close terminates the MCP session best-effort. The legacy SSE transport just drops
// its stream; Streamable HTTP sends DELETE with the session id, per the spec.
// Servers that don't track sessions simply ignore it.
func (c *Client) Close() error {
	if c.legacySSE {
		c.legacyMu.Lock()
		c.closeSSE()
		c.legacyMu.Unlock()
		return nil
	}
	c.mu.Lock()
	sid := c.sessionID
	c.mu.Unlock()
	if sid == "" {
		return nil
	}
	req, err := http.NewRequest(http.MethodDelete, c.url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Mcp-Session-Id", sid)
	for k, v := range c.headers {
		req.Header.Set(k, v)
	}
	if resp, err := c.http.Do(req); err == nil {
		resp.Body.Close()
	}
	return nil
}

// --- JSON-RPC over Streamable HTTP ---

func (c *Client) call(ctx context.Context, method string, params any) (json.RawMessage, error) {
	id := c.takeID()
	resp, err := c.roundTrip(ctx, rpcRequest{JSONRPC: "2.0", ID: id, Method: method, Params: params}, true)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, fmt.Errorf("mcp: empty response for %s", method)
	}
	if resp.Error != nil {
		return nil, resp.Error
	}
	return resp.Result, nil
}

func (c *Client) notify(ctx context.Context, method string, params any) error {
	_, err := c.roundTrip(ctx, rpcRequest{JSONRPC: "2.0", Method: method, Params: params}, false)
	return err
}

// roundTrip POSTs one JSON-RPC frame. When expectResp is false (a notification) the
// server replies 202 Accepted with no body. Otherwise the reply is parsed from JSON
// or from an SSE stream, whichever the server chose.
func (c *Client) roundTrip(ctx context.Context, body rpcRequest, expectResp bool) (*rpcResponse, error) {
	if c.legacySSE {
		return c.legacyRoundTrip(ctx, body, expectResp)
	}
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	version := c.protocol
	if version == "" {
		version = protocolVersion
	}
	req.Header.Set("MCP-Protocol-Version", version)
	for k, v := range c.headers {
		req.Header.Set(k, v)
	}
	c.mu.Lock()
	sid := c.sessionID
	c.mu.Unlock()
	if sid != "" {
		req.Header.Set("Mcp-Session-Id", sid)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Capture the session id the server assigns on initialize.
	if sid == "" {
		if got := resp.Header.Get("Mcp-Session-Id"); got != "" {
			c.mu.Lock()
			c.sessionID = got
			c.mu.Unlock()
		}
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &HTTPError{
			StatusCode:  resp.StatusCode,
			ContentType: resp.Header.Get("Content-Type"),
			Body:        readSnippet(resp.Body),
		}
	}
	if !expectResp {
		return nil, nil // notification — no JSON-RPC body to parse
	}
	if strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		return parseSSE(resp.Body, body.ID)
	}
	var out rpcResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("mcp: decode json response: %w", err)
	}
	return &out, nil
}

// legacyRoundTrip posts to the endpoint announced by the SSE stream. The HTTP POST
// only acknowledges receipt; the JSON-RPC response arrives on that stream.
func (c *Client) legacyRoundTrip(ctx context.Context, body rpcRequest, expectResp bool) (*rpcResponse, error) {
	// Serialising calls keeps delivery deterministic: one POST in flight at a time,
	// while the shared reader still dispatches replies by JSON-RPC id.
	c.legacyMu.Lock()
	defer c.legacyMu.Unlock()
	if err := c.ensureSSE(ctx); err != nil {
		return nil, err
	}
	return c.exchangeSSE(ctx, body, expectResp)
}

// ensureSSE returns the live stream, dialling again (and replaying the handshake)
// when the previous one dropped. Callers hold legacyMu.
func (c *Client) ensureSSE(ctx context.Context) error {
	if c.sse != nil && c.sse.alive() {
		return nil
	}
	return c.connectSSE(ctx)
}

// exchangeSSE POSTs one frame to the announced endpoint and, for requests, waits for
// the matching reply on the stream. One call is bounded by callTimeout.
func (c *Client) exchangeSSE(ctx context.Context, body rpcRequest, expectResp bool) (*rpcResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	sess := c.sse
	if sess == nil {
		return nil, errors.New("mcp sse: not connected")
	}
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	var responseCh chan *rpcResponse
	if expectResp {
		responseCh = make(chan *rpcResponse, 1)
		c.pendingMu.Lock()
		c.pending[body.ID] = responseCh
		c.pendingMu.Unlock()
		defer func() {
			c.pendingMu.Lock()
			delete(c.pending, body.ID)
			c.pendingMu.Unlock()
		}()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, sess.messageURL, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	for k, v := range c.headers {
		req.Header.Set(k, v)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	snippet := readSnippet(resp.Body)
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// The session is gone (server restart, idle reaper): drop the stream so the
		// next call redials and re-handshakes instead of failing forever.
		if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusBadRequest {
			c.closeSSE()
		}
		return nil, fmt.Errorf("mcp sse %s: http %d: %s", safeURL(sess.messageURL), resp.StatusCode, snippet)
	}
	if !expectResp {
		return nil, nil
	}
	select {
	case response := <-responseCh:
		return response, nil
	case <-sess.done:
		return nil, fmt.Errorf("mcp sse stream: %w", sess.failure())
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *Client) closeSSE() {
	sess := c.sse
	c.sse = nil
	if sess == nil {
		return
	}
	sess.close()
}

// parseSSE reads an SSE stream and returns the first data frame that is a JSON-RPC
// response matching wantID (server-to-client requests/notifications are skipped).
func parseSSE(r io.Reader, wantID int) (*rpcResponse, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	var dataBuf strings.Builder
	flush := func() (*rpcResponse, bool) {
		if dataBuf.Len() == 0 {
			return nil, false
		}
		payload := dataBuf.String()
		dataBuf.Reset()
		var out rpcResponse
		if err := json.Unmarshal([]byte(payload), &out); err != nil {
			return nil, false
		}
		if out.ID != wantID {
			return nil, false
		}
		return &out, true
	}
	for sc.Scan() {
		line := sc.Text()
		if line == "" { // event boundary
			if resp, ok := flush(); ok {
				return resp, nil
			}
			continue
		}
		if strings.HasPrefix(line, "data:") {
			dataBuf.WriteString(strings.TrimSpace(line[len("data:"):]))
		}
	}
	if resp, ok := flush(); ok {
		return resp, nil
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("mcp: no matching response in event stream")
}

func readSnippet(r io.Reader) string {
	b, _ := io.ReadAll(io.LimitReader(r, 2048))
	return strings.TrimSpace(string(b))
}

// safeURL renders a URL for logs/errors without its query, which for the legacy SSE
// transport carries the session id.
func safeURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	u.RawQuery = ""
	return u.String()
}
