package gateway

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// toolsCall is a real MCP streamable-HTTP tools/call body (MCP 2025-06-18 §Tools): the tool
// being invoked is params.name, which no amount of URL inspection can reach.
const toolsCall = `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_weather","arguments":{"location":"New York"}}}`

// The JSON-RPC parser itself is unit-tested where it lives, in internal/mcprpc — the gateway
// and the resource-server-side scope check (verify.EnforceScope) share one implementation, so
// they cannot drift into disagreeing about which tool a body invokes. What follows tests the
// gateway's use of it: buffering, forwarding intact, and surfacing the calls to the pipeline.

// recordRequest captures what the pipeline saw and mints, so a test can assert on the
// decision input as well as the proxied result.
func recordRequest(seen **Request) Stage {
	return NewStage("record", func(_ context.Context, r *Request) error {
		*seen = r
		return nil
	})
}

// mcpGateway wires a gateway in front of an upstream that records the body it received, and
// returns a pointer to that recording (read it after the request has been served).
func mcpGateway(t *testing.T, stages ...Stage) (*Gateway, *[]byte) {
	t.Helper()
	var gotBody []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(upstream.Close)

	reg := NewRegistry()
	if err := reg.Register(&Server{ID: "demo", Upstream: mustURL(t, upstream.URL)}); err != nil {
		t.Fatal(err)
	}
	return &Gateway{Registry: reg, Pipeline: Pipeline{Stages: append(stages, stubMint())}}, &gotBody
}

// TestBufferedBodyIsForwardedIntact is the regression this whole change turns on: the gateway
// now READS the request body to find the tool, and if it does not put it back byte-for-byte
// every MCP call it authorizes is silently corrupted at the upstream.
func TestBufferedBodyIsForwardedIntact(t *testing.T) {
	var seen *Request
	g, upstreamBody := mcpGateway(t, recordRequest(&seen))

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/servers/demo/mcp", strings.NewReader(toolsCall))
	r.Header.Set("Content-Type", "application/json")
	g.ServeHTTP(rec, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("got %d (%s), want 200", rec.Code, rec.Body)
	}
	if string(*upstreamBody) != toolsCall {
		t.Fatalf("upstream body = %q,\n                  want %q", *upstreamBody, toolsCall)
	}
	// The decision saw the same bytes, and the tool inside them.
	if string(seen.Body) != toolsCall {
		t.Fatalf("pipeline body = %q, want the request body", seen.Body)
	}
	if len(seen.Calls) != 1 || seen.Calls[0].Tool != "get_weather" {
		t.Fatalf("pipeline calls = %+v, want one tools/call for get_weather", seen.Calls)
	}
	// Framing must match the body we re-supplied, or the upstream reads a truncated call.
	if seen.HTTP.ContentLength != int64(len(toolsCall)) {
		t.Fatalf("ContentLength = %d, want %d", seen.HTTP.ContentLength, len(toolsCall))
	}
	if seen.HTTP.GetBody == nil {
		t.Fatal("GetBody must be supplied so the outbound transport can retry the request")
	}
	replay, err := seen.HTTP.GetBody()
	if err != nil {
		t.Fatalf("GetBody: %v", err)
	}
	again, _ := io.ReadAll(replay)
	if string(again) != toolsCall {
		t.Fatalf("GetBody replayed %q, want the body", again)
	}
}

// TestBufferedBodyIsForwardedIntactOverTheWire runs the same property through real HTTP,
// including a CHUNKED request (no Content-Length), which is where a stale ContentLength or a
// leftover Transfer-Encoding would corrupt the forwarded body.
func TestBufferedBodyIsForwardedIntactOverTheWire(t *testing.T) {
	var upstreamBody []byte
	var upstreamLen int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamBody, _ = io.ReadAll(r.Body)
		upstreamLen = r.ContentLength
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	reg := NewRegistry()
	if err := reg.Register(&Server{ID: "demo", Upstream: mustURL(t, upstream.URL)}); err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(&Gateway{Registry: reg, Pipeline: Pipeline{Stages: []Stage{stubMint()}}})
	defer front.Close()

	// An io.Reader of unknown length: net/http sends this chunked, ContentLength -1.
	body := struct{ io.Reader }{strings.NewReader(toolsCall)}
	req, err := http.NewRequest(http.MethodPost, front.URL+"/servers/demo/mcp", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d, want 200", resp.StatusCode)
	}
	if string(upstreamBody) != toolsCall {
		t.Fatalf("chunked request corrupted: upstream got %q", upstreamBody)
	}
	// Having buffered it, the gateway knows the length and forwards a framed request.
	if upstreamLen != int64(len(toolsCall)) {
		t.Fatalf("upstream Content-Length = %d, want %d", upstreamLen, len(toolsCall))
	}
}

// TestOversizeBodyRejected: the buffer is filled before the caller is authenticated, so an
// unbounded read is a memory DoS. Over the cap the request is refused, not forwarded.
func TestOversizeBodyRejected(t *testing.T) {
	var reached bool
	g, _ := mcpGateway(t, NewStage("reached", func(_ context.Context, _ *Request) error {
		reached = true
		return nil
	}))
	g.MaxRequestBody = 64

	allowed := true
	reason := ""
	g.Audit = func(_ *Request, a bool, rs string) { allowed, reason = a, rs }

	rec := httptest.NewRecorder()
	big := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read","arguments":{"blob":"` +
		strings.Repeat("A", 1024) + `"}}}`
	g.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/servers/demo/mcp", strings.NewReader(big)))

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("got %d, want 413", rec.Code)
	}
	if reached {
		t.Fatal("an oversize request must not reach the decision pipeline, let alone the upstream")
	}
	if allowed || !strings.Contains(reason, "exceeds") {
		t.Fatalf("the refusal must be audited, got allowed=%v reason=%q", allowed, reason)
	}

	// A body exactly at the cap is fine: the bound is a ceiling, not an off-by-one.
	atCap := strings.Repeat("x", 64)
	rec = httptest.NewRecorder()
	g.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/servers/demo/mcp", strings.NewReader(atCap)))
	if rec.Code != http.StatusOK {
		t.Fatalf("a body exactly at the cap: got %d, want 200", rec.Code)
	}
}

func TestDefaultMaxRequestBodyIsUsedWhenUnset(t *testing.T) {
	for _, configured := range []int64{0, -1} {
		g := &Gateway{MaxRequestBody: configured}
		if got := g.maxRequestBody(); got != DefaultMaxRequestBody {
			t.Fatalf("MaxRequestBody=%d yields %d, want the default %d (there is no unlimited setting)",
				configured, got, DefaultMaxRequestBody)
		}
	}
}

// TestMalformedBodies pins the asymmetry: a body that is simply not JSON-RPC is proxied with
// no tool (the PDP still decides it), while a message that claims to be a tools/call but names
// no tool is refused — that is the only shape where "no tool" would launder a tool call.
func TestMalformedBodies(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		wantStatus int
		wantCalls  int
	}{
		{"non-JSON body proxies with no call", "this is not json", http.StatusOK, 0},
		{"non-RPC JSON proxies with no call", `{"query":"select 1"}`, http.StatusOK, 0},
		{"truncated JSON proxies with no call", `{"jsonrpc":"2.0","method"`, http.StatusOK, 0},
		{"tools/call with no name is refused", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}`, http.StatusBadRequest, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var seen *Request
			g, upstreamBody := mcpGateway(t, recordRequest(&seen))
			rec := httptest.NewRecorder()
			g.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/servers/demo/mcp", strings.NewReader(tc.body)))

			if rec.Code != tc.wantStatus {
				t.Fatalf("got %d, want %d", rec.Code, tc.wantStatus)
			}
			if tc.wantStatus != http.StatusOK {
				if seen != nil {
					t.Fatal("a refused request must not reach the pipeline")
				}
				return
			}
			if len(seen.Calls) != tc.wantCalls {
				t.Fatalf("calls = %+v, want %d", seen.Calls, tc.wantCalls)
			}
			// Whatever it was, the upstream still gets it verbatim.
			if string(*upstreamBody) != tc.body {
				t.Fatalf("upstream body = %q, want %q", *upstreamBody, tc.body)
			}
		})
	}
}

// TestBatchExposesEveryCall: the decision layer must see every element of a batch. One call
// per element, in order, with each tools/call's own tool.
func TestBatchExposesEveryCall(t *testing.T) {
	const batch = `[{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}},` +
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read"}},` +
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"admin_delete"}}]`

	var seen *Request
	g, upstreamBody := mcpGateway(t, recordRequest(&seen))
	rec := httptest.NewRecorder()
	g.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/servers/demo/mcp", strings.NewReader(batch)))

	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", rec.Code)
	}
	want := []RPCCall{
		{Method: "initialize"},
		{Method: "tools/call", Tool: "read"},
		{Method: "tools/call", Tool: "admin_delete"},
	}
	if len(seen.Calls) != len(want) {
		t.Fatalf("calls = %+v, want %+v", seen.Calls, want)
	}
	for i := range want {
		if seen.Calls[i] != want[i] {
			t.Fatalf("call %d = %+v, want %+v", i, seen.Calls[i], want[i])
		}
	}
	if string(*upstreamBody) != batch {
		t.Fatalf("batch body not forwarded intact: %q", *upstreamBody)
	}
}

// TestNonPOSTRequestsAreNotBuffered: the body-side change must be inert for the transport's
// other verbs — GET opens the server->client SSE stream, DELETE ends a session — so their
// requests reach the reverse proxy exactly as before, with no calls parsed and no body read.
func TestNonPOSTRequestsAreNotBuffered(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			var seen *Request
			g, _ := mcpGateway(t, recordRequest(&seen))
			rec := httptest.NewRecorder()
			r := httptest.NewRequest(method, "/servers/demo/mcp", nil)
			r.Header.Set("Accept", "text/event-stream")
			g.ServeHTTP(rec, r)

			if rec.Code != http.StatusOK {
				t.Fatalf("%s: got %d, want 200", method, rec.Code)
			}
			if seen.Body != nil || seen.Calls != nil {
				t.Fatalf("%s must not be buffered or parsed, got body=%q calls=%+v", method, seen.Body, seen.Calls)
			}
		})
	}
}

// TestSSEStreamingStillWorks: buffering the REQUEST must not touch the RESPONSE. An SSE
// stream opened with GET has to arrive incrementally — if any event only shows up once the
// upstream closes, streaming has been broken.
func TestSSEStreamingStillWorks(t *testing.T) {
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "event: message\ndata: first\n\n")
		w.(http.Flusher).Flush()
		<-release // hold the stream open: the first event must already have been delivered
		_, _ = io.WriteString(w, "event: message\ndata: second\n\n")
		w.(http.Flusher).Flush()
	}))
	defer upstream.Close()

	reg := NewRegistry()
	if err := reg.Register(&Server{ID: "demo", Upstream: mustURL(t, upstream.URL)}); err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(&Gateway{Registry: reg, Pipeline: Pipeline{Stages: []Stage{stubMint()}}})
	defer front.Close()

	req, _ := http.NewRequest(http.MethodGet, front.URL+"/servers/demo/mcp", nil)
	req.Header.Set("Accept", "text/event-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		close(release)
		resp.Body.Close()
	}()

	lines := bufio.NewReader(resp.Body)
	read := make(chan string, 1)
	go func() {
		for {
			line, err := lines.ReadString('\n')
			if err != nil {
				return
			}
			if strings.HasPrefix(line, "data: ") {
				read <- strings.TrimSpace(strings.TrimPrefix(line, "data: "))
				return
			}
		}
	}()
	select {
	case got := <-read:
		if got != "first" {
			t.Fatalf("first SSE event = %q, want %q", got, "first")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no SSE event arrived while the upstream stream was still open: streaming is buffered")
	}
}

// TestPOSTWithNoBodyIsUnaffected covers the degenerate POST (Content-Length: 0), which must
// not acquire a phantom body or a parse error on its way through.
func TestPOSTWithNoBodyIsUnaffected(t *testing.T) {
	var seen *Request
	g, upstreamBody := mcpGateway(t, recordRequest(&seen))
	rec := httptest.NewRecorder()
	g.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/servers/demo/mcp", bytes.NewReader(nil)))

	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", rec.Code)
	}
	if len(seen.Calls) != 0 {
		t.Fatalf("calls = %+v, want none", seen.Calls)
	}
	if len(*upstreamBody) != 0 {
		t.Fatalf("upstream body = %q, want empty", *upstreamBody)
	}
}
