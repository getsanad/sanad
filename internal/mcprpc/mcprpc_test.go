package mcprpc

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ToolsCallBody is a real MCP streamable-HTTP tools/call body (MCP 2025-06-18 §Tools): the
// tool being invoked is params.name, which no amount of URL inspection can reach.
const toolsCall = `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_weather","arguments":{"location":"New York"}}}`

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		want    []Call
		wantErr bool
	}{
		{
			name: "tools/call names the tool in params.name",
			body: toolsCall,
			want: []Call{{Method: "tools/call", Tool: "get_weather"}},
		},
		{
			name: "tools/list invokes no tool of its own",
			body: `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"cursor":"abc"}}`,
			want: []Call{{Method: "tools/list"}},
		},
		{
			name: "initialize invokes no tool of its own",
			body: `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"c","version":"1"}}}`,
			want: []Call{{Method: "initialize"}},
		},
		{
			name: "notification has no id",
			body: `{"jsonrpc":"2.0","method":"notifications/initialized"}`,
			want: []Call{{Method: "notifications/initialized", Notification: true}},
		},
		{
			// JSON-RPC 2.0 batching, which MCP streamable HTTP permitted through 2025-03-26.
			name: "batch yields one call per element",
			body: `[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}},
			        {"jsonrpc":"2.0","method":"notifications/initialized"},
			        {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"admin_delete"}}]`,
			want: []Call{
				{Method: "tools/call", Tool: "read"},
				{Method: "notifications/initialized", Notification: true},
				{Method: "tools/call", Tool: "admin_delete"},
			},
		},
		{
			// A client POSTing a response to a server-initiated request (sampling, elicitation)
			// invokes nothing: no method, no call, nothing to authorize per tool.
			name: "a JSON-RPC response is not a call",
			body: `{"jsonrpc":"2.0","id":3,"result":{"content":[]}}`,
			want: []Call{},
		},
		{name: "empty batch", body: `[]`, want: []Call{}},
		{name: "malformed JSON", body: `{"jsonrpc":"2.0","method":`, want: []Call{}},
		{name: "not JSON at all", body: "\x00\x01binary", want: []Call{}},
		{name: "JSON that is not JSON-RPC", body: `{"hello":"world"}`, want: []Call{}},
		{name: "JSON scalar", body: `"just a string"`, want: []Call{}},
		{name: "empty body", body: "", want: []Call{}},

		// Fail closed: a message that says it is calling a tool but does not name one would
		// otherwise be authorized as though it called none.
		{name: "tools/call without params", body: `{"jsonrpc":"2.0","id":1,"method":"tools/call"}`, wantErr: true},
		{name: "tools/call with no name", body: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"arguments":{}}}`, wantErr: true},
		{name: "tools/call with an empty name", body: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":""}}`, wantErr: true},
		{name: "tools/call with positional params", body: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":["read"]}`, wantErr: true},
		{
			name:    "a batch is refused if ANY element is unreadable",
			body:    `[{"jsonrpc":"2.0","id":1,"method":"tools/list"},{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{}}]`,
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Parse([]byte(tc.body))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want an error, got calls %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %d calls %+v, want %d %+v", len(got), got, len(tc.want), tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("call %d = %+v, want %+v", i, got[i], tc.want[i])
				}
			}
		})
	}
}

// TestBufferBodyPutsTheBodyBack is the property both callers depend on: after buffering, the
// next reader still sees the exact bytes. Without it every MCP call is silently corrupted.
func TestBufferBodyPutsTheBodyBack(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(toolsCall))
	body, err := BufferBody(httptest.NewRecorder(), r, 0)
	if err != nil {
		t.Fatalf("BufferBody: %v", err)
	}
	if string(body) != toolsCall {
		t.Fatalf("buffered %q, want the body", body)
	}
	again, _ := io.ReadAll(r.Body)
	if string(again) != toolsCall {
		t.Fatalf("re-read %q, want the body", again)
	}
	if r.ContentLength != int64(len(toolsCall)) {
		t.Fatalf("ContentLength = %d, want %d", r.ContentLength, len(toolsCall))
	}
	if r.GetBody == nil {
		t.Fatal("GetBody must be supplied so an outbound transport can replay the body")
	}
}

// TestBufferBodyCapIsAlwaysApplied: max <= 0 must not mean "unlimited" — the buffer is
// filled before the caller has been authenticated.
func TestBufferBodyCapIsAlwaysApplied(t *testing.T) {
	for _, max := range []int64{0, -1} {
		r := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader("x"))
		if _, err := BufferBody(httptest.NewRecorder(), r, max); err != nil {
			t.Fatalf("max=%d: %v", max, err)
		}
	}
	// Over the cap is an ErrBodyTooLarge, distinguishable from a read failure so the caller
	// can answer 413 rather than 400.
	r := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(strings.Repeat("A", 128)))
	_, err := BufferBody(httptest.NewRecorder(), r, 16)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversize body: got %v, want ErrBodyTooLarge", err)
	}
}

func TestHasBodyOnlyPOST(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodDelete, http.MethodPut} {
		r := httptest.NewRequest(method, "/mcp", strings.NewReader(toolsCall))
		if HasBody(r) {
			t.Fatalf("%s must not be buffered: MCP posts every JSON-RPC message", method)
		}
	}
	if !HasBody(httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(toolsCall))) {
		t.Fatal("a POST with a body must be buffered")
	}
	if HasBody(httptest.NewRequest(http.MethodPost, "/mcp", nil)) {
		t.Fatal("a POST with no body has nothing to buffer")
	}
}
