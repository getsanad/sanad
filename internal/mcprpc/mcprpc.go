// Package mcprpc reads an MCP streamable-HTTP request once and finds the tools it invokes.
//
// It exists because the same problem shows up at both ends of the system. In MCP streamable
// HTTP every JSON-RPC message is POSTed to ONE endpoint, so the tool being invoked is in the
// body's params.name — no amount of URL inspection reaches it. The gateway needs the tool to
// authorize the request (policy stage, FR-16); the resource server needs the tool to enforce
// the scope on the passport it was handed (verify.EnforceScope). Both must read a one-shot
// body and put it back byte-for-byte, or they corrupt the call they were trying to protect.
//
// Living in internal/ keeps this shared without either side depending on the other: the
// gateway is a reverse proxy with a registry and a pipeline, and dragging that into every
// MCP server that embeds the small offline verify library would be a poor trade. The gateway
// re-exports Call as gateway.RPCCall (a type alias, so it stays the same type).
package mcprpc

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// DefaultMaxBody bounds how much of a request body is held in memory (1 MiB). The body has
// to be read before the request can be decided, and that happens before authentication, so
// it is attacker-controlled memory multiplied by concurrency. Hence a cap, and an oversize
// body is refused with 413 rather than forwarded undecided (NFR-3). 1 MiB sits far above any
// realistic tools/call argument payload and far below what makes a single request a memory
// event; deployments that legitimately move large blobs through MCP raise it.
const DefaultMaxBody = 1 << 20

// MethodToolsCall is the one MCP method whose params name a tool. Its JSON-RPC body is
//
//	{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_weather","arguments":{…}}}
//
// so the requested tool is params.name (MCP 2025-06-18 §Tools). Every other method names no
// tool of its own: initialize carries protocolVersion/capabilities/clientInfo, tools/list
// carries an optional cursor, and notifications/* (no "id") carry lifecycle signals.
const MethodToolsCall = "tools/call"

// Call is one JSON-RPC message parsed out of a request body, reduced to what a decision
// needs. A batch — a JSON array, permitted by JSON-RPC 2.0 and by MCP streamable HTTP
// through protocol version 2025-03-26, removed again in 2025-06-18 — produces one Call per
// element, because a decision that only looked at the first element would let it authorize
// every element behind it.
type Call struct {
	Method       string // JSON-RPC method, e.g. "tools/call", "tools/list", "initialize"
	Tool         string // tools/call target (params.name); empty for every other method
	Notification bool   // no "id": the caller expects no response for this element
}

// rpcMessage is the JSON-RPC envelope, kept deliberately loose. Method is a pointer so an
// absent one (a client POSTing a *response* back to a server-initiated request, which invokes
// nothing) is distinguishable from a present one, and Params stays raw so a call with
// positional or otherwise odd params still parses far enough for us to see that it IS a
// tools/call — decoding straight into a typed params struct would fail and silently yield
// "no tool", which is the one place that failure mode matters.
type rpcMessage struct {
	Method *string         `json:"method"`
	ID     json.RawMessage `json:"id"`
	Params json.RawMessage `json:"params"`
}

// Parse extracts the JSON-RPC calls a request body contains: one for a single message,
// one per element for a batch, none for a body that is not JSON-RPC at all.
//
// The posture is deliberately asymmetric.
//
// A body we cannot read as JSON-RPC — arbitrary JSON, a form post, a binary upload, garbage —
// yields NO calls rather than an error. The gateway fronts whatever a registered upstream
// speaks and must not turn every non-MCP POST into a 400. "No calls" is also not "allow": it
// lands on exactly the path a bodyless request already takes, where the PDP gets one decision
// naming no tool and no method (policy.MethodNone) — a denial under the shipped
// deny-by-default, and an allow only where the operator's policy says so in as many words. An
// unparseable body cannot invent a tool name, so admitting one bypasses nothing.
//
// A message that positively identifies itself as a tools/call but does not name a tool IS an
// error. That is the one shape where failing open would matter: a request whose entire purpose
// is to invoke a tool would be authorized as though it invoked none. It cannot be legitimate
// either — MCP requires params.name — so it is refused.
//
// One residual: duplicate JSON keys resolve to the last occurrence here, while some parsers
// take the first. The gateway cannot close that differential alone, which is why the tool it
// decided on is carried in the passport for the upstream to re-check.
func Parse(body []byte) ([]Call, error) {
	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		return nil, nil
	}
	switch body[0] {
	case '{':
		var msg rpcMessage
		if json.Unmarshal(body, &msg) != nil {
			return nil, nil // not a JSON-RPC envelope
		}
		call, ok, err := msg.call()
		if err != nil || !ok {
			return nil, err
		}
		return []Call{call}, nil

	case '[':
		var msgs []rpcMessage
		if json.Unmarshal(body, &msgs) != nil {
			return nil, nil
		}
		calls := make([]Call, 0, len(msgs))
		for i, msg := range msgs {
			call, ok, err := msg.call()
			if err != nil {
				return nil, fmt.Errorf("batch element %d: %w", i, err)
			}
			if ok {
				calls = append(calls, call)
			}
		}
		return calls, nil

	default:
		return nil, nil
	}
}

// call reduces one envelope to a Call. ok is false when the message is not a call at all —
// a JSON-RPC response, which carries result/error and no method, and authorizes nothing.
func (m rpcMessage) call() (Call, bool, error) {
	if m.Method == nil {
		return Call{}, false, nil
	}
	c := Call{Method: *m.Method, Notification: len(m.ID) == 0}
	if c.Method != MethodToolsCall {
		return c, true, nil
	}
	var p struct {
		Name *string `json:"name"`
	}
	if err := json.Unmarshal(m.Params, &p); err != nil || p.Name == nil || *p.Name == "" {
		return Call{}, false, errors.New(`tools/call with no params.name: the tool being invoked cannot be determined`)
	}
	c.Tool = *p.Name
	return c, true, nil
}

// ErrBodyTooLarge marks a body that hit the cap, so the caller can answer 413 rather than the
// 400 a truncated or aborted read gets.
var ErrBodyTooLarge = errors.New("request body exceeds the configured limit")

// BufferBody reads the body once, under a cap, and puts it back so the request can still be
// served — forwarded byte-for-byte by a reverse proxy, or read by the handler the middleware
// wraps. This is what makes tool extraction possible at all: the body is a one-shot reader,
// so an extractor that read it directly would leave the next reader with nothing — silently
// corrupting every MCP call.
//
// ContentLength is rewritten and TransferEncoding cleared because the buffered length is now
// exactly known: net/http frames an outbound request from those two fields and ignores the
// header map's Content-Length entirely, so leaving a chunked-request -1 in place would re-chunk
// a body whose size we have. GetBody is supplied because a server request has none, and without
// it an outbound transport cannot replay the body on a retry or an HTTP/2 GOAWAY — the retried
// MCP call would be resent empty.
//
// max <= 0 selects DefaultMaxBody; there is deliberately no "unlimited" setting, because the
// buffer is filled before the caller has been authenticated.
func BufferBody(w http.ResponseWriter, r *http.Request, max int64) ([]byte, error) {
	if max <= 0 {
		max = DefaultMaxBody
	}
	r.Body = http.MaxBytesReader(w, r.Body, max)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return nil, fmt.Errorf("%w (%d bytes)", ErrBodyTooLarge, max)
		}
		return nil, fmt.Errorf("reading request body: %w", err)
	}

	if len(body) == 0 {
		r.Body = http.NoBody
		r.GetBody = func() (io.ReadCloser, error) { return http.NoBody, nil }
	} else {
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	}
	r.ContentLength = int64(len(body))
	r.TransferEncoding = nil
	return body, nil
}

// HasBody reports whether a request carries a body worth buffering.
//
// Only POST does. MCP streamable HTTP sends every JSON-RPC message as a POST to the single MCP
// endpoint, opens the server->client SSE stream with GET, and terminates a session with DELETE.
// Restricting buffering to POST is what keeps body inspection inert for the streaming and
// upgrade paths: a GET passes through exactly as it did before, its body untouched and its
// response unbuffered.
//
// Content-Type is deliberately NOT consulted. MCP requires application/json, but the body is
// parsed for a tool name on its bytes alone, so a caller cannot slip a tools/call past the
// decision by labelling it text/plain and relying on a lenient upstream to run it anyway.
func HasBody(r *http.Request) bool {
	return r.Method == http.MethodPost && r.Body != nil && r.Body != http.NoBody && r.ContentLength != 0
}
