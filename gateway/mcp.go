package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// DefaultMaxRequestBody bounds how much of a request body the gateway will hold in memory
// (1 MiB). The gateway has to read the body before it can decide — in MCP streamable HTTP
// the tool being invoked lives in a JSON-RPC body POSTed to one endpoint, not in the URL
// (see parseRPC) — and buffering happens before authentication, so it is attacker-controlled
// memory multiplied by concurrency. Hence a cap, and an oversize body is refused with 413
// rather than forwarded undecided (NFR-3). 1 MiB sits far above any realistic tools/call
// argument payload and far below what makes a single request a memory event; deployments
// that legitimately move large blobs through MCP raise it with Gateway.MaxRequestBody.
const DefaultMaxRequestBody = 1 << 20

// methodToolsCall is the one MCP method whose params name a tool. Its JSON-RPC body is
//
//	{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_weather","arguments":{…}}}
//
// so the requested tool is params.name (MCP 2025-06-18 §Tools). Every other method names no
// tool of its own: initialize carries protocolVersion/capabilities/clientInfo, tools/list
// carries an optional cursor, and notifications/* (no "id") carry lifecycle signals.
const methodToolsCall = "tools/call"

// RPCCall is one JSON-RPC message the gateway parsed out of a request body, reduced to what
// a decision needs. A batch — a JSON array, permitted by JSON-RPC 2.0 and by MCP streamable
// HTTP through protocol version 2025-03-26, removed again in 2025-06-18 — produces one
// RPCCall per element, because a gateway that only looked at the first element would let it
// authorize every element behind it.
type RPCCall struct {
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

// parseRPC extracts the JSON-RPC calls a request body contains: one for a single message,
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
func parseRPC(body []byte) ([]RPCCall, error) {
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
		return []RPCCall{call}, nil

	case '[':
		var msgs []rpcMessage
		if json.Unmarshal(body, &msgs) != nil {
			return nil, nil
		}
		calls := make([]RPCCall, 0, len(msgs))
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

// call reduces one envelope to an RPCCall. ok is false when the message is not a call at all —
// a JSON-RPC response, which carries result/error and no method, and authorizes nothing.
func (m rpcMessage) call() (RPCCall, bool, error) {
	if m.Method == nil {
		return RPCCall{}, false, nil
	}
	c := RPCCall{Method: *m.Method, Notification: len(m.ID) == 0}
	if c.Method != methodToolsCall {
		return c, true, nil
	}
	var p struct {
		Name *string `json:"name"`
	}
	if err := json.Unmarshal(m.Params, &p); err != nil || p.Name == nil || *p.Name == "" {
		return RPCCall{}, false, errors.New(`tools/call with no params.name: the tool being invoked cannot be determined`)
	}
	c.Tool = *p.Name
	return c, true, nil
}

// errBodyTooLarge marks a body that hit the cap, so the caller can answer 413 rather than the
// 400 a truncated or aborted read gets.
var errBodyTooLarge = errors.New("request body exceeds the configured limit")

// bufferRequestBody reads the body once, under a cap, and puts it back so the reverse proxy
// still forwards it byte-for-byte. This is what makes tool extraction possible at all: the
// body is a one-shot reader, so an extractor that read it directly would leave the proxy
// forwarding an empty body upstream — silently corrupting every MCP call.
//
// ContentLength is rewritten and TransferEncoding cleared because the buffered length is now
// exactly known: net/http frames the outbound request from those two fields and ignores the
// header map's Content-Length entirely, so leaving a chunked-request -1 in place would re-chunk
// a body whose size we have. GetBody is supplied because a server request has none, and without
// it the outbound transport cannot replay the body on a retry or an HTTP/2 GOAWAY — the retried
// MCP call would be resent empty.
func bufferRequestBody(w http.ResponseWriter, r *http.Request, max int64) ([]byte, error) {
	r.Body = http.MaxBytesReader(w, r.Body, max)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return nil, fmt.Errorf("%w (%d bytes)", errBodyTooLarge, max)
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

// hasRequestBody reports whether a request carries a body worth buffering.
//
// Only POST does. MCP streamable HTTP sends every JSON-RPC message as a POST to the single MCP
// endpoint, opens the server->client SSE stream with GET, and terminates a session with DELETE.
// Restricting buffering to POST is what keeps this change inert for the streaming and upgrade
// paths: a GET reaches the reverse proxy exactly as it did before, its body untouched and its
// response unbuffered (registry.go's FlushInterval = -1).
//
// Content-Type is deliberately NOT consulted. MCP requires application/json, but the body is
// parsed for a tool name on its bytes alone, so a caller cannot slip a tools/call past the
// decision by labelling it text/plain and relying on a lenient upstream to run it anyway.
func hasRequestBody(r *http.Request) bool {
	return r.Method == http.MethodPost && r.Body != nil && r.Body != http.NoBody && r.ContentLength != 0
}
