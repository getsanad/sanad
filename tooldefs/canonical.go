package tooldefs

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

// MethodToolsList is the MCP method whose RESULT carries the tool definitions:
//
//	{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":…,"description":…,"inputSchema":…}]}}
//
// It is the only place a client learns what a server's tools are and what they claim to do,
// which makes it the only place drift is observable (MCP 2025-06-18 §Tools).
const MethodToolsList = "tools/list"

// metaField is the one member of a tool definition that is deliberately NOT fingerprinted.
// The MCP spec reserves "_meta" for protocol/implementation metadata, so it is where a server
// legitimately puts things that vary between responses — request ids, timing, instance tags.
// Folding it in would make the fingerprint change for reasons that have nothing to do with
// what the model is shown, and a check that cries wolf gets turned off. Everything else in the
// definition IS fingerprinted, including fields this build has never heard of: a new
// model-visible field must fail closed into the digest rather than out of it.
const metaField = "_meta"

// ErrNotAToolList reports that a JSON-RPC result is not a tools/list result. It is a "nothing
// to check here", not a failure: the same response path sees results from every other method.
var ErrNotAToolList = errors.New("tooldefs: not a tools/list result")

// Defs is one observed tool list, reduced to the form that gets fingerprinted.
type Defs struct {
	// Names are the advertised tool names, sorted. They are NOT what the fingerprint is over —
	// the whole point is that a name can stay put while its description turns malicious — but
	// they are what makes a drift alert investigable at a glance ("…and `exfiltrate` is new").
	Names []string
	// Page reports that the upstream paginated this list (the result carried a nextCursor), so
	// these are some of the tools rather than all of them. A whole-list fingerprint cannot be
	// checked against a fragment; see Guard.observe for what happens instead.
	Page  bool
	bytes []byte
}

// Bytes returns the canonical definitions — the input to Hash and to Approved.Check.
func (d Defs) Bytes() []byte { return d.bytes }

// Fingerprint returns the digest of the canonical definitions.
func (d Defs) Fingerprint() Fingerprint { return Hash(d.bytes) }

// Canonical reduces a tools/list RESULT to stable bytes that can be fingerprinted across
// responses, servers and process restarts.
//
// A fingerprint is only as useful as it is stable, and hashing the response as it arrives is
// not stable at all: the JSON-RPC envelope carries an id that changes every call, a server may
// serialize object keys in any order (Go sorts them, Python and Node do not), and the order of
// the tools array is whatever the server's registry iteration produced. Every one of those
// would read as a rug-pull. So the result is re-serialized instead:
//
//   - only result.tools survives — the envelope and its id are dropped;
//   - each tool is re-encoded with its keys sorted (encoding/json does this for maps), with
//     numbers preserved as written (json.Number), and with "_meta" removed;
//   - the tools are then sorted by name, so a reordered list is not a changed one.
//
// What remains is exactly the surface the model is shown — name, title, description, input and
// output schema, annotations — and a change to any of it changes the digest.
func Canonical(result []byte) (Defs, error) {
	var raw struct {
		Tools      []json.RawMessage `json:"tools"`
		NextCursor string            `json:"nextCursor"`
	}
	if err := json.Unmarshal(result, &raw); err != nil || raw.Tools == nil {
		return Defs{}, ErrNotAToolList
	}

	type entry struct{ name, canon string }
	entries := make([]entry, 0, len(raw.Tools))
	for i, t := range raw.Tools {
		var m map[string]any
		dec := json.NewDecoder(bytes.NewReader(t))
		dec.UseNumber() // 1 and 1.0 are different bytes; do not let the decoder unify them
		if err := dec.Decode(&m); err != nil {
			return Defs{}, fmt.Errorf("tooldefs: tools[%d]: %w", i, err)
		}
		name, _ := m["name"].(string)
		if name == "" {
			// MCP requires a name, and without one the definition cannot be attributed to
			// anything. Refusing beats fingerprinting a list we cannot describe.
			return Defs{}, fmt.Errorf("tooldefs: tools[%d] has no name", i)
		}
		delete(m, metaField)
		canon, err := json.Marshal(m)
		if err != nil {
			return Defs{}, fmt.Errorf("tooldefs: tools[%d] (%s): %w", i, name, err)
		}
		entries = append(entries, entry{name: name, canon: string(canon)})
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].name != entries[j].name {
			return entries[i].name < entries[j].name
		}
		return entries[i].canon < entries[j].canon
	})

	var buf bytes.Buffer
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.name)
		buf.WriteString(e.canon)
		buf.WriteByte('\n')
	}
	return Defs{Names: names, Page: raw.NextCursor != "", bytes: buf.Bytes()}, nil
}

// ToolsResult finds the tools/list result inside a JSON-RPC response body — a single message
// or a batch — and returns it.
//
// It matches on SHAPE (a result carrying a "tools" array) rather than on the request id,
// because the id is the one thing the gateway's parsed request does not keep: mcprpc.Call is
// reduced to what a DECISION needs, and widening it to carry ids would change a type the
// gateway's tests compare by value. The shape is unambiguous in MCP — tools/list is the only
// method whose result has a "tools" array — and the cost of being wrong is bounded anyway:
// a false match yields definitions that fail to canonicalize, and a false miss yields no check.
func ToolsResult(body []byte) (json.RawMessage, bool) {
	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		return nil, false
	}
	type response struct {
		Result json.RawMessage `json:"result"`
	}
	switch body[0] {
	case '{':
		var r response
		if json.Unmarshal(body, &r) == nil && carriesTools(r.Result) {
			return r.Result, true
		}
	case '[':
		var rs []response
		if json.Unmarshal(body, &rs) != nil {
			return nil, false
		}
		for _, r := range rs {
			if carriesTools(r.Result) {
				return r.Result, true
			}
		}
	}
	return nil, false
}

// carriesTools reports whether a JSON-RPC result is a tools/list result.
func carriesTools(result json.RawMessage) bool {
	if len(result) == 0 {
		return false
	}
	var probe struct {
		Tools []json.RawMessage `json:"tools"`
	}
	return json.Unmarshal(result, &probe) == nil && probe.Tools != nil
}
