package tooldefs

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/getsanad/sanad/gateway"
	"github.com/getsanad/sanad/pkg/types"
)

// DefaultMaxListBytes bounds the tools/list response held in memory to fingerprint it (4 MiB).
// The bound exists for the same reason the request-body one does — it is upstream-controlled
// memory multiplied by concurrency — but it is looser, because it is filled only by a response
// to an authenticated, authorized tools/list on a server the operator pinned, which happens
// about once per MCP session, and because a large tool surface is exactly the case worth
// pinning. A list past the bound is unverifiable, and unverifiable is handled like drift.
const DefaultMaxListBytes int64 = 4 << 20

// AuditFunc receives every drift decision for recording. It is the seam the audit log plugs
// into (audit.ToolDefsHook), mirroring gateway.AuditFunc.
type AuditFunc func(Event)

// Event is one tool-definition observation, carrying enough to investigate it without going
// back to the wire: which server, what was approved, what actually arrived, which tools it
// advertised, and whether the request was stopped or merely noted.
type Event struct {
	At       time.Time
	Server   string
	Status   Status
	Mode     Mode
	Blocked  bool   // the response was refused / the request was denied
	Approved string // the pinned fingerprint; empty when the server is watched but unpinned
	Observed string // the fingerprint the upstream actually served
	Tools    []string
	Page     bool   // the observation covered one page of a paginated list
	Reason   string // prose an operator can act on
	// Attribution, copied from the in-flight request. Drift is a property of the SERVER, but it
	// is observed on someone's request, and that someone is where an investigation starts.
	Principal  string
	Agent      string
	PassportID string
	Delegation []string
}

// watch is one server's compiled configuration.
type watch struct {
	pinned bool
	mode   Mode
}

// Guard is the runtime half of tool-definition pinning: the pins, the failure mode, and the
// set of servers currently quarantined for having drifted.
//
// DESIGN — why the response path, and what it costs.
//
// Tool definitions are only ever visible in a tools/list RESPONSE, so a request-path-only check
// cannot see drift at all; that is why tooldefs.Check sat unused. Three integrations were
// possible:
//
//  1. Inspect tools/list responses inline (this one). It catches the poisoned definition on the
//     way to the agent and can stop it BEFORE the model ever sees the text — which is the whole
//     attack, since a rug-pull is delivered by being read. It costs a response-path change,
//     which is where the streaming risk lives.
//  2. Poll each registered server out of band and compare. It never touches the request path,
//     but it does not stop anything: an agent listing between two polls gets the poisoned
//     definitions in full. Worse, the poller is a distinguishable client — no agent identity, no
//     delegation, a fixed cadence — so a server that wants to pass it can simply serve the
//     approved list to the poller and the poisoned one to real callers.
//  3. Check at approval/config time only. That is where the pin comes FROM; on its own it
//     verifies nothing at runtime, which is the state this package was already in.
//
// (1) is the only option that stops the attack rather than reporting it afterwards, so that is
// what Inspect does. (2) remains a worthwhile complement for servers nobody happens to be
// listing — it is not implemented here.
//
// STREAMING. The response path is entered under one condition: the request was a POST whose
// JSON-RPC body asked for tools/list on a pinned server. A GET — which is how MCP opens its
// server-to-client SSE stream — carries no body, so it parses to no calls and is never
// inspected; neither is a tools/call, a DELETE, or anything on an unpinned server. Those
// responses reach httputil.ReverseProxy's copy loop exactly as before, with FlushInterval = -1
// still flushing every write.
//
// A tools/list POST may itself be answered either way, and the two are handled differently
// because only one of them CAN be:
//
//   - text/event-stream: NOT buffered. The body is wrapped in a pass-through reader that
//     fingerprints the tools/list result as it goes by (sseWatcher), so events keep arriving
//     incrementally. The cost is that by the time drift is known the bytes are already on the
//     wire and cannot be recalled. Detection still bites, because it quarantines the server: the
//     agent got one poisoned list and then every tool call it tries to make is denied.
//   - anything else: buffered under DefaultMaxListBytes, checked, and on drift refused outright.
//     Nothing has been written to the client yet, so the poisoned definitions never leave the
//     gateway. Buffering a single JSON reply is not "breaking streaming" — the reply is one
//     object the upstream has already finished writing. The split is on "must this be streamed",
//     not on "is this labelled application/json", because the label is the upstream's to choose
//     and choosing it wrongly would otherwise skip the check on the very response being checked.
//
// WHAT THIS DOES NOT CATCH.
//
//   - Drift on a server nobody lists through the gateway. If an agent cached the tool list from
//     an earlier session and only calls tools, nothing re-checks the pin. (This is what an
//     out-of-band poller would add.)
//   - The first poisoned list delivered over SSE, as above — detected and quarantined, not
//     prevented.
//   - Injection that does not live in a tool DEFINITION: poisoned tool RESULTS, resources/read
//     content, prompts/get templates. Those are a different control.
//   - A paginated tool list, and an SSE stream the upstream compressed. Neither can be compared
//     against a whole-list fingerprint in flight, so both are treated as UNVERIFIABLE rather than
//     quietly passed — otherwise a hostile server would escape every check by returning a
//     nextCursor or setting Content-Encoding.
//   - Anything at all on a server the operator has not pinned.
type Guard struct {
	approved *Approved
	watched  map[string]watch // immutable after Config.Guard

	// Audit receives every drift decision. Set at startup, before serving.
	Audit AuditFunc
	// Logf, if set, receives the same events as operator-facing log lines.
	Logf func(format string, args ...any)
	// MaxListBytes overrides DefaultMaxListBytes.
	MaxListBytes int64

	mu          sync.RWMutex
	quarantined map[string]Event
	reported    map[string]string // server -> last fingerprint reported for an unpinned server
}

func newGuard() *Guard {
	return &Guard{
		approved:    New(),
		watched:     map[string]watch{},
		quarantined: map[string]Event{},
		reported:    map[string]string{},
	}
}

// Watches reports whether a server's tool definitions are inspected at all.
func (g *Guard) Watches(server string) bool {
	if g == nil {
		return false
	}
	_, ok := g.watched[server]
	return ok
}

// Quarantined returns the drift event that quarantined a server, if it is quarantined.
func (g *Guard) Quarantined(server string) (Event, bool) {
	if g == nil {
		return Event{}, false
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	ev, ok := g.quarantined[server]
	return ev, ok
}

// QuarantinedCount is the number of servers currently held drifted. It is exported for the
// metrics gauge: drift that only ever reaches a log line is drift nobody alerts on (P1-11).
func (g *Guard) QuarantinedCount() int {
	if g == nil {
		return 0
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.quarantined)
}

func (g *Guard) maxListBytes() int64 {
	if g.MaxListBytes > 0 {
		return g.MaxListBytes
	}
	return DefaultMaxListBytes
}

// Inspect is the gateway's response hook (gateway.ResponseInspector). It returns an error only
// to refuse a response, and only ever for a drifted tools/list on a pinned server in deny mode.
func (g *Guard) Inspect(req *gateway.Request, resp *http.Response) error {
	if g == nil || req == nil || resp == nil || resp.Body == nil {
		return nil
	}
	// The single condition that admits a response to inspection at all. Everything else the
	// gateway proxies — every stream, every tool call, every unpinned server — returns here
	// having touched nothing.
	if !listsTools(req.Calls) {
		return nil
	}
	w, ok := g.watched[req.Server]
	if !ok || resp.StatusCode/100 != 2 {
		return nil
	}

	// The split is by whether the response CAN be held, not by whether it is JSON. Only
	// text/event-stream must not be buffered; everything else — including a response with a
	// missing, malformed or unexpected Content-Type — takes the buffered path. Choosing on
	// "is it declared application/json" instead would let an upstream escape the check by
	// mislabelling the very response being checked, and the label is the upstream's to pick.
	media, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err == nil && media == "text/event-stream" {
		g.inspectStream(req, resp, w)
		return nil
	}
	return g.inspectBuffered(req, resp, w)
}

// contentEncoding returns the response's transfer compression, or "" when there is none. The
// gateway deliberately does not decompress what it proxies (it would re-buffer an SSE stream),
// so the inspector has to deal with compressed definitions itself.
func contentEncoding(resp *http.Response) string {
	enc := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding")))
	if enc == "identity" {
		return ""
	}
	return enc
}

// decompress returns the definitions to fingerprint, undoing a transfer encoding on a COPY —
// the bytes forwarded to the client are never touched. gzip is handled because it is what an
// MCP server behind a gateway actually sends; any other encoding is reported as unverifiable
// rather than skipped, since "the upstream chose an encoding we do not read" would otherwise be
// a bypass an upstream can select at will.
func decompress(enc string, body []byte, max int64) ([]byte, error) {
	switch enc {
	case "":
		return body, nil
	case "gzip":
		zr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		// Bounded again on the way out: a compressed body under the limit can decompress into
		// one that is not (a zip bomb), and this buffer is upstream-controlled too.
		return io.ReadAll(io.LimitReader(zr, max))
	default:
		return nil, fmt.Errorf("content-encoding %q is not one this build can read", enc)
	}
}

// inspectBuffered holds a non-streaming response, checks it, and refuses it on drift. Refusal
// here is what makes the control preventive: ModifyResponse runs before any byte of the
// response has been written to the client, so the poisoned definitions never leave the gateway.
func (g *Guard) inspectBuffered(req *gateway.Request, resp *http.Response, w watch) error {
	max := g.maxListBytes()
	buf, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		// The response broke mid-read. There is nothing to verify and nothing to forward
		// either; leave the proxy to surface the transport failure.
		resp.Body = struct {
			io.Reader
			io.Closer
		}{io.MultiReader(bytes.NewReader(buf), errReader{err}), resp.Body}
		return nil
	}
	if int64(len(buf)) > max {
		// Too large to fingerprint. Put back what was read so the response is still whole, then
		// treat it as unverifiable — which under a pin is not a pass.
		resp.Body = struct {
			io.Reader
			io.Closer
		}{io.MultiReader(bytes.NewReader(buf), resp.Body), resp.Body}
		if g.unverifiable(req, w, true, fmt.Sprintf("the tools/list response exceeds the %d-byte inspection limit, so its definitions cannot be fingerprinted", max)) {
			return refuse(req.Server, "could not be verified against")
		}
		return nil
	}

	// The body was read to EOF, so the upstream connection is finished with; hand the client an
	// identical copy from memory — including its original compression, which is the client's to
	// undo, not ours.
	_ = resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(buf))

	plain, err := decompress(contentEncoding(resp), buf, max)
	if err != nil {
		if g.unverifiable(req, w, true, "the tools/list response could not be decompressed: "+err.Error()) {
			return refuse(req.Server, "could not be verified against")
		}
		return nil
	}

	result, ok := ToolsResult(plain)
	if !ok {
		return nil // an error reply, or a response carrying no tools/list result
	}
	defs, err := Canonical(result)
	if err != nil {
		if g.unverifiable(req, w, true, "the tools/list result could not be read as tool definitions: "+err.Error()) {
			return refuse(req.Server, "could not be verified against")
		}
		return nil
	}
	if g.observe(req, defs, w, true) {
		return refuse(req.Server, "do not match")
	}
	return nil
}

// refuse is the error that makes the gateway answer 403 instead of forwarding the response.
func refuse(server, verb string) error {
	return fmt.Errorf("%w: tooldefs: server %q advertised tool definitions that %s its approved fingerprint",
		gateway.ErrResponseRefused, server, verb)
}

// inspectStream wraps an SSE body so the tools/list result is fingerprinted as it streams past.
// Nothing is held back: the watcher hands every byte on the instant it is read.
func (g *Guard) inspectStream(req *gateway.Request, resp *http.Response, w watch) {
	if enc := contentEncoding(resp); enc != "" {
		// A compressed event stream cannot be read past without either buffering it or building
		// a streaming decompressor, and neither is worth it for a shape MCP servers do not send.
		// Reporting it is still better than silently not checking: the operator sees the reason
		// and can turn the encoding off or set on_drift to "warn".
		g.unverifiable(req, w, false, fmt.Sprintf("the tools/list SSE stream is %s-encoded, so its definitions cannot be fingerprinted in flight", enc))
		return
	}
	resp.Body = &sseWatcher{
		src: resp.Body,
		max: g.maxListBytes(),
		onEvent: func(data []byte) {
			result, ok := ToolsResult(data)
			if !ok {
				return
			}
			defs, err := Canonical(result)
			if err != nil {
				g.unverifiable(req, w, false, "the tools/list result streamed over SSE could not be read as tool definitions: "+err.Error())
				return
			}
			// canBlock is false: these bytes have already been forwarded. The observation still
			// quarantines the server, which is what stops the NEXT request.
			g.observe(req, defs, w, false)
		},
		onOverflow: func() {
			g.unverifiable(req, w, false, "the tools/list SSE event exceeds the inspection limit, so its definitions cannot be fingerprinted")
		},
	}
}

// observe compares one observed tool list against the pin and reports whether the caller should
// refuse the response. canBlock says whether refusing is still possible — over SSE it is not,
// and an event that claims a block that did not happen is a lie in the audit log.
func (g *Guard) observe(req *gateway.Request, defs Defs, w watch, canBlock bool) bool {
	ev := Event{
		At: time.Now().UTC(), Server: req.Server, Mode: w.mode,
		Observed: defs.Fingerprint().String(), Tools: defs.Names, Page: defs.Page,
	}
	attribute(&ev, req)

	if !w.pinned {
		// Watched but unpinned: report the fingerprint so the operator can adopt it. This is the
		// only way to obtain a pin without reimplementing Canonical by hand.
		ev.Status = Unknown
		ev.Reason = fmt.Sprintf("server %q is watched but not pinned; it advertises %d tool(s) %s with fingerprint %s — "+
			"add that as \"fingerprint\" in the tooldefs section to enforce it", req.Server, len(defs.Names), defs.Names, ev.Observed)
		if g.firstReport(req.Server, ev.Observed) {
			g.emit(ev)
		}
		return false
	}
	if base, ok := g.approved.Baseline(req.Server); ok {
		ev.Approved = base.String()
	}
	if defs.Page {
		// One page of a paginated list cannot be compared against a whole-list fingerprint, and
		// letting it through unchecked would hand every hostile server a one-line bypass.
		return g.unverifiable(req, w, canBlock,
			fmt.Sprintf("server %q paginated its tools/list (the result carries a nextCursor); a pinned tool surface must be served as one page", req.Server))
	}

	switch g.approved.Check(req.Server, defs.Bytes()) {
	case OK:
		ev.Status = OK
		if _, wasQuarantined := g.release(req.Server); wasQuarantined {
			ev.Reason = fmt.Sprintf("server %q matches its approved fingerprint again; the quarantine is lifted", req.Server)
			g.emit(ev)
		}
		return false

	case Drifted:
		ev.Status = Drifted
		ev.Blocked = canBlock && w.mode == ModeDeny
		ev.Reason = driftReason(req.Server, ev, canBlock, defs)
		g.hold(req.Server, ev)
		g.emit(ev)
		return ev.Blocked

	default: // Unknown: pinned in the config but absent from the baseline — cannot happen
		ev.Status = Unknown
		ev.Reason = fmt.Sprintf("server %q has no approved baseline to compare against", req.Server)
		g.emit(ev)
		return false
	}
}

func driftReason(server string, ev Event, canBlock bool, defs Defs) string {
	var b strings.Builder
	fmt.Fprintf(&b, "TOOL-DEFINITION DRIFT: server %q advertised %d tool(s) %s fingerprinting to %s, but %s was approved. ",
		server, len(defs.Names), defs.Names, ev.Observed, ev.Approved)
	switch {
	case ev.Blocked:
		b.WriteString("The response was REFUSED and the server is quarantined: only initialize/tools/list are forwarded until it matches again.")
	case !canBlock:
		b.WriteString("The definitions were streamed over SSE and had already reached the client, so they could NOT be withheld; " +
			"the server is quarantined, so its next tool call is denied.")
	default:
		b.WriteString("on_drift is \"warn\", so the response was FORWARDED as-is; the agent has seen these definitions.")
	}
	return b.String()
}

// unverifiable handles the cases where the definitions could not be checked at all: too large,
// unparseable, paginated, compressed in a way this build cannot read. Under a pin these are
// treated as drift would be, because "I could not
// check" is not "it is fine" — and every one of them is upstream-controlled, so the alternative
// is a bypass an attacker picks off a menu. It reports whether the response must be refused.
func (g *Guard) unverifiable(req *gateway.Request, w watch, canBlock bool, reason string) bool {
	if !w.pinned {
		return false
	}
	ev := Event{
		At: time.Now().UTC(), Server: req.Server, Status: Unknown, Mode: w.mode,
		Blocked: canBlock && w.mode == ModeDeny,
		Reason:  "TOOL-DEFINITION CHECK FAILED: " + reason,
	}
	if base, ok := g.approved.Baseline(req.Server); ok {
		ev.Approved = base.String()
	}
	attribute(&ev, req)
	g.hold(req.Server, ev)
	g.emit(ev)
	return ev.Blocked
}

// hold quarantines a server. It is a latch rather than a per-response verdict because the
// response that revealed the drift is not the only one that matters: an agent may already hold
// the poisoned list (SSE, or a list from before the pin was reached), and a server we have
// caught lying about its tools has no claim on being trusted for the tool calls that follow.
func (g *Guard) hold(server string, ev Event) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.quarantined[server] = ev
}

// release lifts a quarantine, reporting whether there was one. A server whose definitions match
// again — a bad release rolled back — must be able to recover without restarting the gateway,
// which is why the quarantine forwards tools/list instead of denying everything.
func (g *Guard) release(server string) (Event, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	ev, ok := g.quarantined[server]
	delete(g.quarantined, server)
	return ev, ok
}

// firstReport reports whether this fingerprint is new for an unpinned server, so the "here is
// the value to pin" notice is emitted once per surface rather than once per MCP session.
func (g *Guard) firstReport(server, fingerprint string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.reported[server] == fingerprint {
		return false
	}
	g.reported[server] = fingerprint
	return true
}

func (g *Guard) emit(ev Event) {
	if g.Logf != nil {
		g.Logf("tooldefs: %s", ev.Reason)
	}
	if g.Audit != nil {
		g.Audit(ev)
	}
}

func attribute(ev *Event, req *gateway.Request) {
	if req.Principal != nil {
		ev.Principal = req.Principal.ID
	}
	if req.Agent != nil {
		ev.Agent = req.Agent.ID
	}
	if req.Passport != nil {
		ev.PassportID = req.Passport.ID
	}
	ev.Delegation = req.Delegation.Path()
}

// Stage is the request-path half: it refuses traffic to a quarantined server before the
// gateway forwards anything. Without it, drift detected over SSE — where the response could not
// be withheld — would be a log line and nothing more.
//
// The quarantine is not total. A request carrying no JSON-RPC call (the bodyless GET that opens
// the event stream, a DELETE that ends a session) and a request whose every message is
// initialize / notifications/initialized / tools/list still go through, because those are what a
// client needs to ask the server what its tools are — and that answer is itself checked, and
// refused again if it is still drifted. Everything that does work on the server — every
// tools/call, every resources/read, every prompts/get — is denied. The alternative, denying the
// handshake too, makes the quarantine unrecoverable without a restart even after the operator
// has rolled the server back.
func (g *Guard) Stage() gateway.Stage {
	return gateway.NewStage("tooldefs", func(_ context.Context, req *gateway.Request) error {
		if g == nil {
			return nil
		}
		ev, held := g.Quarantined(req.Server)
		if !held || ev.Mode != ModeDeny || recoveryOnly(req) {
			return nil
		}
		reason := fmt.Sprintf("server %q is quarantined for tool-definition drift (approved %s, observed %s at %s); "+
			"only the MCP handshake and tools/list are forwarded until its definitions match again",
			req.Server, short(ev.Approved), short(ev.Observed), ev.At.Format(time.RFC3339))
		req.Decision = &types.Decision{Effect: types.EffectDeny, Reason: reason}
		return errors.New("tooldefs: " + reason)
	})
}

// recoveryOnly reports whether a request may still reach a quarantined server.
func recoveryOnly(req *gateway.Request) bool {
	if len(req.Body) == 0 {
		return true // no JSON-RPC body at all: a GET opening the stream, or a DELETE ending it
	}
	if len(req.Calls) == 0 {
		return false // a body the gateway could not read as JSON-RPC: not a handshake
	}
	for _, c := range req.Calls {
		switch c.Method {
		case "initialize", "notifications/initialized", MethodToolsList:
		default:
			return false
		}
	}
	return true
}

// listsTools reports whether a request asked for tool definitions, which is the only shape of
// request whose response this package looks at.
func listsTools(calls []gateway.RPCCall) bool {
	for _, c := range calls {
		if c.Method == MethodToolsList && !c.Notification {
			return true
		}
	}
	return false
}

func short(fingerprint string) string {
	if rest, ok := strings.CutPrefix(fingerprint, "sha256:"); ok && len(rest) > 8 {
		return "sha256:" + rest[:8] + "…"
	}
	if fingerprint == "" {
		return "(none)"
	}
	return fingerprint
}

// errReader replays a read error, so a response that broke mid-read stays broken for the client
// instead of being silently truncated into a valid-looking short body.
type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }
