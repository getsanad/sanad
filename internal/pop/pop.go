// Package pop makes a proof of possession prove something about THIS request.
//
// A signature over a long-lived value is not a proof of possession; it is a bearer token
// with extra steps. Ed25519 is deterministic, so sign(instanceKey, principalToken) is the
// same 64 bytes on every request for the token's whole lifetime. Anyone who sees one
// request's headers — a TLS-terminating load balancer, an access log with header capture,
// the upstream MCP server, a sidecar, an attacker on the plaintext hop — can replay the
// bundle verbatim and be that instance until the token expires. The signature proves the
// key existed at some point; it says nothing about who is calling now, or what they are
// calling.
//
// # The DPoP shape
//
// This is the problem OAuth solved in RFC 9449 (DPoP), and its answer is adopted here: the
// proof commits to the HTTP method (htm), the target URI (htu), a creation time (iat), a
// unique identifier (jti), and a hash of the access token it accompanies (ath). A verifier
// checks each against the request in front of it, bounds iat to a small window, and refuses
// a jti it has already seen. Claim names, semantics and the checking order below are RFC
// 9449 §4.2/§4.3.
//
// What is NOT adopted is the serialization. A DPoP proof is a JWS: a JOSE header naming an
// algorithm and carrying the public key, then base64url JSON, then a signature. Sanad does
// not need any of that, and each part costs something:
//
//   - The key is already CA-signed. DPoP puts a bare `jwk` in the header and binds it to the
//     access token out-of-band via `cnf`/`jkt`, because the AS and the RS share no key
//     material. Here the instance public key arrives in a workload credential the authority
//     signed (workload.Credential), and the capability's next-key is authenticated by the
//     capability chain. A self-asserted `jwk` would be strictly weaker and would have to be
//     ignored anyway.
//   - An `alg` header is a liability, not a feature. One signature algorithm is supported.
//     A parsed, attacker-supplied algorithm field is the root of the whole JWT confusion
//     family (alg:none, HS256-over-an-RSA-public-key), and re-introducing it in three
//     languages to describe a constant is a poor trade.
//   - Every signature in Sanad is domain-separated through internal/sigctx. A JWS signs
//     `b64(header).b64(payload)` with no context label, so a JWT proof would open the exact
//     signing oracle sigctx exists to close.
//
// So the wire form is the binding inputs, canonically encoded, signed under a sigctx label:
//
//	X-Agent-Proof: base64url(payload JSON) "." base64url(Ed25519 signature)
//
// which is a JWS with the JOSE header replaced by a context string both sides already agree
// on. The signature covers the payload bytes AS TRANSMITTED, so a verifier never re-encodes
// what it is checking: three independent implementations (Go, TypeScript, Python) cannot
// disagree about JSON canonicalization, because canonicalization is not on the verify path.
//
// # One deliberate addition: the body
//
// RFC 9449 §11.7 is explicit that "DPoP does not ensure the integrity of the payload ... The
// DPoP proof only contains claims for the HTTP URI and method, but not the message body."
// For an OAuth resource that is a documented residual risk. For an MCP gateway it is the
// whole authorization decision: in MCP streamable HTTP every JSON-RPC message is POSTed to
// ONE endpoint, so method and path are identical for `tools/list` and for `tools/call` of any
// tool with any arguments (see internal/mcprpc). A proof covering only htm and htu would
// leave a captured header bundle usable to invoke any tool the agent is entitled to, which is
// most of what an attacker wanted. The gateway already buffers the body to find the tool, so
// binding a hash of it (bh) costs one SHA-256 and closes that.
//
// # What is still not covered
//
// Headers other than Authorization, and the network peer. Channel binding to the TLS
// connection is the real answer to the latter and arrives with mTLS (Phase 4); until then a
// replay is bounded to the identical method, path, body and token inside the freshness
// window, not eliminated. See ReplayCache for what a second replica does not know.
package pop

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/getsanad/sanad/internal/sigctx"
)

// Freshness window. RFC 9449 §11.1 asks for "a relatively brief period on the order of
// seconds or minutes" and permits an iat "in the reasonably near future" for client clock
// skew; these are the concrete numbers.
const (
	// DefaultMaxAge is how old a proof may be. It has to cover proof creation through
	// arrival: the sidecar hop, connection setup, load-balancer queueing, a GC pause, and a
	// client that rebuilt nothing when it retried a connection that failed after the proof
	// was signed. Thirty seconds sits far above a same-cluster p99 and still means a proof
	// captured off the wire is inert within half a minute.
	DefaultMaxAge = 30 * time.Second

	// DefaultSkew is how far into the future an iat may sit. It exists only for a client
	// whose clock runs fast; NTP-synced hosts are within milliseconds, and a container that
	// has not yet stepped its clock is the realistic case. It is kept much smaller than
	// DefaultMaxAge because every second of future tolerance is a second added to the window
	// in which a captured proof is replayable on a replica that has not seen its jti.
	DefaultSkew = 5 * time.Second

	// DefaultCacheEntries bounds the replay cache. See ReplayCache.
	DefaultCacheEntries = 1 << 16

	// MaxJTI bounds the length of a jti the cache will store. Without it the memory bound is
	// entries x (whatever the caller sent), which is not a bound. 128 chars is generous for
	// the 128 bits of randomness Sign emits (22 chars) and for a UUID (36).
	MaxJTI = 128
)

// Binding is what a proof commits to: the DPoP claim set (RFC 9449 §4.2) plus bh.
//
// Field order here IS the canonical encoding order (alphabetical), and it is mirrored by the
// TypeScript and Python SDKs. Byte-identical output across the three is a property worth
// keeping — the interop vectors pin it — but it is not load-bearing: Verify checks the
// signature against the bytes that arrived, never against a re-encoding.
type Binding struct {
	ATH string `json:"ath"` // base64url(SHA-256(principal bearer token)), RFC 9449 §4.2
	BH  string `json:"bh"`  // base64url(SHA-256(request body)); Sanad's addition
	HTM string `json:"htm"` // HTTP method, verbatim
	HTU string `json:"htu"` // request target: escaped path, plus "?" and the raw query
	IAT int64  `json:"iat"` // creation time, Unix seconds
	JTI string `json:"jti"` // unique per proof
}

// Target is the htu value: the origin-form request target, which is exactly what both ends
// can see. Two deliberate departures from RFC 9449 §4.2:
//
// The authority is left out. A DPoP htu is an absolute URI, which assumes the server can
// reconstruct the scheme and host the client used. This gateway cannot: there is no TLS yet,
// so the scheme is whatever terminated in front of it; the sidecar is an httputil.ReverseProxy
// and forwards the client's Host header rather than the gateway's; and an ingress may rewrite
// Host again. Binding a value the two ends compute differently does not add security, it adds
// an outage. Cross-host replay is instead bounded by the audience-bound principal token, and
// properly closed by channel binding once mTLS lands (Phase 4).
//
// The query IS included, where DPoP drops it. DPoP drops it because intermediaries rewrite
// query strings; nothing between an agent and this gateway does, both ends read the same
// RawQuery, and including it is strictly stronger.
func Target(u *url.URL) string {
	if u == nil {
		return ""
	}
	t := u.EscapedPath()
	if t == "" {
		t = "/"
	}
	if u.RawQuery != "" {
		t += "?" + u.RawQuery
	}
	return t
}

// Hash is the digest form both ath and bh use: base64url(SHA-256(b)), as RFC 9449 §4.2
// specifies for ath.
func Hash(b []byte) string {
	sum := sha256.Sum256(b)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// NewBinding builds the claims for one request. jti is 128 bits of crypto/rand — above the
// 96 RFC 9449 §4.2 asks for — so a collision is not a thing a caller has to think about even
// across a fleet, and a jti is never reused by an honest client.
func NewBinding(method, target, token string, body []byte, now time.Time) (Binding, error) {
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return Binding{}, fmt.Errorf("pop: generating jti: %w", err)
	}
	return Binding{
		ATH: Hash([]byte(token)),
		BH:  Hash(body),
		HTM: method,
		HTU: target,
		IAT: now.Unix(),
		JTI: base64.RawURLEncoding.EncodeToString(jti),
	}, nil
}

// Encode is the canonical payload encoding: compact JSON, keys in Binding's field order,
// HTML escaping off. Escaping is off because encoding/json otherwise rewrites the characters
// <, > and & into their six-character backslash-u escapes, which JavaScript's JSON.stringify
// and Python's json.dumps do not, and htu can carry any of the three in a query string.
// Keeping the three languages byte-identical is only a nicety (the signature covers what was
// sent, not a re-encoding), but a nicety the pinned interop vectors can then actually assert.
func Encode(b Binding) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(b); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil // Encoder.Encode appends one
}

// Sign returns the header value for b, signed under ctx: base64url(payload) "." base64url(sig).
func Sign(ctx string, key ed25519.PrivateKey, b Binding) (string, error) {
	if len(key) != ed25519.PrivateKeySize {
		return "", errors.New("pop: invalid private key")
	}
	payload, err := Encode(b)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(sigctx.Sign(ctx, key, payload)), nil
}

// Sentinel errors, so a caller can tell a stale proof from a replayed one from a full cache
// without matching on strings.
var (
	ErrStale     = errors.New("pop: proof is outside the freshness window")
	ErrReplayed  = errors.New("pop: proof identifier has already been used")
	ErrCacheFull = errors.New("pop: replay cache is full")
)

// Verifier checks request-bound proofs made under one context label. It owns the replay
// cache, so each verifier (one per stage) has its own jti space and two stages cannot
// invalidate each other's proofs.
type Verifier struct {
	ctx     string
	maxAge  time.Duration
	skew    time.Duration
	entries int
	now     func() time.Time
	cache   *ReplayCache
}

// Option configures a Verifier.
type Option func(*Verifier)

// WithClock replaces the clock, for tests.
func WithClock(now func() time.Time) Option { return func(v *Verifier) { v.now = now } }

// WithWindow sets how old a proof may be and how far ahead its iat may sit. Non-positive
// values keep the defaults.
func WithWindow(maxAge, skew time.Duration) Option {
	return func(v *Verifier) {
		if maxAge > 0 {
			v.maxAge = maxAge
		}
		if skew >= 0 {
			v.skew = skew
		}
	}
}

// WithCacheEntries caps the replay cache. Non-positive keeps the default.
func WithCacheEntries(n int) Option {
	return func(v *Verifier) {
		if n > 0 {
			v.entries = n
		}
	}
}

// window is the longest a proof accepted now can still be accepted, which is how long the
// replay cache has to remember its jti.
func (v *Verifier) window() time.Duration { return v.maxAge + v.skew }

// NewVerifier returns a Verifier for proofs signed under ctx (a sigctx label). The cache is
// built after every option has run, so WithWindow and WithCacheEntries can be given in
// either order without the window silently reverting to the default.
func NewVerifier(ctx string, opts ...Option) *Verifier {
	v := &Verifier{ctx: ctx, maxAge: DefaultMaxAge, skew: DefaultSkew, entries: DefaultCacheEntries, now: time.Now}
	for _, opt := range opts {
		opt(v)
	}
	v.cache = NewReplayCache(v.window(), v.entries)
	return v
}

// Cache exposes the replay cache, for metrics and tests.
func (v *Verifier) Cache() *ReplayCache { return v.cache }

// Check verifies a proof header against the request it arrived on: r supplies the method and
// target, body is the buffered request body (nil for a request that carried none), and token
// is the principal bearer token the proof must accompany.
//
// The order is RFC 9449 §4.3 with one Sanad-specific constraint: the SIGNATURE is checked
// first, and the replay cache is touched LAST. Everything before the signature check is
// parsing; everything after it has been authenticated. That is what keeps the cache — the
// one piece of per-request state here — out of reach of an unauthenticated caller, who would
// otherwise fill it with jtis for free and turn a bounded cache into a denial of service.
func (v *Verifier) Check(pub ed25519.PublicKey, header string, r *http.Request, body []byte, token string) error {
	if header == "" {
		return errors.New("pop: missing proof")
	}
	if r == nil {
		return errors.New("pop: no request to bind the proof to")
	}
	if token == "" {
		return errors.New("pop: no principal token to bind the proof to")
	}

	rawPayload, rawSig, ok := strings.Cut(header, ".")
	if !ok || strings.Contains(rawSig, ".") {
		return errors.New("pop: malformed proof (want base64url(payload).base64url(signature))")
	}
	payload, err := base64.RawURLEncoding.DecodeString(rawPayload)
	if err != nil {
		return fmt.Errorf("pop: bad proof payload encoding: %w", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(rawSig)
	if err != nil {
		return fmt.Errorf("pop: bad proof signature encoding: %w", err)
	}
	// The signature covers the payload bytes exactly as they arrived, never a re-encoding.
	if !sigctx.Verify(v.ctx, pub, payload, sig) {
		return errors.New("pop: proof signature is invalid")
	}

	var b Binding
	if err := json.Unmarshal(payload, &b); err != nil {
		return fmt.Errorf("pop: bad proof payload: %w", err)
	}

	if b.HTM != r.Method {
		return fmt.Errorf("pop: proof is bound to method %q, not %q", b.HTM, r.Method)
	}
	if target := Target(r.URL); b.HTU != target {
		return fmt.Errorf("pop: proof is bound to target %q, not %q", b.HTU, target)
	}
	if b.ATH != Hash([]byte(token)) {
		return errors.New("pop: proof is bound to a different principal token")
	}
	if b.BH != Hash(body) {
		return errors.New("pop: proof is bound to a different request body")
	}

	// Freshness. A zero iat is a proof that never said when it was made, which is the whole
	// failure mode being fixed here, so it is rejected rather than treated as the epoch.
	if b.IAT == 0 {
		return fmt.Errorf("%w: no iat", ErrStale)
	}
	now := v.now()
	iat := time.Unix(b.IAT, 0)
	if iat.After(now.Add(v.skew)) {
		return fmt.Errorf("%w: iat is %s in the future (skew allowance %s)",
			ErrStale, iat.Sub(now).Round(time.Second), v.skew)
	}
	if now.Sub(iat) > v.maxAge {
		return fmt.Errorf("%w: iat is %s old (max age %s)",
			ErrStale, now.Sub(iat).Round(time.Second), v.maxAge)
	}

	if n := len(b.JTI); n == 0 || n > MaxJTI {
		return fmt.Errorf("pop: proof has an unusable jti (%d bytes, max %d)", n, MaxJTI)
	}
	return v.cache.Use(b.JTI, now)
}

// ReplayCache remembers the jti of every accepted proof for as long as that proof could
// still be accepted, so the SECOND presentation of one is refused. Everything the binding
// covers is fixed at signing time, which makes an identical request identically signable —
// the cache is what turns "the same request twice" from valid into replayed.
//
// # Bounds
//
// Entries are held in two generations. Inserts land in the current one; a lookup consults
// both; after each window the current becomes the previous and a fresh map takes over. An
// entry therefore lives at least one window and at most two, with no per-entry timers and no
// scan on the request path. The window is maxAge+skew, which is the longest a proof accepted
// now can still be accepted, so an entry is never dropped while its proof is live.
//
// Memory is bounded twice over: at most `max` entries across both generations, and at most
// MaxJTI bytes per key. Past the cap the cache REFUSES rather than evicting. Evicting the
// oldest entry would silently re-open replay for exactly the proofs an attacker is flooding
// to push out, and NFR-3 says a request we cannot decide safely is denied. The flood is also
// not free: an entry is only ever inserted after a valid signature under a CA-issued
// credential, so filling this is not available to an unauthenticated caller. Size `max` above
// peak requests-per-second times the window.
//
// # Across replicas
//
// This is PROCESS-LOCAL, like the authority's nonce table and the KeyStore. Behind a load
// balancer, replica B has never seen the jtis replica A accepted, so a captured proof CAN be
// replayed once per replica inside the freshness window. What does not weaken with replicas
// is everything else the binding covers: the replay is still restricted to the identical
// method, target, body and principal token, within maxAge. So the residual is "an identical
// request may be re-executed up to N times within ~35s", not "an attacker holds the
// instance's identity until the token expires". Making the jti set shared state (the
// kill-switch's Postgres, or a Redis) is the Phase 3 durability item, and it is also what
// makes the guarantee exact rather than per-replica.
type ReplayCache struct {
	mu      sync.Mutex
	window  time.Duration
	max     int
	rotated time.Time
	cur     map[string]struct{}
	prev    map[string]struct{}
}

// NewReplayCache returns a cache holding each jti for at least window and at most 2*window,
// capped at max entries. Non-positive arguments select the defaults.
func NewReplayCache(window time.Duration, max int) *ReplayCache {
	if window <= 0 {
		window = DefaultMaxAge + DefaultSkew
	}
	if max <= 0 {
		max = DefaultCacheEntries
	}
	return &ReplayCache{window: window, max: max, cur: map[string]struct{}{}, prev: map[string]struct{}{}}
}

// Use records jti as spent, or reports why it cannot be. It is safe for concurrent use.
func (c *ReplayCache) Use(jti string, now time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.rotate(now)
	if _, seen := c.cur[jti]; seen {
		return ErrReplayed
	}
	if _, seen := c.prev[jti]; seen {
		return ErrReplayed
	}
	if len(c.cur)+len(c.prev) >= c.max {
		return ErrCacheFull
	}
	c.cur[jti] = struct{}{}
	return nil
}

// Len is the number of remembered jtis, for tests and metrics.
func (c *ReplayCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.cur) + len(c.prev)
}

// rotate ages out a whole generation at a time. Caller holds the lock.
func (c *ReplayCache) rotate(now time.Time) {
	if c.rotated.IsZero() {
		c.rotated = now
		return
	}
	elapsed := now.Sub(c.rotated)
	if elapsed < c.window {
		return
	}
	// Two windows of silence means even the previous generation is past every proof it could
	// have covered, so both go rather than promoting stale entries into another window.
	if elapsed >= 2*c.window {
		c.prev = map[string]struct{}{}
	} else {
		c.prev = c.cur
	}
	c.cur = map[string]struct{}{}
	c.rotated = now
}
