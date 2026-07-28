// Package verify is the offline passport verification library MCP server owners embed to
// validate Sanads (PRD FR-9): signature + claims only, with no callback to the
// gateway on the common path. It also ships a thin HTTP middleware adapter so a server
// can be protected in a handful of lines (P1-05).
//
// # What a resource server can verify offline
//
// With only the gateway's public key (from its JWKS), and no network call, Verify
// establishes:
//
//   - AUTHENTICITY — the passport was minted by the holder of that key. The algorithm is
//     pinned to Ed25519 structurally, so alg-confusion attacks are impossible by
//     construction (see pkg/passport).
//   - AUDIENCE — it was minted for THIS server and no other (SEC-2). A passport for
//     server-a is refused at server-b.
//   - FRESHNESS — it has not expired. Passports live minutes, which is what makes
//     non-renewal the primary revocation lever (FR-17).
//   - ACCOUNTABILITY — `sub` names the accountable principal, `agent` the acting agent, and
//     `dlg` the ordered delegation path between them plus a digest of the full signed chain
//     (types.DelegationRef). Read it with DelegationPath.
//   - AUTHORITY — `scope` is the effective, most-narrowed set of tools the delegation chain
//     conferred and the gateway policy allowed. EnforceScope / RequireScope turn that from a
//     claim the server merely logs into one it acts on.
//
// What it CANNOT establish offline: that the principal has not been revoked since minting
// (the kill-switch is gateway-side; the short TTL is the bound on that window), and the
// delegation chain's individual hop signatures and attenuation — those are verified by the
// gateway, and `dlg` carries the gateway's signed assertion about them plus a digest that
// lets an auditor holding the full chain confirm it. See types.DelegationRef.
package verify

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/getsanad/sanad/internal/mcprpc"
	"github.com/getsanad/sanad/pkg/passport"
	"github.com/getsanad/sanad/pkg/types"
)

// KeyResolver maps a signing key id (kid) to its Ed25519 public key. Implementations load
// keys from the gateway's JWKS; StaticKeys suffices for pinned-key deployments. Key
// rotation works by serving overlapping keys (P1-12).
type KeyResolver interface {
	Resolve(kid string) (ed25519.PublicKey, bool)
}

// StaticKeys is a fixed kid -> public-key set.
type StaticKeys map[string]ed25519.PublicKey

// Resolve implements KeyResolver.
func (s StaticKeys) Resolve(kid string) (ed25519.PublicKey, bool) {
	k, ok := s[kid]
	return k, ok
}

// Verifier validates passports offline against a set of gateway signing keys.
type Verifier struct {
	keys KeyResolver
	now  func() time.Time
}

// New returns a Verifier backed by the given key resolver.
func New(keys KeyResolver) *Verifier {
	return &Verifier{keys: keys, now: time.Now}
}

// Verify validates raw for the given audience (this server's id) and returns the passport
// on success. It selects the key by kid, then checks signature, pinned algorithm,
// audience, and expiry.
func (v *Verifier) Verify(raw, audience string) (types.Passport, error) {
	kid, err := passport.KeyID(raw)
	if err != nil {
		return types.Passport{}, err
	}
	pub, ok := v.keys.Resolve(kid)
	if !ok {
		return types.Passport{}, errors.New("verify: unknown signing key")
	}
	claims, err := passport.Verify(pub, raw, audience, v.now())
	if err != nil {
		return types.Passport{}, err
	}
	return claims.ToPassport(), nil
}

type ctxKey struct{}

// FromContext returns the verified passport attached by Middleware, if present.
func FromContext(ctx context.Context) (types.Passport, bool) {
	p, ok := ctx.Value(ctxKey{}).(types.Passport)
	return p, ok
}

// Option configures Middleware.
type Option func(*options)

type options struct {
	enforceScope  bool
	requireScoped bool
	maxBody       int64
}

// EnforceScope makes the middleware check every tool the request invokes against the
// passport's scope, answering 403 if any is outside it. Without it the scope is decorative
// at the point of use: a passport scoped to ["read"] would be accepted for a "delete" call,
// because nothing looked.
//
// It has to read the request body to do this. In MCP streamable HTTP the tool is
// params.name in a JSON-RPC body POSTed to one endpoint, not in the URL, so there is nowhere
// else to look — the body is buffered under a cap (WithMaxRequestBody) and put back intact
// for the wrapped handler. The parsing is the same code the gateway authorized the request
// with (internal/mcprpc), so the two cannot drift into disagreeing about which tool a body
// invokes. A batch is checked element by element, and refused whole if any element is out of
// scope: the server executes the batch as a unit, so partial authorization is not available.
//
// The reason to enforce here as well as at the gateway is that this is where the action
// actually happens. A resource server reachable by any other route — a second gateway, a
// misrouted internal caller, a future bug in the proxy — still refuses work its passport
// does not name.
func EnforceScope() Option { return func(o *options) { o.enforceScope = true } }

// RequireScopedPassport refuses a passport whose scope names no tools at all.
//
// An empty scope is the unconstrained wildcard everywhere in this system (see Allows), which
// means EnforceScope alone lets an unscoped passport invoke anything. That is correct
// behavior — the passport asserts no narrower authority to enforce — but a server holding
// something dangerous may reasonably decline to serve on unbounded authority no matter who
// signed it. This is that refusal, answered as 403 before any tool is looked at.
func RequireScopedPassport() Option { return func(o *options) { o.requireScoped = true } }

// WithMaxRequestBody caps the request body EnforceScope buffers (default
// mcprpc.DefaultMaxBody, 1 MiB). Zero or negative selects the default; there is no unlimited
// setting, because the buffer is filled before the request has been authorized.
func WithMaxRequestBody(n int64) Option { return func(o *options) { o.maxBody = n } }

// Middleware gates an MCP server: it requires a valid passport bound to audience on the
// `Authorization: Bearer` header, returning 401 otherwise. On success it injects the
// passport into the request context (see FromContext) and calls next.
//
// Protecting a server is a handful of lines:
//
//	v := verify.New(verify.StaticKeys{kid: gatewayPubKey})
//	http.ListenAndServe(addr, verify.Middleware(v, "my-server-id", mcpHandler, verify.EnforceScope()))
//
// With EnforceScope the middleware also refuses any tools/call the passport's scope does not
// name (403). Without it, authentication is enforced and authorization is not — which is
// only the right choice if the handler checks the scope itself with RequireScope.
func Middleware(v *Verifier, audience string, next http.Handler, opts ...Option) http.Handler {
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, ok := bearer(r)
		if !ok {
			http.Error(w, "missing passport", http.StatusUnauthorized)
			return
		}
		p, err := v.Verify(raw, audience)
		if err != nil {
			http.Error(w, "invalid passport", http.StatusUnauthorized)
			return
		}
		if o.requireScoped && len(p.Scope.Tools) == 0 {
			http.Error(w, "passport carries no tool scope", http.StatusForbidden)
			return
		}
		if o.enforceScope && mcprpc.HasBody(r) {
			body, err := mcprpc.BufferBody(w, r, o.maxBody)
			if err != nil {
				status := http.StatusBadRequest
				if errors.Is(err, mcprpc.ErrBodyTooLarge) {
					status = http.StatusRequestEntityTooLarge
				}
				http.Error(w, http.StatusText(status), status)
				return
			}
			calls, err := mcprpc.Parse(body)
			if err != nil {
				// A body that says it is calling a tool but does not name one cannot be
				// scope-checked, so it is refused rather than served unchecked (NFR-3).
				http.Error(w, "malformed JSON-RPC request", http.StatusBadRequest)
				return
			}
			for _, c := range calls {
				if c.Tool == "" {
					continue // initialize, tools/list, notifications: no tool to check
				}
				if !Allows(p, c.Tool) {
					http.Error(w, "tool outside the passport scope", http.StatusForbidden)
					return
				}
			}
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, p)))
	})
}

func bearer(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", false
	}
	return h[len(prefix):], true
}
