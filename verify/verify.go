// Package verify is the offline passport verification library MCP server owners embed to
// validate Sanads (PRD FR-9): signature + claims only, with no callback to the
// gateway on the common path. It also ships a thin HTTP middleware adapter so a server
// can be protected in a handful of lines (P1-05).
package verify

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"strings"
	"time"

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

// Middleware gates an MCP server: it requires a valid passport bound to audience on the
// `Authorization: Bearer` header, returning 401 otherwise. On success it injects the
// passport into the request context (see FromContext) and calls next.
//
// Protecting a server is a handful of lines:
//
//	v := verify.New(verify.StaticKeys{kid: gatewayPubKey})
//	http.ListenAndServe(addr, verify.Middleware(v, "my-server-id", mcpHandler))
func Middleware(v *Verifier, audience string, next http.Handler) http.Handler {
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
