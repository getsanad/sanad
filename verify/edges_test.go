package verify

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/getsanad/sanad/jwks"
	"github.com/getsanad/sanad/pkg/passport"
)

// signed mints a token with full control over kid, audience and expiry, returning the
// token and the public key that verifies it.
func signed(t *testing.T, kid, audience string, exp time.Time) (string, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c := passport.Claims{
		ID: "j1", Issuer: "sanad", Principal: "p1", Audience: audience,
		Agent: "a1", IssuedAt: time.Now().Add(-time.Minute).Unix(), ExpiresAt: exp.Unix(),
	}
	tok, err := passport.Sign(priv, kid, c)
	if err != nil {
		t.Fatal(err)
	}
	return tok, pub
}

// --- Verifier.Verify -----------------------------------------------------------------

func TestVerifyExpired(t *testing.T) {
	tok, pub := signed(t, "kid-1", "server-a", time.Now().Add(-time.Second))
	v := New(StaticKeys{"kid-1": pub})
	if _, err := v.Verify(tok, "server-a"); err == nil {
		t.Fatal("expired passport must be rejected")
	}
}

func TestVerifyTampered(t *testing.T) {
	tok, pub := signed(t, "kid-1", "server-a", time.Now().Add(time.Minute))
	v := New(StaticKeys{"kid-1": pub})

	parts := strings.Split(tok, ".")
	sig := []byte(parts[2])
	sig[len(sig)-1] ^= 0x01
	parts[2] = string(sig)
	tampered := strings.Join(parts, ".")

	if _, err := v.Verify(tampered, "server-a"); err == nil {
		t.Fatal("tampered signature must be rejected")
	}
}

func TestVerifyMalformedToken(t *testing.T) {
	pub := mustPub(t)
	v := New(StaticKeys{"kid-1": pub})
	for _, raw := range []string{"", "abc", "a.b", "a.b.c.d", "!!!.b.c"} {
		t.Run(raw, func(t *testing.T) {
			if _, err := v.Verify(raw, "server-a"); err == nil {
				t.Fatalf("expected error for %q", raw)
			}
		})
	}
}

// TestVerifyResolverMissingKey covers both an unknown kid and a resolver that never has
// any keys (empty StaticKeys / nil-ish). Resolution failure must error before crypto.
func TestVerifyResolverMissingKey(t *testing.T) {
	tok, pub := signed(t, "kid-1", "server-a", time.Now().Add(time.Minute))

	cases := []struct {
		name     string
		resolver KeyResolver
	}{
		{"unknown kid", StaticKeys{"kid-OTHER": pub}},
		{"empty resolver", StaticKeys{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := New(tc.resolver)
			if _, err := v.Verify(tok, "server-a"); err == nil {
				t.Fatal("expected error when resolver cannot supply the key")
			}
		})
	}
}

// --- NewJWKSResolver -----------------------------------------------------------------

func TestNewJWKSResolverBadDoc(t *testing.T) {
	cases := []struct {
		name string
		doc  string
	}{
		{"garbage", "not json"},
		{"empty bytes", ""},
		{"truncated", `{"keys":[`},
		{"bad x base64", `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k","x":"!!!"}]}`},
		{"wrong key length", `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k","x":"YWJj"}]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewJWKSResolver([]byte(tc.doc)); err == nil {
				t.Fatalf("expected error for %q", tc.doc)
			}
		})
	}
}

func TestNewJWKSResolverResolvesKnownKid(t *testing.T) {
	pub := mustPub(t)
	doc, err := jwks.Marshal(jwks.Key{Kid: "kid-1", Pub: pub})
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewJWKSResolver(doc)
	if err != nil {
		t.Fatalf("resolver: %v", err)
	}
	got, ok := r.Resolve("kid-1")
	if !ok || !got.Equal(pub) {
		t.Fatal("resolver did not return the published key")
	}
	if _, ok := r.Resolve("missing"); ok {
		t.Fatal("resolver returned a key for an unknown kid")
	}
}

// TestNewJWKSResolverEmptyDocResolvesNothing: an empty (but valid) JWKS yields a usable,
// empty resolver — not an error.
func TestNewJWKSResolverEmptyDoc(t *testing.T) {
	r, err := NewJWKSResolver([]byte(`{"keys":[]}`))
	if err != nil {
		t.Fatalf("empty JWKS should not error: %v", err)
	}
	if _, ok := r.Resolve("anything"); ok {
		t.Fatal("empty resolver must not resolve any kid")
	}
}

// --- Middleware ----------------------------------------------------------------------

func TestMiddlewareEdgeCases(t *testing.T) {
	tok, pub := signed(t, "kid-1", "server-a", time.Now().Add(time.Minute))
	expiredTok, expiredPub := signed(t, "kid-1", "server-a", time.Now().Add(-time.Minute))

	served := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served = true
		if p, ok := FromContext(r.Context()); !ok || p.PrincipalID != "p1" {
			t.Error("passport not injected into context on success")
		}
		w.WriteHeader(http.StatusOK)
	})

	cases := []struct {
		name       string
		resolver   KeyResolver
		audience   string
		setHeader  bool
		header     string
		wantStatus int
		wantServed bool
	}{
		{"valid", StaticKeys{"kid-1": pub}, "server-a", true, "Bearer " + tok, http.StatusOK, true},
		{"missing header", StaticKeys{"kid-1": pub}, "server-a", false, "", http.StatusUnauthorized, false},
		{"empty header value", StaticKeys{"kid-1": pub}, "server-a", true, "", http.StatusUnauthorized, false},
		{"wrong scheme Basic", StaticKeys{"kid-1": pub}, "server-a", true, "Basic " + tok, http.StatusUnauthorized, false},
		{"lowercase bearer accepted (case-insensitive scheme)", StaticKeys{"kid-1": pub}, "server-a", true, "bearer " + tok, http.StatusOK, true},
		{"bearer no space prefix", StaticKeys{"kid-1": pub}, "server-a", true, "Bearer" + tok, http.StatusUnauthorized, false},
		{"empty bearer token", StaticKeys{"kid-1": pub}, "server-a", true, "Bearer ", http.StatusUnauthorized, false},
		{"bearer with only spaces", StaticKeys{"kid-1": pub}, "server-a", true, "Bearer    ", http.StatusUnauthorized, false},
		{"garbage token", StaticKeys{"kid-1": pub}, "server-a", true, "Bearer not-a-token", http.StatusUnauthorized, false},
		{"wrong audience", StaticKeys{"kid-1": pub}, "server-b", true, "Bearer " + tok, http.StatusUnauthorized, false},
		{"unknown kid", StaticKeys{"kid-OTHER": pub}, "server-a", true, "Bearer " + tok, http.StatusUnauthorized, false},
		{"expired", StaticKeys{"kid-1": expiredPub}, "server-a", true, "Bearer " + expiredTok, http.StatusUnauthorized, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			served = false
			h := Middleware(New(tc.resolver), tc.audience, next)
			r := httptest.NewRequest(http.MethodGet, "/tools/list", nil)
			if tc.setHeader {
				r.Header.Set("Authorization", tc.header)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, r)

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			if served != tc.wantServed {
				t.Fatalf("served = %v, want %v", served, tc.wantServed)
			}
		})
	}
}

// TestFromContextAbsent: with no middleware-injected passport, FromContext reports absence.
func TestFromContextAbsent(t *testing.T) {
	if _, ok := FromContext(context.Background()); ok {
		t.Fatal("FromContext must report absence on a bare context")
	}
}

func mustPub(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}
