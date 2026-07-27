package verify

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/getsanad/sanad/gateway"
	"github.com/getsanad/sanad/pkg/passport"
	"github.com/getsanad/sanad/pkg/types"
	"github.com/getsanad/sanad/sts"
)

func mint(t *testing.T, kid, audience string, exp time.Time) (token string, pub ed25519.PublicKey) {
	t.Helper()
	pubKey, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c := passport.Claims{
		ID: "j1", Issuer: "sanad", Principal: "p1", Audience: audience,
		Agent: "a1", IssuedAt: time.Now().Unix(), ExpiresAt: exp.Unix(),
	}
	tok, err := passport.Sign(priv, kid, c)
	if err != nil {
		t.Fatal(err)
	}
	return tok, pubKey
}

func TestVerifyValid(t *testing.T) {
	tok, pub := mint(t, "kid-1", "server-a", time.Now().Add(time.Minute))
	v := New(StaticKeys{"kid-1": pub})

	p, err := v.Verify(tok, "server-a")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if p.PrincipalID != "p1" || p.Audience != "server-a" {
		t.Fatalf("passport mismatch: %+v", p)
	}
}

func TestVerifyWrongAudience(t *testing.T) {
	tok, pub := mint(t, "kid-1", "server-a", time.Now().Add(time.Minute))
	v := New(StaticKeys{"kid-1": pub})
	if _, err := v.Verify(tok, "server-b"); err == nil {
		t.Fatal("passport for server-a must not verify at server-b")
	}
}

func TestVerifyUnknownKid(t *testing.T) {
	tok, pub := mint(t, "kid-1", "server-a", time.Now().Add(time.Minute))
	v := New(StaticKeys{"kid-OTHER": pub})
	if _, err := v.Verify(tok, "server-a"); err == nil {
		t.Fatal("unknown signing key must be rejected")
	}
}

func TestMiddleware(t *testing.T) {
	tok, pub := mint(t, "kid-1", "server-a", time.Now().Add(time.Minute))
	v := New(StaticKeys{"kid-1": pub})

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p, ok := FromContext(r.Context()); !ok || p.PrincipalID != "p1" {
			t.Error("passport not injected into context")
		}
		_, _ = io.WriteString(w, "served")
	})
	h := Middleware(v, "server-a", next)

	cases := []struct {
		name string
		auth string
		want int
	}{
		{"valid", "Bearer " + tok, http.StatusOK},
		{"missing", "", http.StatusUnauthorized},
		{"garbage", "Bearer not-a-token", http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/tools/list", nil)
			if tc.auth != "" {
				r.Header.Set("Authorization", tc.auth)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, r)
			if rec.Code != tc.want {
				t.Fatalf("got %d, want %d", rec.Code, tc.want)
			}
		})
	}
}

func TestMiddlewareRejectsWrongAudience(t *testing.T) {
	tok, pub := mint(t, "kid-1", "server-a", time.Now().Add(time.Minute))
	v := New(StaticKeys{"kid-1": pub})
	h := Middleware(v, "server-b", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	r := httptest.NewRequest(http.MethodGet, "/tools/list", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401 (wrong-audience passport)", rec.Code)
	}
}

// TestVerifiesGatewayIssuedPassport proves the verify library validates a passport minted
// by the real STS, fully offline — the gateway and an MCP server only share the public key.
func TestVerifiesGatewayIssuedPassport(t *testing.T) {
	var served bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served = true
	}))
	defer upstream.Close()

	signer, _ := sts.NewLocalSigner("kid-gw")
	issuer := sts.New(signer, sts.Config{Issuer: "sanad"})

	reg := gateway.NewRegistry()
	u, _ := url.Parse(upstream.URL)
	if err := reg.Register(&gateway.Server{ID: "demo", Upstream: u}); err != nil {
		t.Fatal(err)
	}
	principal := gateway.NewStage("principal", func(ctx context.Context, req *gateway.Request) error {
		req.Principal = &types.Principal{ID: "p1"}
		return nil
	})
	g := &gateway.Gateway{Registry: reg, Pipeline: gateway.Pipeline{Stages: []gateway.Stage{principal, sts.MintStage(issuer)}}}

	// Capture the passport the gateway forwards by pointing the upstream at a verifier.
	v := New(StaticKeys{"kid-gw": signer.Public()})
	r := httptest.NewRequest(http.MethodGet, "/servers/demo/tools/list", nil)
	rec := httptest.NewRecorder()
	g.ServeHTTP(rec, r)
	if !served {
		t.Fatal("gateway did not forward to upstream")
	}

	// The forwarded Authorization header now carries the passport; verify it offline.
	auth := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(auth) <= len(prefix) {
		t.Fatalf("no passport forwarded: %q", auth)
	}
	if _, err := v.Verify(auth[len(prefix):], "demo"); err != nil {
		t.Fatalf("offline verification of gateway-issued passport failed: %v", err)
	}
}
