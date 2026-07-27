package principal

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/getsanad/sanad/gateway"
	"github.com/getsanad/sanad/pkg/types"
)

const (
	testIssuer   = "https://idp.example.com"
	testClientID = "sanad"
)

// signIDToken hand-builds an RS256 OIDC ID token so the authenticator can be tested fully
// offline (no IdP, no network), mirroring what an IdP would issue.
func signIDToken(t *testing.T, priv *rsa.PrivateKey, sub string, exp time.Time) string {
	t.Helper()
	return signRS256(priv, sub, exp)
}

// signRS256 is the testing-independent signer shared by tests and benchmarks; it panics
// on error since key/marshal failures here are test-setup bugs.
func signRS256(priv *rsa.PrivateKey, sub string, exp time.Time) string {
	enc := base64.RawURLEncoding.EncodeToString
	hb, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": "test"})
	cb, _ := json.Marshal(map[string]any{
		"iss": testIssuer,
		"aud": testClientID,
		"sub": sub,
		"iat": time.Now().Unix(),
		"exp": exp.Unix(),
	})
	signingInput := enc(hb) + "." + enc(cb)
	sum := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, sum[:])
	if err != nil {
		panic(err)
	}
	return signingInput + "." + enc(sig)
}

func newAuth(t *testing.T, opts ...Option) (*OIDCAuthenticator, *rsa.PrivateKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ks := &oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{priv.Public()}}
	verifier := oidc.NewVerifier(testIssuer, ks, &oidc.Config{ClientID: testClientID})
	return NewOIDC(verifier, opts...), priv
}

func TestAuthenticateValid(t *testing.T) {
	a, priv := newAuth(t, WithAssurance(types.AssuranceOrg))
	tok := signIDToken(t, priv, "user-123", time.Now().Add(time.Hour))

	p, err := a.Authenticate(context.Background(), tok)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if p.ID != "user-123" || p.Assurance != types.AssuranceOrg {
		t.Fatalf("principal mismatch: %+v", p)
	}
}

func TestAuthenticateExpired(t *testing.T) {
	a, priv := newAuth(t)
	tok := signIDToken(t, priv, "user-123", time.Now().Add(-time.Minute))
	if _, err := a.Authenticate(context.Background(), tok); err == nil {
		t.Fatal("expired token must be rejected")
	}
}

func TestAuthenticateWrongKey(t *testing.T) {
	a, _ := newAuth(t)
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tok := signIDToken(t, other, "user-123", time.Now().Add(time.Hour))
	if _, err := a.Authenticate(context.Background(), tok); err == nil {
		t.Fatal("token signed by an unknown key must be rejected")
	}
}

type denyList map[string]bool

func (d denyList) Revoked(id string) bool { return d[id] }

func TestAuthenticateRevoked(t *testing.T) {
	a, priv := newAuth(t, WithStatusChecker(denyList{"user-123": true}))
	tok := signIDToken(t, priv, "user-123", time.Now().Add(time.Hour))
	if _, err := a.Authenticate(context.Background(), tok); err == nil {
		t.Fatal("revoked principal must be rejected (fail closed)")
	}
}

func TestStageSetsPrincipalAndFailsClosed(t *testing.T) {
	a, priv := newAuth(t)
	stage := Stage(a)

	// Missing token -> fail closed.
	missing := &gateway.Request{HTTP: httptest.NewRequest(http.MethodGet, "/servers/demo/x", nil)}
	if err := stage.Handle(context.Background(), missing); err == nil {
		t.Fatal("missing bearer token must fail closed")
	}

	// Valid token -> principal set on the request.
	r := httptest.NewRequest(http.MethodGet, "/servers/demo/x", nil)
	r.Header.Set("Authorization", "Bearer "+signIDToken(t, priv, "user-123", time.Now().Add(time.Hour)))
	req := &gateway.Request{HTTP: r}
	if err := stage.Handle(context.Background(), req); err != nil {
		t.Fatalf("valid token: %v", err)
	}
	if req.Principal == nil || req.Principal.ID != "user-123" {
		t.Fatalf("principal not set: %+v", req.Principal)
	}
}
