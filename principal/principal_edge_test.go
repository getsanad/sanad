package principal

import (
	"context"
	"crypto"
	"crypto/hmac"
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

// signCustom hand-builds an RS256 token with caller-controlled claims so we can forge
// wrong-issuer / wrong-audience / missing-sub tokens that are still validly RS256-signed
// by the verifier's key. It deliberately mirrors signRS256 but exposes the claim set.
func signCustom(t *testing.T, priv *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	enc := base64.RawURLEncoding.EncodeToString
	hb, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": "test"})
	cb, _ := json.Marshal(claims)
	signingInput := enc(hb) + "." + enc(cb)
	sum := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + enc(sig)
}

// stdClaims returns a valid claim set that callers mutate to forge specific failures.
func stdClaims(sub string, exp time.Time) map[string]any {
	return map[string]any{
		"iss": testIssuer,
		"aud": testClientID,
		"sub": sub,
		"iat": time.Now().Unix(),
		"exp": exp.Unix(),
	}
}

// signNoneAlg builds an unsigned ("alg":"none") JWT — the classic algorithm-confusion
// attack. A correct verifier must reject it because no signature is present.
func signNoneAlg(t *testing.T, claims map[string]any) string {
	t.Helper()
	enc := base64.RawURLEncoding.EncodeToString
	hb, _ := json.Marshal(map[string]string{"alg": "none", "typ": "JWT"})
	cb, _ := json.Marshal(claims)
	return enc(hb) + "." + enc(cb) + "."
}

// signHS256 signs the token symmetrically with the RSA public modulus bytes as the HMAC
// key — the classic RS256->HS256 key-confusion attack. A correct verifier expecting RS256
// must reject it.
func signHS256(t *testing.T, pub *rsa.PublicKey, claims map[string]any) string {
	t.Helper()
	enc := base64.RawURLEncoding.EncodeToString
	hb, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	cb, _ := json.Marshal(claims)
	signingInput := enc(hb) + "." + enc(cb)
	mac := hmac.New(sha256.New, pub.N.Bytes())
	mac.Write([]byte(signingInput))
	return signingInput + "." + enc(mac.Sum(nil))
}

func TestAuthenticateRejectsForgedTokens(t *testing.T) {
	a, priv := newAuth(t)
	ctx := context.Background()

	cases := []struct {
		name string
		tok  string
	}{
		{
			name: "wrong issuer",
			tok: signCustom(t, priv, func() map[string]any {
				c := stdClaims("user-1", time.Now().Add(time.Hour))
				c["iss"] = "https://evil.example.com"
				return c
			}()),
		},
		{
			name: "wrong audience",
			tok: signCustom(t, priv, func() map[string]any {
				c := stdClaims("user-1", time.Now().Add(time.Hour))
				c["aud"] = "some-other-client"
				return c
			}()),
		},
		{
			name: "expired",
			tok:  signCustom(t, priv, stdClaims("user-1", time.Now().Add(-time.Minute))),
		},
		{
			name: "alg none (unsigned)",
			tok:  signNoneAlg(t, stdClaims("user-1", time.Now().Add(time.Hour))),
		},
		{
			name: "alg HS256 key confusion",
			tok:  signHS256(t, &priv.PublicKey, stdClaims("user-1", time.Now().Add(time.Hour))),
		},
		{name: "empty token", tok: ""},
		{name: "malformed: not a jwt", tok: "not-a-jwt"},
		{name: "malformed: two segments", tok: "aaa.bbb"},
		{name: "malformed: bad base64", tok: "@@@.@@@.@@@"},
		{
			name: "tampered payload (sub swapped after signing)",
			tok: func() string {
				good := signCustom(t, priv, stdClaims("user-1", time.Now().Add(time.Hour)))
				// Replace the payload segment with a different one; signature no longer matches.
				enc := base64.RawURLEncoding.EncodeToString
				forged, _ := json.Marshal(stdClaims("attacker", time.Now().Add(time.Hour)))
				parts := []byte(good)
				// rebuild header.forgedPayload.originalSig
				first := indexByte(good, '.')
				last := lastIndexByte(good, '.')
				return string(parts[:first+1]) + enc(forged) + string(parts[last:])
			}(),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := a.Authenticate(ctx, tc.tok); err == nil {
				t.Fatalf("%s: expected rejection, got nil error", tc.name)
			}
		})
	}
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

func lastIndexByte(s string, b byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == b {
			return i
		}
	}
	return -1
}

func TestAuthenticateMissingSubject(t *testing.T) {
	a, priv := newAuth(t)
	claims := stdClaims("placeholder", time.Now().Add(time.Hour))
	delete(claims, "sub")
	tok := signCustom(t, priv, claims)

	if _, err := a.Authenticate(context.Background(), tok); err == nil {
		t.Fatal("token without sub must be rejected")
	}
}

func TestAuthenticatePropagatesAssuranceLevels(t *testing.T) {
	for _, lvl := range []types.AssuranceLevel{
		types.AssuranceUnverified, types.AssuranceIndividual, types.AssuranceOrg,
	} {
		a, priv := newAuth(t, WithAssurance(lvl))
		tok := signCustom(t, priv, stdClaims("user-x", time.Now().Add(time.Hour)))
		p, err := a.Authenticate(context.Background(), tok)
		if err != nil {
			t.Fatalf("level %s: authenticate: %v", lvl, err)
		}
		if p.Assurance != lvl {
			t.Fatalf("assurance = %q, want %q", p.Assurance, lvl)
		}
		if p.ID != "user-x" || p.Subject != "user-x" {
			t.Fatalf("principal id/subject mismatch: %+v", p)
		}
	}
}

func TestAuthenticateDefaultAssuranceIsUnverified(t *testing.T) {
	a, priv := newAuth(t) // no WithAssurance
	tok := signCustom(t, priv, stdClaims("user-x", time.Now().Add(time.Hour)))
	p, err := a.Authenticate(context.Background(), tok)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if p.Assurance != types.AssuranceUnverified {
		t.Fatalf("default assurance = %q, want unverified", p.Assurance)
	}
}

func TestAuthenticateRevokedTakesPrecedenceOverValidToken(t *testing.T) {
	// A valid, correctly-signed token must still be rejected when the principal is on the
	// kill-switch (fail closed, FR-18).
	a, priv := newAuth(t, WithStatusChecker(denyList{"banned": true}))
	tok := signCustom(t, priv, stdClaims("banned", time.Now().Add(time.Hour)))
	if _, err := a.Authenticate(context.Background(), tok); err == nil {
		t.Fatal("revoked principal must be rejected even with a valid token")
	}

	// A non-revoked subject through the same authenticator still succeeds.
	tok2 := signCustom(t, priv, stdClaims("ok-user", time.Now().Add(time.Hour)))
	if _, err := a.Authenticate(context.Background(), tok2); err != nil {
		t.Fatalf("non-revoked principal should authenticate: %v", err)
	}
}

func TestStageNilHTTPFailsClosed(t *testing.T) {
	a, _ := newAuth(t)
	stage := Stage(a)
	req := &gateway.Request{HTTP: nil}
	if err := stage.Handle(context.Background(), req); err == nil {
		t.Fatal("nil HTTP request must fail closed")
	}
	if req.Principal != nil {
		t.Fatal("principal must not be set when authentication fails")
	}
}

func TestStageMalformedBearerHeaders(t *testing.T) {
	a, priv := newAuth(t)
	stage := Stage(a)
	valid := signCustom(t, priv, stdClaims("user-1", time.Now().Add(time.Hour)))

	cases := []struct {
		name   string
		header string
	}{
		{"no authorization header", ""},
		{"missing bearer scheme", valid},
		{"wrong scheme", "Basic " + valid},
		{"bearer no space", "Bearer" + valid},
		{"bearer empty token", "Bearer "},
		{"only the word bearer", "Bearer"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/servers/demo/x", nil)
			if tc.header != "" {
				r.Header.Set("Authorization", tc.header)
			}
			req := &gateway.Request{HTTP: r}
			if err := stage.Handle(context.Background(), req); err == nil {
				t.Fatalf("%s: expected fail closed", tc.name)
			}
			if req.Principal != nil {
				t.Fatalf("%s: principal must not be set on failure", tc.name)
			}
		})
	}
}

func TestStageBearerSchemeIsCaseInsensitive(t *testing.T) {
	// RFC 6750 / RFC 7235: the auth-scheme token is case-insensitive. The bearer() helper
	// uses EqualFold, so "bearer", "BEARER" etc. must all be accepted.
	a, priv := newAuth(t)
	stage := Stage(a)
	tok := signCustom(t, priv, stdClaims("user-1", time.Now().Add(time.Hour)))

	for _, scheme := range []string{"Bearer", "bearer", "BEARER", "BeArEr"} {
		r := httptest.NewRequest(http.MethodGet, "/servers/demo/x", nil)
		r.Header.Set("Authorization", scheme+" "+tok)
		req := &gateway.Request{HTTP: r}
		if err := stage.Handle(context.Background(), req); err != nil {
			t.Fatalf("scheme %q should be accepted: %v", scheme, err)
		}
		if req.Principal == nil || req.Principal.ID != "user-1" {
			t.Fatalf("scheme %q: principal not set: %+v", scheme, req.Principal)
		}
	}
}

func TestStageValidTokenSetsPrincipalWithAssurance(t *testing.T) {
	a, priv := newAuth(t, WithAssurance(types.AssuranceOrg))
	stage := Stage(a)
	r := httptest.NewRequest(http.MethodGet, "/servers/demo/x", nil)
	r.Header.Set("Authorization", "Bearer "+signCustom(t, priv, stdClaims("acct-9", time.Now().Add(time.Hour))))
	req := &gateway.Request{HTTP: r}
	if err := stage.Handle(context.Background(), req); err != nil {
		t.Fatalf("valid token: %v", err)
	}
	if req.Principal == nil || req.Principal.ID != "acct-9" || req.Principal.Assurance != types.AssuranceOrg {
		t.Fatalf("principal not propagated correctly: %+v", req.Principal)
	}
}

// sanity: confirm the verifier used in these tests behaves like the one in newAuth.
func TestStaticVerifierAcceptsGoodToken(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ks := &oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{priv.Public()}}
	v := oidc.NewVerifier(testIssuer, ks, &oidc.Config{ClientID: testClientID})
	a := NewOIDC(v)
	tok := signCustom(t, priv, stdClaims("u", time.Now().Add(time.Hour)))
	if _, err := a.Authenticate(context.Background(), tok); err != nil {
		t.Fatalf("good token rejected: %v", err)
	}
}
