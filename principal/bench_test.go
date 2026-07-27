package principal

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

// BenchmarkAuthenticateOIDC measures principal authentication: verifying an RS256 IdP
// token (the cold-path cost). Caching verified principals to hit NFR-1's ~50ms common
// path is a later optimization; this shows the uncached cost.
func BenchmarkAuthenticateOIDC(b *testing.B) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	ks := &oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{priv.Public()}}
	verifier := oidc.NewVerifier(testIssuer, ks, &oidc.Config{ClientID: testClientID})
	a := NewOIDC(verifier)

	tok := signRS256(priv, "user-123", time.Now().Add(time.Hour))
	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := a.Authenticate(ctx, tok); err != nil {
			b.Fatal(err)
		}
	}
}
