package sts

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/getsanad/sanad/pkg/passport"
	"github.com/getsanad/sanad/pkg/types"
)

func TestLoadSignerIsDeterministic(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	a, err := LoadSigner("kid-1", seed)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := LoadSigner("kid-1", seed)
	if !a.Public().Equal(b.Public()) {
		t.Fatal("same seed must yield the same key (stable JWKS across restarts/replicas)")
	}
	if _, err := LoadSigner("kid", []byte("too short")); err == nil {
		t.Fatal("a wrong-length seed must be rejected")
	}

	// A passport minted by a seed-loaded signer verifies under its public key.
	iss := New(a, Config{Issuer: "sanad"})
	m, _ := iss.Issue(context.Background(), IssueRequest{Principal: &types.Principal{ID: "p1"}, Audience: "demo"})
	if _, err := passport.Verify(a.Public(), m.Token, "demo", time.Now()); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestRemoteSignerDelegatesToKMS(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	calls := 0
	// Simulate a KMS: the private key never appears in the signer; it is reached only
	// through this function.
	kms := func(msg []byte) ([]byte, error) {
		calls++
		return ed25519.Sign(priv, msg), nil
	}
	rs, err := NewRemoteSigner("kms-kid", pub, kms)
	if err != nil {
		t.Fatal(err)
	}

	iss := New(rs, Config{Issuer: "sanad"})
	m, err := iss.Issue(context.Background(), IssueRequest{Principal: &types.Principal{ID: "p1"}, Audience: "demo"})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if calls == 0 {
		t.Fatal("the KMS sign function should have been invoked")
	}
	if _, err := passport.Verify(rs.Public(), m.Token, "demo", time.Now()); err != nil {
		t.Fatalf("KMS-signed passport must verify under the public key: %v", err)
	}
}
