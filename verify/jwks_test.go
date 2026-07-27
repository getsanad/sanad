package verify

import (
	"testing"

	"github.com/getsanad/sanad/jwks"
	"github.com/getsanad/sanad/pkg/types"
	"github.com/getsanad/sanad/sts"
)

// TestJWKSResolverVerifiesAcrossRotation publishes two signing keys (current + previous)
// in a JWKS and confirms passports signed by either verify via the JWKS resolver — the
// rotation story for offline verification.
func TestJWKSResolverVerifiesAcrossRotation(t *testing.T) {
	oldSigner, _ := sts.NewLocalSigner("kid-old")
	newSigner, _ := sts.NewLocalSigner("kid-new")

	doc, err := jwks.Marshal(
		jwks.Key{Kid: oldSigner.KeyID(), Pub: oldSigner.Public()},
		jwks.Key{Kid: newSigner.KeyID(), Pub: newSigner.Public()},
	)
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := NewJWKSResolver(doc)
	if err != nil {
		t.Fatal(err)
	}
	v := New(resolver)

	for _, signer := range []*sts.LocalSigner{newSigner, oldSigner} {
		issuer := sts.New(signer, sts.Config{Issuer: "sanad"})
		m, err := issuer.Issue(t.Context(), sts.IssueRequest{
			Principal: &types.Principal{ID: "p1"},
			Audience:  "server-a",
		})
		if err != nil {
			t.Fatalf("issue (%s): %v", signer.KeyID(), err)
		}
		if _, err := v.Verify(m.Token, "server-a"); err != nil {
			t.Fatalf("verify (%s) via JWKS resolver failed: %v", signer.KeyID(), err)
		}
	}
}
