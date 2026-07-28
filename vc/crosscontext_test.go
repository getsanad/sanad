package vc

// Cross-context tests for the VC proof. Principals are did:key identities: the same key that
// a trusted issuer signs credentials with can be registered as a principal key and root a
// delegation chain (a self-issued credential makes issuer and subject literally the same
// key). Without distinct contexts, an issued credential doubles as a delegation from that
// principal, and a delegation hop doubles as an issued credential.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/getsanad/sanad/delegation"
	"github.com/getsanad/sanad/pkg/types"
)

func TestVCProofIsNotADelegationHop(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	did := EncodeDIDKey(pub)
	now := time.Now()

	cred, err := Issue(did, priv, Subject{ID: did, Assurance: types.AssuranceOrg}, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(cred.Proof.ProofValue)
	if err != nil {
		t.Fatal(err)
	}

	// The issuer's proof, presented as this principal's root delegation hop.
	keys := delegation.MemKeyRegistry{Principals: map[string]ed25519.PublicKey{did: pub}}
	forged := delegation.Chain{Hops: []delegation.Hop{{
		Delegator: did, Delegate: "agent-1",
		Grant:     delegation.Grant{Tools: []string{"admin"}},
		Signature: sig,
	}}}
	if _, _, err := delegation.Verify(forged, keys, did, now); err == nil {
		t.Fatal("a VC issuer proof was accepted as a delegation hop")
	}

	// Each still verifies as itself.
	if _, err := Verify(cred, StaticTrust{did: true}, now); err != nil {
		t.Fatalf("a genuine credential must still verify: %v", err)
	}
	chain, err := delegation.NewRoot(priv, did, "agent-1", delegation.Grant{Tools: []string{"read"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := delegation.Verify(chain, keys, did, now); err != nil {
		t.Fatalf("a genuine chain must still verify: %v", err)
	}
}

func TestDelegationHopIsNotAVCProof(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	did := EncodeDIDKey(pub)
	now := time.Now()

	// Take a real credential, then swap its proof for a delegation hop signature this key
	// made. The hop covers different bytes, but the point is that a signature by the trusted
	// issuer key must not be readable as a credential proof at all.
	cred, err := Issue(did, priv, Subject{ID: did, Assurance: types.AssuranceOrg}, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := canonical(cred)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := delegation.NewRoot(priv, did, string(msg), delegation.Grant{})
	if err != nil {
		t.Fatal(err)
	}
	cred.Proof.ProofValue = base64.RawURLEncoding.EncodeToString(chain.Hops[0].Signature)

	if _, err := Verify(cred, StaticTrust{did: true}, now); err == nil {
		t.Fatal("a delegation hop signature was accepted as a VC issuer proof")
	}
}
