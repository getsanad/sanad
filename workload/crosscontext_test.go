package workload

// Cross-context tests for the two signatures the authority side makes. A small self-hosted
// deployment can plausibly run the credential CA and the platform attestation key off one
// key pair, and the instance-proof/delegation-hop pair (the sharper of the two, since the
// agent's instance key really is registered for both) is covered in delegation.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/getsanad/sanad/internal/sigctx"
)

func TestCredentialSignatureIsNotAnAttestationQuote(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil { // one key serving as both the CA and the attestation key
		t.Fatal(err)
	}
	instPub, _ := instanceKey(t)
	nonce := []byte("nonce-nonce-nonce-nonce-nonce-32")

	q := Quote{
		AgentID:     "agent-1",
		Measurement: "build-1",
		Nonce:       nonce,
		Confirm:     confirmKey(instPub),
		IssuedAt:    time.Now().UTC(),
	}
	// A signature over the quote's bytes, but made in the credential-signing context.
	q.Signature = sigctx.Sign(sigctx.WorkloadCredential, priv, quoteMsg(q))
	evidence, err := json.Marshal(q)
	if err != nil {
		t.Fatal(err)
	}

	m, err := NewMeasuredAttestor(pub, []string{"build-1"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Attest(evidence, nonce, instPub); err == nil {
		t.Fatal("a credential CA signature was accepted as an attestation quote signature")
	}

	// A genuine quote from the same key still attests.
	genuine, err := SignQuote(priv, "agent-1", "build-1", nonce, instPub, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Attest(genuine, nonce, instPub); err != nil {
		t.Fatalf("a genuine quote must still attest: %v", err)
	}
}

func TestAttestationQuoteSignatureIsNotACredentialSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	instPub, _ := instanceKey(t)
	now := time.Now().UTC()

	c := Credential{
		AgentID:   "agent-1",
		PublicKey: instPub,
		IssuedAt:  now,
		NotAfter:  now.Add(time.Hour),
		KeyID:     "ca-1",
	}
	// A signature over the credential's bytes, but made in the quote-signing context.
	c.Signature = sigctx.Sign(sigctx.AttestationQuote, priv, canonical(c))
	if err := Verify(pub, c, now); err == nil {
		t.Fatal("an attestation quote signature was accepted as a credential signature")
	}

	c.Signature = sigctx.Sign(sigctx.WorkloadCredential, priv, canonical(c))
	if err := Verify(pub, c, now); err != nil {
		t.Fatalf("a genuine credential signature must still verify: %v", err)
	}
}
