package workload

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"
)

func attKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// challenge returns a nonce of the shape the authority issues, for attestor-level tests that
// do not go through an Authority.
func challenge(t *testing.T) []byte {
	t.Helper()
	n := make([]byte, nonceSize)
	if _, err := rand.Read(n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestMeasuredAttestorApprovesGoodBuild(t *testing.T) {
	attPub, attPriv := attKeys(t)
	att, err := NewMeasuredAttestor(attPub, []string{"build-v1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	instPub, _ := attKeys(t)
	nonce := challenge(t)
	evidence, _ := SignQuote(attPriv, "agent-1", "build-v1", nonce, instPub, time.Now())

	id, err := att.Attest(evidence, nonce, instPub)
	if err != nil {
		t.Fatalf("attest: %v", err)
	}
	if id != "agent-1" {
		t.Fatalf("attested id = %q", id)
	}
}

func TestMeasuredAttestorRejectsUnknownMeasurement(t *testing.T) {
	attPub, attPriv := attKeys(t)
	att, _ := NewMeasuredAttestor(attPub, []string{"build-v1"}, time.Hour)
	instPub, _ := attKeys(t)
	nonce := challenge(t)
	evidence, _ := SignQuote(attPriv, "agent-1", "build-EVIL", nonce, instPub, time.Now())
	if _, err := att.Attest(evidence, nonce, instPub); err == nil {
		t.Fatal("an unrecognized build measurement must be rejected")
	}
}

func TestMeasuredAttestorRejectsStale(t *testing.T) {
	attPub, attPriv := attKeys(t)
	att, _ := NewMeasuredAttestor(attPub, []string{"build-v1"}, time.Minute)
	instPub, _ := attKeys(t)
	nonce := challenge(t)
	evidence, _ := SignQuote(attPriv, "agent-1", "build-v1", nonce, instPub, time.Now().Add(-time.Hour))
	if _, err := att.Attest(evidence, nonce, instPub); err == nil {
		t.Fatal("a stale quote must be rejected")
	}
}

func TestMeasuredAttestorRejectsUntrustedKey(t *testing.T) {
	attPub, _ := attKeys(t)
	_, attackerPriv := attKeys(t)
	att, _ := NewMeasuredAttestor(attPub, []string{"build-v1"}, time.Hour)
	instPub, _ := attKeys(t)
	nonce := challenge(t)
	evidence, _ := SignQuote(attackerPriv, "agent-1", "build-v1", nonce, instPub, time.Now())
	if _, err := att.Attest(evidence, nonce, instPub); err == nil {
		t.Fatal("a quote signed by an untrusted key must be rejected")
	}
}

// TestMeasuredAttestorRejectsForeignKeyAndNonce is the core binding property: a quote is
// evidence for one key answering one challenge, and is worthless against either any other
// key or any other challenge.
func TestMeasuredAttestorRejectsForeignKeyAndNonce(t *testing.T) {
	attPub, attPriv := attKeys(t)
	att, _ := NewMeasuredAttestor(attPub, []string{"build-v1"}, time.Hour)

	honestPub, _ := attKeys(t)
	attackerPub, _ := attKeys(t)
	nonce := challenge(t)
	evidence, _ := SignQuote(attPriv, "agent-1", "build-v1", nonce, honestPub, time.Now())

	if _, err := att.Attest(evidence, nonce, attackerPub); err == nil {
		t.Fatal("a quote must not attest to a public key it does not name")
	}
	if _, err := att.Attest(evidence, challenge(t), honestPub); err == nil {
		t.Fatal("a quote must not answer a challenge it does not name")
	}
}

// TestMeasuredQuoteCnfIsSigned pins that the cnf claim is inside the signed message: swapping
// the confirmed key in a captured quote invalidates it rather than re-targeting it.
func TestMeasuredQuoteCnfIsSigned(t *testing.T) {
	attPub, attPriv := attKeys(t)
	att, _ := NewMeasuredAttestor(attPub, []string{"build-v1"}, time.Hour)

	honestPub, _ := attKeys(t)
	attackerPub, _ := attKeys(t)
	nonce := challenge(t)
	evidence, _ := SignQuote(attPriv, "agent-1", "build-v1", nonce, honestPub, time.Now())

	var q Quote
	if err := json.Unmarshal(evidence, &q); err != nil {
		t.Fatal(err)
	}
	q.Confirm = confirmKey(attackerPub) // keep the attestation signature, swap the bound key
	forged, _ := json.Marshal(q)

	if _, err := att.Attest(forged, nonce, attackerPub); err == nil {
		t.Fatal("rewriting the cnf claim of a captured quote must break its signature")
	}
}

// TestMeasuredAttestorWithAuthority shows the high-assurance tier end-to-end: an Authority
// backed by a MeasuredAttestor only issues a workload credential for an approved build.
func TestMeasuredAttestorWithAuthority(t *testing.T) {
	attPub, attPriv := attKeys(t)
	att, _ := NewMeasuredAttestor(attPub, []string{"build-v1"}, time.Hour)

	_, caPriv := attKeys(t)
	authority, _ := NewAuthority(caPriv, "ca-1", att, time.Hour)
	instPub, _ := attKeys(t)

	nonce, _ := authority.Nonce()
	good, _ := SignQuote(attPriv, "agent-1", "build-v1", nonce, instPub, time.Now())
	if _, err := authority.Issue(good, nonce, instPub); err != nil {
		t.Fatalf("approved build should yield a credential: %v", err)
	}

	nonce, _ = authority.Nonce()
	bad, _ := SignQuote(attPriv, "agent-1", "build-EVIL", nonce, instPub, time.Now())
	if _, err := authority.Issue(bad, nonce, instPub); err == nil {
		t.Fatal("an unapproved build must not yield a credential")
	}
}

func TestSignQuoteRejectsInvalidKey(t *testing.T) {
	_, attPriv := attKeys(t)
	if _, err := SignQuote(attPriv, "agent-1", "build-v1", challenge(t), ed25519.PublicKey("short"), time.Now()); err == nil {
		t.Fatal("SignQuote must refuse to bind a quote to a malformed public key")
	}
}
