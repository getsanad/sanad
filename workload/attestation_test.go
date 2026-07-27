package workload

import (
	"crypto/ed25519"
	"crypto/rand"
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

func TestMeasuredAttestorApprovesGoodBuild(t *testing.T) {
	attPub, attPriv := attKeys(t)
	att, err := NewMeasuredAttestor(attPub, []string{"build-v1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	evidence, _ := SignQuote(attPriv, "agent-1", "build-v1", time.Now())

	id, err := att.Attest(evidence)
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
	evidence, _ := SignQuote(attPriv, "agent-1", "build-EVIL", time.Now())
	if _, err := att.Attest(evidence); err == nil {
		t.Fatal("an unrecognized build measurement must be rejected")
	}
}

func TestMeasuredAttestorRejectsStale(t *testing.T) {
	attPub, attPriv := attKeys(t)
	att, _ := NewMeasuredAttestor(attPub, []string{"build-v1"}, time.Minute)
	evidence, _ := SignQuote(attPriv, "agent-1", "build-v1", time.Now().Add(-time.Hour))
	if _, err := att.Attest(evidence); err == nil {
		t.Fatal("a stale quote must be rejected")
	}
}

func TestMeasuredAttestorRejectsUntrustedKey(t *testing.T) {
	attPub, _ := attKeys(t)
	_, attackerPriv := attKeys(t)
	att, _ := NewMeasuredAttestor(attPub, []string{"build-v1"}, time.Hour)
	evidence, _ := SignQuote(attackerPriv, "agent-1", "build-v1", time.Now())
	if _, err := att.Attest(evidence); err == nil {
		t.Fatal("a quote signed by an untrusted key must be rejected")
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

	good, _ := SignQuote(attPriv, "agent-1", "build-v1", time.Now())
	if _, err := authority.Issue(good, instPub); err != nil {
		t.Fatalf("approved build should yield a credential: %v", err)
	}

	bad, _ := SignQuote(attPriv, "agent-1", "build-EVIL", time.Now())
	if _, err := authority.Issue(bad, instPub); err == nil {
		t.Fatal("an unapproved build must not yield a credential")
	}
}
