package vc

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/getsanad/sanad/pkg/types"
)

func newDID(t *testing.T) (string, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return EncodeDIDKey(pub), priv
}

func TestIssueAndVerify(t *testing.T) {
	issuerDID, issuerKey := newDID(t)
	subjectDID, _ := newDID(t)
	now := time.Now()

	c, err := Issue(issuerDID, issuerKey, Subject{ID: subjectDID, Assurance: types.AssuranceOrg}, time.Hour, now)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	subj, err := Verify(c, StaticTrust{issuerDID: true}, now)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if subj.ID != subjectDID || subj.Assurance != types.AssuranceOrg {
		t.Fatalf("subject mismatch: %+v", subj)
	}
}

func TestVerifyUntrustedIssuer(t *testing.T) {
	issuerDID, issuerKey := newDID(t)
	subjectDID, _ := newDID(t)
	c, _ := Issue(issuerDID, issuerKey, Subject{ID: subjectDID}, time.Hour, time.Now())

	if _, err := Verify(c, StaticTrust{}, time.Now()); err == nil {
		t.Fatal("an untrusted issuer must be rejected")
	}
}

func TestVerifyExpired(t *testing.T) {
	issuerDID, issuerKey := newDID(t)
	subjectDID, _ := newDID(t)
	now := time.Now()
	c, _ := Issue(issuerDID, issuerKey, Subject{ID: subjectDID}, time.Minute, now)

	if _, err := Verify(c, StaticTrust{issuerDID: true}, now.Add(2*time.Minute)); err == nil {
		t.Fatal("expired credential must be rejected")
	}
}

func TestVerifyTampered(t *testing.T) {
	issuerDID, issuerKey := newDID(t)
	subjectDID, _ := newDID(t)
	c, _ := Issue(issuerDID, issuerKey, Subject{ID: subjectDID, Assurance: types.AssuranceIndividual}, time.Hour, time.Now())

	c.Subject.Assurance = types.AssuranceOrg // escalate assurance after signing
	if _, err := Verify(c, StaticTrust{issuerDID: true}, time.Now()); err == nil {
		t.Fatal("tampering with the subject must invalidate the signature")
	}
}

func TestIssueRejectsMismatchedKey(t *testing.T) {
	issuerDID, _ := newDID(t)
	_, otherKey := newDID(t)
	if _, err := Issue(issuerDID, otherKey, Subject{ID: issuerDID}, time.Hour, time.Now()); err == nil {
		t.Fatal("issuing with a key that doesn't match the issuer DID must fail")
	}
}

func TestVerifyForgedIssuer(t *testing.T) {
	// A credential signed by attacker, but claiming a trusted issuer DID.
	trustedDID, _ := newDID(t)
	attackerDID, attackerKey := newDID(t)
	subjectDID, _ := newDID(t)

	c, _ := Issue(attackerDID, attackerKey, Subject{ID: subjectDID}, time.Hour, time.Now())
	c.Issuer = trustedDID // claim to be the trusted issuer without its key

	if _, err := Verify(c, StaticTrust{trustedDID: true}, time.Now()); err == nil {
		t.Fatal("a credential claiming a trusted issuer it can't sign for must be rejected")
	}
}
