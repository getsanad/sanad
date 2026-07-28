package vc

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/getsanad/sanad/internal/sigctx"
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

// b64Sig is what Issue writes into proofValue, for tests that build or alter a credential by
// hand and then have to sign whatever it now is.
func b64Sig(key ed25519.PrivateKey, msg []byte) string {
	return base64.RawURLEncoding.EncodeToString(sigctx.Sign(sigctx.VCProof, key, msg))
}

func TestIssueAndVerify(t *testing.T) {
	issuerDID, issuerKey := newDID(t)
	subjectDID, _ := newDID(t)
	now := time.Now()

	c, err := Issue(issuerDID, issuerKey, Subject{ID: subjectDID, Assurance: types.AssuranceOrg}, time.Hour, now)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	subj, exp, err := Verify(c, StaticTrust{issuerDID: true}, now)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if subj.ID != subjectDID || subj.Assurance != types.AssuranceOrg {
		t.Fatalf("subject mismatch: %+v", subj)
	}
	// Verify hands back the expiry so nothing downstream has to re-parse it (and get zero).
	if want := now.Add(time.Hour).Truncate(time.Second); !exp.Equal(want) {
		t.Fatalf("expiry = %s, want %s", exp, want)
	}
}

func TestVerifyUntrustedIssuer(t *testing.T) {
	issuerDID, issuerKey := newDID(t)
	subjectDID, _ := newDID(t)
	c, _ := Issue(issuerDID, issuerKey, Subject{ID: subjectDID}, time.Hour, time.Now())

	if _, _, err := Verify(c, StaticTrust{}, time.Now()); err == nil {
		t.Fatal("an untrusted issuer must be rejected")
	}
}

func TestVerifyExpired(t *testing.T) {
	issuerDID, issuerKey := newDID(t)
	subjectDID, _ := newDID(t)
	now := time.Now()
	c, _ := Issue(issuerDID, issuerKey, Subject{ID: subjectDID}, time.Minute, now)

	if _, _, err := Verify(c, StaticTrust{issuerDID: true}, now.Add(2*time.Minute)); err == nil {
		t.Fatal("expired credential must be rejected")
	}
}

func TestVerifyTampered(t *testing.T) {
	issuerDID, issuerKey := newDID(t)
	subjectDID, _ := newDID(t)
	c, _ := Issue(issuerDID, issuerKey, Subject{ID: subjectDID, Assurance: types.AssuranceIndividual}, time.Hour, time.Now())

	c.Subject.Assurance = types.AssuranceOrg // escalate assurance after signing
	if _, _, err := Verify(c, StaticTrust{issuerDID: true}, time.Now()); err == nil {
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

	if _, _, err := Verify(c, StaticTrust{trustedDID: true}, time.Now()); err == nil {
		t.Fatal("a credential claiming a trusted issuer it can't sign for must be rejected")
	}
}

// A trusted issuer signs more than principal credentials. Verify used to check the signature
// and the dates and nothing about WHAT it had signed, so any credential of any type — an
// employment claim, a membership, anything the same issuer vouches for — was accepted as a
// principal credential and its subject became a principal of this gateway.
func TestVerifyRejectsAnotherCredentialType(t *testing.T) {
	issuerDID, issuerKey := newDID(t)
	subjectDID, _ := newDID(t)
	now := time.Now()

	for name, mangle := range map[string]func(*Credential){
		"not a principal credential": func(c *Credential) { c.Type = []string{typeVC, "AlumniCredential"} },
		"no type at all":             func(c *Credential) { c.Type = nil },
		"not a verifiable credential": func(c *Credential) {
			c.Type = []string{typePrincipal}
		},
		"wrong @context":  func(c *Credential) { c.Context = []string{"https://example.com/creds/v1"} },
		"no @context":     func(c *Credential) { c.Context = nil },
		"@context second": func(c *Credential) { c.Context = []string{"https://example.com/creds/v1", contextVC} },
		"unknown proof suite": func(c *Credential) {
			c.Proof.Type = "Ed25519Signature2020" // the suite this profile deliberately does not implement
		},
	} {
		t.Run(name, func(t *testing.T) {
			c := Credential{
				Context:        []string{contextVC},
				Type:           []string{typeVC, typePrincipal},
				Issuer:         issuerDID,
				IssuanceDate:   now.UTC().Format(time.RFC3339),
				ExpirationDate: now.Add(time.Hour).UTC().Format(time.RFC3339),
				Subject:        Subject{ID: subjectDID, Assurance: types.AssuranceOrg},
				Proof:          Proof{Type: proofType, Created: now.UTC().Format(time.RFC3339), VerificationMethod: issuerDID},
			}
			mangle(&c)
			// Sign whatever it now is, so the only thing wrong is the shape.
			msg, err := canonical(c)
			if err != nil {
				t.Fatal(err)
			}
			c.Proof.ProofValue = b64Sig(issuerKey, msg)

			if _, _, err := Verify(c, StaticTrust{issuerDID: true}, now); err == nil {
				t.Fatal("a credential that is not a principal credential was accepted as one")
			}
		})
	}
}

// A credential with no expiration date is permanent impersonation of its subject, and it also
// registered a principal key with a zero notAfter, which KeyStore reads as never expiring.
func TestVerifyRequiresAnExpirationDate(t *testing.T) {
	issuerDID, issuerKey := newDID(t)
	subjectDID, _ := newDID(t)
	now := time.Now()

	for name, date := range map[string]string{
		"missing":     "",
		"unparseable": "whenever",
		"not RFC3339": "2026-07-28",
	} {
		t.Run(name, func(t *testing.T) {
			c, err := Issue(issuerDID, issuerKey, Subject{ID: subjectDID}, time.Hour, now)
			if err != nil {
				t.Fatal(err)
			}
			c.ExpirationDate = date
			msg, err := canonical(c)
			if err != nil {
				t.Fatal(err)
			}
			c.Proof.ProofValue = b64Sig(issuerKey, msg) // re-sign: the date is inside the proof

			if _, _, err := Verify(c, StaticTrust{issuerDID: true}, now); err == nil {
				t.Fatalf("a credential with a %s expiration date was accepted", name)
			}
		})
	}
}

// The same for the issuance date, which used to be skipped silently when it did not parse —
// disabling the not-yet-valid check for exactly the credentials most likely to be forged.
func TestVerifyRequiresAParseableIssuanceDate(t *testing.T) {
	issuerDID, issuerKey := newDID(t)
	subjectDID, _ := newDID(t)
	now := time.Now()

	c, _ := Issue(issuerDID, issuerKey, Subject{ID: subjectDID}, time.Hour, now)
	c.IssuanceDate = "sometime"
	msg, _ := canonical(c)
	c.Proof.ProofValue = b64Sig(issuerKey, msg)

	if _, _, err := Verify(c, StaticTrust{issuerDID: true}, now); err == nil {
		t.Fatal("a credential with an unparseable issuance date was accepted")
	}
}

func TestIssueRejectsANonExpiringCredential(t *testing.T) {
	issuerDID, issuerKey := newDID(t)
	subjectDID, _ := newDID(t)
	for _, ttl := range []time.Duration{0, -time.Hour} {
		if _, err := Issue(issuerDID, issuerKey, Subject{ID: subjectDID}, ttl, time.Now()); err == nil {
			t.Fatalf("issuing with ttl=%s must fail: a credential that never expires cannot be presented", ttl)
		}
	}
}
