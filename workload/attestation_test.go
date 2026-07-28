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

// TestMeasuredAttestorRejectsFutureDated is the regression: time.Sub is negative for a future
// IssuedAt, so a one-sided max-age check accepted a quote dated arbitrarily far ahead — and
// accepted it forever, since it only got further from going stale.
func TestMeasuredAttestorRejectsFutureDated(t *testing.T) {
	attPub, attPriv := attKeys(t)
	att, _ := NewMeasuredAttestor(attPub, []string{"build-v1"}, time.Minute)
	base := time.Now().UTC()
	att.now = func() time.Time { return base }
	instPub, _ := attKeys(t)

	for _, ahead := range []time.Duration{MaxQuoteSkew + time.Second, time.Hour, 100 * 365 * 24 * time.Hour} {
		nonce := challenge(t)
		evidence, _ := SignQuote(attPriv, "agent-1", "build-v1", nonce, instPub, base.Add(ahead))
		if _, err := att.Attest(evidence, nonce, instPub); err == nil {
			t.Fatalf("a quote dated %s in the future must be rejected", ahead)
		}
	}
}

// TestMeasuredAttestorAllowsClockSkew pins the other edge: the allowance is for an attesting
// platform whose clock runs fast, so a quote inside MaxQuoteSkew still attests.
func TestMeasuredAttestorAllowsClockSkew(t *testing.T) {
	attPub, attPriv := attKeys(t)
	att, _ := NewMeasuredAttestor(attPub, []string{"build-v1"}, time.Minute)
	base := time.Now().UTC()
	att.now = func() time.Time { return base }
	instPub, _ := attKeys(t)
	nonce := challenge(t)
	evidence, _ := SignQuote(attPriv, "agent-1", "build-v1", nonce, instPub, base.Add(MaxQuoteSkew-time.Second))

	id, err := att.Attest(evidence, nonce, instPub)
	if err != nil {
		t.Fatalf("a quote inside the skew allowance must attest: %v", err)
	}
	if id != "agent-1" {
		t.Fatalf("attested id = %q", id)
	}
}

// TestMeasuredAttestorZeroMaxAgeDefaults pins that a non-positive maxAge selects
// DefaultQuoteMaxAge rather than disabling the check: an attestor built with 0 still ages
// quotes out on both sides.
func TestMeasuredAttestorZeroMaxAgeDefaults(t *testing.T) {
	attPub, attPriv := attKeys(t)
	att, err := NewMeasuredAttestor(attPub, []string{"build-v1"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if att.maxAge != DefaultQuoteMaxAge {
		t.Fatalf("maxAge = %s, want the default %s", att.maxAge, DefaultQuoteMaxAge)
	}
	base := time.Now().UTC()
	att.now = func() time.Time { return base }
	instPub, _ := attKeys(t)

	fresh := challenge(t)
	ok, _ := SignQuote(attPriv, "agent-1", "build-v1", fresh, instPub, base)
	if _, err := att.Attest(ok, fresh, instPub); err != nil {
		t.Fatalf("a fresh quote must still attest: %v", err)
	}
	stale := challenge(t)
	old, _ := SignQuote(attPriv, "agent-1", "build-v1", stale, instPub, base.Add(-DefaultQuoteMaxAge-time.Second))
	if _, err := att.Attest(old, stale, instPub); err == nil {
		t.Fatal("maxAge 0 must select the default window, not disable the freshness check")
	}
	future := challenge(t)
	ahead, _ := SignQuote(attPriv, "agent-1", "build-v1", future, instPub, base.Add(time.Hour))
	if _, err := att.Attest(ahead, future, instPub); err == nil {
		t.Fatal("maxAge 0 must not disable the future-date check either")
	}
}

// TestNewMeasuredAttestorRequiresMeasurements: an empty appraisal policy fails closed, but it
// fails closed at every enrollment for a reason the operator's config does not show. Refuse it
// where the mistake is.
func TestNewMeasuredAttestorRequiresMeasurements(t *testing.T) {
	attPub, _ := attKeys(t)
	if _, err := NewMeasuredAttestor(attPub, nil, time.Hour); err == nil {
		t.Fatal("an attestor with no approved measurements must be refused at construction")
	}
	if _, err := NewMeasuredAttestor(attPub, []string{}, time.Hour); err == nil {
		t.Fatal("an attestor with an empty measurement list must be refused at construction")
	}
	// "" is what a trailing separator in a config list parses to, and it would approve a quote
	// carrying no measurement at all.
	if _, err := NewMeasuredAttestor(attPub, []string{"build-v1", ""}, time.Hour); err == nil {
		t.Fatal("an empty approved measurement must be refused at construction")
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
