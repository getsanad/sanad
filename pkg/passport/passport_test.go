package passport

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func newKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return pub, priv
}

func sampleClaims(now time.Time) Claims {
	return Claims{
		ID:        "jti-1",
		Issuer:    "sanad",
		Principal: "principal-1",
		Audience:  "server-a",
		Agent:     "agent-1",
		Tools:     []string{"read", "list"},
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(2 * time.Minute).Unix(),
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv := newKey(t)
	now := time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC)

	tok, err := Sign(priv, "kid-1", sampleClaims(now))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	got, err := Verify(pub, tok, "server-a", now)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.Principal != "principal-1" || got.Audience != "server-a" || got.Agent != "agent-1" {
		t.Fatalf("claims mismatch: %+v", got)
	}
	if len(got.Tools) != 2 || got.Tools[0] != "read" {
		t.Fatalf("scope mismatch: %v", got.Tools)
	}
}

func TestVerifyWrongAudienceRejected(t *testing.T) {
	pub, priv := newKey(t)
	now := time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC)
	tok, _ := Sign(priv, "kid-1", sampleClaims(now))

	if _, err := Verify(pub, tok, "server-b", now); err == nil {
		t.Fatal("a passport for server-a must not verify for server-b (SEC-2)")
	}
}

func TestVerifyExpiredRejected(t *testing.T) {
	pub, priv := newKey(t)
	now := time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC)
	tok, _ := Sign(priv, "kid-1", sampleClaims(now))

	later := now.Add(3 * time.Minute) // past the 2-minute expiry
	if _, err := Verify(pub, tok, "server-a", later); err == nil {
		t.Fatal("expired passport must be rejected")
	}
	// And exactly at expiry is rejected (deny-on-boundary).
	atExpiry := time.Unix(sampleClaims(now).ExpiresAt, 0)
	if _, err := Verify(pub, tok, "server-a", atExpiry); err == nil {
		t.Fatal("passport must be rejected exactly at expiry")
	}
}

func TestVerifyTamperedSignatureRejected(t *testing.T) {
	pub, priv := newKey(t)
	now := time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC)
	tok, _ := Sign(priv, "kid-1", sampleClaims(now))

	// Flip the last character of the signature segment.
	parts := strings.Split(tok, ".")
	sig := []byte(parts[2])
	sig[len(sig)-1] ^= 0x01
	parts[2] = string(sig)
	tampered := strings.Join(parts, ".")

	if _, err := Verify(pub, tampered, "server-a", now); err == nil {
		t.Fatal("tampered signature must be rejected")
	}
}

func TestVerifyWrongKeyRejected(t *testing.T) {
	_, priv := newKey(t)
	otherPub, _ := newKey(t)
	now := time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC)
	tok, _ := Sign(priv, "kid-1", sampleClaims(now))

	if _, err := Verify(otherPub, tok, "server-a", now); err == nil {
		t.Fatal("a passport must not verify under a different public key")
	}
}

// TestVerifyRejectsAlgNone is the core hardening guarantee from ADR-002: a token whose
// header claims alg:none (or any non-EdDSA alg) is rejected outright.
func TestVerifyRejectsAlgNone(t *testing.T) {
	pub, _ := newKey(t)
	now := time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC)

	hb, _ := json.Marshal(map[string]string{"alg": "none", "typ": typ})
	pb, _ := json.Marshal(sampleClaims(now))
	enc := base64.RawURLEncoding.EncodeToString
	forged := enc(hb) + "." + enc(pb) + "." + enc([]byte("")) // empty signature

	if _, err := Verify(pub, forged, "server-a", now); err == nil {
		t.Fatal("alg:none token must be rejected (ADR-002 hardening)")
	}
}
