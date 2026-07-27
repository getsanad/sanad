package passport

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func benchClaims(now time.Time) Claims {
	return Claims{
		ID: "jti-1", Issuer: "sanad", Principal: "principal-1",
		Audience: "server-a", Agent: "agent-1", Tools: []string{"read", "list"},
		IssuedAt: now.Unix(), ExpiresAt: now.Add(2 * time.Minute).Unix(),
	}
}

func BenchmarkSign(b *testing.B) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	c := benchClaims(time.Now())
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Sign(priv, "kid-1", c); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerify(b *testing.B) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	tok, _ := Sign(priv, "kid-1", benchClaims(now))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Verify(pub, tok, "server-a", now); err != nil {
			b.Fatal(err)
		}
	}
}
