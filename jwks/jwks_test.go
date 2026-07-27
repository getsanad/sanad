package jwks

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMarshalParseRoundTrip(t *testing.T) {
	pub1, _, _ := ed25519.GenerateKey(rand.Reader)
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)

	doc, err := Marshal(Key{Kid: "k1", Pub: pub1}, Key{Kid: "k2", Pub: pub2})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	keys, err := Parse(doc)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("got %d keys, want 2", len(keys))
	}
	if keys[0].Kid != "k1" || !keys[0].Pub.Equal(pub1) {
		t.Fatal("k1 did not round-trip")
	}
	if keys[1].Kid != "k2" || !keys[1].Pub.Equal(pub2) {
		t.Fatal("k2 did not round-trip")
	}
}

func TestParseSkipsNonEd25519(t *testing.T) {
	const doc = `{"keys":[{"kty":"RSA","kid":"r1","n":"...","e":"AQAB"}]}`
	keys, err := Parse([]byte(doc))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("RSA key should be skipped, got %d keys", len(keys))
	}
}

func TestHandler(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	rec := httptest.NewRecorder()
	Handler(Key{Kid: "k1", Pub: pub}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	keys, err := Parse(rec.Body.Bytes())
	if err != nil || len(keys) != 1 {
		t.Fatalf("served JWKS not parseable: %v (%d keys)", err, len(keys))
	}
}
