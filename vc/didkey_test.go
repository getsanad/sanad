package vc

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
)

func TestDIDKeyRoundTrip(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	did := EncodeDIDKey(pub)
	if !strings.HasPrefix(did, "did:key:z") {
		t.Fatalf("did:key should start with did:key:z, got %q", did)
	}
	got, err := PublicKeyFromDID(did)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !got.Equal(pub) {
		t.Fatal("public key did not round-trip through did:key")
	}
}

func TestPublicKeyFromDIDRejects(t *testing.T) {
	cases := []string{
		"",
		"did:web:example.com",
		"did:key:zINVALID0", // 0 not in base58 alphabet
		"did:key:z111",      // too short / wrong prefix
	}
	for _, did := range cases {
		if _, err := PublicKeyFromDID(did); err == nil {
			t.Fatalf("expected %q to be rejected", did)
		}
	}
}

func TestBase58RoundTrip(t *testing.T) {
	for _, in := range [][]byte{{}, {0}, {0, 0, 1}, {255, 254, 253}, []byte("hello world")} {
		got, err := base58Decode(base58Encode(in))
		if err != nil {
			t.Fatalf("decode(%v): %v", in, err)
		}
		if string(got) != string(in) {
			t.Fatalf("base58 round-trip: got %v want %v", got, in)
		}
	}
}
