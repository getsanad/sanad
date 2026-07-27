package workload

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http/httptest"
	"testing"
	"time"
)

func enrollSetup(t *testing.T) (*httptest.Server, ed25519.PublicKey) {
	t.Helper()
	caPub, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	att := NewTokenAttestor()
	att.Register("boot-token", "agent-1")
	authority, err := NewAuthority(caPriv, "ca-1", att, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return httptest.NewServer(EnrollHandler(authority)), caPub
}

func TestEnrollRoundTrip(t *testing.T) {
	srv, caPub := enrollSetup(t)
	defer srv.Close()

	instPub, _, _ := ed25519.GenerateKey(rand.Reader)
	cred, err := Enroll(context.Background(), srv.Client(), srv.URL, []byte("boot-token"), instPub)
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if cred.AgentID != "agent-1" || !cred.PublicKey.Equal(instPub) {
		t.Fatalf("credential mismatch: %+v", cred)
	}
	if err := Verify(caPub, cred, time.Now()); err != nil {
		t.Fatalf("issued credential should verify against the CA: %v", err)
	}
}

func TestEnrollRejectsBadAttestation(t *testing.T) {
	srv, _ := enrollSetup(t)
	defer srv.Close()

	instPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := Enroll(context.Background(), srv.Client(), srv.URL, []byte("not-a-real-token"), instPub); err == nil {
		t.Fatal("enrollment with unrecognized attestation must be denied")
	}
}
