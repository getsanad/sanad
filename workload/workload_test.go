package workload

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/getsanad/sanad/delegation"
)

// KeyStore must satisfy the delegation key registry so it can feed delegation verification.
var _ delegation.KeyRegistry = (*KeyStore)(nil)

func newCA(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func instanceKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	return newCA(t)
}

// enroll runs one full enrollment: take a nonce from the authority, build bootstrap evidence
// covering that nonce and pub, and present it.
func enroll(t *testing.T, a *Authority, token string, pub ed25519.PublicKey) (Credential, error) {
	t.Helper()
	nonce, err := a.Nonce()
	if err != nil {
		t.Fatal(err)
	}
	return a.Issue(BootstrapEvidence(token, nonce, pub), nonce, pub)
}

func TestIssueAndVerify(t *testing.T) {
	caPub, caPriv := newCA(t)
	att := NewTokenAttestor()
	att.Register("boot-token-1", "agent-1")
	authority, err := NewAuthority(caPriv, "ca-1", att, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	pub, _ := instanceKey(t)
	cred, err := enroll(t, authority, "boot-token-1", pub)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if cred.AgentID != "agent-1" || !cred.PublicKey.Equal(pub) {
		t.Fatalf("credential mismatch: %+v", cred)
	}
	if err := Verify(caPub, cred, time.Now()); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestAttestationRejected(t *testing.T) {
	_, caPriv := newCA(t)
	authority, _ := NewAuthority(caPriv, "ca-1", NewTokenAttestor(), time.Hour)
	pub, _ := instanceKey(t)
	if _, err := enroll(t, authority, "unknown-token", pub); err == nil {
		t.Fatal("issuing with unrecognized attestation evidence must fail")
	}
}

func TestVerifyExpired(t *testing.T) {
	caPub, caPriv := newCA(t)
	att := NewTokenAttestor()
	att.Register("t", "agent-1")
	authority, _ := NewAuthority(caPriv, "ca-1", att, time.Hour)
	pub, _ := instanceKey(t)
	cred, _ := enroll(t, authority, "t", pub)

	if err := Verify(caPub, cred, cred.NotAfter); err == nil {
		t.Fatal("credential must be rejected at/after expiry")
	}
	if err := Verify(caPub, cred, cred.IssuedAt.Add(-time.Second)); err == nil {
		t.Fatal("credential must be rejected before it is valid")
	}
}

func TestVerifyTamperedAndWrongCA(t *testing.T) {
	caPub, caPriv := newCA(t)
	att := NewTokenAttestor()
	att.Register("t", "agent-1")
	authority, _ := NewAuthority(caPriv, "ca-1", att, time.Hour)
	pub, _ := instanceKey(t)
	cred, _ := enroll(t, authority, "t", pub)

	tampered := cred
	tampered.AgentID = "agent-evil" // changing a signed field invalidates the signature
	if err := Verify(caPub, tampered, time.Now()); err == nil {
		t.Fatal("tampered credential must be rejected")
	}

	otherPub, _ := newCA(t)
	if err := Verify(otherPub, cred, time.Now()); err == nil {
		t.Fatal("credential must not verify under a different CA key")
	}
}

func TestNewAuthorityValidation(t *testing.T) {
	if _, err := NewAuthority(ed25519.PrivateKey("short"), "k", NewTokenAttestor(), time.Hour); err == nil {
		t.Fatal("invalid CA key must error")
	}
	if _, err := NewAuthority(make(ed25519.PrivateKey, ed25519.PrivateKeySize), "k", nil, time.Hour); err == nil {
		t.Fatal("nil attestor must error")
	}
	// Zero TTL falls back to DefaultTTL.
	_, caPriv := newCA(t)
	a, err := NewAuthority(caPriv, "k", NewTokenAttestor(), 0)
	if err != nil || a.ttl != DefaultTTL {
		t.Fatalf("zero TTL should default: ttl=%s err=%v", a.ttl, err)
	}
}

func TestKeyStore(t *testing.T) {
	caPub, caPriv := newCA(t)
	att := NewTokenAttestor()
	att.Register("t", "agent-1")
	authority, _ := NewAuthority(caPriv, "ca-1", att, time.Hour)
	pub, _ := instanceKey(t)
	cred, _ := enroll(t, authority, "t", pub)

	ks := NewKeyStore(caPub)
	if err := ks.Add(cred); err != nil {
		t.Fatalf("add: %v", err)
	}
	got, ok := ks.AgentKey("agent-1")
	if !ok || !got.Equal(pub) {
		t.Fatal("agent key not resolvable after Add")
	}
	if _, ok := ks.AgentKey("unknown"); ok {
		t.Fatal("unknown subject must not resolve")
	}
	// The agent's key lives in the agent namespace ONLY: the same id read as a principal
	// resolves nothing.
	if _, ok := ks.PrincipalKey("agent-1"); ok {
		t.Fatal("an agent key must not resolve as a principal key")
	}

	// A directly-added principal key (no expiry) resolves — and only as a principal.
	ppub, _ := newCA(t)
	ks.AddPrincipalKey("principal-1", ppub, time.Time{})
	if _, ok := ks.PrincipalKey("principal-1"); !ok {
		t.Fatal("principal key should resolve")
	}
	if _, ok := ks.AgentKey("principal-1"); ok {
		t.Fatal("a principal key must not resolve as an agent key")
	}
	// An empty id is not a subject: nothing may be registered under it.
	ks.AddPrincipalKey("", ppub, time.Time{})
	if _, ok := ks.PrincipalKey(""); ok {
		t.Fatal("an empty principal id must not register a key")
	}

	// An expired credential is not cached.
	expAuth, _ := NewAuthority(caPriv, "ca-1", att, time.Nanosecond)
	expCred, _ := enroll(t, expAuth, "t", pub)
	time.Sleep(time.Millisecond)
	if err := ks.Add(expCred); err == nil {
		t.Fatal("expired credential must not be added")
	}
}

func TestKeyStoreExpiryHidesKey(t *testing.T) {
	caPub := make(ed25519.PublicKey, ed25519.PublicKeySize)
	ks := NewKeyStore(caPub)
	pub, _ := newCA(t)
	// Inject a clock so we can cross the expiry deterministically.
	base := time.Now()
	ks.now = func() time.Time { return base }
	ks.AddPrincipalKey("principal-1", pub, base.Add(time.Minute))
	if _, ok := ks.PrincipalKey("principal-1"); !ok {
		t.Fatal("key should resolve before expiry")
	}
	ks.now = func() time.Time { return base.Add(2 * time.Minute) }
	if _, ok := ks.PrincipalKey("principal-1"); ok {
		t.Fatal("key must not resolve after expiry")
	}
}
