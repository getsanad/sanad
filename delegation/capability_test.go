package delegation

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func rootKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestCapabilityNewAndVerify(t *testing.T) {
	rootPub, rootPriv := rootKeys(t)
	cap, _, err := NewCapability(rootPriv, Grant{Tools: []string{"read", "write"}})
	if err != nil {
		t.Fatal(err)
	}
	g, err := cap.Verify(rootPub, time.Now())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(g.Tools) != 2 {
		t.Fatalf("effective grant = %v", g.Tools)
	}
}

func TestCapabilityOfflineAttenuation(t *testing.T) {
	rootPub, rootPriv := rootKeys(t)
	cap, s0, _ := NewCapability(rootPriv, Grant{Tools: []string{"read", "write"}, Servers: []string{"s1", "s2"}})

	// A holder narrows it OFFLINE (no issuer contact, only s0).
	narrowed, _, err := cap.Attenuate(s0, Grant{Tools: []string{"read"}, Servers: []string{"s1"}})
	if err != nil {
		t.Fatalf("attenuate: %v", err)
	}
	g, err := narrowed.Verify(rootPub, time.Now())
	if err != nil {
		t.Fatalf("verify narrowed: %v", err)
	}
	if len(g.Tools) != 1 || g.Tools[0] != "read" {
		t.Fatalf("effective grant not narrowed: %v", g.Tools)
	}
}

func TestCapabilityWideningRejected(t *testing.T) {
	_, rootPriv := rootKeys(t)
	cap, s0, _ := NewCapability(rootPriv, Grant{Tools: []string{"read"}})
	if _, _, err := cap.Attenuate(s0, Grant{Tools: []string{"read", "write"}}); err == nil {
		t.Fatal("widening on Attenuate must be rejected")
	}
}

func TestCapabilityWrongRootRejected(t *testing.T) {
	otherPub, _ := rootKeys(t)
	_, rootPriv := rootKeys(t)
	cap, _, _ := NewCapability(rootPriv, Grant{Tools: []string{"read"}})
	if _, err := cap.Verify(otherPub, time.Now()); err == nil {
		t.Fatal("a capability must not verify under a different root key")
	}
}

func TestCapabilityWrongHolderSecretRejected(t *testing.T) {
	_, rootPriv := rootKeys(t)
	cap, _, _ := NewCapability(rootPriv, Grant{Tools: []string{"read"}})
	_, attacker := rootKeys(t)
	if _, _, err := cap.Attenuate(attacker, Grant{Tools: []string{"read"}}); err == nil {
		t.Fatal("attenuating with a non-holder secret must be rejected")
	}
}

func TestCapabilityExpired(t *testing.T) {
	rootPub, rootPriv := rootKeys(t)
	cap, _, _ := NewCapability(rootPriv, Grant{NotAfter: time.Now().Add(-time.Minute)})
	if _, err := cap.Verify(rootPub, time.Now()); err == nil {
		t.Fatal("expired capability must be rejected")
	}
}

func TestCapabilityHolderProof(t *testing.T) {
	rootPub, rootPriv := rootKeys(t)
	cap, s0, _ := NewCapability(rootPriv, Grant{Tools: []string{"read"}})
	narrowed, s1, _ := cap.Attenuate(s0, Grant{Tools: []string{"read"}})
	if _, err := narrowed.Verify(rootPub, time.Now()); err != nil {
		t.Fatal(err)
	}

	msg := []byte("principal-token")
	if !narrowed.VerifyHolder(msg, HolderProof(s1, msg)) {
		t.Fatal("the current holder's proof must verify")
	}
	// The previous secret (s0) is NOT the final holder key.
	if narrowed.VerifyHolder(msg, HolderProof(s0, msg)) {
		t.Fatal("a stale holder secret must not satisfy the holder proof")
	}
}

// TestCapabilityRecipientCannotBroaden is the core offline-attenuation guarantee: a
// recipient given a narrowed token (and only its final secret) cannot truncate back to the
// broader parent, because using the broader token requires the parent's next-secret, which
// they do not hold.
func TestCapabilityRecipientCannotBroaden(t *testing.T) {
	rootPub, rootPriv := rootKeys(t)
	broad, s0, _ := NewCapability(rootPriv, Grant{Tools: []string{"read", "write"}})
	narrowed, s1, _ := broad.Attenuate(s0, Grant{Tools: []string{"read"}})

	// The recipient holds `narrowed` + s1 only (not s0). They try to present the broader
	// parent token. It is well-formed (verifies), but they cannot prove they hold it.
	if _, err := broad.Verify(rootPub, time.Now()); err != nil {
		t.Fatal("parent token is itself well-formed")
	}
	msg := []byte("principal-token")
	if broad.VerifyHolder(msg, HolderProof(s1, msg)) {
		t.Fatal("recipient must NOT be able to wield the broader parent token with only the narrowed secret")
	}
	_ = narrowed
}

func TestCapabilityEncodeDecode(t *testing.T) {
	rootPub, rootPriv := rootKeys(t)
	cap, s0, _ := NewCapability(rootPriv, Grant{Tools: []string{"read", "write"}})
	cap, _, _ = cap.Attenuate(s0, Grant{Tools: []string{"read"}})

	enc, err := EncodeCapability(cap)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeCapability(enc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := got.Verify(rootPub, time.Now()); err != nil {
		t.Fatalf("round-tripped capability failed to verify: %v", err)
	}
}
