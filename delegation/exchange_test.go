package delegation

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func newExchange(t *testing.T, ttl time.Duration) *ExchangeAuthority {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	a, err := NewExchange(priv, "ex-1", ttl)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestExchangeIssueAndVerify(t *testing.T) {
	a := newExchange(t, time.Hour)
	root, err := a.IssueRoot("principal-1", "agent-1", Grant{Tools: []string{"read", "write"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Verify(root, time.Now()); err != nil {
		t.Fatalf("verify root: %v", err)
	}

	child, err := a.Exchange(root, "agent-2", Grant{Tools: []string{"read"}})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if child.Subject != "agent-2" || len(child.Grant.Tools) != 1 {
		t.Fatalf("child token wrong: %+v", child.Grant)
	}
	if err := a.Verify(child, time.Now()); err != nil {
		t.Fatalf("verify child: %v", err)
	}
}

func TestExchangeWideningRejected(t *testing.T) {
	a := newExchange(t, time.Hour)
	root, _ := a.IssueRoot("p", "agent-1", Grant{Tools: []string{"read"}})
	if _, err := a.Exchange(root, "agent-2", Grant{Tools: []string{"read", "write"}}); err == nil {
		t.Fatal("widening on exchange must be rejected")
	}
}

func TestExchangeForgedTokenRejected(t *testing.T) {
	a := newExchange(t, time.Hour)
	root, _ := a.IssueRoot("p", "agent-1", Grant{Tools: []string{"read"}})
	root.Grant.Tools = []string{"read", "write"} // tamper after signing
	if err := a.Verify(root, time.Now()); err == nil {
		t.Fatal("a tampered token must fail verification")
	}
}

func TestExchangeExpired(t *testing.T) {
	a := newExchange(t, time.Hour)
	a.now = func() time.Time { return time.Now().Add(-2 * time.Hour) } // issue in the past
	root, _ := a.IssueRoot("p", "agent-1", Grant{Tools: []string{"read"}})
	if err := a.Verify(root, time.Now()); err == nil {
		t.Fatal("an expired token must fail verification")
	}
}

// TestExchangeMidChainRevocation is the centralized-mode benefit: revoking a token denies
// it and everything exchanged from it, while unrelated branches keep working.
func TestExchangeMidChainRevocation(t *testing.T) {
	a := newExchange(t, time.Hour)
	now := time.Now()

	root, _ := a.IssueRoot("p", "agent-1", Grant{Tools: []string{"read", "write"}})
	mid, _ := a.Exchange(root, "agent-2", Grant{Tools: []string{"read"}})
	leaf, _ := a.Exchange(mid, "agent-3", Grant{Tools: []string{"read"}})
	sibling, _ := a.Exchange(root, "agent-9", Grant{Tools: []string{"read"}})

	a.Revoke(mid.ID)

	if err := a.Verify(mid, now); err == nil {
		t.Fatal("revoked token must fail")
	}
	if err := a.Verify(leaf, now); err == nil {
		t.Fatal("descendant of a revoked token must fail (cascade)")
	}
	if err := a.Verify(root, now); err != nil {
		t.Fatalf("ancestor of a revoked token should still be valid: %v", err)
	}
	if err := a.Verify(sibling, now); err != nil {
		t.Fatalf("a sibling branch should be unaffected: %v", err)
	}
}

func TestExchangeFromRevokedParentRejected(t *testing.T) {
	a := newExchange(t, time.Hour)
	root, _ := a.IssueRoot("p", "agent-1", Grant{Tools: []string{"read"}})
	a.Revoke(root.ID)
	if _, err := a.Exchange(root, "agent-2", Grant{Tools: []string{"read"}}); err == nil {
		t.Fatal("exchanging from a revoked parent must be rejected")
	}
}
