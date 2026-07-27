package revoke

import (
	"testing"
	"time"
)

var _ Checker = (*CachedStore)(nil)
var _ Checker = (*MemStore)(nil)

func TestCachedStoreReadWrite(t *testing.T) {
	c, err := NewCachedStore(NewMemSource(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if c.Revoked("x") {
		t.Fatal("nothing revoked yet")
	}
	if err := c.Revoke("x"); err != nil {
		t.Fatal(err)
	}
	if !c.Revoked("x") {
		t.Fatal("x should be revoked locally right after write-through")
	}
	if err := c.Restore("x"); err != nil {
		t.Fatal(err)
	}
	if c.Revoked("x") {
		t.Fatal("x should be restored")
	}
}

// TestCachedStoreCrossReplica simulates two gateway replicas over one shared Source: a
// revocation written by one replica reaches the other after its next refresh.
func TestCachedStoreCrossReplica(t *testing.T) {
	src := NewMemSource()
	replicaA, _ := NewCachedStore(src, 0)
	replicaB, _ := NewCachedStore(src, 0)

	if err := replicaA.Revoke("agent-1"); err != nil {
		t.Fatal(err)
	}
	// B hasn't refreshed yet, so it doesn't see it (bounded staleness).
	if replicaB.Revoked("agent-1") {
		t.Fatal("replica B should not see the revocation before refreshing")
	}
	if err := replicaB.Refresh(); err != nil {
		t.Fatal(err)
	}
	if !replicaB.Revoked("agent-1") {
		t.Fatal("replica B must see the revocation after refreshing from the shared source")
	}
}

func TestCachedStoreBackgroundRefresh(t *testing.T) {
	src := NewMemSource()
	c, err := NewCachedStore(src, 10*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// Write directly to the shared source (as another replica / the admin plane would).
	_ = src.Revoke("agent-9")

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if c.Revoked("agent-9") {
			return // background refresh picked it up
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("background refresh did not pick up the revocation")
}
