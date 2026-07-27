package revoke

import (
	"context"
	"testing"

	"github.com/getsanad/sanad/gateway"
	"github.com/getsanad/sanad/pkg/types"
	"github.com/getsanad/sanad/principal"
)

// MemStore must satisfy principal.StatusChecker so the same kill-switch enforces
// principal revocation at authentication time.
var _ principal.StatusChecker = (*MemStore)(nil)
var _ principal.StatusChecker = (*CachedStore)(nil)

func TestMemStoreRevokeRestore(t *testing.T) {
	ks := NewMemStore()
	if ks.Revoked("p1") {
		t.Fatal("nothing revoked yet")
	}
	ks.Revoke("p1")
	if !ks.Revoked("p1") {
		t.Fatal("p1 should be revoked")
	}
	ks.Restore("p1")
	if ks.Revoked("p1") {
		t.Fatal("p1 should be restored")
	}
}

func TestStageBlocksRevoked(t *testing.T) {
	ks := NewMemStore()
	stage := Stage(ks)
	ctx := context.Background()

	req := func() *gateway.Request {
		return &gateway.Request{
			Principal: &types.Principal{ID: "p1"},
			Agent:     &types.Agent{ID: "a1", BlueprintID: "bp1"},
		}
	}

	// Nothing revoked -> passes.
	if err := stage.Handle(ctx, req()); err != nil {
		t.Fatalf("clean request should pass: %v", err)
	}

	// Principal revoked -> denied.
	ks.Revoke("p1")
	if err := stage.Handle(ctx, req()); err == nil {
		t.Fatal("revoked principal must be denied")
	}
	ks.Restore("p1")

	// Agent revoked -> denied.
	ks.Revoke("a1")
	if err := stage.Handle(ctx, req()); err == nil {
		t.Fatal("revoked agent must be denied")
	}
	ks.Restore("a1")

	// Blueprint revoked -> denied (cascades to its instances).
	ks.Revoke("bp1")
	if err := stage.Handle(ctx, req()); err == nil {
		t.Fatal("revoked blueprint must be denied")
	}
}

func TestList(t *testing.T) {
	ks := NewMemStore()
	ks.Revoke("c")
	ks.Revoke("a")
	ks.Revoke("b")
	got := ks.List()
	want := []string{"a", "b", "c"}
	if len(got) != 3 || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Fatalf("List() = %v, want %v (sorted)", got, want)
	}
}
