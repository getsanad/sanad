package revoke

import (
	"context"
	"sync"
	"testing"

	"github.com/getsanad/sanad/gateway"
	"github.com/getsanad/sanad/pkg/types"
)

func TestRevokeSameIDTwiceIsIdempotent(t *testing.T) {
	ks := NewMemStore()
	ks.Revoke("p1")
	ks.Revoke("p1")
	if !ks.Revoked("p1") {
		t.Fatal("p1 should be revoked")
	}
	if got := ks.List(); len(got) != 1 || got[0] != "p1" {
		t.Fatalf("List() = %v, want [p1] (no duplicates)", got)
	}
	// One restore clears it despite two revokes (set semantics, not a counter).
	ks.Restore("p1")
	if ks.Revoked("p1") {
		t.Fatal("a single restore must clear the id")
	}
	if got := ks.List(); len(got) != 0 {
		t.Fatalf("List() = %v, want empty after restore", got)
	}
}

func TestRestoreUnknownIDIsNoop(t *testing.T) {
	ks := NewMemStore()
	ks.Restore("never-revoked") // must not panic
	if ks.Revoked("never-revoked") {
		t.Fatal("restoring an unknown id must not revoke it")
	}
	if len(ks.List()) != 0 {
		t.Fatal("store should still be empty")
	}
}

func TestListSortedAndDeduped(t *testing.T) {
	ks := NewMemStore()
	// Insert out of order, with repeats.
	for _, id := range []string{"c", "a", "b", "a", "c", "a"} {
		ks.Revoke(id)
	}
	got := ks.List()
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("List() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("List()[%d] = %q, want %q (got %v)", i, got[i], want[i], got)
		}
	}
}

func TestEmptyStringID(t *testing.T) {
	// The empty string is a legal map key; revoking it must be observable and not collide
	// with the "not revoked" case (which is keyed by absence).
	ks := NewMemStore()
	if ks.Revoked("") {
		t.Fatal("empty id should not be revoked initially")
	}
	ks.Revoke("")
	if !ks.Revoked("") {
		t.Fatal("empty id should be revoked after Revoke(\"\")")
	}
	if got := ks.List(); len(got) != 1 || got[0] != "" {
		t.Fatalf("List() = %v, want [\"\"]", got)
	}
	ks.Restore("")
	if ks.Revoked("") {
		t.Fatal("empty id should be restored")
	}
}

func TestStageEmptyRequestPasses(t *testing.T) {
	ks := NewMemStore()
	stage := Stage(ks)
	// No principal, no agent -> nothing to check, must pass.
	if err := stage.Handle(context.Background(), &gateway.Request{}); err != nil {
		t.Fatalf("empty request should pass: %v", err)
	}
}

func TestStageBlocksIndependently(t *testing.T) {
	type checks struct {
		name    string
		revoke  string
		req     *gateway.Request
		wantErr bool
	}
	mk := func() *gateway.Request {
		return &gateway.Request{
			Principal: &types.Principal{ID: "p1"},
			Agent:     &types.Agent{ID: "a1", BlueprintID: "bp1"},
		}
	}

	cases := []checks{
		{"clean", "", mk(), false},
		{"principal", "p1", mk(), true},
		{"agent", "a1", mk(), true},
		{"blueprint", "bp1", mk(), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ks := NewMemStore()
			if tc.revoke != "" {
				ks.Revoke(tc.revoke)
			}
			err := Stage(ks).Handle(context.Background(), tc.req)
			if tc.wantErr && err == nil {
				t.Fatalf("revoking %q should block the request", tc.revoke)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("clean request should pass: %v", err)
			}
		})
	}
}

func TestStageAgentWithoutBlueprintIgnoresEmptyBlueprintID(t *testing.T) {
	// An agent with no blueprint must not be blocked just because the empty string is on
	// the deny list (the code guards against an empty BlueprintID).
	ks := NewMemStore()
	ks.Revoke("") // revoke the empty id
	stage := Stage(ks)
	req := &gateway.Request{
		Principal: &types.Principal{ID: "p1"},
		Agent:     &types.Agent{ID: "a1"}, // BlueprintID == ""
	}
	if err := stage.Handle(context.Background(), req); err != nil {
		t.Fatalf("agent without a blueprint must not be blocked by an empty-id revocation: %v", err)
	}
}

func TestStageBlueprintOnlyRevocationAllowsCleanAgent(t *testing.T) {
	// Revoking a blueprint blocks its instances but not unrelated agents.
	ks := NewMemStore()
	ks.Revoke("bp1")
	stage := Stage(ks)

	blocked := &gateway.Request{Agent: &types.Agent{ID: "a1", BlueprintID: "bp1"}}
	if err := stage.Handle(context.Background(), blocked); err == nil {
		t.Fatal("instance of a revoked blueprint must be blocked")
	}
	clean := &gateway.Request{Agent: &types.Agent{ID: "a2", BlueprintID: "bp2"}}
	if err := stage.Handle(context.Background(), clean); err != nil {
		t.Fatalf("agent of a different blueprint should pass: %v", err)
	}
}

// TestConcurrentRevokeRevoked exercises the RWMutex under concurrent writers, readers,
// listers, and restorers (run with -race).
func TestConcurrentRevokeRevoked(t *testing.T) {
	ks := NewMemStore()
	const workers = 8
	const iters = 500

	var wg sync.WaitGroup
	wg.Add(workers * 4)

	ids := []string{"a", "b", "c", "d"}
	for w := 0; w < workers; w++ {
		go func(w int) { // revokers
			defer wg.Done()
			for i := 0; i < iters; i++ {
				ks.Revoke(ids[i%len(ids)])
			}
		}(w)
		go func(w int) { // readers
			defer wg.Done()
			for i := 0; i < iters; i++ {
				_ = ks.Revoked(ids[i%len(ids)])
			}
		}(w)
		go func(w int) { // listers
			defer wg.Done()
			for i := 0; i < iters; i++ {
				_ = ks.List()
			}
		}(w)
		go func(w int) { // restorers
			defer wg.Done()
			for i := 0; i < iters; i++ {
				ks.Restore(ids[i%len(ids)])
			}
		}(w)
	}
	wg.Wait()

	// Final state is nondeterministic, but List must always be sorted and deduped.
	got := ks.List()
	for i := 1; i < len(got); i++ {
		if got[i-1] >= got[i] {
			t.Fatalf("List() not strictly sorted/deduped: %v", got)
		}
	}
}
