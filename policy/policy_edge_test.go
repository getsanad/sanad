package policy

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/getsanad/sanad/gateway"
	"github.com/getsanad/sanad/pkg/types"
)

func TestAllowListDenyByDefaultOnEmpty(t *testing.T) {
	al := NewAllowList()
	d, err := al.Evaluate(context.Background(), Input{Server: "server-a", Tool: "read"})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if d.Effect != types.EffectDeny {
		t.Fatalf("empty allowlist must deny, got %s", d.Effect)
	}
}

func TestAllowListPerServerIsolation(t *testing.T) {
	// A tool allowed on server-a must not leak to server-b.
	al := NewAllowList().Allow("server-a", "read").Allow("server-b", "write")
	ctx := context.Background()

	cases := []struct {
		server, tool string
		wantAllow    bool
	}{
		{"server-a", "read", true},
		{"server-a", "write", false}, // write only on server-b
		{"server-b", "write", true},
		{"server-b", "read", false}, // read only on server-a
		{"server-c", "read", false}, // unknown server
	}
	for _, tc := range cases {
		d, _ := al.Evaluate(ctx, Input{Server: tc.server, Tool: tc.tool})
		if d.Allowed() != tc.wantAllow {
			t.Fatalf("%s/%s: allowed=%v, want %v", tc.server, tc.tool, d.Allowed(), tc.wantAllow)
		}
	}
}

func TestAllowListWildcardIsPerServer(t *testing.T) {
	al := NewAllowList().Allow("server-a", "*")
	ctx := context.Background()
	if d, _ := al.Evaluate(ctx, Input{Server: "server-a", Tool: "anything"}); !d.Allowed() {
		t.Fatal("wildcard must allow any tool on its server")
	}
	if d, _ := al.Evaluate(ctx, Input{Server: "server-b", Tool: "anything"}); d.Allowed() {
		t.Fatal("wildcard on server-a must not leak to server-b")
	}
}

func TestAllowListReviewBeatsAllowAndWildcard(t *testing.T) {
	// review is checked first: a tool both allowed and marked for review routes to review.
	al := NewAllowList().Allow("server-a", "transfer", "*").Review("server-a", "transfer")
	d, _ := al.Evaluate(context.Background(), Input{Server: "server-a", Tool: "transfer"})
	if d.Effect != types.EffectReview {
		t.Fatalf("review must take precedence over allow/wildcard, got %s", d.Effect)
	}
}

func TestStageNoPrincipalFailsClosed(t *testing.T) {
	stage := Stage(NewAllowList().Allow("server-a", "read"), toolIs("read"), nil)
	req := &gateway.Request{Server: "server-a"} // no Principal
	if err := stage.Handle(context.Background(), req); err == nil {
		t.Fatal("missing principal must fail closed")
	}
}

func TestStageNilExtractorDecidedAsMethodNone(t *testing.T) {
	// A nil extractor yields no tool, so the decision is made in the METHOD namespace, under
	// MethodNone. A method entry for it permits the request; the granted scope stays empty
	// (there is no concrete tool to record).
	stage := Stage(NewAllowList().AllowMethods("server-a", MethodNone), nil, nil)
	req := authedReq("server-a")
	if err := stage.Handle(context.Background(), req); err != nil {
		t.Fatalf("nil extractor + a MethodNone entry should allow: %v", err)
	}
	if len(req.Scope.Tools) != 0 {
		t.Fatalf("empty tool must not be recorded in scope, got %v", req.Scope.Tools)
	}

	// A method wildcard covers it too, and so does nothing else.
	if err := Stage(NewAllowList().AllowMethods("server-a", Wildcard), nil, nil).Handle(context.Background(), authedReq("server-a")); err != nil {
		t.Fatalf("nil extractor + method wildcard should allow: %v", err)
	}
}

func TestStageNilExtractorToolRulesDoNotApply(t *testing.T) {
	// The namespaces are separate on purpose: a request that invokes no tool is not authorized
	// by tool entries — not by a named one, and not by the tool wildcard either, which would
	// otherwise be the only way to permit a tools/call and would drag every non-MCP request
	// through with it.
	for _, al := range []*AllowList{
		NewAllowList().Allow("server-a", "read"),
		NewAllowList().Allow("server-a", Wildcard),
	} {
		req := authedReq("server-a")
		if err := Stage(al, nil, nil).Handle(context.Background(), req); err == nil {
			t.Fatal("a request naming no tool must not be authorized by tool entries")
		}
	}
}

func TestStageDeniedRecordsDecision(t *testing.T) {
	stage := Stage(NewAllowList(), toolIs("read"), nil)
	req := authedReq("server-a")
	_ = stage.Handle(context.Background(), req)
	if req.Decision == nil || req.Decision.Effect != types.EffectDeny {
		t.Fatalf("denied decision should be recorded, got %+v", req.Decision)
	}
	if len(req.Scope.Tools) != 0 {
		t.Fatal("denied request must not be granted scope")
	}
}

func TestManualApproverApproveUnknownIDReturnsFalse(t *testing.T) {
	m := NewManualApprover(time.Second)
	if m.Approve("does-not-exist") {
		t.Fatal("approving an unknown id must return false")
	}
	if m.Deny("does-not-exist", "nope") {
		t.Fatal("denying an unknown id must return false")
	}
}

func TestManualApproverDenyResolvesDenied(t *testing.T) {
	m := NewManualApprover(time.Second)
	out := make(chan types.Decision, 1)
	go func() {
		d, _ := m.Decide(context.Background(), Input{Server: "s", Tool: "transfer"})
		out <- d
	}()
	id := waitPending(t, m)
	if !m.Deny(id, "policy violation") {
		t.Fatal("deny returned false for a pending review")
	}
	d := <-out
	if d.Allowed() || d.Reason != "policy violation" {
		t.Fatalf("expected deny with reason, got %+v", d)
	}
}

func TestManualApproverDoubleResolve(t *testing.T) {
	// Once a review is resolved and Decide returns, the entry is deleted; a second resolve
	// for the same id must return false (and must not panic on the closed/absent channel).
	m := NewManualApprover(time.Second)
	done := make(chan struct{})
	go func() {
		_, _ = m.Decide(context.Background(), Input{Server: "s", Tool: "transfer"})
		close(done)
	}()
	id := waitPending(t, m)
	if !m.Approve(id) {
		t.Fatal("first approve should succeed")
	}
	<-done // ensure Decide has returned and deleted the entry
	if m.Approve(id) {
		t.Fatal("second resolve of the same id must return false")
	}
	if m.Deny(id, "x") {
		t.Fatal("deny after resolution must return false")
	}
}

func TestManualApproverContextCancelReturnsError(t *testing.T) {
	m := NewManualApprover(0) // wait indefinitely
	ctx, cancel := context.WithCancel(context.Background())
	out := make(chan error, 1)
	go func() {
		_, err := m.Decide(ctx, Input{Server: "s", Tool: "transfer"})
		out <- err
	}()
	waitPending(t, m)
	cancel()
	select {
	case err := <-out:
		if err == nil {
			t.Fatal("cancelled context must return an error")
		}
	case <-time.After(time.Second):
		t.Fatal("Decide did not unblock on context cancel")
	}
}

func TestManualApproverTimeoutDeniesNotErrors(t *testing.T) {
	m := NewManualApprover(20 * time.Millisecond)
	d, err := m.Decide(context.Background(), Input{Server: "s", Tool: "transfer"})
	if err != nil {
		t.Fatalf("timeout path must not error, got %v", err)
	}
	if d.Allowed() {
		t.Fatal("timeout must deny")
	}
}

func TestManualApproverPendingClearedAfterResolve(t *testing.T) {
	m := NewManualApprover(time.Second)
	done := make(chan struct{})
	go func() {
		_, _ = m.Decide(context.Background(), Input{Server: "s", Tool: "t"})
		close(done)
	}()
	id := waitPending(t, m)
	m.Approve(id)
	<-done
	if p := m.Pending(); len(p) != 0 {
		t.Fatalf("pending should be empty after resolve, got %d", len(p))
	}
}

// TestManualApproverConcurrentReviews drives many concurrent pending reviews and resolves
// each by its own id, asserting no cross-talk and no data races (run with -race).
func TestManualApproverConcurrentReviews(t *testing.T) {
	m := NewManualApprover(2 * time.Second)
	const n = 50

	results := make([]types.Decision, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			d, err := m.Decide(context.Background(), Input{Server: "s", Tool: "transfer"})
			if err != nil {
				t.Errorf("decide %d: %v", i, err)
				return
			}
			results[i] = d
		}(i)
	}

	// Collect all n ids, then resolve alternating approve/deny concurrently.
	ids := collectPending(t, m, n)
	var rw sync.WaitGroup
	for i, id := range ids {
		rw.Add(1)
		go func(i int, id string) {
			defer rw.Done()
			if i%2 == 0 {
				if !m.Approve(id) {
					t.Errorf("approve %s returned false", id)
				}
			} else {
				if !m.Deny(id, "denied") {
					t.Errorf("deny %s returned false", id)
				}
			}
		}(i, id)
	}
	rw.Wait()
	wg.Wait()

	var allowed, denied int
	for _, d := range results {
		if d.Allowed() {
			allowed++
		} else {
			denied++
		}
	}
	if allowed+denied != n {
		t.Fatalf("got %d allowed + %d denied, want %d total", allowed, denied, n)
	}
	if p := m.Pending(); len(p) != 0 {
		t.Fatalf("pending should be drained, got %d", len(p))
	}
}

func collectPending(t *testing.T, m *ManualApprover, n int) []string {
	t.Helper()
	seen := map[string]struct{}{}
	deadline := time.Now().Add(2 * time.Second)
	for len(seen) < n && time.Now().Before(deadline) {
		for _, p := range m.Pending() {
			seen[p.ID] = struct{}{}
		}
		time.Sleep(time.Millisecond)
	}
	if len(seen) != n {
		t.Fatalf("collected %d pending ids, want %d", len(seen), n)
	}
	out := make([]string, 0, n)
	for id := range seen {
		out = append(out, id)
	}
	return out
}

// TestStageReviewRoutesThroughManualApprover is an end-to-end check: the policy stage
// routes EffectReview to a ManualApprover, blocks, and proceeds once approved.
func TestStageReviewRoutesThroughManualApprover(t *testing.T) {
	m := NewManualApprover(time.Second)
	stage := Stage(NewAllowList().Review("server-a", "transfer"), toolIs("transfer"), m)
	req := authedReq("server-a")

	done := make(chan error, 1)
	go func() { done <- stage.Handle(context.Background(), req) }()
	id := waitPending(t, m)
	if !m.Approve(id) {
		t.Fatal("approve returned false")
	}
	if err := <-done; err != nil {
		t.Fatalf("approved review should pass: %v", err)
	}
	// On allow with a concrete tool, scope must be granted.
	if len(req.Scope.Tools) != 1 || req.Scope.Tools[0] != "transfer" {
		t.Fatalf("scope = %v, want [transfer]", req.Scope.Tools)
	}
}
