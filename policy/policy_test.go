package policy

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/getsanad/sanad/gateway"
	"github.com/getsanad/sanad/pkg/types"
)

func toolIs(name string) ToolExtractor {
	return func(*gateway.Request) string { return name }
}

func authedReq(server string) *gateway.Request {
	return &gateway.Request{Server: server, Principal: &types.Principal{ID: "p1"}}
}

func TestAllowListDecisions(t *testing.T) {
	al := NewAllowList().Allow("server-a", "read", "list").Review("server-a", "transfer")
	ctx := context.Background()

	cases := []struct {
		tool string
		want types.Effect
	}{
		{"read", types.EffectAllow},
		{"list", types.EffectAllow},
		{"delete", types.EffectDeny},     // not listed -> deny-by-default
		{"transfer", types.EffectReview}, // needs approval
	}
	for _, tc := range cases {
		d, err := al.Evaluate(ctx, Input{Server: "server-a", Tool: tc.tool})
		if err != nil {
			t.Fatalf("%s: %v", tc.tool, err)
		}
		if d.Effect != tc.want {
			t.Fatalf("tool %q: got %s, want %s", tc.tool, d.Effect, tc.want)
		}
	}

	// Unknown server denies everything.
	if d, _ := al.Evaluate(ctx, Input{Server: "other", Tool: "read"}); d.Allowed() {
		t.Fatal("unknown server must be denied")
	}
}

func TestAllowListWildcard(t *testing.T) {
	al := NewAllowList().Allow("server-a", "*")
	d, _ := al.Evaluate(context.Background(), Input{Server: "server-a", Tool: "anything"})
	if !d.Allowed() {
		t.Fatal("wildcard must allow any tool")
	}
}

func TestDenyAll(t *testing.T) {
	d, _ := DenyAll.Evaluate(context.Background(), Input{Server: "server-a", Tool: "read"})
	if d.Allowed() {
		t.Fatal("DenyAll must deny")
	}
}

func TestStageDenyByDefaultFailsClosed(t *testing.T) {
	stage := Stage(NewAllowList(), toolIs("read"), nil) // empty allowlist
	req := authedReq("server-a")
	if err := stage.Handle(context.Background(), req); err == nil {
		t.Fatal("deny-by-default must fail closed")
	}
	if req.Decision == nil || req.Decision.Allowed() {
		t.Fatal("decision should be recorded as deny")
	}
}

func TestStageAllowSetsScope(t *testing.T) {
	stage := Stage(NewAllowList().Allow("server-a", "read"), toolIs("read"), nil)
	req := authedReq("server-a")
	if err := stage.Handle(context.Background(), req); err != nil {
		t.Fatalf("allowlisted tool should pass: %v", err)
	}
	if len(req.Scope.Tools) != 1 || req.Scope.Tools[0] != "read" {
		t.Fatalf("granted scope = %v, want [read]", req.Scope.Tools)
	}
}

// delegatedReq is an authenticated request that already carries what the delegation stage
// put on it (P2-04): the effective grant's scope plus the verified chain.
func delegatedReq(server string, scope types.Scope) *gateway.Request {
	req := authedReq(server)
	req.Scope = scope
	req.Delegation = &types.DelegationChain{Hops: []types.DelegationHop{
		{Delegator: "p1", Delegate: "agent-1", Scope: scope, Signature: []byte("sig")},
	}}
	return req
}

// allowAny is a PDP that permits everything, so these tests isolate the stage's own
// attenuation enforcement from any allowlist decision.
var allowAny = Func(func(context.Context, Input) (types.Decision, error) {
	return types.Decision{Effect: types.EffectAllow, Reason: "test allow-all"}, nil
})

// TestStageDeniesToolOutsideDelegatedScope covers the escalation the stage used to have: it
// ASSIGNED types.Scope{Tools: []string{tool}}, replacing the attenuated grant, so a chain
// limited to ["read"] minted a passport for admin_delete the moment a tool extractor existed.
func TestStageDeniesToolOutsideDelegatedScope(t *testing.T) {
	grant := types.Scope{Tools: []string{"read", "list"}}
	req := delegatedReq("server-a", grant)

	err := Stage(allowAny, toolIs("admin_delete"), nil).Handle(context.Background(), req)
	if err == nil {
		t.Fatal("a tool outside the delegated scope must be denied, not silently re-scoped")
	}
	if req.Decision == nil || req.Decision.Effect != types.EffectDeny {
		t.Fatalf("the denial should be recorded for audit, got %+v", req.Decision)
	}
	if !slices.Equal(req.Scope.Tools, grant.Tools) {
		t.Fatalf("a denied request must not have its scope rewritten: %v", req.Scope.Tools)
	}
}

// TestStageIntersectsWithDelegatedScope: a tool inside the grant is allowed, and the scope
// handed to the mint stage is the intersection — never broader than the grant — with the
// delegated Budget carried through rather than dropped.
func TestStageIntersectsWithDelegatedScope(t *testing.T) {
	budget := &types.Budget{Limit: 100, Unit: "usd"}
	grant := types.Scope{Tools: []string{"read", "list"}, Budget: budget}
	req := delegatedReq("server-a", grant)

	if err := Stage(allowAny, toolIs("read"), nil).Handle(context.Background(), req); err != nil {
		t.Fatalf("a tool inside the delegated scope should pass: %v", err)
	}
	if !slices.Equal(req.Scope.Tools, []string{"read"}) {
		t.Fatalf("granted scope = %v, want [read]", req.Scope.Tools)
	}
	for _, got := range req.Scope.Tools { // the property that matters: never wider than the grant
		if !slices.Contains(grant.Tools, got) {
			t.Fatalf("granted tool %q is not in the delegated grant %v", got, grant.Tools)
		}
	}
	if req.Scope.Budget == nil || *req.Scope.Budget != *budget {
		t.Fatalf("delegated budget = %+v, want %+v", req.Scope.Budget, budget)
	}
}

// TestStageEmptyDelegatedScopeIsUnconstrained pins the empty-set semantics to the ones
// delegation's subset() already enforces: an empty tool set is the wildcard, not "deny all".
// It arises both with no chain (PASSPORT_ALLOW_DIRECT_PRINCIPAL) and from a chain that never
// constrained tools — in neither case is there an attenuation to bypass. Any Budget the
// grant did carry must still survive.
func TestStageEmptyDelegatedScopeIsUnconstrained(t *testing.T) {
	budget := &types.Budget{Limit: 5, Unit: "calls"}
	tests := []struct {
		name string
		req  *gateway.Request
	}{
		{"no delegation at all", authedReq("server-a")},
		{"chain unconstrained on tools", delegatedReq("server-a", types.Scope{Budget: budget})},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := Stage(allowAny, toolIs("read"), nil).Handle(context.Background(), tc.req); err != nil {
				t.Fatalf("an unconstrained grant must not deny: %v", err)
			}
			if !slices.Equal(tc.req.Scope.Tools, []string{"read"}) {
				t.Fatalf("granted scope = %v, want [read]", tc.req.Scope.Tools)
			}
		})
	}
	if b := tests[1].req.Scope.Budget; b == nil || *b != *budget {
		t.Fatalf("budget = %+v, want %+v", b, budget)
	}
}

// TestStageEmptyToolKeepsDelegatedScope: with no tool to narrow to (a nil extractor today),
// the delegated grant must reach the passport intact — not be cleared or replaced.
func TestStageEmptyToolKeepsDelegatedScope(t *testing.T) {
	grant := types.Scope{Tools: []string{"read"}, Budget: &types.Budget{Limit: 1, Unit: "calls"}}
	req := delegatedReq("server-a", grant)

	if err := Stage(allowAny, nil, nil).Handle(context.Background(), req); err != nil {
		t.Fatalf("nil extractor should pass an allow-all PDP: %v", err)
	}
	if !slices.Equal(req.Scope.Tools, grant.Tools) || req.Scope.Budget != grant.Budget {
		t.Fatalf("delegated scope not preserved: %+v", req.Scope)
	}
}

// TestStagePDPSeesDelegationContext: the PDP cannot enforce against a grant it cannot see,
// so the verified chain and its scope are part of the Input (and of what an approver sees).
func TestStagePDPSeesDelegationContext(t *testing.T) {
	grant := types.Scope{Tools: []string{"read"}, Budget: &types.Budget{Limit: 42, Unit: "usd"}}
	req := delegatedReq("server-a", grant)

	var got Input
	pdp := Func(func(_ context.Context, in Input) (types.Decision, error) {
		got = in
		return types.Decision{Effect: types.EffectAllow, Reason: "ok"}, nil
	})
	if err := Stage(pdp, toolIs("read"), nil).Handle(context.Background(), req); err != nil {
		t.Fatalf("stage: %v", err)
	}
	if got.Delegation == nil || len(got.Delegation.Hops) != 1 || got.Delegation.Hops[0].Delegate != "agent-1" {
		t.Fatalf("verified chain not handed to the PDP: %+v", got.Delegation)
	}
	if !slices.Equal(got.DelegatedScope.Tools, grant.Tools) || got.DelegatedScope.Budget != grant.Budget {
		t.Fatalf("delegated scope not handed to the PDP: %+v", got.DelegatedScope)
	}

	// With no delegation the fields are simply absent, so a PDP can tell the two apart.
	direct := authedReq("server-a")
	if err := Stage(pdp, toolIs("read"), nil).Handle(context.Background(), direct); err != nil {
		t.Fatalf("stage: %v", err)
	}
	if got.Delegation != nil || got.DelegatedScope.Tools != nil {
		t.Fatalf("a direct principal must not look delegated: %+v", got)
	}
}

// TestStageOutOfScopeToolSkipsApproval: the attenuation floor is checked before the PDP, so
// an action the chain cannot authorize never pages a human who could not approve it anyway.
func TestStageOutOfScopeToolSkipsApproval(t *testing.T) {
	var consulted bool
	approver := ApproverFunc(func(context.Context, Input) (types.Decision, error) {
		consulted = true
		return types.Decision{Effect: types.EffectAllow, Reason: "approved"}, nil
	})
	al := NewAllowList().Review("server-a", "transfer")
	req := delegatedReq("server-a", types.Scope{Tools: []string{"read"}})

	if err := Stage(al, toolIs("transfer"), approver).Handle(context.Background(), req); err == nil {
		t.Fatal("a tool outside the delegated scope must be denied")
	}
	if consulted {
		t.Fatal("no approver should be asked to bless authority the chain never conferred")
	}
}

func TestStagePDPErrorFailsClosed(t *testing.T) {
	boom := Func(func(context.Context, Input) (types.Decision, error) {
		return types.Decision{}, context.DeadlineExceeded
	})
	stage := Stage(boom, toolIs("read"), nil)
	if err := stage.Handle(context.Background(), authedReq("server-a")); err == nil {
		t.Fatal("a PDP error must fail closed")
	}
}

func TestStageReviewWithoutApproverFailsClosed(t *testing.T) {
	stage := Stage(NewAllowList().Review("server-a", "transfer"), toolIs("transfer"), nil)
	if err := stage.Handle(context.Background(), authedReq("server-a")); err == nil {
		t.Fatal("EffectReview without an approver must fail closed")
	}
}

func TestStageReviewApproverDecides(t *testing.T) {
	allow := ApproverFunc(func(context.Context, Input) (types.Decision, error) {
		return types.Decision{Effect: types.EffectAllow, Reason: "ok"}, nil
	})
	deny := ApproverFunc(func(context.Context, Input) (types.Decision, error) {
		return types.Decision{Effect: types.EffectDeny, Reason: "no"}, nil
	})
	al := NewAllowList().Review("server-a", "transfer")

	if err := Stage(al, toolIs("transfer"), allow).Handle(context.Background(), authedReq("server-a")); err != nil {
		t.Fatalf("approved review should pass: %v", err)
	}
	if err := Stage(al, toolIs("transfer"), deny).Handle(context.Background(), authedReq("server-a")); err == nil {
		t.Fatal("denied review must fail closed")
	}
}

func TestManualApproverApprove(t *testing.T) {
	approver := NewManualApprover(time.Second)
	stage := Stage(NewAllowList().Review("server-a", "transfer"), toolIs("transfer"), approver)

	req := authedReq("server-a")
	done := make(chan error, 1)
	go func() { done <- stage.Handle(context.Background(), req) }()

	id := waitPending(t, approver)
	if !approver.Approve(id) {
		t.Fatal("approve returned false")
	}
	if err := <-done; err != nil {
		t.Fatalf("expected allow after approval: %v", err)
	}
	if req.Decision == nil || !req.Decision.Allowed() {
		t.Fatal("decision should be allow after approval")
	}
}

func TestManualApproverTimeoutDenies(t *testing.T) {
	approver := NewManualApprover(30 * time.Millisecond)
	d, err := approver.Decide(context.Background(), Input{Server: "server-a", Tool: "transfer"})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if d.Allowed() {
		t.Fatal("a timed-out review must deny")
	}
}

func waitPending(t *testing.T, m *ManualApprover) string {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if p := m.Pending(); len(p) > 0 {
			return p[0].ID
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("no pending review appeared")
	return ""
}
