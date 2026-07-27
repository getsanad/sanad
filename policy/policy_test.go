package policy

import (
	"context"
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
