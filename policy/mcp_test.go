package policy

import (
	"context"
	"slices"
	"testing"

	"github.com/getsanad/sanad/gateway"
	"github.com/getsanad/sanad/pkg/types"
)

// batchReq is an authenticated request carrying the JSON-RPC calls the gateway parsed out of
// an MCP body, optionally already narrowed by the delegation stage.
func batchReq(scope types.Scope, calls ...gateway.RPCCall) *gateway.Request {
	req := authedReq("server-a")
	req.Calls = calls
	req.Scope = scope
	return req
}

func call(tool string) gateway.RPCCall { return gateway.RPCCall{Method: "tools/call", Tool: tool} }
func method(m string) gateway.RPCCall  { return gateway.RPCCall{Method: m} }
func notify(m string) gateway.RPCCall  { return gateway.RPCCall{Method: m, Notification: true} }

func TestMCPToolsProjectsOneEntryPerCall(t *testing.T) {
	tests := []struct {
		name string
		req  *gateway.Request
		want []string
	}{
		{"no calls at all", authedReq("server-a"), nil},
		{"single tools/call", batchReq(types.Scope{}, call("read")), []string{"read"}},
		{
			// One entry per ELEMENT, empties included: the protocol methods still need a
			// decision, they just do not name a tool.
			name: "batch keeps position and arity",
			req:  batchReq(types.Scope{}, method("initialize"), call("read"), notify("notifications/initialized"), call("write")),
			want: []string{"", "read", "", "write"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := MCPTools(tc.req); !slices.Equal(got, tc.want) {
				t.Fatalf("MCPTools = %v, want %v", got, tc.want)
			}
		})
	}
	if got := MCPTools(nil); got != nil {
		t.Fatalf("MCPTools(nil) = %v, want nil", got)
	}
}

// TestStageDecidesEveryBatchElement: the PDP must be asked about each element, in order, and
// about repeats too — a stateful PDP (budget, rate limit) counts invocations, not tool names.
func TestStageDecidesEveryBatchElement(t *testing.T) {
	var asked []string
	pdp := Func(func(_ context.Context, in Input) (types.Decision, error) {
		asked = append(asked, in.Tool)
		return types.Decision{Effect: types.EffectAllow, Reason: "ok"}, nil
	})
	req := batchReq(types.Scope{}, method("initialize"), call("read"), call("read"), call("write"))

	if err := Stage(pdp, MCPTools, nil).Handle(context.Background(), req); err != nil {
		t.Fatalf("stage: %v", err)
	}
	if want := []string{"", "read", "read", "write"}; !slices.Equal(asked, want) {
		t.Fatalf("PDP saw %v, want one decision per element %v", asked, want)
	}
	// The scope minted from those decisions is the set of tools, without the empties.
	if !slices.Equal(req.Scope.Tools, []string{"read", "write"}) {
		t.Fatalf("granted scope = %v, want [read write]", req.Scope.Tools)
	}
}

// TestStageDeniesWholeBatchIfAnyElementDenied is the property that makes batching safe: the
// gateway forwards a batch as one upstream POST, so a permitted element must never carry a
// forbidden one through with it. In particular the FIRST element does not decide the batch.
func TestStageDeniesWholeBatchIfAnyElementDenied(t *testing.T) {
	al := NewAllowList().Allow("server-a", "read")

	tests := []struct {
		name  string
		calls []gateway.RPCCall
	}{
		{"forbidden element last", []gateway.RPCCall{call("read"), call("admin_delete")}},
		{"forbidden element first", []gateway.RPCCall{call("admin_delete"), call("read")}},
		{"forbidden element in the middle", []gateway.RPCCall{call("read"), call("admin_delete"), call("read")}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := batchReq(types.Scope{}, tc.calls...)
			if err := Stage(al, MCPTools, nil).Handle(context.Background(), req); err == nil {
				t.Fatal("a batch containing a denied element must be denied whole")
			}
			if req.Decision == nil || req.Decision.Allowed() {
				t.Fatalf("the denial must be recorded for audit, got %+v", req.Decision)
			}
			if len(req.Scope.Tools) != 0 {
				t.Fatalf("a denied batch must not be granted scope, got %v", req.Scope.Tools)
			}
		})
	}

	// The all-allowed batch still passes, so the denial above is the element and not the shape.
	req := batchReq(types.Scope{}, call("read"), call("read"))
	if err := Stage(al, MCPTools, nil).Handle(context.Background(), req); err != nil {
		t.Fatalf("a batch of permitted elements should pass: %v", err)
	}
	if !slices.Equal(req.Scope.Tools, []string{"read"}) {
		t.Fatalf("granted scope = %v, want [read] (a repeat is still one authority)", req.Scope.Tools)
	}
}

// TestStageBatchIsBoundedByTheDelegatedScope: the attenuation floor applies per element too,
// so a batch cannot smuggle a tool the signed chain gave up past an element that is in scope.
func TestStageBatchIsBoundedByTheDelegatedScope(t *testing.T) {
	grant := types.Scope{Tools: []string{"read"}, Budget: &types.Budget{Limit: 10, Unit: "usd"}}

	var consulted bool
	pdp := Func(func(context.Context, Input) (types.Decision, error) {
		consulted = true
		return types.Decision{Effect: types.EffectAllow, Reason: "allow-all"}, nil
	})

	req := batchReq(grant, call("read"), call("write"))
	err := Stage(pdp, MCPTools, nil).Handle(context.Background(), req)
	if err == nil {
		t.Fatal("a batch element outside the delegated scope must be denied")
	}
	if !slices.Equal(req.Scope.Tools, grant.Tools) {
		t.Fatalf("a denied batch must not have its scope rewritten: %v", req.Scope.Tools)
	}
	if !consulted {
		t.Fatal("the in-scope element should still have reached the PDP before the floor stopped the batch")
	}

	// Every element inside the grant: allowed, scope is the intersection, budget survives.
	ok := batchReq(grant, method("tools/list"), call("read"))
	if err := Stage(pdp, MCPTools, nil).Handle(context.Background(), ok); err != nil {
		t.Fatalf("a batch inside the grant should pass: %v", err)
	}
	if !slices.Equal(ok.Scope.Tools, []string{"read"}) {
		t.Fatalf("granted scope = %v, want [read]", ok.Scope.Tools)
	}
	if ok.Scope.Budget != grant.Budget {
		t.Fatalf("delegated budget dropped: %+v", ok.Scope.Budget)
	}
}

// TestStageProtocolMethodsDoNotNarrowScope: initialize / tools/list / notifications name no
// tool, so they are decided once with an empty tool and leave the delegated grant intact —
// otherwise a chain attenuated to ["read"] could never even open an MCP session.
func TestStageProtocolMethodsDoNotNarrowScope(t *testing.T) {
	grant := types.Scope{Tools: []string{"read"}}
	req := batchReq(grant, method("initialize"))

	if err := Stage(allowAny, MCPTools, nil).Handle(context.Background(), req); err != nil {
		t.Fatalf("a protocol method inside a scoped chain must not be denied by attenuation: %v", err)
	}
	if !slices.Equal(req.Scope.Tools, grant.Tools) {
		t.Fatalf("scope = %v, want the delegated grant %v untouched", req.Scope.Tools, grant.Tools)
	}
}

// TestStageEmptyExtractionStillDecidesOnce: an extractor that finds nothing (a GET, a
// non-JSON-RPC POST) must not skip the PDP — a request nobody decided is a request nobody
// authorized.
func TestStageEmptyExtractionStillDecidesOnce(t *testing.T) {
	var calls int
	pdp := Func(func(_ context.Context, in Input) (types.Decision, error) {
		calls++
		if in.Tool != "" {
			t.Errorf("tool = %q, want empty", in.Tool)
		}
		return types.Decision{Effect: types.EffectDeny, Reason: "deny-by-default"}, nil
	})
	empty := ToolExtractor(func(*gateway.Request) []string { return nil })

	if err := Stage(pdp, empty, nil).Handle(context.Background(), authedReq("server-a")); err == nil {
		t.Fatal("deny-by-default must fail closed when no tool was extracted")
	}
	if calls != 1 {
		t.Fatalf("PDP consulted %d times, want exactly 1", calls)
	}
}
