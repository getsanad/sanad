package delegation

import (
	"context"
	"testing"
	"time"

	"github.com/getsanad/sanad/gateway"
	"github.com/getsanad/sanad/pkg/types"
)

func staticChain(c Chain, err error) ChainExtractor {
	return func(*gateway.Request) (Chain, bool, error) {
		if err != nil {
			return Chain{}, false, err
		}
		return c, true, nil
	}
}

func TestStageNarrowsScopeAndSetsAgent(t *testing.T) {
	principal := newParty(t, "principal-1")
	a1 := newParty(t, "agent-1")
	keys := registry(principal, a1)

	chain, _ := NewRoot(principal.priv, principal.id, a1.id, Grant{
		Tools: []string{"read"}, NotAfter: time.Now().Add(time.Hour),
	})
	stage := Stage(keys, staticChain(chain, nil))

	req := &gateway.Request{Principal: &types.Principal{ID: "principal-1"}}
	if err := stage.Handle(context.Background(), req); err != nil {
		t.Fatalf("stage: %v", err)
	}
	if len(req.Scope.Tools) != 1 || req.Scope.Tools[0] != "read" {
		t.Fatalf("scope not narrowed to delegated grant: %v", req.Scope.Tools)
	}
	if req.Agent == nil || req.Agent.ID != "agent-1" {
		t.Fatalf("acting agent not set: %+v", req.Agent)
	}
	if req.Delegation == nil || len(req.Delegation.Hops) != 1 {
		t.Fatal("verified chain not recorded on the request")
	}
}

func TestStageNoChainPasses(t *testing.T) {
	stage := Stage(MemKeyRegistry{}, func(*gateway.Request) (Chain, bool, error) {
		return Chain{}, false, nil
	})
	req := &gateway.Request{Principal: &types.Principal{ID: "principal-1"}}
	if err := stage.Handle(context.Background(), req); err != nil {
		t.Fatalf("absent delegation should pass: %v", err)
	}
	if req.Delegation != nil {
		t.Fatal("no delegation should have been recorded")
	}
}

// TestStageRequireChainMissingFailsClosed covers the opt-in hole: with delegation optional
// a delegate can omit its chain and be minted a passport with NO scope — unconstrained,
// hence wider than the chain it holds. WithRequireChain must reject that.
func TestStageRequireChainMissingFailsClosed(t *testing.T) {
	noChain := func(*gateway.Request) (Chain, bool, error) { return Chain{}, false, nil }
	req := &gateway.Request{Principal: &types.Principal{ID: "principal-1"}}
	if err := Stage(MemKeyRegistry{}, noChain, WithRequireChain()).Handle(context.Background(), req); err == nil {
		t.Fatal("a missing chain must fail closed in require mode")
	}
	if req.Scope.Tools != nil || req.Delegation != nil {
		t.Fatalf("a rejected request must carry no scope or delegation: %+v", req)
	}
}

func TestStageRequireChainAcceptsPresentChain(t *testing.T) {
	principal := newParty(t, "principal-1")
	a1 := newParty(t, "agent-1")
	keys := registry(principal, a1)

	chain, _ := NewRoot(principal.priv, principal.id, a1.id, Grant{Tools: []string{"read"}})
	req := &gateway.Request{Principal: &types.Principal{ID: "principal-1"}}
	if err := Stage(keys, staticChain(chain, nil), WithRequireChain()).Handle(context.Background(), req); err != nil {
		t.Fatalf("a valid chain must still pass in require mode: %v", err)
	}
	if len(req.Scope.Tools) != 1 || req.Scope.Tools[0] != "read" {
		t.Fatalf("scope not narrowed to delegated grant: %v", req.Scope.Tools)
	}
}

// TestStageEnforcesGrantServers covers the gap the Servers constraint had: it was signed,
// carried and attenuation-checked, but never compared to the server being called, so a
// chain scoped to one server authorized every other one.
func TestStageEnforcesGrantServers(t *testing.T) {
	principal := newParty(t, "principal-1")
	a1 := newParty(t, "agent-1")
	keys := registry(principal, a1)

	chain, _ := NewRoot(principal.priv, principal.id, a1.id, Grant{
		Tools: []string{"read"}, Servers: []string{"readonly-reports"},
	})
	stage := Stage(keys, staticChain(chain, nil))

	denied := &gateway.Request{Principal: &types.Principal{ID: "principal-1"}, Server: "payments"}
	if err := stage.Handle(context.Background(), denied); err == nil {
		t.Fatal("a chain granting readonly-reports must not authorize payments")
	}
	if denied.Scope.Tools != nil || denied.Delegation != nil {
		t.Fatalf("a rejected request must carry no scope or delegation: %+v", denied)
	}

	allowed := &gateway.Request{Principal: &types.Principal{ID: "principal-1"}, Server: "readonly-reports"}
	if err := stage.Handle(context.Background(), allowed); err != nil {
		t.Fatalf("the granted server must be allowed: %v", err)
	}
	if len(allowed.Scope.Tools) != 1 || allowed.Scope.Tools[0] != "read" {
		t.Fatalf("scope not narrowed to delegated grant: %v", allowed.Scope.Tools)
	}
}

// TestStageChecksResolvedTarget: Target is the server the gateway will actually proxy to,
// so it is what the grant is checked against.
func TestStageChecksResolvedTarget(t *testing.T) {
	principal := newParty(t, "principal-1")
	a1 := newParty(t, "agent-1")
	keys := registry(principal, a1)

	chain, _ := NewRoot(principal.priv, principal.id, a1.id, Grant{Servers: []string{"reports"}})
	stage := Stage(keys, staticChain(chain, nil))

	req := &gateway.Request{
		Principal: &types.Principal{ID: "principal-1"},
		Server:    "reports",
		Target:    &gateway.Server{ID: "payments"},
	}
	if err := stage.Handle(context.Background(), req); err == nil {
		t.Fatal("the resolved target, not the requested id, must be checked against the grant")
	}
}

// TestStageServerConstraintNeedsATarget: a request with no target at all cannot satisfy a
// server-limited grant, so it fails closed rather than passing unchecked.
func TestStageServerConstraintNeedsATarget(t *testing.T) {
	principal := newParty(t, "principal-1")
	a1 := newParty(t, "agent-1")
	keys := registry(principal, a1)

	chain, _ := NewRoot(principal.priv, principal.id, a1.id, Grant{Servers: []string{"reports"}})
	req := &gateway.Request{Principal: &types.Principal{ID: "principal-1"}}
	if err := Stage(keys, staticChain(chain, nil)).Handle(context.Background(), req); err == nil {
		t.Fatal("a server-limited grant with no request target must fail closed")
	}
}

// TestStageServerWildcardSemantics pins the two halves of the wildcard question to what
// attenuation already treats as broader: an EMPTY list is the wildcard, and "*" is not — it
// is an ordinary server id there, so it stays an ordinary server id here.
func TestStageServerWildcardSemantics(t *testing.T) {
	principal := newParty(t, "principal-1")
	a1 := newParty(t, "agent-1")
	keys := registry(principal, a1)

	tests := []struct {
		name    string
		servers []string
		target  string
		wantErr bool
	}{
		{"empty list is any server", nil, "payments", false},
		{"listed server allowed", []string{"reports", "payments"}, "payments", false},
		{"unlisted server denied", []string{"reports"}, "payments", true},
		{"star is literal, not a wildcard", []string{"*"}, "payments", true},
		{"star matches only a server named *", []string{"*"}, "*", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			chain, _ := NewRoot(principal.priv, principal.id, a1.id, Grant{Servers: tc.servers})
			req := &gateway.Request{Principal: &types.Principal{ID: "principal-1"}, Server: tc.target}
			err := Stage(keys, staticChain(chain, nil)).Handle(context.Background(), req)
			if tc.wantErr && err == nil {
				t.Fatalf("servers %v at %q should be denied", tc.servers, tc.target)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("servers %v at %q should be allowed: %v", tc.servers, tc.target, err)
			}
		})
	}
}

// TestStageEnforcesAttenuatedServers: the effective (last-hop) grant is what binds, so a
// sub-agent may only reach the server its own hop kept.
func TestStageEnforcesAttenuatedServers(t *testing.T) {
	principal := newParty(t, "principal-1")
	a1 := newParty(t, "agent-1")
	a2 := newParty(t, "agent-2")
	keys := registry(principal, a1, a2)

	chain := buildChain(t, []party{principal, a1, a2}, []Grant{
		{Servers: []string{"reports", "payments"}},
		{Servers: []string{"reports"}},
	})
	stage := Stage(keys, staticChain(chain, nil))

	req := &gateway.Request{Principal: &types.Principal{ID: "principal-1"}, Server: "payments"}
	if err := stage.Handle(context.Background(), req); err == nil {
		t.Fatal("a sub-agent must not reach a server its own hop gave up")
	}
	ok := &gateway.Request{Principal: &types.Principal{ID: "principal-1"}, Server: "reports"}
	if err := stage.Handle(context.Background(), ok); err != nil {
		t.Fatalf("the retained server must still be reachable: %v", err)
	}
}

func TestStageInvalidChainFailsClosed(t *testing.T) {
	principal := newParty(t, "principal-1")
	a1 := newParty(t, "agent-1")
	keys := registry(principal, a1)

	chain, _ := NewRoot(principal.priv, principal.id, a1.id, Grant{Tools: []string{"read"}})
	chain.Hops[0].Signature[0] ^= 0x01 // tamper
	stage := Stage(keys, staticChain(chain, nil))

	req := &gateway.Request{Principal: &types.Principal{ID: "principal-1"}}
	if err := stage.Handle(context.Background(), req); err == nil {
		t.Fatal("an invalid chain must fail closed")
	}
}
