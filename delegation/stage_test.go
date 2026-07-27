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
