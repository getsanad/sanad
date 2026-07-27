package admin

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/getsanad/sanad/gateway"
	"github.com/getsanad/sanad/revoke"
)

func TestRegisterBlueprintAndInstantiate(t *testing.T) {
	svc := NewService(gateway.NewRegistry(), revoke.NewMemStore())
	ctx := context.Background()
	if err := svc.RegisterPrincipal(ctx, principal("p1")); err != nil {
		t.Fatal(err)
	}

	// Blueprint must reference a known principal.
	if err := svc.RegisterBlueprint(ctx, Blueprint{ID: "bp1", PrincipalID: "ghost"}); err == nil {
		t.Fatal("blueprint under unknown principal must be rejected")
	}
	if err := svc.RegisterBlueprint(ctx, Blueprint{ID: "bp1", PrincipalID: "p1", Tools: []string{"read"}}); err != nil {
		t.Fatalf("register blueprint: %v", err)
	}

	// Instances inherit the blueprint's principal.
	a, err := svc.InstantiateAgent(ctx, "bp1", "a1")
	if err != nil {
		t.Fatalf("instantiate: %v", err)
	}
	if a.PrincipalID != "p1" || a.BlueprintID != "bp1" {
		t.Fatalf("instance did not inherit governance: %+v", a)
	}

	if _, err := svc.InstantiateAgent(ctx, "ghost-bp", "a2"); err == nil {
		t.Fatal("instantiating from an unknown blueprint must be rejected")
	}
}

// TestRevokeBlueprintCascades confirms revoking a blueprint disables + kill-switches all
// of its instances (FR-3), without touching unrelated agents.
func TestRevokeBlueprintCascades(t *testing.T) {
	kill := revoke.NewMemStore()
	svc := NewService(gateway.NewRegistry(), kill)
	ctx := context.Background()
	_ = svc.RegisterPrincipal(ctx, principal("p1"))
	_ = svc.RegisterBlueprint(ctx, Blueprint{ID: "bp1", PrincipalID: "p1"})
	_, _ = svc.InstantiateAgent(ctx, "bp1", "a1")
	_, _ = svc.InstantiateAgent(ctx, "bp1", "a2")
	// An unrelated agent (no blueprint).
	_ = svc.RegisterAgent(ctx, agent("solo", "p1"))

	if err := svc.Revoke(ctx, "bp1"); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"a1", "a2"} {
		if !kill.Revoked(id) {
			t.Fatalf("instance %s should be revoked when its blueprint is", id)
		}
	}
	// "solo" has no blueprint, so revoking bp1 must not touch it.
	if kill.Revoked("solo") {
		t.Fatal("an agent with no blueprint must not be caught by a blueprint revocation")
	}
}

func TestBlueprintHTTP(t *testing.T) {
	svc := NewService(gateway.NewRegistry(), revoke.NewMemStore())
	_ = svc.RegisterPrincipal(context.Background(), principal("p1"))
	h := NewHandler(svc, adminToken)

	if rec := do(t, h, http.MethodPost, "/admin/blueprints", adminToken, `{"id":"bp1","principalId":"p1","tools":["read"]}`); rec.Code != http.StatusCreated {
		t.Fatalf("register blueprint: %d (%s)", rec.Code, rec.Body)
	}
	if rec := do(t, h, http.MethodPost, "/admin/agents/instantiate", adminToken, `{"blueprintId":"bp1","agentId":"a1"}`); rec.Code != http.StatusCreated {
		t.Fatalf("instantiate: %d (%s)", rec.Code, rec.Body)
	}
	rec := do(t, h, http.MethodGet, "/admin/agents", adminToken, "")
	if !strings.Contains(rec.Body.String(), `"bp1"`) {
		t.Fatalf("instantiated agent should reference its blueprint: %s", rec.Body)
	}
}
