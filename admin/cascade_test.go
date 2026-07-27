package admin

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/getsanad/sanad/audit"
	"github.com/getsanad/sanad/gateway"
	"github.com/getsanad/sanad/pkg/types"
	"github.com/getsanad/sanad/revoke"
)

func principal(id string) types.Principal { return types.Principal{ID: id} }
func agent(id, principalID string) types.Agent {
	return types.Agent{ID: id, PrincipalID: principalID}
}

func TestRegisterServerRejectsEmptyUpstream(t *testing.T) {
	svc := NewService(gateway.NewRegistry(), revoke.NewMemStore())
	if err := svc.RegisterServer("demo", ""); err == nil {
		t.Fatal("empty upstream URL must be rejected")
	}
	if _, ok := gateway.NewRegistry().Lookup("demo"); ok {
		t.Fatal("nothing should have been registered")
	}
}

func TestRevokePrincipalCascades(t *testing.T) {
	kill := revoke.NewMemStore()
	svc := NewService(gateway.NewRegistry(), kill)
	ctx := context.Background()

	mustRegister(t, svc, "p1", "a1", "a2")
	// An agent under a different principal must NOT be caught by the cascade.
	if err := svc.RegisterPrincipal(ctx, principal("p2")); err != nil {
		t.Fatal(err)
	}
	if err := svc.RegisterAgent(ctx, agent("a3", "p2")); err != nil {
		t.Fatal(err)
	}

	if err := svc.Revoke(ctx, "p1"); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	for _, id := range []string{"p1", "a1", "a2"} {
		if !kill.Revoked(id) {
			t.Fatalf("%s should be on the kill-switch after cascade", id)
		}
	}
	if kill.Revoked("a3") {
		t.Fatal("a3 (different principal) must NOT be cascaded")
	}
}

func TestInvestigateEndpoint(t *testing.T) {
	log := audit.NewHashChainLog(nil)
	_ = log.Append(context.Background(), audit.Entry{
		Action: "allow", Principal: "p1", Agent: "a1", Server: "payments", PassportID: "pp-9",
	})

	svc := NewService(gateway.NewRegistry(), revoke.NewMemStore(), WithAuditLog(log))
	h := NewHandler(svc, adminToken)

	rec := do(t, h, http.MethodGet, "/admin/investigate?passport=pp-9", adminToken, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("investigate: %d (%s)", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), `"principal":"p1"`) {
		t.Fatalf("report missing principal: %s", rec.Body)
	}

	if rec := do(t, h, http.MethodGet, "/admin/investigate?passport=nope", adminToken, ""); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown passport: got %d, want 404", rec.Code)
	}
}

func TestInvestigateRouteAbsentWithoutAudit(t *testing.T) {
	svc := NewService(gateway.NewRegistry(), revoke.NewMemStore())
	h := NewHandler(svc, adminToken)
	// No audit log wired: the route is not registered, so the mux returns 404.
	if rec := do(t, h, http.MethodGet, "/admin/investigate?passport=x", adminToken, ""); rec.Code != http.StatusNotFound {
		t.Fatalf("expected route absent (404), got %d", rec.Code)
	}
}

func mustRegister(t *testing.T, svc *Service, principalID string, agentIDs ...string) {
	t.Helper()
	ctx := context.Background()
	if err := svc.RegisterPrincipal(ctx, principal(principalID)); err != nil {
		t.Fatal(err)
	}
	for _, a := range agentIDs {
		if err := svc.RegisterAgent(ctx, agent(a, principalID)); err != nil {
			t.Fatal(err)
		}
	}
}
