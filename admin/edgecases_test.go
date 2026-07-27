package admin

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/getsanad/sanad/audit"
	"github.com/getsanad/sanad/gateway"
	"github.com/getsanad/sanad/revoke"
)

// --- auth: open when token is empty -------------------------------------------------

func TestOpenWhenTokenEmpty(t *testing.T) {
	h := NewHandler(NewService(gateway.NewRegistry(), revoke.NewMemStore()), "")
	// No Authorization header, but token=="" means the guard is disabled.
	if rec := do(t, h, http.MethodGet, "/admin/principals", "", ""); rec.Code != http.StatusOK {
		t.Fatalf("open mode (token=\"\") should allow unauthenticated access, got %d", rec.Code)
	}
}

func TestAuthAcceptsCorrectTokenRejectsBad(t *testing.T) {
	h, _, _ := newHarness(t)
	if rec := do(t, h, http.MethodGet, "/admin/principals", adminToken, ""); rec.Code != http.StatusOK {
		t.Fatalf("correct token should be accepted, got %d", rec.Code)
	}
	if rec := do(t, h, http.MethodGet, "/admin/principals", "nope", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token should be 401, got %d", rec.Code)
	}
}

// --- register principal: missing fields ---------------------------------------------

func TestRegisterPrincipalMissingID(t *testing.T) {
	h, _, _ := newHarness(t)
	if rec := do(t, h, http.MethodPost, "/admin/principals", adminToken, `{"subject":"u@example.com"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("principal without id should be 400, got %d (%s)", rec.Code, rec.Body)
	}
}

// --- register agent: missing fields / unknown principal -----------------------------

func TestRegisterAgentMissingFields(t *testing.T) {
	h, _, _ := newHarness(t)
	tests := []struct {
		name string
		body string
	}{
		{"missing id", `{"principalId":"p1"}`},
		{"missing principal", `{"id":"a1"}`},
		{"empty body object", `{}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if rec := do(t, h, http.MethodPost, "/admin/agents", adminToken, tc.body); rec.Code != http.StatusBadRequest {
				t.Fatalf("%s should be 400, got %d (%s)", tc.name, rec.Code, rec.Body)
			}
		})
	}
}

func TestRegisterAgentUnknownPrincipal(t *testing.T) {
	h, _, _ := newHarness(t)
	if rec := do(t, h, http.MethodPost, "/admin/agents", adminToken, `{"id":"a1","principalId":"ghost"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("agent referencing unknown principal should be 400, got %d", rec.Code)
	}
}

// --- register server: bad upstream URL ----------------------------------------------

func TestRegisterServerBadUpstream(t *testing.T) {
	h, reg, _ := newHarness(t)
	// "://bad" has no scheme and makes url.Parse return an error -> RegisterServer 400.
	if rec := do(t, h, http.MethodPost, "/admin/servers", adminToken, `{"id":"demo","upstream":"://bad"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad upstream URL should be 400, got %d (%s)", rec.Code, rec.Body)
	}
	if _, ok := reg.Lookup("demo"); ok {
		t.Fatal("a server with a bad upstream must not be registered")
	}
}

func TestRegisterServerMissingID(t *testing.T) {
	h, _, _ := newHarness(t)
	if rec := do(t, h, http.MethodPost, "/admin/servers", adminToken, `{"upstream":"http://localhost:9000"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("server without id should be 400, got %d", rec.Code)
	}
}

// --- malformed JSON -> 400 ----------------------------------------------------------

func TestMalformedJSONBodies(t *testing.T) {
	h, _, _ := newHarness(t)
	for _, path := range []string{"/admin/principals", "/admin/agents", "/admin/servers", "/admin/revoke", "/admin/restore"} {
		path := path
		t.Run(path, func(t *testing.T) {
			if rec := do(t, h, http.MethodPost, path, adminToken, `{not json`); rec.Code != http.StatusBadRequest {
				t.Fatalf("malformed JSON to %s should be 400, got %d", path, rec.Code)
			}
		})
	}
}

// --- duplicate registration overwrites ----------------------------------------------

func TestDuplicatePrincipalOverwrites(t *testing.T) {
	svc := NewService(gateway.NewRegistry(), revoke.NewMemStore())
	ctx := context.Background()
	mustRegister(t, svc, "p1")
	// Re-register the same id with a different subject; the record is overwritten.
	if err := svc.RegisterPrincipal(ctx, principal("p1")); err != nil {
		t.Fatalf("re-register: %v", err)
	}
	if got := svc.Principals(); len(got) != 1 {
		t.Fatalf("duplicate registration should not add a second record, got %d", len(got))
	}
}

func TestDuplicateAgentOverwrites(t *testing.T) {
	svc := NewService(gateway.NewRegistry(), revoke.NewMemStore())
	mustRegister(t, svc, "p1", "a1")
	if err := svc.RegisterAgent(context.Background(), agent("a1", "p1")); err != nil {
		t.Fatalf("re-register agent: %v", err)
	}
	if got := svc.Agents(); len(got) != 1 {
		t.Fatalf("duplicate agent registration should overwrite, got %d", len(got))
	}
}

// --- revoke: agent-only does not touch principal or siblings ------------------------

func TestRevokeAgentOnly(t *testing.T) {
	kill := revoke.NewMemStore()
	svc := NewService(gateway.NewRegistry(), kill)
	ctx := context.Background()
	mustRegister(t, svc, "p1", "a1", "a2")

	if err := svc.Revoke(ctx, "a1"); err != nil {
		t.Fatalf("revoke agent: %v", err)
	}
	if !kill.Revoked("a1") {
		t.Fatal("a1 should be revoked")
	}
	if kill.Revoked("p1") {
		t.Fatal("revoking an agent must not revoke its principal")
	}
	if kill.Revoked("a2") {
		t.Fatal("revoking an agent must not revoke a sibling agent")
	}
	// The agent record should be marked disabled.
	for _, a := range svc.Agents() {
		if a.ID == "a1" && !a.Disabled {
			t.Fatal("revoked agent should be marked Disabled")
		}
		if a.ID == "a2" && a.Disabled {
			t.Fatal("sibling agent must not be disabled")
		}
	}
}

func TestRevokePrincipalDisablesRecords(t *testing.T) {
	kill := revoke.NewMemStore()
	svc := NewService(gateway.NewRegistry(), kill)
	ctx := context.Background()
	mustRegister(t, svc, "p1", "a1")

	if err := svc.Revoke(ctx, "p1"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	for _, p := range svc.Principals() {
		if p.ID == "p1" && !p.Disabled {
			t.Fatal("revoked principal should be marked Disabled")
		}
	}
	for _, a := range svc.Agents() {
		if a.ID == "a1" && !a.Disabled {
			t.Fatal("cascaded agent should be marked Disabled")
		}
	}
}

func TestRevokeEmptyIDErrors(t *testing.T) {
	svc := NewService(gateway.NewRegistry(), revoke.NewMemStore())
	if err := svc.Revoke(context.Background(), ""); err == nil {
		t.Fatal("revoking an empty id must error")
	}
}

// --- restore clears the kill-switch and disabled flag -------------------------------

func TestRestoreClearsDisabledFlag(t *testing.T) {
	kill := revoke.NewMemStore()
	svc := NewService(gateway.NewRegistry(), kill)
	ctx := context.Background()
	mustRegister(t, svc, "p1", "a1")

	if err := svc.Revoke(ctx, "p1"); err != nil {
		t.Fatal(err)
	}
	if err := svc.Restore("p1"); err != nil {
		t.Fatalf("restore: %v", err)
	}

	if kill.Revoked("p1") {
		t.Fatal("p1 should be off the kill-switch after restore")
	}
	for _, p := range svc.Principals() {
		if p.ID == "p1" && p.Disabled {
			t.Fatal("restored principal should not be Disabled")
		}
	}
	// Restoring a principal now reverses the cascade: its agents come back too.
	if kill.Revoked("a1") {
		t.Fatal("cascaded agent a1 should be off the kill-switch after restoring the principal")
	}
	for _, a := range svc.Agents() {
		if a.ID == "a1" && a.Disabled {
			t.Fatal("cascaded agent a1 should be re-enabled after restore")
		}
	}
}

// --- revocations listing ------------------------------------------------------------

func TestRevocationsListing(t *testing.T) {
	h, _, _ := newHarness(t)
	if rec := do(t, h, http.MethodPost, "/admin/revoke", adminToken, `{"id":"x1"}`); rec.Code != http.StatusOK {
		t.Fatalf("revoke: %d", rec.Code)
	}
	rec := do(t, h, http.MethodGet, "/admin/revocations", adminToken, "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"x1"`) {
		t.Fatalf("revocations listing missing x1: %d %s", rec.Code, rec.Body)
	}
}

// --- investigate route: 404 for unknown passport when audit IS present --------------

func TestInvestigateUnknownPassport404WithAudit(t *testing.T) {
	// Distinct from the route-absent case: the route exists (audit wired) but the
	// passport id is unknown -> 404 from Investigate's error path.
	svc := NewService(gateway.NewRegistry(), revoke.NewMemStore(), WithAuditLog(audit.NewHashChainLog(nil)))
	h := NewHandler(svc, adminToken)
	if rec := do(t, h, http.MethodGet, "/admin/investigate?passport=missing", adminToken, ""); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown passport with audit present should be 404, got %d", rec.Code)
	}
}
