package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/getsanad/sanad/gateway"
	"github.com/getsanad/sanad/revoke"
)

const adminToken = "secret"

func newHarness(t *testing.T) (http.Handler, *gateway.Registry, *revoke.MemStore) {
	t.Helper()
	reg := gateway.NewRegistry()
	kill := revoke.NewMemStore()
	return NewHandler(NewService(reg, kill), adminToken), reg, kill
}

func do(t *testing.T, h http.Handler, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func TestAuthRequired(t *testing.T) {
	h, _, _ := newHarness(t)
	if rec := do(t, h, http.MethodGet, "/admin/principals", "", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: got %d, want 401", rec.Code)
	}
	if rec := do(t, h, http.MethodGet, "/admin/principals", "wrong", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad token: got %d, want 401", rec.Code)
	}
}

func TestRegisterPrincipalAndAgent(t *testing.T) {
	h, _, _ := newHarness(t)

	if rec := do(t, h, http.MethodPost, "/admin/principals", adminToken, `{"id":"p1","subject":"u@example.com","assurance":"org"}`); rec.Code != http.StatusCreated {
		t.Fatalf("register principal: %d (%s)", rec.Code, rec.Body)
	}
	// Agent referencing a missing principal is rejected.
	if rec := do(t, h, http.MethodPost, "/admin/agents", adminToken, `{"id":"a1","principalId":"ghost"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("agent w/ unknown principal: got %d, want 400", rec.Code)
	}
	// Agent referencing a real principal succeeds.
	if rec := do(t, h, http.MethodPost, "/admin/agents", adminToken, `{"id":"a1","principalId":"p1"}`); rec.Code != http.StatusCreated {
		t.Fatalf("register agent: %d (%s)", rec.Code, rec.Body)
	}

	rec := do(t, h, http.MethodGet, "/admin/agents", adminToken, "")
	if !strings.Contains(rec.Body.String(), `"a1"`) {
		t.Fatalf("agent listing missing a1: %s", rec.Body)
	}
}

func TestRegisterServer(t *testing.T) {
	h, reg, _ := newHarness(t)
	if rec := do(t, h, http.MethodPost, "/admin/servers", adminToken, `{"id":"demo","upstream":"http://localhost:9000"}`); rec.Code != http.StatusCreated {
		t.Fatalf("register server: %d (%s)", rec.Code, rec.Body)
	}
	if _, ok := reg.Lookup("demo"); !ok {
		t.Fatal("server not registered in gateway registry")
	}
}

func TestRevokeRestore(t *testing.T) {
	h, _, kill := newHarness(t)

	if rec := do(t, h, http.MethodPost, "/admin/revoke", adminToken, `{"id":"p1"}`); rec.Code != http.StatusOK {
		t.Fatalf("revoke: %d", rec.Code)
	}
	if !kill.Revoked("p1") {
		t.Fatal("p1 should be on the kill-switch")
	}
	rec := do(t, h, http.MethodGet, "/admin/revocations", adminToken, "")
	if !strings.Contains(rec.Body.String(), `"p1"`) {
		t.Fatalf("revocations listing missing p1: %s", rec.Body)
	}

	if rec := do(t, h, http.MethodPost, "/admin/restore", adminToken, `{"id":"p1"}`); rec.Code != http.StatusOK {
		t.Fatalf("restore: %d", rec.Code)
	}
	if kill.Revoked("p1") {
		t.Fatal("p1 should be restored")
	}
}
