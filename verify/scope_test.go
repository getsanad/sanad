package verify

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/getsanad/sanad/pkg/passport"
	"github.com/getsanad/sanad/pkg/types"
)

// scoped mints a passport for server-a carrying the given tool scope and delegation.
func scoped(t *testing.T, tools []string, chain *types.DelegationChain) (string, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := types.Passport{
		ID: "j1", PrincipalID: "p1", AgentID: "a1", Audience: "server-a",
		Scope:      types.Scope{Tools: tools},
		Delegation: chain,
		IssuedAt:   time.Now(), ExpiresAt: time.Now().Add(time.Minute),
	}
	tok, err := passport.Sign(priv, "kid-1", passport.ToClaims(p, "sanad"))
	if err != nil {
		t.Fatal(err)
	}
	return tok, pub
}

// toolsCall is a real MCP streamable-HTTP tools/call body: the tool is params.name.
func toolsCall(name string) string {
	return `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + name + `","arguments":{}}}`
}

// serve runs one POST through a middleware-protected handler and reports the status, the
// body the handler saw, and whether it ran at all.
func serve(t *testing.T, tok string, pub ed25519.PublicKey, body string, opts ...Option) (int, string, bool) {
	t.Helper()
	var reached bool
	var seen string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		b, _ := io.ReadAll(r.Body)
		seen = string(b)
	})
	h := Middleware(New(StaticKeys{"kid-1": pub}), "server-a", next, opts...)

	r := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec.Code, seen, reached
}

// TestEnforceScopeRejectsOutsideAcceptsInside is the headline: "task-scoped" has to mean
// something at the point of use. A passport scoped to read must not be able to delete.
func TestEnforceScopeRejectsOutsideAcceptsInside(t *testing.T) {
	tok, pub := scoped(t, []string{"read", "list"}, nil)

	t.Run("inside the scope is served", func(t *testing.T) {
		code, seen, reached := serve(t, tok, pub, toolsCall("read"), EnforceScope())
		if code != http.StatusOK || !reached {
			t.Fatalf("got %d reached=%v, want 200 served", code, reached)
		}
		// The body must reach the handler intact: the middleware read it to find the tool.
		if seen != toolsCall("read") {
			t.Fatalf("handler saw %q, want the request body", seen)
		}
	})

	t.Run("outside the scope is refused", func(t *testing.T) {
		code, _, reached := serve(t, tok, pub, toolsCall("delete"), EnforceScope())
		if code != http.StatusForbidden {
			t.Fatalf("got %d, want 403 for a tool outside the scope", code)
		}
		if reached {
			t.Fatal("an out-of-scope call must never reach the handler")
		}
	})

	t.Run("without EnforceScope nothing checks", func(t *testing.T) {
		// The prior behavior, kept as the default so existing embeddings do not change
		// meaning silently: authentication is enforced, authorization is the server's job.
		code, _, reached := serve(t, tok, pub, toolsCall("delete"))
		if code != http.StatusOK || !reached {
			t.Fatalf("got %d reached=%v, want the unenforced default to serve", code, reached)
		}
	})
}

// TestEnforceScopeChecksEveryBatchElement: a batch is executed as a unit, so one permitted
// element must not carry a forbidden one through — the confused-deputy shape the passport
// exists to prevent.
func TestEnforceScopeChecksEveryBatchElement(t *testing.T) {
	tok, pub := scoped(t, []string{"read"}, nil)
	batch := `[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}},` +
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"admin_delete"}}]`

	code, _, reached := serve(t, tok, pub, batch, EnforceScope())
	if code != http.StatusForbidden {
		t.Fatalf("got %d, want 403: the second element is outside the scope", code)
	}
	if reached {
		t.Fatal("a batch containing an out-of-scope call must not reach the handler")
	}
}

// TestEnforceScopeIgnoresProtocolMethods: the MCP handshake and tools/list name no tool, so
// a scope of ["read"] must still be able to open a session and list what it may call.
func TestEnforceScopeIgnoresProtocolMethods(t *testing.T) {
	tok, pub := scoped(t, []string{"read"}, nil)
	for _, body := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
	} {
		code, _, reached := serve(t, tok, pub, body, EnforceScope())
		if code != http.StatusOK || !reached {
			t.Fatalf("%s: got %d reached=%v, want 200 (no tool to check)", body, code, reached)
		}
	}
}

// TestEnforceScopeRefusesUncheckableBodies: a message that says it is invoking a tool but
// does not name one cannot be scope-checked, so it is refused rather than served unchecked.
// A body that is simply not JSON-RPC names no tool and is passed through — it cannot invent
// one, so admitting it bypasses nothing.
func TestEnforceScopeRefusesUncheckableBodies(t *testing.T) {
	tok, pub := scoped(t, []string{"read"}, nil)
	cases := []struct {
		name string
		body string
		want int
	}{
		{"tools/call with no name", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}`, http.StatusBadRequest},
		{"not JSON-RPC at all", `{"query":"select 1"}`, http.StatusOK},
		{"not JSON at all", `hello`, http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, _, _ := serve(t, tok, pub, tc.body, EnforceScope())
			if code != tc.want {
				t.Fatalf("got %d, want %d", code, tc.want)
			}
		})
	}
}

// TestEnforceScopeBoundsTheBody: the middleware buffers before it has authorized anything,
// so an unbounded read would be a memory DoS on the resource server.
func TestEnforceScopeBoundsTheBody(t *testing.T) {
	tok, pub := scoped(t, []string{"read"}, nil)
	big := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read","arguments":{"blob":"` +
		strings.Repeat("A", 4096) + `"}}}`

	code, _, reached := serve(t, tok, pub, big, EnforceScope(), WithMaxRequestBody(256))
	if code != http.StatusRequestEntityTooLarge {
		t.Fatalf("got %d, want 413", code)
	}
	if reached {
		t.Fatal("an oversize body must not reach the handler")
	}
}

// TestEmptyScopeIsTheUnconstrainedWildcard pins the semantics to the rest of the system —
// delegation's subset() and policy's granted() both read an empty set as "unconstrained" —
// and pins the security consequence that follows, so it is a decision on the record rather
// than an accident: an unscoped passport is accepted for ANY tool.
func TestEmptyScopeIsTheUnconstrainedWildcard(t *testing.T) {
	for _, tools := range [][]string{nil, {}} {
		tok, pub := scoped(t, tools, nil)

		code, _, reached := serve(t, tok, pub, toolsCall("anything_at_all"), EnforceScope())
		if code != http.StatusOK || !reached {
			t.Fatalf("empty scope: got %d reached=%v; an empty set is the wildcard here, as it is "+
				"in delegation.subset and policy.granted", code, reached)
		}

		// RequireScopedPassport is the opt-out for a server that will not serve on unbounded
		// authority no matter who signed the passport.
		code, _, reached = serve(t, tok, pub, toolsCall("anything_at_all"), EnforceScope(), RequireScopedPassport())
		if code != http.StatusForbidden {
			t.Fatalf("RequireScopedPassport: got %d, want 403 for a passport with no scope", code)
		}
		if reached {
			t.Fatal("RequireScopedPassport must refuse before the handler runs")
		}
	}
}

// TestRequireScopeInAHandler covers the one-line form for a server that has already worked
// out which tool it is about to run.
func TestRequireScopeInAHandler(t *testing.T) {
	tok, pub := scoped(t, []string{"read"}, nil)

	var readErr, deleteErr error
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		readErr = RequireScope(r.Context(), "read")
		deleteErr = RequireScope(r.Context(), "delete")
	})
	h := Middleware(New(StaticKeys{"kid-1": pub}), "server-a", next)
	r := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(toolsCall("read")))
	r.Header.Set("Authorization", "Bearer "+tok)
	h.ServeHTTP(httptest.NewRecorder(), r)

	if readErr != nil {
		t.Fatalf("RequireScope(read) = %v, want nil", readErr)
	}
	if !errors.Is(deleteErr, ErrOutOfScope) {
		t.Fatalf("RequireScope(delete) = %v, want ErrOutOfScope", deleteErr)
	}

	// Outside the middleware there is no verified passport, so the answer is a refusal
	// rather than a pass — a scope check that silently succeeds is worse than none.
	if err := RequireScope(t.Context(), "read"); !errors.Is(err, ErrNoPassport) {
		t.Fatalf("RequireScope with no passport = %v, want ErrNoPassport", err)
	}
}

// TestDelegationReachesTheResourceServer is the other half of the fix: the MCP server can
// now see who delegated what to whom, which before lived only in the gateway's audit log.
func TestDelegationReachesTheResourceServer(t *testing.T) {
	chain := &types.DelegationChain{Hops: []types.DelegationHop{
		{Delegator: "p1", Delegate: "agent-x", Scope: types.Scope{Tools: []string{"read", "write"}}, Signature: []byte("s1")},
		{Delegator: "agent-x", Delegate: "a1", Scope: types.Scope{Tools: []string{"read"}}, Signature: []byte("s2")},
	}}
	tok, pub := scoped(t, []string{"read"}, chain)

	p, err := New(StaticKeys{"kid-1": pub}).Verify(tok, "server-a")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	path, ok := DelegationPath(p)
	if !ok {
		t.Fatal("no delegation path on the verified passport: accountability stops at the gateway")
	}
	if strings.Join(path, " -> ") != "p1 -> agent-x -> a1" {
		t.Fatalf("path = %v, want p1 -> agent-x -> a1", path)
	}
	// And an auditor holding the real chain can prove this passport belongs to it.
	if !chain.Matches(p.DelegationRef) {
		t.Fatal("the passport does not commit to the chain it was minted from")
	}

	// A passport with no delegation says so, rather than presenting an empty path.
	plain, plainPub := scoped(t, []string{"read"}, nil)
	q, err := New(StaticKeys{"kid-1": plainPub}).Verify(plain, "server-a")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if _, ok := DelegationPath(q); ok {
		t.Fatal("a passport with no chain must not report a delegation path")
	}
}
