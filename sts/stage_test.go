package sts

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/getsanad/sanad/gateway"
	"github.com/getsanad/sanad/pkg/passport"
	"github.com/getsanad/sanad/pkg/types"
)

// TestMintStageTokenIsolation proves FR-8 end-to-end through the gateway: the caller's
// inbound token never reaches the upstream MCP server, which instead receives a valid,
// audience-bound passport.
func TestMintStageTokenIsolation(t *testing.T) {
	var gotAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	signer, err := NewLocalSigner("kid-1")
	if err != nil {
		t.Fatal(err)
	}
	issuer := New(signer, Config{Issuer: "sanad"})

	reg := gateway.NewRegistry()
	u, _ := url.Parse(upstream.URL)
	if err := reg.Register(&gateway.Server{ID: "demo", Upstream: u}); err != nil {
		t.Fatal(err)
	}

	// Stand-in for the principal-auth stage (the real one is P1-03).
	principalStage := gateway.NewStage("principal", func(ctx context.Context, req *gateway.Request) error {
		req.Principal = &types.Principal{ID: "principal-1"}
		req.Agent = &types.Agent{ID: "agent-1"}
		return nil
	})

	g := &gateway.Gateway{
		Registry: reg,
		Pipeline: gateway.Pipeline{Stages: []gateway.Stage{principalStage, MintStage(issuer)}},
	}

	r := httptest.NewRequest(http.MethodGet, "/servers/demo/tools/list", nil)
	r.Header.Set("Authorization", "Bearer INBOUND-CALLER-TOKEN") // must NOT be forwarded
	rec := httptest.NewRecorder()
	g.ServeHTTP(rec, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", rec.Code)
	}
	if gotAuth == "Bearer INBOUND-CALLER-TOKEN" {
		t.Fatal("inbound caller token leaked to upstream (FR-8 violation)")
	}

	const prefix = "Bearer "
	if len(gotAuth) <= len(prefix) {
		t.Fatalf("upstream did not receive a passport bearer token: %q", gotAuth)
	}
	tok := gotAuth[len(prefix):]
	if _, err := passport.Verify(signer.Public(), tok, "demo", time.Now()); err != nil {
		t.Fatalf("forwarded passport invalid or not audience-bound to demo: %v", err)
	}
}

// TestMintStageFailsClosedWithoutPrincipal ensures the mint stage denies (errors) when no
// principal was established, which the gateway turns into a fail-closed 403.
func TestMintStageFailsClosedWithoutPrincipal(t *testing.T) {
	signer, _ := NewLocalSigner("kid-1")
	stage := MintStage(New(signer, Config{Issuer: "sanad"}))
	if err := stage.Handle(context.Background(), &gateway.Request{Server: "demo"}); err == nil {
		t.Fatal("mint must fail closed when there is no authenticated principal")
	}
}
