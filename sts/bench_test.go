package sts

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/getsanad/sanad/gateway"
	"github.com/getsanad/sanad/pkg/types"
)

func BenchmarkIssue(b *testing.B) {
	signer, _ := NewLocalSigner("kid-1")
	iss := New(signer, Config{Issuer: "sanad"})
	req := IssueRequest{
		Principal: &types.Principal{ID: "principal-1"},
		Agent:     &types.Agent{ID: "agent-1"},
		Audience:  "server-a",
		Scope:     types.Scope{Tools: []string{"read"}},
	}
	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := iss.Issue(ctx, req); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkGatewayMintProxy measures a full gateway request through the hot path that we
// control: identity (stubbed) -> mint passport + token isolation -> reverse-proxy to a
// local upstream. It excludes IdP OIDC verification (benchmarked separately in principal).
func BenchmarkGatewayMintProxy(b *testing.B) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer upstream.Close()

	signer, _ := NewLocalSigner("kid-1")
	issuer := New(signer, Config{Issuer: "sanad"})
	reg := gateway.NewRegistry()
	u, _ := url.Parse(upstream.URL)
	_ = reg.Register(&gateway.Server{ID: "demo", Upstream: u})

	principal := gateway.NewStage("principal", func(ctx context.Context, req *gateway.Request) error {
		req.Principal = &types.Principal{ID: "p1"}
		req.Agent = &types.Agent{ID: "a1"}
		return nil
	})
	g := &gateway.Gateway{Registry: reg, Pipeline: gateway.Pipeline{Stages: []gateway.Stage{principal, MintStage(issuer)}}}

	b.ReportAllocs()
	for b.Loop() {
		rec := httptest.NewRecorder()
		g.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/servers/demo/tools/list", nil))
		if rec.Code != http.StatusOK {
			b.Fatalf("status %d", rec.Code)
		}
	}
}
