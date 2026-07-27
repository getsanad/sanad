package gateway

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/getsanad/sanad/pkg/types"
)

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u
}

// stubMint stands in for the real mint stage (sts.MintStage, which cannot be imported
// here without a cycle). Forwarding requires a minted passport, so any test that expects
// the upstream to be reached needs this stage in its pipeline.
func stubMint() Stage {
	return NewStage("mint", func(ctx context.Context, r *Request) error {
		r.Passport = &types.Passport{ID: "passport-1", Audience: r.Server}
		return nil
	})
}

func TestPipelineRunsInOrderAndStopsOnError(t *testing.T) {
	var calls []string
	p := Pipeline{Stages: []Stage{
		NewStage("a", func(ctx context.Context, r *Request) error { calls = append(calls, "a"); return nil }),
		NewStage("b", func(ctx context.Context, r *Request) error { calls = append(calls, "b"); return errors.New("boom") }),
		NewStage("c", func(ctx context.Context, r *Request) error { calls = append(calls, "c"); return nil }),
	}}

	if err := p.Run(context.Background(), &Request{}); err == nil {
		t.Fatal("expected error from stage b")
	}
	if len(calls) != 2 || calls[0] != "a" || calls[1] != "b" {
		t.Fatalf("stages ran %v; want [a b] (c must not run after an error)", calls)
	}
}

func TestUnknownServerFailsClosed(t *testing.T) {
	g := &Gateway{Registry: NewRegistry()}
	rec := httptest.NewRecorder()
	g.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/servers/ghost/tools/list", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown server: got %d, want 404", rec.Code)
	}
}

func TestPipelineFailureFailsClosed(t *testing.T) {
	upstreamHit := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHit = true
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	reg := NewRegistry()
	if err := reg.Register(&Server{ID: "demo", Upstream: mustURL(t, upstream.URL)}); err != nil {
		t.Fatal(err)
	}
	g := &Gateway{
		Registry: reg,
		Pipeline: Pipeline{Stages: []Stage{
			NewStage("deny", func(ctx context.Context, r *Request) error { return errors.New("policy denied") }),
		}},
	}

	rec := httptest.NewRecorder()
	g.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/servers/demo/tools/list", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("pipeline failure: got %d, want 403", rec.Code)
	}
	if upstreamHit {
		t.Fatal("upstream must not be contacted when the pipeline fails (fail-closed)")
	}
}

// TestNoPassportMintedFailsClosed pins the structural invariant: a pipeline that runs
// clean but mints nothing — an empty one being the worst case — must never turn the
// gateway into an open reverse proxy (NFR-3, FR-8).
func TestNoPassportMintedFailsClosed(t *testing.T) {
	upstreamHits := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits++
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	reg := NewRegistry()
	if err := reg.Register(&Server{ID: "demo", Upstream: mustURL(t, upstream.URL)}); err != nil {
		t.Fatal(err)
	}

	pipelines := map[string]Pipeline{
		"empty": {},
		"stages that never mint": {Stages: []Stage{
			NewStage("noop", func(ctx context.Context, r *Request) error { return nil }),
		}},
	}
	for name, p := range pipelines {
		t.Run(name, func(t *testing.T) {
			var reason string
			var allowed bool
			g := &Gateway{
				Registry: reg,
				Pipeline: p,
				Audit:    func(_ *Request, a bool, rs string) { allowed, reason = a, rs },
			}

			rec := httptest.NewRecorder()
			g.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/servers/demo/tools/list", nil))

			if rec.Code != http.StatusForbidden {
				t.Fatalf("got %d, want 403", rec.Code)
			}
			if allowed || reason == "" {
				t.Fatalf("denial must be audited, got allowed=%v reason=%q", allowed, reason)
			}
		})
	}
	if upstreamHits != 0 {
		t.Fatalf("upstream contacted %d times; it must never be reached without a passport", upstreamHits)
	}
}

func TestProxiesToUpstreamWithStrippedPath(t *testing.T) {
	var gotPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = io.WriteString(w, "pong")
	}))
	defer upstream.Close()

	reg := NewRegistry()
	if err := reg.Register(&Server{ID: "demo", Upstream: mustURL(t, upstream.URL)}); err != nil {
		t.Fatal(err)
	}
	g := &Gateway{Registry: reg, Pipeline: Pipeline{Stages: []Stage{stubMint()}}}

	rec := httptest.NewRecorder()
	g.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/servers/demo/tools/list", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("proxy: got %d, want 200", rec.Code)
	}
	if rec.Body.String() != "pong" {
		t.Fatalf("proxy body = %q, want pong", rec.Body.String())
	}
	if gotPath != "/tools/list" {
		t.Fatalf("upstream saw path %q, want /tools/list (prefix must be stripped)", gotPath)
	}
}

func TestHealthAndReady(t *testing.T) {
	g := &Gateway{Registry: NewRegistry()}
	for _, path := range []string{"/healthz", "/readyz"} {
		rec := httptest.NewRecorder()
		g.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: got %d, want 200", path, rec.Code)
		}
	}
}
