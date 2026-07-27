package gateway

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u
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
	// Empty pipeline = allow; identity stages arrive in later issues.
	g := &Gateway{Registry: reg}

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
