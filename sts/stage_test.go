package sts

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/getsanad/sanad/gateway"
	"github.com/getsanad/sanad/pkg/passport"
	"github.com/getsanad/sanad/pkg/types"
)

// mintGateway wires a gateway whose pipeline is a stand-in principal stage (the real one is
// P1-03) followed by the mint stage under test, proxying to upstream.
func mintGateway(t *testing.T, upstreamURL string, opts ...StageOption) (*gateway.Gateway, *LocalSigner) {
	t.Helper()
	signer, err := NewLocalSigner("kid-1")
	if err != nil {
		t.Fatal(err)
	}
	reg := gateway.NewRegistry()
	u, err := url.Parse(upstreamURL)
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Register(&gateway.Server{ID: "demo", Upstream: u}); err != nil {
		t.Fatal(err)
	}
	principalStage := gateway.NewStage("principal", func(ctx context.Context, req *gateway.Request) error {
		req.Principal = &types.Principal{ID: "principal-1"}
		req.Agent = &types.Agent{ID: "agent-1"}
		return nil
	})
	mint := MintStage(New(signer, Config{Issuer: "sanad"}), opts...)
	return &gateway.Gateway{
		Registry: reg,
		Pipeline: gateway.Pipeline{Stages: []gateway.Stage{principalStage, mint}},
	}, signer
}

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

	g, signer := mintGateway(t, upstream.URL)

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

// TestMintStageForwardsOnlyAllowlistedHeaders proves token isolation is an allowlist rather
// than a two-name denylist (FR-8). A protected MCP server is semi-trusted, so it must not be
// handed the caller's session cookie, an arbitrary API key, or the agent's own workload
// credential / proof-of-possession / delegation chain — while everything the MCP transport
// actually needs, plus an operator-configured extra, still arrives.
func TestMintStageForwardsOnlyAllowlistedHeaders(t *testing.T) {
	var got http.Header
	var gotLen int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, gotLen = r.Header.Clone(), r.ContentLength
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	// "X-Tenant" stands in for the operator's PASSPORT_FORWARD_HEADERS entry.
	g, signer := mintGateway(t, upstream.URL, WithForwardHeaders("X-Tenant"))

	const body = `{"jsonrpc":"2.0","method":"tools/list"}`
	r := httptest.NewRequest(http.MethodPost, "/servers/demo/mcp", strings.NewReader(body))
	for name, v := range map[string]string{
		// Caller credentials — none of these may reach the upstream.
		"Authorization":       "Bearer INBOUND-CALLER-TOKEN",
		"Proxy-Authorization": "Basic SECRET",
		"Cookie":              "session=SECRET",
		"X-Api-Key":           "SECRET-KEY",
		"X-Agent-Credential":  "SECRET-CREDENTIAL",
		"X-Agent-Proof":       "SECRET-PROOF",
		"X-Agent-Delegation":  "SECRET-CHAIN",
		// Transport headers the proxied MCP request needs.
		"Accept":               "application/json, text/event-stream",
		"Content-Type":         "application/json",
		"Accept-Encoding":      "identity",
		"User-Agent":           "mcp-client/1.0",
		"Mcp-Session-Id":       "1868a90c",
		"MCP-Protocol-Version": "2025-06-18",
		"Last-Event-ID":        "42",
		"X-Tenant":             "acme",
	} {
		r.Header.Set(name, v)
	}
	rec := httptest.NewRecorder()
	g.ServeHTTP(rec, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", rec.Code)
	}
	for _, name := range []string{
		"Proxy-Authorization", "Cookie", "X-Api-Key",
		"X-Agent-Credential", "X-Agent-Proof", "X-Agent-Delegation",
	} {
		if v := got.Get(name); v != "" {
			t.Errorf("%s reached the upstream as %q (FR-8 violation)", name, v)
		}
	}
	for name, want := range map[string]string{
		"Accept":               "application/json, text/event-stream",
		"Content-Type":         "application/json",
		"Accept-Encoding":      "identity",
		"User-Agent":           "mcp-client/1.0",
		"Mcp-Session-Id":       "1868a90c",
		"MCP-Protocol-Version": "2025-06-18",
		"Last-Event-ID":        "42",
		"X-Tenant":             "acme",
	} {
		if v := got.Get(name); v != want {
			t.Errorf("upstream %s = %q, want %q", name, v, want)
		}
	}
	// Content-Length is not forwarded from the header map; net/http regenerates the framing
	// from the request body, so the upstream still reads a correctly delimited request.
	if gotLen != int64(len(body)) {
		t.Errorf("upstream ContentLength = %d, want %d", gotLen, len(body))
	}

	// And the one credential it does get is the minted, audience-bound passport.
	tok, ok := strings.CutPrefix(got.Get("Authorization"), "Bearer ")
	if !ok || tok == "" {
		t.Fatalf("upstream did not receive a passport bearer token: %q", got.Get("Authorization"))
	}
	if tok == "INBOUND-CALLER-TOKEN" {
		t.Fatal("inbound caller token leaked to upstream (FR-8 violation)")
	}
	if _, err := passport.Verify(signer.Public(), tok, "demo", time.Now()); err != nil {
		t.Fatalf("forwarded passport invalid or not audience-bound to demo: %v", err)
	}
}

// TestMintStageKeepsSSEStreaming guards the streaming path against the header filtering:
// Accept and Accept-Encoding must survive, so the upstream still opens an SSE stream and
// events reach the caller as they are flushed rather than at end of response.
func TestMintStageKeepsSSEStreaming(t *testing.T) {
	var once sync.Once
	released := make(chan struct{})
	release := func() { once.Do(func() { close(released) }) }

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Accept"); !strings.Contains(got, "text/event-stream") {
			t.Errorf("upstream Accept = %q, want it to still ask for an SSE stream", got)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		<-released // held open: the caller must already have the first event
		_, _ = io.WriteString(w, "data: second\n\n")
	}))
	defer upstream.Close()

	g, _ := mintGateway(t, upstream.URL)
	gw := httptest.NewServer(g)
	defer gw.Close()
	defer release() // must run before either server closes (LIFO)

	req, err := http.NewRequest(http.MethodGet, gw.URL+"/servers/demo/mcp", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept", "text/event-stream")
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	br := bufio.NewReader(resp.Body)
	if line, err := br.ReadString('\n'); err != nil || line != "data: first\n" {
		t.Fatalf("first event not flushed through the gateway: %q, %v", line, err)
	}
	release()
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("second event never arrived: %v", err)
		}
		if line == "data: second\n" {
			return
		}
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
