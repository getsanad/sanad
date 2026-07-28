package workload_test

// The replay tests for the instance proof of possession, driven through the REAL gateway
// handler rather than the stage in isolation — the binding covers the buffered body, which
// only exists once the gateway has read it, so a stage-level test would be checking a
// different thing from what production does.
//
// The scenario throughout is the one that made the old proof worthless: an observer with a
// copy of one request's headers. A TLS-terminating load balancer, an access log with header
// capture, the upstream MCP server, a sidecar, or anyone on the plaintext hop.

import (
	"context"
	"crypto/ed25519"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/getsanad/sanad/gateway"
	"github.com/getsanad/sanad/internal/pop"
	"github.com/getsanad/sanad/internal/sigctx"
	"github.com/getsanad/sanad/pkg/types"
	"github.com/getsanad/sanad/sts"
	"github.com/getsanad/sanad/workload"
)

const replayToken = "principal-bearer-token"

// replayFixture stands up a gateway whose only identity stage is the instance stage, plus an
// upstream that records whether it was ever reached. Reaching the upstream is the thing a
// replay is trying to achieve, so "denied" is asserted on that and not only on the status.
type replayFixture struct {
	gw        *gateway.Gateway
	agentKey  ed25519.PrivateKey
	credHdr   string
	reached   *int
	upstreamC func()
}

func newReplayFixture(t *testing.T, opts ...workload.ProofOption) *replayFixture {
	t.Helper()
	caPub, caPriv := key(t)
	att := workload.NewTokenAttestor()
	att.Register("boot", "agent-1")
	authority, err := workload.NewAuthority(caPriv, "ca-1", att, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	agentPub, agentPriv := key(t)
	nonce, err := authority.Nonce()
	if err != nil {
		t.Fatal(err)
	}
	cred, err := authority.Issue(workload.BootstrapEvidence("boot", nonce, agentPub), nonce, agentPub)
	if err != nil {
		t.Fatal(err)
	}
	credHdr, err := workload.EncodeCredential(cred)
	if err != nil {
		t.Fatal(err)
	}

	reached := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached++
		_, _ = io.WriteString(w, "ok")
	}))
	reg := gateway.NewRegistry()
	u, _ := url.Parse(upstream.URL)
	if err := reg.Register(&gateway.Server{ID: "demo", Upstream: u}); err != nil {
		t.Fatal(err)
	}
	signer, _ := sts.NewLocalSigner("kid-gw")
	stubPrincipal := gateway.NewStage("principal", func(_ context.Context, req *gateway.Request) error {
		req.Principal = &types.Principal{ID: "principal-1"}
		return nil
	})
	g := &gateway.Gateway{Registry: reg, Pipeline: gateway.Pipeline{Stages: []gateway.Stage{
		stubPrincipal,
		workload.InstanceStage(caPub, workload.NewKeyStore(caPub), opts...),
		sts.MintStage(sts.New(signer, sts.Config{Issuer: "sanad"})),
	}}}
	return &replayFixture{gw: g, agentKey: agentPriv, credHdr: credHdr, reached: &reached, upstreamC: upstream.Close}
}

// request builds an authenticated request. proof is the exact X-Agent-Proof to present, so a
// test can hand it a captured one.
func (f *replayFixture) request(method, target, body, proof string) *http.Request {
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, target, nil)
	} else {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	}
	r.Header.Set("Authorization", "Bearer "+replayToken)
	r.Header.Set(workload.HeaderCredential, f.credHdr)
	r.Header.Set(workload.HeaderProof, proof)
	return r
}

// sign builds an honest proof for a method/target/body.
func (f *replayFixture) sign(t *testing.T, method, target, body string) string {
	t.Helper()
	u, err := url.ParseRequestURI(target)
	if err != nil {
		t.Fatal(err)
	}
	p, err := workload.Proof(f.agentKey, method, workload.ProofTarget(u), replayToken, []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func (f *replayFixture) send(r *http.Request) int {
	rec := httptest.NewRecorder()
	f.gw.ServeHTTP(rec, r)
	return rec.Code
}

// The honest path still works: an agent that builds a fresh proof per request is served.
func TestInstanceProofHonestPath(t *testing.T) {
	f := newReplayFixture(t)
	defer f.upstreamC()

	const body = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}}`
	for i := 0; i < 3; i++ {
		code := f.send(f.request(http.MethodPost, "/servers/demo/mcp", body, f.sign(t, http.MethodPost, "/servers/demo/mcp", body)))
		if code != http.StatusOK {
			t.Fatalf("request %d: got %d, want 200", i, code)
		}
	}
	if *f.reached != 3 {
		t.Fatalf("upstream reached %d times, want 3", *f.reached)
	}
}

// The headline case: one captured header bundle, replayed against a different method, path,
// query and body. Every one of those is inside the binding, so every one is refused.
func TestCapturedProofIsUselessOnADifferentRequest(t *testing.T) {
	f := newReplayFixture(t)
	defer f.upstreamC()

	const path = "/servers/demo/mcp"
	const body = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}}`
	captured := f.sign(t, http.MethodPost, path, body)

	cases := []struct{ name, method, target, body string }{
		{"different method", http.MethodGet, path, ""},
		{"different path", http.MethodPost, "/servers/demo/other", body},
		{"query appended", http.MethodPost, path + "?tool=delete", body},
		{"different tool in the body", http.MethodPost, path, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete"}}`},
		{"body stripped", http.MethodPost, path, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			before := *f.reached
			if code := f.send(f.request(c.method, c.target, c.body, captured)); code == http.StatusOK {
				t.Fatal("a captured proof was accepted on a different request")
			}
			if *f.reached != before {
				t.Fatal("a denied request reached the upstream")
			}
		})
	}

	// And the capture is still no good on its own request either, because the jti is spent
	// the first time it is served (below) — here it was never served, so prove it would have
	// been: the binding itself is satisfied.
	if code := f.send(f.request(http.MethodPost, path, body, captured)); code != http.StatusOK {
		t.Fatalf("the captured proof must be valid for the request it was made for, got %d", code)
	}
}

// The same request, replayed byte-for-byte. Nothing in the binding can catch this — the
// binding matches, that is what "the same request" means — so this is the replay cache alone.
func TestIdenticalRequestReplayedIsRejected(t *testing.T) {
	f := newReplayFixture(t)
	defer f.upstreamC()

	const body = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}}`
	proof := f.sign(t, http.MethodPost, "/servers/demo/mcp", body)

	if code := f.send(f.request(http.MethodPost, "/servers/demo/mcp", body, proof)); code != http.StatusOK {
		t.Fatalf("first call: got %d, want 200", code)
	}
	if code := f.send(f.request(http.MethodPost, "/servers/demo/mcp", body, proof)); code == http.StatusOK {
		t.Fatal("an identical replayed request was served twice")
	}
	if *f.reached != 1 {
		t.Fatalf("upstream reached %d times, want 1", *f.reached)
	}
}

// A proof kept and presented later is refused once it falls out of the freshness window,
// which is what bounds how long a capture is worth anything at all.
func TestProofOutsideTheClockSkewWindowIsRejected(t *testing.T) {
	// The verifier's clock is moved instead of the proof's iat, so this exercises the same
	// code path a real stale capture takes.
	now := time.Now()
	f := newReplayFixture(t, workload.WithProofClock(func() time.Time { return now }))
	defer f.upstreamC()

	proof := f.sign(t, http.MethodGet, "/servers/demo/tools/list", "")
	fresh := f.request(http.MethodGet, "/servers/demo/tools/list", "", proof)

	now = now.Add(pop.DefaultMaxAge + time.Second)
	if code := f.send(fresh); code == http.StatusOK {
		t.Fatal("a proof older than the max age was accepted")
	}

	// And the other side of the window: a client whose clock runs further ahead than the skew
	// allowance is refused too, so future-dating cannot buy a longer replay window.
	ahead, err := pop.NewBinding(http.MethodGet, "/servers/demo/tools/list", replayToken, nil,
		now.Add(pop.DefaultSkew+time.Second))
	if err != nil {
		t.Fatal(err)
	}
	hdr, err := pop.Sign(sigctx.InstanceProof, f.agentKey, ahead)
	if err != nil {
		t.Fatal(err)
	}
	if code := f.send(f.request(http.MethodGet, "/servers/demo/tools/list", "", hdr)); code == http.StatusOK {
		t.Fatal("a proof dated past the skew allowance was accepted")
	}
	if *f.reached != 0 {
		t.Fatalf("upstream reached %d times, want 0", *f.reached)
	}
}

// The bound on the cache, at the stage: a gateway configured with a tiny cache refuses rather
// than evicting, and the cache never exceeds its cap.
func TestInstanceProofReplayCacheIsBounded(t *testing.T) {
	const max = 4
	f := newReplayFixture(t, workload.WithProofCacheEntries(max))
	defer f.upstreamC()

	served, denied := 0, 0
	for i := 0; i < 4*max; i++ {
		proof := f.sign(t, http.MethodGet, "/servers/demo/tools/list", "")
		if f.send(f.request(http.MethodGet, "/servers/demo/tools/list", "", proof)) == http.StatusOK {
			served++
		} else {
			denied++
		}
	}
	// Exactly `max` distinct proofs fit; the rest are refused, not silently made room for by
	// evicting somebody else's still-live jti.
	if served != max {
		t.Fatalf("%d requests served, want %d (the cache cap)", served, max)
	}
	if denied != 3*max {
		t.Fatalf("%d requests denied, want %d", denied, 3*max)
	}
}

// The proof is bound to the request it names, and Proof produces exactly that. This is what
// ties the interop vectors (built from a fixed Binding) to the function the SDKs mirror.
func TestProofIsBoundToTheRequest(t *testing.T) {
	_, priv := key(t)
	const body = `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	hdr, err := workload.Proof(priv, http.MethodPost, "/servers/demo/mcp", replayToken, []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	payload, _, ok := strings.Cut(hdr, ".")
	if !ok {
		t.Fatalf("proof is not payload.signature: %q", hdr)
	}

	// Ed25519 is deterministic, so before this change two proofs for the same token were the
	// same bytes. They must not be now, even for the identical request: the jti differs.
	again, err := workload.Proof(priv, http.MethodPost, "/servers/demo/mcp", replayToken, []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if again == hdr {
		t.Fatal("two proofs for the same request must differ: a repeatable proof is a bearer token")
	}
	if p2, _, _ := strings.Cut(again, "."); p2 == payload {
		t.Fatal("two proofs for the same request must carry different jtis")
	}
}
