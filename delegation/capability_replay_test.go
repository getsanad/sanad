package delegation

// Replay tests for the capability holder proof. The same flaw was here in full: the proof was
// a signature over the bare principal token, so it was one fixed value for that token's
// lifetime, and it travels in X-Agent-Capability-Proof right next to the X-Agent-Capability
// it unlocks. Anyone who saw one request's headers could wield the capability — which is
// exactly the property VerifyHolder exists to deny.

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/getsanad/sanad/gateway"
	"github.com/getsanad/sanad/internal/pop"
	"github.com/getsanad/sanad/pkg/types"
)

// capStageRequest builds a gateway request presenting capHdr and proofHdr verbatim, with the
// body already buffered the way the gateway buffers it.
func capStageRequest(method, target, body, capHdr, proofHdr string) *gateway.Request {
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, target, nil)
	} else {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	}
	r.Header.Set("Authorization", "Bearer "+capTestToken)
	r.Header.Set(HeaderCapability, capHdr)
	r.Header.Set(HeaderCapabilityProof, proofHdr)
	req := &gateway.Request{HTTP: r, Principal: &types.Principal{ID: "principal-1"}}
	if body != "" {
		req.Body = []byte(body)
	}
	return req
}

func signHolder(t *testing.T, secret ed25519.PrivateKey, method, target, body string) string {
	t.Helper()
	r := httptest.NewRequest(method, target, nil)
	p, err := HolderProof(secret, method, ProofTarget(r.URL), capTestToken, []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// A captured holder proof is worthless on any other request.
func TestCapturedHolderProofIsUselessOnADifferentRequest(t *testing.T) {
	rootPub, rootPriv := rootKeys(t)
	cap, s0, _ := NewCapability(rootPriv, Grant{Tools: []string{"read"}})
	capHdr, _ := EncodeCapability(cap)

	const path = "/servers/demo/mcp"
	const body = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}}`
	captured := signHolder(t, s0, http.MethodPost, path, body)

	cases := []struct{ name, method, target, body string }{
		{"different method", http.MethodGet, path, ""},
		{"different path", http.MethodPost, "/servers/demo/other", body},
		{"different body", http.MethodPost, path, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete"}}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stage := CapabilityStage(rootPub, WithRequireChain())
			req := capStageRequest(c.method, c.target, c.body, capHdr, captured)
			if err := stage.Handle(context.Background(), req); err == nil {
				t.Fatal("a captured holder proof was accepted on a different request")
			}
			if req.Scope.Tools != nil {
				t.Fatalf("a rejected request must carry no scope: %v", req.Scope.Tools)
			}
		})
	}
}

// The identical request, replayed: caught by the replay cache and nothing else.
func TestHolderProofIdenticalReplayIsRejected(t *testing.T) {
	rootPub, rootPriv := rootKeys(t)
	cap, s0, _ := NewCapability(rootPriv, Grant{Tools: []string{"read"}})
	capHdr, _ := EncodeCapability(cap)

	const path = "/servers/demo/mcp"
	const body = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}}`
	proof := signHolder(t, s0, http.MethodPost, path, body)

	// One stage, i.e. one replay cache, as a running gateway has.
	stage := CapabilityStage(rootPub, WithRequireChain())
	if err := stage.Handle(context.Background(), capStageRequest(http.MethodPost, path, body, capHdr, proof)); err != nil {
		t.Fatalf("first presentation must be accepted: %v", err)
	}
	if err := stage.Handle(context.Background(), capStageRequest(http.MethodPost, path, body, capHdr, proof)); err == nil {
		t.Fatal("an identical replayed holder proof was accepted twice")
	}
}

func TestHolderProofOutsideTheWindowIsRejected(t *testing.T) {
	rootPub, rootPriv := rootKeys(t)
	cap, s0, _ := NewCapability(rootPriv, Grant{Tools: []string{"read"}})
	capHdr, _ := EncodeCapability(cap)

	now := time.Now()
	stage := CapabilityStage(rootPub, WithRequireChain(),
		WithHolderProofClock(func() time.Time { return now }))

	proof := signHolder(t, s0, http.MethodGet, "/servers/demo/tools/list", "")
	now = now.Add(pop.DefaultMaxAge + time.Second)
	if err := stage.Handle(context.Background(),
		capStageRequest(http.MethodGet, "/servers/demo/tools/list", "", capHdr, proof)); err == nil {
		t.Fatal("a holder proof older than the max age was accepted")
	}
}

// The cap holds at the stage: past it, requests are refused rather than an existing live jti
// being evicted to make room.
func TestHolderProofReplayCacheIsBounded(t *testing.T) {
	const max = 4
	rootPub, rootPriv := rootKeys(t)
	cap, s0, _ := NewCapability(rootPriv, Grant{Tools: []string{"read"}})
	capHdr, _ := EncodeCapability(cap)

	stage := CapabilityStage(rootPub, WithRequireChain(), WithHolderProofCacheEntries(max))
	accepted := 0
	for i := 0; i < 4*max; i++ {
		proof := signHolder(t, s0, http.MethodGet, "/servers/demo/tools/list", "")
		if err := stage.Handle(context.Background(),
			capStageRequest(http.MethodGet, "/servers/demo/tools/list", "", capHdr, proof)); err == nil {
			accepted++
		}
	}
	if accepted != max {
		t.Fatalf("%d requests accepted, want %d (the cache cap)", accepted, max)
	}
}

// Two proofs for the identical request must differ; a repeatable proof is a bearer token.
func TestHolderProofIsNotDeterministic(t *testing.T) {
	_, rootPriv := rootKeys(t)
	_, s0, _ := NewCapability(rootPriv, Grant{Tools: []string{"read"}})
	a := signHolder(t, s0, http.MethodGet, "/servers/demo/tools/list", "")
	b := signHolder(t, s0, http.MethodGet, "/servers/demo/tools/list", "")
	if a == b {
		t.Fatal("two holder proofs for one request must differ")
	}
}
