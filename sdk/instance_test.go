package sdk

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/getsanad/sanad/delegation"
	"github.com/getsanad/sanad/gateway"
	"github.com/getsanad/sanad/pkg/types"
	"github.com/getsanad/sanad/sts"
	"github.com/getsanad/sanad/workload"
)

// A Go agent using WithInstance is admitted by a real gateway running the instance stage,
// and the proof it sends is bound to the request it sends — including the body, which the
// SDK has to buffer to hash. This is the Go half of the parity the TypeScript and Python
// SDKs already had.
func TestWithInstanceIsAcceptedByTheGateway(t *testing.T) {
	caPub, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	att := workload.NewTokenAttestor()
	att.Register("boot", "agent-1")
	authority, err := workload.NewAuthority(caPriv, "ca-1", att, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	agentPub, agentPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := authority.Nonce()
	if err != nil {
		t.Fatal(err)
	}
	cred, err := authority.Issue(workload.BootstrapEvidence("boot", nonce, agentPub), nonce, agentPub)
	if err != nil {
		t.Fatal(err)
	}

	var upstreamBody string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		upstreamBody = string(b)
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

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
	g := httptest.NewServer(&gateway.Gateway{Registry: reg, Pipeline: gateway.Pipeline{Stages: []gateway.Stage{
		stubPrincipal,
		workload.InstanceStage(caPub, workload.NewKeyStore(caPub)),
		sts.MintStage(sts.New(signer, sts.Config{Issuer: "sanad"})),
	}}})
	defer g.Close()

	c := New(g.URL, func(context.Context) (string, error) { return "idp-token", nil },
		WithInstance(agentPriv, cred))

	const body = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}}`
	// Twice: each call must mint its own proof. A client that cached one would be denied
	// here by the replay cache, which is the regression this guards.
	for i := 0; i < 2; i++ {
		resp, err := c.Call(context.Background(), "demo", http.MethodPost, "/mcp", strings.NewReader(body))
		if err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("call %d: got %d, want 200", i, resp.StatusCode)
		}
	}
	// Buffering the body to hash it must not cost the upstream the bytes.
	if upstreamBody != body {
		t.Fatalf("upstream received %q, want it forwarded intact: %q", upstreamBody, body)
	}
}

// A malformed configuration surfaces on the call rather than being swallowed by an Option
// that cannot return an error — and in particular it does NOT quietly downgrade to sending
// no proof at all, which would look like a gateway problem rather than a client one.
func TestConfigErrorSurfacesOnCall(t *testing.T) {
	var reached bool
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))
	defer srv.Close()

	c := New(srv.URL, func(context.Context) (string, error) { return "tok", nil },
		WithDelegation(delegation.Chain{}), WithInstance(nil, workload.Credential{}))
	_, err := c.Call(context.Background(), "demo", http.MethodGet, "/x", nil)
	if err == nil || !strings.Contains(err.Error(), "instance key") {
		t.Fatalf("err = %v, want an instance key configuration error", err)
	}
	if reached {
		t.Fatal("a misconfigured client must not send an unproven request")
	}
}
