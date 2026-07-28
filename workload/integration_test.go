package workload_test

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
	"github.com/getsanad/sanad/pkg/passport"
	"github.com/getsanad/sanad/pkg/types"
	"github.com/getsanad/sanad/policy"
	"github.com/getsanad/sanad/sts"
	"github.com/getsanad/sanad/workload"
)

func key(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// TestLiveInstanceAndDelegation drives the full P2 vertical through the real gateway:
// principal auth (stubbed) -> instance auth via workload credential + proof of possession
// -> multi-hop delegation verified against the shared KeyStore -> passport minted with the
// narrowed scope + chain -> token isolation -> offline verification at the upstream.
//
// Chain: principal -> agent-1 -> agent-2. The request is made by the agent-2 instance.
// agent-1's key is pre-registered (it authenticated earlier / is in the directory); the
// agent-2 instance authenticates on this request and is registered by the instance stage.
func TestLiveInstanceAndDelegation(t *testing.T) {
	// Workload authority + attestation for agent-2 (the calling instance).
	caPub, caPriv := key(t)
	att := workload.NewTokenAttestor()
	att.Register("boot-2", "agent-2")
	authority, err := workload.NewAuthority(caPriv, "ca-1", att, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	principalPub, principalPriv := key(t)
	a1Pub, a1Priv := key(t)
	a2Pub, a2Priv := key(t)

	// Shared key directory: principal root key + agent-1 (already known) + the CA for
	// verifying the agent-2 credential the instance stage will add.
	store := workload.NewKeyStore(caPub)
	store.AddKey("principal-1", principalPub, time.Time{})
	store.AddKey("agent-1", a1Pub, time.Now().Add(time.Hour))

	// agent-2 obtains its instance credential.
	cred, err := authority.Issue([]byte("boot-2"), a2Pub)
	if err != nil {
		t.Fatal(err)
	}

	// Delegation chain principal -> agent-1 (read,write) -> agent-2 (read).
	root, err := delegation.NewRoot(principalPriv, "principal-1", "agent-1", delegation.Grant{Tools: []string{"read", "write"}})
	if err != nil {
		t.Fatal(err)
	}
	chain, err := root.Extend(a1Priv, "agent-2", delegation.Grant{Tools: []string{"read"}})
	if err != nil {
		t.Fatal(err)
	}

	// Upstream MCP server: capture the forwarded credential and verify it offline.
	signer, _ := sts.NewLocalSigner("kid-gw")
	var forwarded string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded = r.Header.Get("Authorization")
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	reg := gateway.NewRegistry()
	u, _ := url.Parse(upstream.URL)
	if err := reg.Register(&gateway.Server{ID: "demo", Upstream: u}); err != nil {
		t.Fatal(err)
	}

	stubPrincipal := gateway.NewStage("principal", func(_ context.Context, req *gateway.Request) error {
		req.Principal = &types.Principal{ID: "principal-1"}
		return nil
	})
	g := &gateway.Gateway{Registry: reg, Pipeline: gateway.Pipeline{Stages: []gateway.Stage{
		stubPrincipal,
		workload.InstanceStage(caPub, store),
		delegation.Stage(store, delegation.HeaderExtractor(delegation.HeaderDelegation)),
		sts.MintStage(sts.New(signer, sts.Config{Issuer: "sanad"})),
	}}}

	// agent-2 builds the request: principal token + its credential + proof + the chain.
	const principalToken = "principal-bearer-token"
	credHdr, _ := workload.EncodeCredential(cred)
	chainHdr, _ := delegation.EncodeChain(chain)

	r := httptest.NewRequest(http.MethodGet, "/servers/demo/tools/list", nil)
	r.Header.Set("Authorization", "Bearer "+principalToken)
	r.Header.Set(workload.HeaderCredential, credHdr)
	r.Header.Set(workload.HeaderProof, workload.Proof(a2Priv, principalToken))
	r.Header.Set(delegation.HeaderDelegation, chainHdr)

	rec := httptest.NewRecorder()
	g.ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("request denied: %d (%s)", rec.Code, rec.Body)
	}

	// The upstream must receive a passport (not the principal token), bound to demo,
	// scoped to the attenuated grant [read], carrying the 2-hop delegation path.
	const prefix = "Bearer "
	if forwarded == "Bearer "+principalToken || len(forwarded) <= len(prefix) {
		t.Fatalf("token isolation failed or no passport forwarded: %q", forwarded)
	}
	claims, err := passport.Verify(signer.Public(), forwarded[len(prefix):], "demo", time.Now())
	if err != nil {
		t.Fatalf("forwarded passport invalid: %v", err)
	}
	if len(claims.Tools) != 1 || claims.Tools[0] != "read" {
		t.Fatalf("scope not attenuated to [read]: %v", claims.Tools)
	}
}

// TestLiveDelegationBoundsThePolicyStage drives the same vertical over REAL MCP traffic: a
// streamable-HTTP POST whose JSON-RPC body names the tool, the gateway buffering and parsing
// it, and policy.MCPActions handing it to the policy stage (FR-16).
//
// Two things are pinned at once. The policy stage used to ASSIGN types.Scope{Tools: {tool}},
// so wiring a real extractor would have silently replaced the attenuated grant: a chain
// narrowed to [read] would mint a passport for write. And buffering the body to see the tool
// must not cost the upstream the body — an extractor that consumed the reader would forward
// an empty POST and break every MCP call it authorized.
//
// Chain: principal -> agent-1 (read,write) -> agent-2 (read). agent-2 calls, so [read] binds.
func TestLiveDelegationBoundsThePolicyStage(t *testing.T) {
	caPub, caPriv := key(t)
	att := workload.NewTokenAttestor()
	att.Register("boot-2", "agent-2")
	authority, err := workload.NewAuthority(caPriv, "ca-1", att, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	principalPub, principalPriv := key(t)
	a1Pub, a1Priv := key(t)
	a2Pub, a2Priv := key(t)

	store := workload.NewKeyStore(caPub)
	store.AddKey("principal-1", principalPub, time.Time{})
	store.AddKey("agent-1", a1Pub, time.Now().Add(time.Hour))
	cred, err := authority.Issue([]byte("boot-2"), a2Pub)
	if err != nil {
		t.Fatal(err)
	}

	budget := &types.Budget{Limit: 25, Unit: "usd"}
	root, err := delegation.NewRoot(principalPriv, "principal-1", "agent-1", delegation.Grant{
		Tools: []string{"read", "write"}, Budget: budget,
	})
	if err != nil {
		t.Fatal(err)
	}
	chain, err := root.Extend(a1Priv, "agent-2", delegation.Grant{Tools: []string{"read"}, Budget: budget})
	if err != nil {
		t.Fatal(err)
	}

	signer, _ := sts.NewLocalSigner("kid-gw")
	var forwarded string
	var upstreamBody []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded = r.Header.Get("Authorization")
		upstreamBody, _ = io.ReadAll(r.Body)
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	reg := gateway.NewRegistry()
	u, _ := url.Parse(upstream.URL)
	if err := reg.Register(&gateway.Server{ID: "demo", Upstream: u}); err != nil {
		t.Fatal(err)
	}

	// A permissive operator policy: the only thing standing between the caller and the tool
	// it asked for is the delegation chain.
	allowAll := policy.Func(func(_ context.Context, _ policy.Input) (types.Decision, error) {
		return types.Decision{Effect: types.EffectAllow, Reason: "test allow-all"}, nil
	})
	stubPrincipal := gateway.NewStage("principal", func(_ context.Context, req *gateway.Request) error {
		req.Principal = &types.Principal{ID: "principal-1"}
		return nil
	})
	gatewayFor := func() *gateway.Gateway {
		return &gateway.Gateway{Registry: reg, Pipeline: gateway.Pipeline{Stages: []gateway.Stage{
			stubPrincipal,
			workload.InstanceStage(caPub, store),
			delegation.Stage(store, delegation.HeaderExtractor(delegation.HeaderDelegation)),
			policy.Stage(allowAll, policy.MCPActions, nil),
			sts.MintStage(sts.New(signer, sts.Config{Issuer: "sanad"})),
		}}}
	}

	const principalToken = "principal-bearer-token"
	credHdr, _ := workload.EncodeCredential(cred)
	chainHdr, _ := delegation.EncodeChain(chain)
	// A real MCP streamable-HTTP call: the tool is params.name in the POSTed JSON-RPC body.
	callBody := func(tool string) string {
		return `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"` + tool + `","arguments":{"path":"/etc/hosts"}}}`
	}
	send := func(tool string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/servers/demo/mcp", strings.NewReader(callBody(tool)))
		r.Header.Set("Authorization", "Bearer "+principalToken)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set(workload.HeaderCredential, credHdr)
		r.Header.Set(workload.HeaderProof, workload.Proof(a2Priv, principalToken))
		r.Header.Set(delegation.HeaderDelegation, chainHdr)
		rec := httptest.NewRecorder()
		gatewayFor().ServeHTTP(rec, r)
		return rec
	}

	// "write" was given up at the agent-1 -> agent-2 hop: denied, and nothing forwarded.
	forwarded = ""
	if rec := send("write"); rec.Code != http.StatusForbidden {
		t.Fatalf("a tool the chain gave up must be denied, got %d", rec.Code)
	}
	if forwarded != "" {
		t.Fatalf("a denied request must never reach the upstream (forwarded %q)", forwarded)
	}

	// "read" is within the grant: allowed, and the passport is scoped to it — no broader
	// than the chain — with the delegated budget intact.
	rec := send("read")
	if rec.Code != http.StatusOK {
		t.Fatalf("a tool inside the chain should be allowed, got %d (%s)", rec.Code, rec.Body)
	}
	const prefix = "Bearer "
	if len(forwarded) <= len(prefix) {
		t.Fatalf("no passport forwarded: %q", forwarded)
	}
	claims, err := passport.Verify(signer.Public(), forwarded[len(prefix):], "demo", time.Now())
	if err != nil {
		t.Fatalf("forwarded passport invalid: %v", err)
	}
	if len(claims.Tools) != 1 || claims.Tools[0] != "read" {
		t.Fatalf("passport scope = %v, want [read]", claims.Tools)
	}
	if claims.Budget == nil || claims.Budget.Limit != budget.Limit || claims.Budget.Unit != budget.Unit {
		t.Fatalf("delegated budget dropped by the policy stage: %+v", claims.Budget)
	}
	// The body the decision was made from must also be the body the upstream executes:
	// buffering it to read the tool cannot cost the call its arguments.
	if string(upstreamBody) != callBody("read") {
		t.Fatalf("upstream received body %q, want it forwarded intact: %q", upstreamBody, callBody("read"))
	}
}

// TestLiveInstanceWrongProofDenied confirms a stolen credential without the private key
// (bad proof of possession) is rejected by the live pipeline.
func TestLiveInstanceWrongProofDenied(t *testing.T) {
	caPub, caPriv := key(t)
	att := workload.NewTokenAttestor()
	att.Register("boot-2", "agent-2")
	authority, _ := workload.NewAuthority(caPriv, "ca-1", att, time.Hour)
	a2Pub, _ := key(t)
	cred, _ := authority.Issue([]byte("boot-2"), a2Pub)

	_, attackerPriv := key(t) // attacker holds a different key
	store := workload.NewKeyStore(caPub)
	stage := workload.InstanceStage(caPub, store)

	const principalToken = "tok"
	r := httptest.NewRequest(http.MethodGet, "/servers/demo/x", nil)
	r.Header.Set("Authorization", "Bearer "+principalToken)
	credHdr, _ := workload.EncodeCredential(cred)
	r.Header.Set(workload.HeaderCredential, credHdr)
	r.Header.Set(workload.HeaderProof, workload.Proof(attackerPriv, principalToken))

	req := &gateway.Request{HTTP: r, Principal: &types.Principal{ID: "p1"}}
	if err := stage.Handle(context.Background(), req); err == nil {
		t.Fatal("a credential presented without its private key must be rejected")
	}
}
