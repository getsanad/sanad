package workload_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/getsanad/sanad/delegation"
	"github.com/getsanad/sanad/gateway"
	"github.com/getsanad/sanad/pkg/passport"
	"github.com/getsanad/sanad/pkg/types"
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
