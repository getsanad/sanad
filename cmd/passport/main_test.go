package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
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
	"github.com/getsanad/sanad/principal"
	"github.com/getsanad/sanad/sts"
	"github.com/getsanad/sanad/vc"
	"github.com/getsanad/sanad/workload"
)

func mustKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// TestSidecarInjectsCredentials proves the zero-code-change story: the agent makes a PLAIN
// request to the local sidecar (no passport headers at all); the sidecar adds the principal
// token, workload credential + proof, and delegation chain, and the upstream MCP server
// receives a valid, scoped passport.
func TestSidecarInjectsCredentials(t *testing.T) {
	// Workload authority + agent-1 instance credential.
	caPub, caPriv := mustKey(t)
	att := workload.NewTokenAttestor()
	att.Register("boot", "agent-1")
	authority, _ := workload.NewAuthority(caPriv, "ca-1", att, time.Hour)
	a1Pub, a1Priv := mustKey(t)
	nonce, _ := authority.Nonce()
	cred, _ := authority.Issue(workload.BootstrapEvidence("boot", nonce, a1Pub), nonce, a1Pub)
	credHeader, _ := workload.EncodeCredential(cred)

	// Principal key + delegation chain principal -> agent-1.
	principalPub, principalPriv := mustKey(t)
	store := workload.NewKeyStore(caPub)
	store.AddPrincipalKey("principal-1", principalPub, time.Time{})
	chain, _ := delegation.NewRoot(principalPriv, "principal-1", "agent-1", delegation.Grant{Tools: []string{"read"}})
	chainHeader, _ := delegation.EncodeChain(chain)

	// Upstream MCP server captures the credential it receives.
	signer, _ := sts.NewLocalSigner("kid-gw")
	var forwarded string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded = r.Header.Get("Authorization")
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	reg := gateway.NewRegistry()
	u, _ := url.Parse(upstream.URL)
	_ = reg.Register(&gateway.Server{ID: "demo", Upstream: u})
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
	gw := httptest.NewServer(g)
	defer gw.Close()

	// The sidecar, configured like `passport proxy` would be.
	sidecar, err := newSidecar(sidecarConfig{
		gatewayURL:  gw.URL,
		instanceKey: a1Priv,
		credHeader:  credHeader,
		chainHeader: chainHeader,
		token:       func() (string, error) { return "principal-bearer-token", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(sidecar)
	defer proxy.Close()

	// The agent makes a BARE request to the sidecar — no passport headers.
	resp, err := http.Get(proxy.URL + "/servers/demo/tools/list")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("request through sidecar got %d, want 200", resp.StatusCode)
	}

	const prefix = "Bearer "
	if len(forwarded) <= len(prefix) {
		t.Fatalf("upstream received no passport: %q", forwarded)
	}
	claims, err := passport.Verify(signer.Public(), forwarded[len(prefix):], "demo", time.Now())
	if err != nil {
		t.Fatalf("upstream did not receive a valid passport: %v", err)
	}
	if claims.Principal != "principal-1" || len(claims.Tools) != 1 || claims.Tools[0] != "read" {
		t.Fatalf("passport not as expected: %+v", claims)
	}
}

// TestSidecarPresentsThePrincipalHolderProof runs the same zero-code-change path against a
// gateway in VC mode, where the principal credential is NOT a bearer token: the gateway also
// wants a proof of possession of the principal's did:key on every request. The sidecar builds
// it from --principal-key, and without that key the identical request is denied.
func TestSidecarPresentsThePrincipalHolderProof(t *testing.T) {
	// A trusted issuer vouching for a did:key principal.
	issuerPub, issuerPriv := mustKey(t)
	issuerDID := vc.EncodeDIDKey(issuerPub)
	principalPub, principalPriv := mustKey(t)
	principalDID := vc.EncodeDIDKey(principalPub)
	cred, err := vc.Issue(issuerDID, issuerPriv,
		vc.Subject{ID: principalDID, Assurance: types.AssuranceOrg}, time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	credJSON, _ := json.Marshal(cred)
	principalToken := base64.RawURLEncoding.EncodeToString(credJSON)

	// Workload authority + agent-1 instance, and the chain principal -> agent-1.
	caPub, caPriv := mustKey(t)
	att := workload.NewTokenAttestor()
	att.Register("boot", "agent-1")
	authority, _ := workload.NewAuthority(caPriv, "ca-1", att, time.Hour)
	a1Pub, a1Priv := mustKey(t)
	nonce, _ := authority.Nonce()
	agentCred, _ := authority.Issue(workload.BootstrapEvidence("boot", nonce, a1Pub), nonce, a1Pub)
	credHeader, _ := workload.EncodeCredential(agentCred)
	chain, _ := delegation.NewRoot(principalPriv, principalDID, "agent-1", delegation.Grant{Tools: []string{"read"}})
	chainHeader, _ := delegation.EncodeChain(chain)

	store := workload.NewKeyStore(caPub)
	signer, _ := sts.NewLocalSigner("kid-gw")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	reg := gateway.NewRegistry()
	u, _ := url.Parse(upstream.URL)
	_ = reg.Register(&gateway.Server{ID: "demo", Upstream: u})
	g := &gateway.Gateway{Registry: reg, Pipeline: gateway.Pipeline{Stages: []gateway.Stage{
		principal.Stage(vc.NewAuthenticator(vc.StaticTrust{issuerDID: true}, vc.WithKeyRegistrar(store))),
		workload.InstanceStage(caPub, store),
		delegation.Stage(store, delegation.HeaderExtractor(delegation.HeaderDelegation)),
		sts.MintStage(sts.New(signer, sts.Config{Issuer: "sanad"})),
	}}}
	gw := httptest.NewServer(g)
	defer gw.Close()

	call := func(t *testing.T, principalKey ed25519.PrivateKey) int {
		t.Helper()
		sidecar, err := newSidecar(sidecarConfig{
			gatewayURL:   gw.URL,
			instanceKey:  a1Priv,
			principalKey: principalKey,
			credHeader:   credHeader,
			chainHeader:  chainHeader,
			token:        func() (string, error) { return principalToken, nil },
		})
		if err != nil {
			t.Fatal(err)
		}
		proxy := httptest.NewServer(sidecar)
		defer proxy.Close()

		resp, err := http.Get(proxy.URL + "/servers/demo/tools/list")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	if code := call(t, principalPriv); code != http.StatusOK {
		t.Fatalf("sidecar with --principal-key got %d, want 200", code)
	}
	// The same credential, the same valid instance identity, no principal key: denied.
	if code := call(t, nil); code == http.StatusOK {
		t.Fatal("a sidecar with no principal key presented the credential as a bearer token and was admitted")
	}
}

func TestTokenSourceFromEnv(t *testing.T) {
	t.Setenv("PASSPORT_PRINCIPAL_TOKEN", "tok-123")
	got, err := tokenSource("", "PASSPORT_PRINCIPAL_TOKEN")()
	if err != nil || got != "tok-123" {
		t.Fatalf("token from env: %q, %v", got, err)
	}
	if _, err := tokenSource("", "PASSPORT_MISSING_VAR")(); err == nil {
		t.Fatal("missing token env must error")
	}
}
