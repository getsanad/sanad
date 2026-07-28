package vc

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
	"github.com/getsanad/sanad/workload"
)

// The VC authenticator must satisfy the principal-auth interface so it drops into the
// gateway stage in place of OIDC.
var _ principal.Authenticator = (*Authenticator)(nil)

func kp(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

type fakeRegistrar struct {
	id  string
	pub ed25519.PublicKey
}

func (f *fakeRegistrar) AddKey(id string, pub ed25519.PublicKey, _ time.Time) {
	f.id, f.pub = id, pub
}

func TestAuthenticateAndRegister(t *testing.T) {
	issuerDID, issuerKey := newDID(t)
	subjPub, _ := kp(t)
	subjectDID := EncodeDIDKey(subjPub)
	now := time.Now()
	cred, _ := Issue(issuerDID, issuerKey, Subject{ID: subjectDID, Assurance: types.AssuranceOrg}, time.Hour, now)
	raw, _ := json.Marshal(cred)

	reg := &fakeRegistrar{}
	a := NewAuthenticator(StaticTrust{issuerDID: true}, WithKeyRegistrar(reg))

	// Raw JSON and base64url(JSON) are both accepted.
	for name, token := range map[string]string{
		"json":   string(raw),
		"base64": base64.RawURLEncoding.EncodeToString(raw),
	} {
		t.Run(name, func(t *testing.T) {
			p, err := a.Authenticate(context.Background(), token)
			if err != nil {
				t.Fatalf("authenticate: %v", err)
			}
			if p.ID != subjectDID || p.Assurance != types.AssuranceOrg {
				t.Fatalf("principal mismatch: %+v", p)
			}
		})
	}

	// The registrar received the principal's did:key public key.
	if reg.id != subjectDID || !reg.pub.Equal(subjPub) {
		t.Fatalf("registrar did not receive the principal key: %+v", reg)
	}
}

func TestAuthenticateUntrustedRejected(t *testing.T) {
	issuerDID, issuerKey := newDID(t)
	subjPub, _ := kp(t)
	cred, _ := Issue(issuerDID, issuerKey, Subject{ID: EncodeDIDKey(subjPub)}, time.Hour, time.Now())
	raw, _ := json.Marshal(cred)

	a := NewAuthenticator(StaticTrust{}) // trusts no one
	if _, err := a.Authenticate(context.Background(), string(raw)); err == nil {
		t.Fatal("untrusted issuer must be rejected")
	}
}

// TestLivePipelineWithVCPrincipal closes the P2-02 gap: a principal authenticates via a VC
// (did:key), which auto-registers its key in the workload KeyStore, so a delegation chain
// rooted at that principal verifies live through the real gateway.
func TestLivePipelineWithVCPrincipal(t *testing.T) {
	issuerDID, issuerKey := newDID(t)
	principalPub, principalPriv := kp(t)
	principalDID := EncodeDIDKey(principalPub)

	cred, _ := Issue(issuerDID, issuerKey, Subject{ID: principalDID, Assurance: types.AssuranceOrg}, time.Hour, time.Now())
	rawVC, _ := json.Marshal(cred)
	bearer := base64.RawURLEncoding.EncodeToString(rawVC)

	// Workload CA + agent-1 instance.
	caPub, caPriv := kp(t)
	att := workload.NewTokenAttestor()
	att.Register("boot", "agent-1")
	authority, _ := workload.NewAuthority(caPriv, "ca-1", att, time.Hour)
	a1Pub, a1Priv := kp(t)
	nonce, _ := authority.Nonce()
	agentCred, _ := authority.Issue(workload.BootstrapEvidence("boot", nonce, a1Pub), nonce, a1Pub)

	store := workload.NewKeyStore(caPub)
	vcAuth := NewAuthenticator(StaticTrust{issuerDID: true}, WithKeyRegistrar(store))

	// principal -> agent-1 (read), signed by the principal's did:key key.
	chain, _ := delegation.NewRoot(principalPriv, principalDID, "agent-1", delegation.Grant{Tools: []string{"read"}})
	chainHdr, _ := delegation.EncodeChain(chain)

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
	g := &gateway.Gateway{Registry: reg, Pipeline: gateway.Pipeline{Stages: []gateway.Stage{
		principal.Stage(vcAuth),
		workload.InstanceStage(caPub, store),
		delegation.Stage(store, delegation.HeaderExtractor(delegation.HeaderDelegation)),
		sts.MintStage(sts.New(signer, sts.Config{Issuer: "sanad"})),
	}}}

	r := httptest.NewRequest(http.MethodGet, "/servers/demo/tools/list", nil)
	r.Header.Set("Authorization", "Bearer "+bearer)
	credHdr, _ := workload.EncodeCredential(agentCred)
	r.Header.Set(workload.HeaderCredential, credHdr)
	r.Header.Set(workload.HeaderProof, workload.Proof(a1Priv, bearer))
	r.Header.Set(delegation.HeaderDelegation, chainHdr)

	rec := httptest.NewRecorder()
	g.ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("request denied: %d (%s)", rec.Code, rec.Body)
	}

	const prefix = "Bearer "
	if len(forwarded) <= len(prefix) {
		t.Fatalf("no passport forwarded: %q", forwarded)
	}
	claims, err := passport.Verify(signer.Public(), forwarded[len(prefix):], "demo", time.Now())
	if err != nil {
		t.Fatalf("forwarded passport invalid: %v", err)
	}
	if claims.Principal != principalDID {
		t.Fatalf("passport principal = %q, want %q", claims.Principal, principalDID)
	}
	if len(claims.Tools) != 1 || claims.Tools[0] != "read" {
		t.Fatalf("scope not attenuated to [read]: %v", claims.Tools)
	}
}
