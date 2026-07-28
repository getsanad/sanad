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
	"strings"
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

// The VC authenticator must satisfy the principal-auth interfaces so it drops into the
// gateway stage in place of OIDC — including the request-aware one, without which the stage
// would take the token-only path and the holder binding would never be checked.
var (
	_ principal.Authenticator        = (*Authenticator)(nil)
	_ principal.RequestAuthenticator = (*Authenticator)(nil)
)

func kp(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

type fakeRegistrar struct {
	calls    int
	id       string
	pub      ed25519.PublicKey
	notAfter time.Time
}

func (f *fakeRegistrar) AddPrincipalKey(id string, pub ed25519.PublicKey, notAfter time.Time) {
	f.calls++
	f.id, f.pub, f.notAfter = id, pub, notAfter
}

type denyList map[string]bool

func (d denyList) Revoked(id string) bool { return d[id] }

// holder is a principal ready to present its credential: the DID, the private key, and the
// exact bearer string the proof's ath commits to.
type holder struct {
	did    string
	key    ed25519.PrivateKey
	bearer string
	cred   Credential
}

func newHolder(t *testing.T, issuerDID string, issuerKey ed25519.PrivateKey, ttl time.Duration, now time.Time) holder {
	t.Helper()
	pub, priv := kp(t)
	did := EncodeDIDKey(pub)
	cred, err := Issue(issuerDID, issuerKey, Subject{ID: did, Assurance: types.AssuranceOrg}, ttl, now)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(cred)
	if err != nil {
		t.Fatal(err)
	}
	return holder{did: did, key: priv, bearer: base64.RawURLEncoding.EncodeToString(raw), cred: cred}
}

// present builds a request carrying the credential and a holder proof over it, signed by
// signWith (which is the holder's own key on the honest path).
func present(t *testing.T, h holder, signWith ed25519.PrivateKey, method, target, body string) *http.Request {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, target, nil)
	} else {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
	}
	r.Header.Set("Authorization", "Bearer "+h.bearer)
	proof, err := HolderProof(signWith, method, ProofTarget(r.URL), h.bearer, bodyBytes(body))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set(HeaderPrincipalProof, proof)
	return r
}

func bodyBytes(s string) []byte {
	if s == "" {
		return nil
	}
	return []byte(s)
}

func TestAuthenticateRequestAndRegister(t *testing.T) {
	issuerDID, issuerKey := newDID(t)
	now := time.Now()
	h := newHolder(t, issuerDID, issuerKey, time.Hour, now)

	reg := &fakeRegistrar{}
	a := NewAuthenticator(StaticTrust{issuerDID: true}, WithKeyRegistrar(reg))

	// Raw JSON and base64url(JSON) are both accepted — but the proof's ath covers the exact
	// bearer string, so each form needs its own proof.
	rawJSON, _ := json.Marshal(h.cred)
	for name, token := range map[string]string{
		"json":   string(rawJSON),
		"base64": h.bearer,
	} {
		t.Run(name, func(t *testing.T) {
			presented := h
			presented.bearer = token
			r := present(t, presented, h.key, http.MethodGet, "/servers/demo/tools/list", "")
			p, err := a.AuthenticateRequest(context.Background(), token, r, nil)
			if err != nil {
				t.Fatalf("authenticate: %v", err)
			}
			if p.ID != h.did || p.Assurance != types.AssuranceOrg {
				t.Fatalf("principal mismatch: %+v", p)
			}
		})
	}

	// The registrar received the principal's did:key public key, expiring WITH the credential.
	subjPub, err := PublicKeyFromDID(h.did)
	if err != nil {
		t.Fatal(err)
	}
	if reg.id != h.did || !reg.pub.Equal(subjPub) {
		t.Fatalf("registrar did not receive the principal key: %+v", reg)
	}
	if reg.notAfter.IsZero() {
		t.Fatal("principal key registered with a zero notAfter, which the KeyStore reads as never expiring")
	}
	if want := now.Add(time.Hour).Truncate(time.Second); !reg.notAfter.Equal(want) {
		t.Fatalf("registered notAfter = %s, want the credential's expiry %s", reg.notAfter, want)
	}
}

// TestCopiedCredentialIsNotAnIdentity is the proof of concept, inverted. The credential
// travels in a header on every request, so a copy of it is available to anything that sees
// one: a log, a proxy, the upstream server. Every one of these attempts holds the whole
// credential and does NOT hold the subject's private key, and every one must fail.
func TestCopiedCredentialIsNotAnIdentity(t *testing.T) {
	issuerDID, issuerKey := newDID(t)
	h := newHolder(t, issuerDID, issuerKey, time.Hour, time.Now())
	_, attackerKey := kp(t)

	reg := &fakeRegistrar{}
	a := NewAuthenticator(StaticTrust{issuerDID: true}, WithKeyRegistrar(reg))
	ctx := context.Background()

	t.Run("no proof at all", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/servers/demo/tools/list", nil)
		r.Header.Set("Authorization", "Bearer "+h.bearer)
		if _, err := a.AuthenticateRequest(ctx, h.bearer, r, nil); err == nil {
			t.Fatal("a credential with no holder proof authenticated")
		}
	})

	t.Run("proof signed by another key", func(t *testing.T) {
		r := present(t, h, attackerKey, http.MethodGet, "/servers/demo/tools/list", "")
		if _, err := a.AuthenticateRequest(ctx, h.bearer, r, nil); err == nil {
			t.Fatal("a holder proof made without the subject's key authenticated")
		}
	})

	t.Run("two proofs, one of them valid", func(t *testing.T) {
		// Header.Get would take the first; presenting both is how a parser differential gets
		// exploited, so the count is checked instead.
		r := present(t, h, attackerKey, http.MethodGet, "/servers/demo/tools/list", "")
		good, _ := HolderProof(h.key, http.MethodGet, "/servers/demo/tools/list", h.bearer, nil)
		r.Header.Add(HeaderPrincipalProof, good)
		if _, err := a.AuthenticateRequest(ctx, h.bearer, r, nil); err == nil {
			t.Fatal("two holder proof headers were accepted")
		}
	})

	t.Run("token-only path", func(t *testing.T) {
		if _, err := a.Authenticate(ctx, h.bearer); err == nil {
			t.Fatal("the credential authenticated from the token alone — it is a bearer blob again")
		}
		if _, err := a.AuthenticateRequest(ctx, h.bearer, nil, nil); err == nil {
			t.Fatal("a nil request authenticated")
		}
	})

	// Nothing above may have installed a principal key: a failed authentication that still
	// registers the subject's key hands an attacker a delegation root.
	if reg.calls != 0 {
		t.Fatalf("registrar was called %d times on failed authentications", reg.calls)
	}
}

// A captured bundle — credential and proof together, copied verbatim off one request — must
// not authenticate a different request, and must not authenticate the same one twice.
func TestHolderProofIsBoundToTheRequest(t *testing.T) {
	issuerDID, issuerKey := newDID(t)
	h := newHolder(t, issuerDID, issuerKey, time.Hour, time.Now())
	a := NewAuthenticator(StaticTrust{issuerDID: true})
	ctx := context.Background()

	const body = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}}`
	captured := present(t, h, h.key, http.MethodPost, "/servers/demo/mcp", body).Header.Get(HeaderPrincipalProof)

	replay := func(method, target, body string) *http.Request {
		var r *http.Request
		if body == "" {
			r = httptest.NewRequest(method, target, nil)
		} else {
			r = httptest.NewRequest(method, target, strings.NewReader(body))
		}
		r.Header.Set("Authorization", "Bearer "+h.bearer)
		r.Header.Set(HeaderPrincipalProof, captured)
		return r
	}

	for name, tc := range map[string]struct{ method, target, body string }{
		"different method": {http.MethodGet, "/servers/demo/mcp", ""},
		"different path":   {http.MethodPost, "/servers/other/mcp", body},
		"different body":   {http.MethodPost, "/servers/demo/mcp", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete"}}`},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := a.AuthenticateRequest(ctx, h.bearer, replay(tc.method, tc.target, tc.body), bodyBytes(tc.body)); err == nil {
				t.Fatalf("a proof bound to another request authenticated (%s)", name)
			}
		})
	}

	// The identical request: valid once, replayed never.
	if _, err := a.AuthenticateRequest(ctx, h.bearer, replay(http.MethodPost, "/servers/demo/mcp", body), []byte(body)); err != nil {
		t.Fatalf("the honest request must authenticate: %v", err)
	}
	if _, err := a.AuthenticateRequest(ctx, h.bearer, replay(http.MethodPost, "/servers/demo/mcp", body), []byte(body)); err == nil {
		t.Fatal("an identical replay of a spent proof authenticated")
	}
}

// A proof made while presenting one credential must not carry another. Two principals of the
// same issuer would otherwise be interchangeable to anyone holding both credentials and
// either key.
func TestHolderProofDoesNotCarryAnotherCredential(t *testing.T) {
	issuerDID, issuerKey := newDID(t)
	now := time.Now()
	victim := newHolder(t, issuerDID, issuerKey, time.Hour, now)
	attacker := newHolder(t, issuerDID, issuerKey, time.Hour, now)

	a := NewAuthenticator(StaticTrust{issuerDID: true})

	// The attacker presents the VICTIM's credential with a proof it validly made over its OWN.
	r := present(t, attacker, attacker.key, http.MethodGet, "/servers/demo/tools/list", "")
	r.Header.Set("Authorization", "Bearer "+victim.bearer)
	if _, err := a.AuthenticateRequest(context.Background(), victim.bearer, r, nil); err == nil {
		t.Fatal("a holder proof over one credential was accepted while presenting another")
	}
}

func TestAuthenticateUntrustedRejected(t *testing.T) {
	issuerDID, issuerKey := newDID(t)
	h := newHolder(t, issuerDID, issuerKey, time.Hour, time.Now())

	a := NewAuthenticator(StaticTrust{}) // trusts no one
	r := present(t, h, h.key, http.MethodGet, "/servers/demo/tools/list", "")
	if _, err := a.AuthenticateRequest(context.Background(), h.bearer, r, nil); err == nil {
		t.Fatal("untrusted issuer must be rejected")
	}
}

// The kill-switch is enforced at authentication in VC mode as it is in OIDC mode: a revoked
// principal does not authenticate, so its key is never (re-)registered as a delegation root.
func TestRevokedPrincipalIsRejected(t *testing.T) {
	issuerDID, issuerKey := newDID(t)
	h := newHolder(t, issuerDID, issuerKey, time.Hour, time.Now())

	reg := &fakeRegistrar{}
	a := NewAuthenticator(StaticTrust{issuerDID: true},
		WithKeyRegistrar(reg), WithStatusChecker(denyList{h.did: true}))

	r := present(t, h, h.key, http.MethodGet, "/servers/demo/tools/list", "")
	if _, err := a.AuthenticateRequest(context.Background(), h.bearer, r, nil); err == nil {
		t.Fatal("a revoked principal authenticated")
	}
	if reg.calls != 0 {
		t.Fatal("a revoked principal's key was registered for delegation")
	}
}

// A credential whose expiration date is missing or unusable must never reach the registrar:
// that is the path that installed a principal key with a zero notAfter, which the KeyStore
// treats as never expiring.
func TestUnexpiringCredentialNeverRegistersAKey(t *testing.T) {
	issuerDID, issuerKey := newDID(t)
	h := newHolder(t, issuerDID, issuerKey, time.Hour, time.Now())

	for name, date := range map[string]string{"missing": "", "unparseable": "never"} {
		t.Run(name, func(t *testing.T) {
			cred := h.cred
			cred.ExpirationDate = date
			msg, err := canonical(cred)
			if err != nil {
				t.Fatal(err)
			}
			cred.Proof.ProofValue = b64Sig(issuerKey, msg) // a genuinely signed, genuinely endless credential
			raw, _ := json.Marshal(cred)

			presented := h
			presented.bearer = base64.RawURLEncoding.EncodeToString(raw)
			reg := &fakeRegistrar{}
			a := NewAuthenticator(StaticTrust{issuerDID: true}, WithKeyRegistrar(reg))
			r := present(t, presented, h.key, http.MethodGet, "/servers/demo/tools/list", "")

			if _, err := a.AuthenticateRequest(context.Background(), presented.bearer, r, nil); err == nil {
				t.Fatal("a credential with no usable expiry authenticated")
			}
			if reg.calls != 0 {
				t.Fatal("a never-expiring principal key was registered")
			}
		})
	}
}

// A property the credential's JSON does not carry into the Go struct is a property no
// signature covers. Dropping it silently would let an unsigned field ride along through
// verification, so it is refused instead.
func TestUnknownCredentialPropertiesAreRefused(t *testing.T) {
	issuerDID, issuerKey := newDID(t)
	h := newHolder(t, issuerDID, issuerKey, time.Hour, time.Now())

	var doc map[string]any
	raw, _ := json.Marshal(h.cred)
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["termsOfUse"] = map[string]string{"type": "IssuerPolicy", "profile": "unsigned, invisible"}
	tampered, _ := json.Marshal(doc)

	if _, err := decodeCredential(string(tampered)); err == nil {
		t.Fatal("a credential carrying a property no signature covers was accepted")
	}
}

// TestLivePipelineWithVCPrincipal closes the P2-02 gap: a principal authenticates via a VC
// (did:key) it proves possession of, which auto-registers its key in the workload KeyStore,
// so a delegation chain rooted at that principal verifies live through the real gateway.
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

	credHdr, _ := workload.EncodeCredential(agentCred)
	// build assembles one fully-credentialled request, with the principal holder proof signed
	// by holderKey — the principal's own key on the honest path.
	build := func(holderKey ed25519.PrivateKey) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/servers/demo/tools/list", nil)
		r.Header.Set("Authorization", "Bearer "+bearer)
		r.Header.Set(workload.HeaderCredential, credHdr)
		proof, err := workload.Proof(a1Priv, r.Method, workload.ProofTarget(r.URL), bearer, nil)
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set(workload.HeaderProof, proof)
		holderProof, err := HolderProof(holderKey, r.Method, ProofTarget(r.URL), bearer, nil)
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set(HeaderPrincipalProof, holderProof)
		r.Header.Set(delegation.HeaderDelegation, chainHdr)
		return r
	}

	rec := httptest.NewRecorder()
	g.ServeHTTP(rec, build(principalPriv))
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

	// The same agent, with the same credential copied verbatim, but without the principal's
	// private key: through the real gateway, that is a denial.
	_, thiefKey := kp(t)
	forwarded = ""
	rec2 := httptest.NewRecorder()
	g.ServeHTTP(rec2, build(thiefKey))
	if rec2.Code == http.StatusOK {
		t.Fatal("a copied credential authenticated without the principal's key")
	}
	if forwarded != "" {
		t.Fatalf("a passport was minted for a copied credential: %q", forwarded)
	}
}
