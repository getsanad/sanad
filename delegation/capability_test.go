package delegation

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/getsanad/sanad/gateway"
	"github.com/getsanad/sanad/internal/pop"
	"github.com/getsanad/sanad/pkg/types"
)

func rootKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestCapabilityNewAndVerify(t *testing.T) {
	rootPub, rootPriv := rootKeys(t)
	cap, _, err := NewCapability(rootPriv, Grant{Tools: []string{"read", "write"}})
	if err != nil {
		t.Fatal(err)
	}
	g, err := cap.Verify(rootPub, time.Now())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(g.Tools) != 2 {
		t.Fatalf("effective grant = %v", g.Tools)
	}
}

func TestCapabilityOfflineAttenuation(t *testing.T) {
	rootPub, rootPriv := rootKeys(t)
	cap, s0, _ := NewCapability(rootPriv, Grant{Tools: []string{"read", "write"}, Servers: []string{"s1", "s2"}})

	// A holder narrows it OFFLINE (no issuer contact, only s0).
	narrowed, _, err := cap.Attenuate(rootPub, s0, Grant{Tools: []string{"read"}, Servers: []string{"s1"}})
	if err != nil {
		t.Fatalf("attenuate: %v", err)
	}
	g, err := narrowed.Verify(rootPub, time.Now())
	if err != nil {
		t.Fatalf("verify narrowed: %v", err)
	}
	if len(g.Tools) != 1 || g.Tools[0] != "read" {
		t.Fatalf("effective grant not narrowed: %v", g.Tools)
	}
}

func TestCapabilityWideningRejected(t *testing.T) {
	rootPub, rootPriv := rootKeys(t)
	cap, s0, _ := NewCapability(rootPriv, Grant{Tools: []string{"read"}})
	if _, _, err := cap.Attenuate(rootPub, s0, Grant{Tools: []string{"read", "write"}}); err == nil {
		t.Fatal("widening on Attenuate must be rejected")
	}
}

func TestCapabilityWrongRootRejected(t *testing.T) {
	otherPub, _ := rootKeys(t)
	_, rootPriv := rootKeys(t)
	cap, _, _ := NewCapability(rootPriv, Grant{Tools: []string{"read"}})
	if _, err := cap.Verify(otherPub, time.Now()); err == nil {
		t.Fatal("a capability must not verify under a different root key")
	}
}

func TestCapabilityWrongHolderSecretRejected(t *testing.T) {
	rootPub, rootPriv := rootKeys(t)
	cap, _, _ := NewCapability(rootPriv, Grant{Tools: []string{"read"}})
	_, attacker := rootKeys(t)
	if _, _, err := cap.Attenuate(rootPub, attacker, Grant{Tools: []string{"read"}}); err == nil {
		t.Fatal("attenuating with a non-holder secret must be rejected")
	}
}

func TestCapabilityExpired(t *testing.T) {
	rootPub, rootPriv := rootKeys(t)
	cap, _, _ := NewCapability(rootPriv, Grant{NotAfter: time.Now().Add(-time.Minute)})
	if _, err := cap.Verify(rootPub, time.Now()); err == nil {
		t.Fatal("expired capability must be rejected")
	}
}

func TestCapabilityHolderProof(t *testing.T) {
	rootPub, rootPriv := rootKeys(t)
	cap, s0, _ := NewCapability(rootPriv, Grant{Tools: []string{"read"}})
	narrowed, s1, _ := cap.Attenuate(rootPub, s0, Grant{Tools: []string{"read"}})
	if _, err := narrowed.Verify(rootPub, time.Now()); err != nil {
		t.Fatal(err)
	}

	r, body := capHTTP()
	if err := narrowed.VerifyHolder(holderVerifier(), capProof(t, s1, r, body), r, body, capTestToken); err != nil {
		t.Fatalf("the current holder's proof must verify: %v", err)
	}
	// The previous secret (s0) is NOT the final holder key.
	r2, body2 := capHTTP()
	if err := narrowed.VerifyHolder(holderVerifier(), capProof(t, s0, r2, body2), r2, body2, capTestToken); err == nil {
		t.Fatal("a stale holder secret must not satisfy the holder proof")
	}
}

// TestCapabilityRecipientCannotBroaden is the core offline-attenuation guarantee: a
// recipient given a narrowed token (and only its final secret) cannot truncate back to the
// broader parent, because using the broader token requires the parent's next-secret, which
// they do not hold.
func TestCapabilityRecipientCannotBroaden(t *testing.T) {
	rootPub, rootPriv := rootKeys(t)
	broad, s0, _ := NewCapability(rootPriv, Grant{Tools: []string{"read", "write"}})
	narrowed, s1, _ := broad.Attenuate(rootPub, s0, Grant{Tools: []string{"read"}})

	// The recipient holds `narrowed` + s1 only (not s0). They try to present the broader
	// parent token. It is well-formed (verifies), but they cannot prove they hold it.
	if _, err := broad.Verify(rootPub, time.Now()); err != nil {
		t.Fatal("parent token is itself well-formed")
	}
	r, body := capHTTP()
	if err := broad.VerifyHolder(holderVerifier(), capProof(t, s1, r, body), r, body, capTestToken); err == nil {
		t.Fatal("recipient must NOT be able to wield the broader parent token with only the narrowed secret")
	}
	_ = narrowed
}

const capTestToken = "principal-token"

// holderVerifier is a stage-independent verifier for the direct VerifyHolder tests. Each
// call returns a fresh one so its replay cache is empty, which keeps the tests about the
// property under test rather than about proof reuse between them.
func holderVerifier() *HolderProofVerifier { return NewHolderProofVerifier() }

// capHTTP is the request a capability is presented on, and its body.
func capHTTP() (*http.Request, []byte) {
	r := httptest.NewRequest(http.MethodGet, "/servers/demo/tools/list", nil)
	r.Header.Set("Authorization", "Bearer "+capTestToken)
	return r, nil
}

// capProof builds a holder proof bound to r. Proofs are per-request now, so tests build one
// alongside every request rather than reusing a constant.
func capProof(t *testing.T, secret ed25519.PrivateKey, r *http.Request, body []byte) string {
	t.Helper()
	p, err := HolderProof(secret, r.Method, ProofTarget(r.URL), capTestToken, body)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// capPayload is the canonical proof payload for r — the bytes a genuine holder proof signs.
// Tests use it to build a proof that is correct in every respect except the signature.
func capPayload(t *testing.T, r *http.Request, body []byte) []byte {
	t.Helper()
	b, err := pop.NewBinding(r.Method, pop.Target(r.URL), capTestToken, body, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	payload, err := pop.Encode(b)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

// capRequest builds an authenticated gateway request, optionally presenting a capability.
// The proof is built for THIS request by proofFor, so every call gets a distinct jti.
func capRequest(t *testing.T, capHdr string, proofFor func(*http.Request) string) *gateway.Request {
	t.Helper()
	r, _ := capHTTP()
	if capHdr != "" {
		r.Header.Set(HeaderCapability, capHdr)
		r.Header.Set(HeaderCapabilityProof, proofFor(r))
	}
	return &gateway.Request{HTTP: r, Principal: &types.Principal{ID: "principal-1"}}
}

// TestCapabilityStageMissingCapability is the offline-mode half of the opt-in hole: a
// holder of a narrowed capability could simply not present it and be minted a passport
// with NO scope — unconstrained, hence wider than the capability it holds.
func TestCapabilityStageMissingCapability(t *testing.T) {
	rootPub, _ := rootKeys(t)

	req := capRequest(t, "", nil)
	if err := CapabilityStage(rootPub, WithRequireChain()).Handle(context.Background(), req); err == nil {
		t.Fatal("a missing capability must fail closed in require mode")
	}
	if req.Scope.Tools != nil {
		t.Fatalf("a rejected request must carry no scope: %v", req.Scope.Tools)
	}

	permissive := capRequest(t, "", nil)
	if err := CapabilityStage(rootPub).Handle(context.Background(), permissive); err != nil {
		t.Fatalf("absent capability should pass in permissive mode: %v", err)
	}
}

func TestCapabilityStageRequireModeAcceptsPresentCapability(t *testing.T) {
	rootPub, rootPriv := rootKeys(t)
	cap, s0, _ := NewCapability(rootPriv, Grant{Tools: []string{"read"}})
	enc, _ := EncodeCapability(cap)
	proofFor := func(r *http.Request) string { return capProof(t, s0, r, nil) }

	req := capRequest(t, enc, proofFor)
	if err := CapabilityStage(rootPub, WithRequireChain()).Handle(context.Background(), req); err != nil {
		t.Fatalf("a valid capability must still pass in require mode: %v", err)
	}
	if len(req.Scope.Tools) != 1 || req.Scope.Tools[0] != "read" {
		t.Fatalf("scope not narrowed to the effective grant: %v", req.Scope.Tools)
	}
}

// TestCapabilityStageEnforcesGrantServers is the offline-mode half of the server-constraint
// gap: the capability's Servers list must bind to the server actually being called.
func TestCapabilityStageEnforcesGrantServers(t *testing.T) {
	rootPub, rootPriv := rootKeys(t)
	cap, s0, _ := NewCapability(rootPriv, Grant{Tools: []string{"read"}, Servers: []string{"readonly-reports"}})
	enc, _ := EncodeCapability(cap)
	proofFor := func(r *http.Request) string { return capProof(t, s0, r, nil) }

	denied := capRequest(t, enc, proofFor)
	denied.Server = "payments"
	if err := CapabilityStage(rootPub).Handle(context.Background(), denied); err == nil {
		t.Fatal("a capability granting readonly-reports must not authorize payments")
	}
	if denied.Scope.Tools != nil {
		t.Fatalf("a rejected request must carry no scope: %v", denied.Scope.Tools)
	}

	allowed := capRequest(t, enc, proofFor)
	allowed.Server = "readonly-reports"
	if err := CapabilityStage(rootPub).Handle(context.Background(), allowed); err != nil {
		t.Fatalf("the granted server must be allowed: %v", err)
	}
	if len(allowed.Scope.Tools) != 1 || allowed.Scope.Tools[0] != "read" {
		t.Fatalf("scope not narrowed to the effective grant: %v", allowed.Scope.Tools)
	}
}

// TestCapabilityStageEmptyServersIsAnyServer: an unconstrained list stays unconstrained,
// exactly as attenuation reads it.
func TestCapabilityStageEmptyServersIsAnyServer(t *testing.T) {
	rootPub, rootPriv := rootKeys(t)
	cap, s0, _ := NewCapability(rootPriv, Grant{Tools: []string{"read"}})
	enc, _ := EncodeCapability(cap)

	req := capRequest(t, enc, func(r *http.Request) string { return capProof(t, s0, r, nil) })
	req.Server = "payments"
	if err := CapabilityStage(rootPub).Handle(context.Background(), req); err != nil {
		t.Fatalf("a capability with no server constraint must reach any server: %v", err)
	}
}

func TestCapabilityEncodeDecode(t *testing.T) {
	rootPub, rootPriv := rootKeys(t)
	cap, s0, _ := NewCapability(rootPriv, Grant{Tools: []string{"read", "write"}})
	cap, _, _ = cap.Attenuate(rootPub, s0, Grant{Tools: []string{"read"}})

	enc, err := EncodeCapability(cap)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeCapability(enc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := got.Verify(rootPub, time.Now()); err != nil {
		t.Fatalf("round-tripped capability failed to verify: %v", err)
	}
}
