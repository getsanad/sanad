package workload

// The two identity namespaces the KeyStore holds — agents and principals — and the rule that
// stops an agent being named like a principal.
//
// The flaw these close: the store was ONE flat map, written by Add (keyed on a credential's
// AgentID) and by the principal registrar (keyed on the principal's DID) alike, last write
// wins, with InstanceStage calling Add on every request. A credential whose agent id equalled
// a principal's id therefore replaced that principal's root signing key, after which
// delegation.Verify's root check passed against a key the attacker held and they could mint
// chains rooted at a principal they had never been.

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/getsanad/sanad/delegation"
	"github.com/getsanad/sanad/gateway"
	"github.com/getsanad/sanad/internal/sigctx"
	"github.com/getsanad/sanad/pkg/types"
)

// aDID is a well-formed did:key — the shape a principal id takes in VC mode.
const aDID = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"

// fixedAttestor attests to whatever id it is handed. It stands for an Attestor an operator
// plugged in themselves, or one written before the agent-id rule existed: Authority.Issue is
// the choke point that has to refuse the name whatever the attestor says.
type fixedAttestor struct{ id string }

func (f fixedAttestor) Attest(_, _ []byte, _ ed25519.PublicKey) (string, error) { return f.id, nil }

// TestAgentCredentialDoesNotOverwriteAPrincipalKey is the proof of concept, run through the
// live instance stage. The principal here is an OIDC subject rather than a DID, deliberately:
// "user-42" is both a perfectly good agent name and a perfectly good IdP subject, so this is
// the collision NO id rule can catch and only separate namespaces prevent.
func TestAgentCredentialDoesNotOverwriteAPrincipalKey(t *testing.T) {
	const sharedID = "user-42" // the principal's OIDC subject AND the attacker's agent id
	caPub, caPriv := newCA(t)
	att := NewTokenAttestor()
	if err := att.Register("boot-evil", sharedID); err != nil {
		t.Fatal(err)
	}
	if err := att.Register("boot-1", "agent-1"); err != nil {
		t.Fatal(err)
	}
	authority, err := NewAuthority(caPriv, "ca-1", att, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	principalPub, principalPriv := newCA(t)
	attackerPub, attackerPriv := instanceKey(t)
	a1Pub, a1Priv := instanceKey(t)

	store := NewKeyStore(caPub)
	store.AddPrincipalKey(sharedID, principalPub, time.Time{})

	// An honest agent enrolled earlier; the attacker enrolls one named after the principal.
	a1Cred, err := enroll(t, authority, "boot-1", a1Pub)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Add(a1Cred); err != nil {
		t.Fatal(err)
	}
	evilCred, err := enroll(t, authority, "boot-evil", attackerPub)
	if err != nil {
		t.Fatal(err)
	}

	// The live path: the instance stage authenticates the attacker's instance and caches its
	// key, exactly as it does on every request. The credential is genuine, so this succeeds —
	// what must not follow is the principal losing its key.
	credHdr, err := EncodeCredential(evilCred)
	if err != nil {
		t.Fatal(err)
	}
	const token = "principal-bearer-token"
	r := httptest.NewRequest(http.MethodGet, "/servers/demo/x", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set(HeaderCredential, credHdr)
	proof, err := Proof(attackerPriv, r.Method, ProofTarget(r.URL), token, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set(HeaderProof, proof)
	req := &gateway.Request{HTTP: r, Principal: &types.Principal{ID: sharedID}}
	if err := InstanceStage(caPub, store).Handle(context.Background(), req); err != nil {
		t.Fatalf("the agent credential is genuine and must authenticate: %v", err)
	}

	// The principal's key is untouched; the attacker's answers only as an agent.
	if got, ok := store.PrincipalKey(sharedID); !ok || !got.Equal(principalPub) {
		t.Fatal("the agent credential overwrote the principal's root signing key")
	}
	if got, ok := store.AgentKey(sharedID); !ok || !got.Equal(attackerPub) {
		t.Fatal("the agent's own key must still resolve in the agent namespace")
	}

	// The attack: a chain rooted at the principal, signed with the attacker's key. The root
	// hop is resolved in the principal namespace, where that key is not.
	forged, err := delegation.NewRoot(attackerPriv, sharedID, "evil-agent", delegation.Grant{Tools: []string{"admin"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, agent, err := delegation.Verify(forged, store, sharedID, time.Now()); err == nil {
		t.Fatalf("a chain rooted at the principal was forged with an agent's key: agent=%q", agent)
	}

	// The honest multi-hop path still verifies end to end: the principal roots the chain (root
	// hop resolved as a principal) and agent-1 extends it (resolved as an agent).
	honest, err := delegation.NewRoot(principalPriv, sharedID, "agent-1", delegation.Grant{Tools: []string{"read", "write"}})
	if err != nil {
		t.Fatal(err)
	}
	honest, err = honest.Extend(a1Priv, "agent-2", delegation.Grant{Tools: []string{"read"}})
	if err != nil {
		t.Fatal(err)
	}
	grant, acting, err := delegation.Verify(honest, store, sharedID, time.Now())
	if err != nil {
		t.Fatalf("an honest principal -> agent -> agent chain must still verify: %v", err)
	}
	if acting != "agent-2" || len(grant.Tools) != 1 || grant.Tools[0] != "read" {
		t.Fatalf("effective grant = %+v, acting = %q", grant, acting)
	}
}

// TestDIDShapedAgentIDRejectedAtTheAuthority covers the second lock: an agent can never be
// given a principal's name in the first place, at either point where an id enters the
// authority.
func TestDIDShapedAgentIDRejectedAtTheAuthority(t *testing.T) {
	// Bootstrap-token configuration (PASSPORT_BOOTSTRAP_TOKENS parses into this call) refuses
	// it, so cmd/authority fails at startup rather than issuing later.
	if err := NewTokenAttestor().Register("boot", aDID); err == nil {
		t.Fatal("a bootstrap token naming an agent after a DID must be refused")
	}

	// And issuance refuses it whatever the attestor asserts.
	_, caPriv := newCA(t)
	pub, _ := instanceKey(t)
	bad, err := NewAuthority(caPriv, "ca-1", fixedAttestor{aDID}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := enroll(t, bad, "ignored", pub); err == nil {
		t.Fatal("the authority must not issue a credential whose agent id is a DID")
	}

	// The same attestor with a real agent name still issues, so it is the name being refused
	// and nothing else.
	good, err := NewAuthority(caPriv, "ca-1", fixedAttestor{"agent-1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cred, err := enroll(t, good, "ignored", pub)
	if err != nil || cred.AgentID != "agent-1" {
		t.Fatalf("a well-named agent must still enroll: cred=%+v err=%v", cred, err)
	}

	// A measured (TEE/TPM) quote naming a DID is refused on the same rule.
	attPub, attPriv := newCA(t)
	m, err := NewMeasuredAttestor(attPub, []string{"build-1"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	nonce := []byte("nonce-nonce-nonce-nonce-nonce-32")
	quote, err := SignQuote(attPriv, aDID, "build-1", nonce, pub, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Attest(quote, nonce, pub); err == nil {
		t.Fatal("an attestation quote naming an agent after a DID must be refused")
	}
}

func TestValidAgentID(t *testing.T) {
	for _, id := range []string{
		"a", "A9", "agent-1", "agent.worker_2", "agent-7f3a9c2e41b8", strings.Repeat("a", MaxAgentIDLen),
	} {
		if err := ValidAgentID(id); err != nil {
			t.Fatalf("%q should be a usable agent id: %v", id, err)
		}
	}
	for name, id := range map[string]string{
		"empty":                 "",
		"did:key":               aDID,
		"did:web":               "did:web:example.com:agent-1",
		"urn":                   "urn:example:agent-1",
		"an issuer-shaped id":   "https://accounts.example.com/user-42",
		"a leading separator":   "-agent-1",
		"a token-list comma":    "agent-1,agent-2",
		"a token-list equals":   "agent=1",
		"an embedded space":     "agent 1",
		"an embedded newline":   "agent\n1",
		"a path separator":      "agents/agent-1",
		"longer than the bound": strings.Repeat("a", MaxAgentIDLen+1),
	} {
		if err := ValidAgentID(id); err == nil {
			t.Fatalf("%s (%q) must not be a usable agent id", name, id)
		}
	}
}

// signedCredential is a credential the CA really signed — the only thing wrong with it is the
// name. It stands for an authority that predates the agent-id rule, or one an operator wired
// with their own Attestor: the verifying side re-checks the id rather than trusting the issuer
// to have done it.
func signedCredential(caPriv ed25519.PrivateKey, agentID string, pub ed25519.PublicKey, now time.Time) Credential {
	c := Credential{AgentID: agentID, PublicKey: pub, IssuedAt: now, NotAfter: now.Add(time.Hour), KeyID: "ca-1"}
	c.Signature = sigctx.Sign(sigctx.WorkloadCredential, caPriv, canonical(c))
	return c
}

func TestCredentialWithUnusableAgentIDRejected(t *testing.T) {
	caPub, caPriv := newCA(t)
	pub, _ := instanceKey(t)
	now := time.Now()

	for name, id := range map[string]string{"empty": "", "a principal DID": aDID} {
		t.Run(name, func(t *testing.T) {
			cred := signedCredential(caPriv, id, pub, now)
			if err := Verify(caPub, cred, now); err == nil {
				t.Fatalf("a credential with an %s agent id must not verify", name)
			}
			store := NewKeyStore(caPub)
			if err := store.Add(cred); err == nil {
				t.Fatalf("a credential with an %s agent id must not be cached", name)
			}
			if _, ok := store.AgentKey(id); ok {
				t.Fatalf("a key was registered under %q", id)
			}
		})
	}

	// The same credential with a real agent id verifies, so it is the id being rejected.
	if err := Verify(caPub, signedCredential(caPriv, "agent-1", pub, now), now); err != nil {
		t.Fatalf("a well-named credential must still verify: %v", err)
	}
}
