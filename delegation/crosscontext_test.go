package delegation

// Cross-context tests: a signature made for one purpose must never verify for another.
//
// These exercise the pairs where one key genuinely signs in two message spaces, using the
// real APIs rather than the primitive — the primitive's exhaustive pairwise property (every
// context against every other) lives in internal/sigctx. Each pair is tested in both
// directions, and each context is confirmed to still verify its own messages.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/getsanad/sanad/gateway"
	"github.com/getsanad/sanad/internal/pop"
	"github.com/getsanad/sanad/internal/sigctx"
	"github.com/getsanad/sanad/pkg/types"
	"github.com/getsanad/sanad/workload"
)

// enrolledAgent returns an agent instance whose key is registered in a KeyStore, exactly as
// InstanceStage registers it: the same key then authenticates the agent's delegation hops.
func enrolledAgent(t *testing.T, agentID string) (ed25519.PrivateKey, *workload.KeyStore, ed25519.PublicKey) {
	t.Helper()
	caPub, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	att := workload.NewTokenAttestor()
	att.Register("boot", agentID)
	authority, err := workload.NewAuthority(caPriv, "ca-1", att, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := authority.Nonce()
	if err != nil {
		t.Fatal(err)
	}
	cred, err := authority.Issue(workload.BootstrapEvidence("boot", nonce, pub), nonce, pub)
	if err != nil {
		t.Fatal(err)
	}
	store := workload.NewKeyStore(caPub)
	if err := store.Add(cred); err != nil {
		t.Fatal(err)
	}
	return priv, store, caPub
}

// --- instance proof of possession <-> delegation hop ---------------------------------
//
// The instance key is a signing oracle over a caller-supplied principal token AND the key
// delegation.Verify authenticates hops with. This is the proof of concept for the flaw:
// feed Proof the exact bytes of a hop's canonical encoding and the returned signature used
// to verify as a delegation from that agent to anyone, under any grant.

func TestInstanceProofDoesNotForgeADelegationHop(t *testing.T) {
	const agentID, principalID = "agent-1", "principal-1"
	agentPriv, store, _ := enrolledAgent(t, agentID)

	principalPub, principalPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store.AddPrincipalKey(principalID, principalPub, time.Time{})

	// A legitimate, unconstrained root hop principal -> agent.
	chain, err := NewRoot(principalPriv, principalID, agentID, Grant{})
	if err != nil {
		t.Fatal(err)
	}

	// The attack: get the agent's instance key to sign the exact bytes of the hop the attacker
	// wants. workload.Proof no longer takes caller-chosen bytes at all — it only ever signs a
	// request binding — so the oracle is modelled at the primitive, which is the strongest
	// form of it: even a signature made under the instance-proof context over precisely the
	// hop's canonical encoding must not verify as a hop.
	forged := Hop{Delegator: agentID, Delegate: "EVIL", Grant: Grant{Tools: []string{"admin"}}}
	hopBytes := canonical(forged.Delegator, forged.Delegate, forged.Grant, chain.Hops[0].Signature)
	forged.Signature = sigctx.Sign(sigctx.InstanceProof, agentPriv, hopBytes)

	attack := Chain{Hops: append(append([]Hop(nil), chain.Hops...), forged)}
	grant, agent, err := Verify(attack, store, principalID, time.Now())
	if err == nil {
		t.Fatalf("a proof of possession was accepted as a delegation hop: agent=%q grant=%+v", agent, grant)
	}

	// And the hop the agent honestly signs still verifies, so the context did not simply
	// break delegation.
	honest, err := chain.Extend(agentPriv, "sub-agent", Grant{Tools: []string{"read"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Verify(honest, store, principalID, time.Now()); err != nil {
		t.Fatalf("an honestly signed hop must still verify: %v", err)
	}
}

func TestDelegationHopDoesNotForgeAnInstanceProof(t *testing.T) {
	const agentID, principalID = "agent-1", "principal-1"
	caPub, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	att := workload.NewTokenAttestor()
	att.Register("boot", agentID)
	authority, err := workload.NewAuthority(caPriv, "ca-1", att, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := authority.Nonce()
	if err != nil {
		t.Fatal(err)
	}
	cred, err := authority.Issue(workload.BootstrapEvidence("boot", nonce, pub), nonce, pub)
	if err != nil {
		t.Fatal(err)
	}
	credHdr, err := workload.EncodeCredential(cred)
	if err != nil {
		t.Fatal(err)
	}

	// The reverse direction: a signature this agent made as a delegation hop, presented as
	// the proof of possession for a request. The proof payload is well-formed and correct for
	// the request in every way — only the context the signature was made under differs, which
	// is exactly the property under test.
	const token = "principal-bearer-token"
	stage := workload.InstanceStage(caPub, workload.NewKeyStore(caPub))
	handle := func(proofFor func(*http.Request) string) error {
		r := httptest.NewRequest(http.MethodGet, "/servers/demo/x", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set(workload.HeaderCredential, credHdr)
		r.Header.Set(workload.HeaderProof, proofFor(r))
		req := &gateway.Request{HTTP: r, Principal: &types.Principal{ID: principalID}}
		return stage.Handle(context.Background(), req)
	}

	hopSigned := func(r *http.Request) string {
		b, err := pop.NewBinding(r.Method, pop.Target(r.URL), token, nil, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		hdr, err := pop.Sign(sigctx.DelegationHop, priv, b)
		if err != nil {
			t.Fatal(err)
		}
		return hdr
	}
	if err := handle(hopSigned); err == nil {
		t.Fatal("a delegation hop signature was accepted as an instance proof of possession")
	}

	honest := func(r *http.Request) string {
		p, err := workload.Proof(priv, r.Method, workload.ProofTarget(r.URL), token, nil)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	if err := handle(honest); err != nil {
		t.Fatalf("a real proof of possession must still be accepted: %v", err)
	}
}

// --- capability holder proof <-> capability block -------------------------------------
//
// The holder secret signs both: it proves possession to wield the capability, and it signs
// the next block when attenuating. Untagged, a holder proof over an attacker-chosen message
// is a block signature, so whoever picks the message can re-point the capability at a key
// they hold.

func TestHolderProofDoesNotForgeACapabilityBlock(t *testing.T) {
	rootPub, rootPriv := rootKeys(t)
	cap, holderSecret, err := NewCapability(rootPriv, Grant{Tools: []string{"read", "write"}})
	if err != nil {
		t.Fatal(err)
	}

	// The attacker's own key, which they want the capability to end at.
	attackerPub, attackerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// HolderProof no longer signs caller-chosen bytes — it only ever signs a request binding —
	// so the oracle is modelled at the primitive: a signature made under the holder-proof
	// context over precisely the block's signing input must still not verify as a block.
	stolenGrant := Grant{Tools: []string{"read"}}
	msg := blockMsg(rootPub, 1, cap.Blocks[0].Signature, stolenGrant, attackerPub)
	proof := sigctx.Sign(sigctx.CapabilityHolderProof, holderSecret, msg)

	// Sealed by the attacker's own key, so only the block signature's context is under test:
	// an unsealed capability would be rejected by the seal check whatever the block said.
	stolenBlocks := append(append([]Block(nil), cap.Blocks...),
		Block{Grant: stolenGrant, NextPub: attackerPub, Signature: proof})
	stolen := Capability{Blocks: stolenBlocks, Seal: seal(attackerPriv, rootPub, stolenBlocks)}
	if _, err := stolen.Verify(rootPub, time.Now()); err == nil {
		t.Fatal("a holder proof was accepted as a capability block signature")
	}

	// A genuine attenuation by the holder still verifies.
	att, _, err := cap.Attenuate(rootPub, holderSecret, stolenGrant)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := att.Verify(rootPub, time.Now()); err != nil {
		t.Fatalf("a genuine attenuation must still verify: %v", err)
	}
}

func TestCapabilityBlockSignatureDoesNotForgeAHolderProof(t *testing.T) {
	rootPub, rootPriv := rootKeys(t)
	cap, holderSecret, err := NewCapability(rootPriv, Grant{Tools: []string{"read"}})
	if err != nil {
		t.Fatal(err)
	}
	att, _, err := cap.Attenuate(rootPub, holderSecret, Grant{Tools: []string{"read"}})
	if err != nil {
		t.Fatal(err)
	}

	// The block signature the holder made, pasted into an otherwise perfectly correct proof
	// for this request. Verified against cap's final next-key, which is the key that signed
	// it, so only the context stands between the attacker and a valid holder proof.
	r, body := capHTTP()
	payload := capPayload(t, r, body)
	forged := base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(att.Blocks[1].Signature)
	if err := cap.VerifyHolder(holderVerifier(), forged, r, body, capTestToken); err == nil {
		t.Fatal("a capability block signature was accepted as a holder proof")
	}
	if err := cap.VerifyHolder(holderVerifier(), capProof(t, holderSecret, r, body), r, body, capTestToken); err != nil {
		t.Fatalf("a real holder proof must still verify: %v", err)
	}
}

// --- instance proof of possession <-> capability holder proof --------------------------
//
// Both are proofs over the same principal bearer token, presented on the same request. An
// agent that used its instance key as the capability holder secret would otherwise hand out
// a free capability holder proof with every request it makes.

func TestInstanceProofDoesNotForgeACapabilityHolderProof(t *testing.T) {
	rootPub, rootPriv := rootKeys(t)

	// The holder secret and the instance key are the same key.
	cap, holderSecret, err := NewCapability(rootPriv, Grant{Tools: []string{"read"}})
	if err != nil {
		t.Fatal(err)
	}
	capHdr, err := EncodeCapability(cap)
	if err != nil {
		t.Fatal(err)
	}

	stage := CapabilityStage(rootPub)
	handle := func(proofFor func(*http.Request) string) error {
		r, _ := capHTTP()
		r.Header.Set(HeaderCapability, capHdr)
		r.Header.Set(HeaderCapabilityProof, proofFor(r))
		req := &gateway.Request{HTTP: r, Principal: &types.Principal{ID: "p1"}}
		return stage.Handle(context.Background(), req)
	}

	// The instance proof this agent makes for the very same request: identical payload,
	// different context. That is the whole difference, and it has to be enough.
	asInstance := func(r *http.Request) string {
		p, err := workload.Proof(holderSecret, r.Method, workload.ProofTarget(r.URL), capTestToken, nil)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	if err := handle(asInstance); err == nil {
		t.Fatal("an instance proof of possession was accepted as a capability holder proof")
	}
	if err := handle(func(r *http.Request) string { return capProof(t, holderSecret, r, nil) }); err != nil {
		t.Fatalf("a real capability holder proof must still be accepted: %v", err)
	}
}

// --- delegation hop <-> capability block ----------------------------------------------
//
// A principal key roots both: NewRoot signs the first hop of a chain, NewCapability signs
// block 0 of an offline capability.

func TestDelegationHopDoesNotForgeACapabilityBlock(t *testing.T) {
	const principalID = "principal-1"
	rootPub, rootPriv := rootKeys(t)

	nextPub, nextPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	g := Grant{Tools: []string{"read"}}

	// A hop whose canonical bytes were chosen to be a block's signing input. The forged
	// capability is correctly sealed with the next-secret, so the block signature's context is
	// the only thing standing in the way.
	msg := blockMsg(rootPub, 0, nil, g, nextPub)
	chain, err := NewRoot(rootPriv, principalID, string(msg), g)
	if err != nil {
		t.Fatal(err)
	}
	forgedBlocks := []Block{{Grant: g, NextPub: nextPub, Signature: chain.Hops[0].Signature}}
	forged := Capability{Blocks: forgedBlocks, Seal: seal(nextPriv, rootPub, forgedBlocks)}
	if _, err := forged.Verify(rootPub, time.Now()); err == nil {
		t.Fatal("a delegation hop signature was accepted as a capability block signature")
	}

	// The reverse: a block signature presented as the root hop of a chain.
	cap, _, err := NewCapability(rootPriv, g)
	if err != nil {
		t.Fatal(err)
	}
	keys := MemKeyRegistry{Principals: map[string]ed25519.PublicKey{principalID: rootPub}}
	spliced := Chain{Hops: []Hop{{
		Delegator: principalID, Delegate: "agent-1", Grant: g, Signature: cap.Blocks[0].Signature,
	}}}
	if _, _, err := Verify(spliced, keys, principalID, time.Now()); err == nil {
		t.Fatal("a capability block signature was accepted as a delegation hop")
	}

	// Both still verify as themselves.
	if _, err := cap.Verify(rootPub, time.Now()); err != nil {
		t.Fatalf("a genuine capability must still verify: %v", err)
	}
	honest, err := NewRoot(rootPriv, principalID, "agent-1", g)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Verify(honest, keys, principalID, time.Now()); err != nil {
		t.Fatalf("a genuine chain must still verify: %v", err)
	}
}

// --- exchange token <-> delegation hop ------------------------------------------------
//
// Both are delegation records; an operator running the exchange authority off the same key
// it registers as a principal key would otherwise let either stand in for the other.

func TestExchangeTokenDoesNotForgeADelegationHop(t *testing.T) {
	const principalID = "principal-1"
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	exch, err := NewExchange(priv, "x-1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	g := Grant{Tools: []string{"read"}}
	tok, err := exch.IssueRoot(principalID, "agent-1", g)
	if err != nil {
		t.Fatal(err)
	}

	keys := MemKeyRegistry{Principals: map[string]ed25519.PublicKey{principalID: pub}}
	spliced := Chain{Hops: []Hop{{
		Delegator: principalID, Delegate: "agent-1", Grant: g, Signature: tok.Signature,
	}}}
	if _, _, err := Verify(spliced, keys, principalID, time.Now()); err == nil {
		t.Fatal("an exchange token signature was accepted as a delegation hop")
	}

	// The reverse, and each still verifying as itself.
	chain, err := NewRoot(priv, principalID, "agent-1", g)
	if err != nil {
		t.Fatal(err)
	}
	forged := tok
	forged.Signature = chain.Hops[0].Signature
	if err := exch.Verify(forged, time.Now()); err == nil {
		t.Fatal("a delegation hop signature was accepted as an exchange token signature")
	}
	if err := exch.Verify(tok, time.Now()); err != nil {
		t.Fatalf("a genuine exchange token must still verify: %v", err)
	}
	if _, _, err := Verify(chain, keys, principalID, time.Now()); err != nil {
		t.Fatalf("a genuine chain must still verify: %v", err)
	}
}
