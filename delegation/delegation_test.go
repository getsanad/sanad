package delegation

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/getsanad/sanad/pkg/types"
)

type party struct {
	id   string
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func newParty(t *testing.T, id string) party {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return party{id: id, pub: pub, priv: priv}
}

func registry(parties ...party) MemKeyRegistry {
	m := MemKeyRegistry{}
	for _, p := range parties {
		m[p.id] = p.pub
	}
	return m
}

func TestSingleHopVerifies(t *testing.T) {
	principal := newParty(t, "principal-1")
	agent := newParty(t, "agent-1")
	keys := registry(principal, agent)

	g := Grant{Tools: []string{"read", "write"}, Servers: []string{"s1"}, NotAfter: time.Now().Add(time.Hour)}
	chain, err := NewRoot(principal.priv, principal.id, agent.id, g)
	if err != nil {
		t.Fatal(err)
	}

	eff, acting, err := Verify(chain, keys, principal.id, time.Now())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if acting != "agent-1" {
		t.Fatalf("acting agent = %q, want agent-1", acting)
	}
	if len(eff.Tools) != 2 {
		t.Fatalf("effective tools = %v", eff.Tools)
	}
}

func TestMultiHopNarrowingVerifies(t *testing.T) {
	principal := newParty(t, "principal-1")
	a1 := newParty(t, "agent-1")
	a2 := newParty(t, "agent-2")
	keys := registry(principal, a1, a2)

	now := time.Now()
	root, _ := NewRoot(principal.priv, principal.id, a1.id, Grant{
		Tools: []string{"read", "write"}, Servers: []string{"s1", "s2"}, NotAfter: now.Add(time.Hour),
	})
	chain, err := root.Extend(a1.priv, a2.id, Grant{
		Tools: []string{"read"}, Servers: []string{"s1"}, NotAfter: now.Add(30 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}

	eff, acting, err := Verify(chain, keys, principal.id, now)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if acting != "agent-2" || len(eff.Tools) != 1 || eff.Tools[0] != "read" {
		t.Fatalf("effective grant wrong: agent=%q tools=%v", acting, eff.Tools)
	}
}

func TestWideningRejected(t *testing.T) {
	principal := newParty(t, "principal-1")
	a1 := newParty(t, "agent-1")
	a2 := newParty(t, "agent-2")
	keys := registry(principal, a1, a2)

	root, _ := NewRoot(principal.priv, principal.id, a1.id, Grant{Tools: []string{"read"}})
	// a1 tries to grant a2 "write", which it was never granted.
	chain, _ := root.Extend(a1.priv, a2.id, Grant{Tools: []string{"read", "write"}})

	if _, _, err := Verify(chain, keys, principal.id, time.Now()); err == nil {
		t.Fatal("widening tools must be rejected (attenuation-only)")
	}
}

func TestForgedSignatureRejected(t *testing.T) {
	principal := newParty(t, "principal-1")
	agent := newParty(t, "agent-1")
	keys := registry(principal, agent)

	chain, _ := NewRoot(principal.priv, principal.id, agent.id, Grant{Tools: []string{"read"}})
	chain.Hops[0].Signature[0] ^= 0x01 // tamper

	if _, _, err := Verify(chain, keys, principal.id, time.Now()); err == nil {
		t.Fatal("forged signature must be rejected")
	}
}

func TestImpersonationRejected(t *testing.T) {
	principal := newParty(t, "principal-1")
	a1 := newParty(t, "agent-1")
	a2 := newParty(t, "agent-2")
	attacker := newParty(t, "agent-1") // same id, different key (impostor)
	keys := registry(principal, a1, a2)

	root, _ := NewRoot(principal.priv, principal.id, a1.id, Grant{Tools: []string{"read"}})
	// The attacker (not the real a1) signs the extension with its own key.
	chain, _ := root.Extend(attacker.priv, a2.id, Grant{Tools: []string{"read"}})

	if _, _, err := Verify(chain, keys, principal.id, time.Now()); err == nil {
		t.Fatal("a hop signed by an impostor key must be rejected (FR-13)")
	}
}

func TestUnknownDelegatorKeyRejected(t *testing.T) {
	principal := newParty(t, "principal-1")
	agent := newParty(t, "agent-1")
	keys := registry(agent) // principal key missing

	chain, _ := NewRoot(principal.priv, principal.id, agent.id, Grant{Tools: []string{"read"}})
	if _, _, err := Verify(chain, keys, principal.id, time.Now()); err == nil {
		t.Fatal("a hop whose delegator key is unknown must be rejected")
	}
}

func TestWrongRootRejected(t *testing.T) {
	principal := newParty(t, "principal-1")
	agent := newParty(t, "agent-1")
	keys := registry(principal, agent)

	chain, _ := NewRoot(principal.priv, principal.id, agent.id, Grant{Tools: []string{"read"}})
	if _, _, err := Verify(chain, keys, "different-principal", time.Now()); err == nil {
		t.Fatal("chain whose root is not the principal must be rejected")
	}
}

func TestExpiredRejected(t *testing.T) {
	principal := newParty(t, "principal-1")
	agent := newParty(t, "agent-1")
	keys := registry(principal, agent)

	chain, _ := NewRoot(principal.priv, principal.id, agent.id, Grant{NotAfter: time.Now().Add(-time.Minute)})
	if _, _, err := Verify(chain, keys, principal.id, time.Now()); err == nil {
		t.Fatal("expired hop must be rejected")
	}
}

func TestBudgetAttenuation(t *testing.T) {
	parent := Grant{Budget: &types.Budget{Limit: 100, Unit: "usd"}}
	if err := attenuates(parent, Grant{Budget: &types.Budget{Limit: 50, Unit: "usd"}}); err != nil {
		t.Fatalf("lowering budget should be allowed: %v", err)
	}
	if err := attenuates(parent, Grant{Budget: &types.Budget{Limit: 200, Unit: "usd"}}); err == nil {
		t.Fatal("raising budget must be rejected")
	}
	if err := attenuates(parent, Grant{}); err == nil {
		t.Fatal("removing a budget constraint must be rejected")
	}
}
