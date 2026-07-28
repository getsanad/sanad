package delegation

// Tests for the two shapes a delegation must not have: too long, and looping.
//
// The point of the ceiling is not only that an over-long chain is REJECTED — it already was
// once every hop had been checked — but that it is rejected without doing the work. So the
// tests here measure the work: countingRegistry counts key resolutions, and Verify resolves
// exactly one key per hop it processes, so zero resolutions means zero Ed25519 verifications.
// Capability.Verify has no registry, so the same property is asserted through the error's
// identity: a capability whose blocks are all junk still fails with ErrTooDeep, which is only
// possible if the depth check ran before the block loop.

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/getsanad/sanad/gateway"
	"github.com/getsanad/sanad/internal/sigctx"
	"github.com/getsanad/sanad/pkg/types"
)

// countingRegistry wraps a KeyRegistry and counts how many keys were resolved — one per hop
// Verify actually got to.
type countingRegistry struct {
	inner   KeyRegistry
	lookups int
}

func (c *countingRegistry) PrincipalKey(id string) (ed25519.PublicKey, bool) {
	c.lookups++
	return c.inner.PrincipalKey(id)
}

func (c *countingRegistry) AgentKey(id string) (ed25519.PublicKey, bool) {
	c.lookups++
	return c.inner.AgentKey(id)
}

// signHop signs one hop the way NewRoot/Extend do, bypassing their input validation. Tests
// that need a chain the constructors now refuse to build (a cycle, an over-long chain) have
// to forge it exactly as an attacker sending a header would.
func signHop(t *testing.T, priv ed25519.PrivateKey, delegator, delegate string, g Grant, prevSig []byte) Hop {
	t.Helper()
	return Hop{
		Delegator: delegator, Delegate: delegate, Grant: g,
		Signature: sigctx.Sign(sigctx.DelegationHop, priv, canonical(delegator, delegate, g, prevSig)),
	}
}

// --- chain depth ----------------------------------------------------------------------

// TestOverLongChainIsRejectedWithoutVerifyingIt is the amplification PoC. A 1 MiB header
// holds ~4000 hops, and checking them measured ~113ms of pre-authorization CPU per request.
// The chain here is the same size; the assertion is that it now costs zero signature
// verifications, not that it is merely denied.
func TestOverLongChainIsRejectedWithoutVerifyingIt(t *testing.T) {
	const hops = 4001
	principal := newParty(t, "principal-1")
	keys := &countingRegistry{inner: registry(principal)}

	// Distinct delegates, so it is the LENGTH that is refused and not the cycle rule. The
	// signatures are junk: reaching them at all is the failure this test is about.
	chain := Chain{Hops: make([]Hop, 0, hops)}
	chain.Hops = append(chain.Hops, Hop{Delegator: principal.id, Delegate: "a0", Signature: []byte("junk")})
	for i := 1; i < hops; i++ {
		chain.Hops = append(chain.Hops, Hop{
			Delegator: fmt.Sprintf("a%d", i-1), Delegate: fmt.Sprintf("a%d", i), Signature: []byte("junk"),
		})
	}

	start := time.Now()
	_, _, err := Verify(chain, keys, principal.id, time.Now())
	elapsed := time.Since(start)

	if !errors.Is(err, ErrTooDeep) {
		t.Fatalf("a %d-hop chain must be rejected as too deep, got %v", hops, err)
	}
	if keys.lookups != 0 {
		t.Fatalf("rejection resolved %d delegator keys; it must refuse the chain before verifying any hop", keys.lookups)
	}
	t.Logf("%d hops rejected in %v with %d key resolutions (was ~113ms and %d)", hops, elapsed, keys.lookups, hops)
}

func TestChainAtTheCeilingStillVerifies(t *testing.T) {
	// MaxDepth hops, all honestly signed and non-widening: the ceiling is inclusive.
	parties := []party{newParty(t, "principal-1")}
	for i := 1; i <= MaxDepth; i++ {
		parties = append(parties, newParty(t, fmt.Sprintf("a%d", i)))
	}
	keys := registry(parties[0], parties[1:]...)
	grants := make([]Grant, MaxDepth)
	for i := range grants {
		grants[i] = Grant{Tools: []string{"read"}}
	}

	chain := buildChain(t, parties, grants)
	if len(chain.Hops) != MaxDepth {
		t.Fatalf("expected %d hops, got %d", MaxDepth, len(chain.Hops))
	}
	if _, acting, err := Verify(chain, keys, parties[0].id, time.Now()); err != nil {
		t.Fatalf("a %d-hop chain is at the ceiling and must verify: %v", MaxDepth, err)
	} else if acting != fmt.Sprintf("a%d", MaxDepth) {
		t.Fatalf("acting agent = %q", acting)
	}
}

// TestChainOneOverTheCeilingIsRejected pins the boundary from the other side: MaxDepth+1
// hops, all honestly signed, all narrowing. Nothing but the ceiling refuses it.
func TestChainOneOverTheCeilingIsRejected(t *testing.T) {
	parties := []party{newParty(t, "principal-1")}
	for i := 1; i <= MaxDepth+1; i++ {
		parties = append(parties, newParty(t, fmt.Sprintf("a%d", i)))
	}
	grants := make([]Grant, MaxDepth)
	for i := range grants {
		grants[i] = Grant{Tools: []string{"read"}}
	}
	chain := buildChain(t, parties[:MaxDepth+1], grants)

	// Extend refuses to build hop MaxDepth+1, so forge it the way a caller sending the header
	// would: signed by the real holder, over the real previous signature.
	holder, next := parties[MaxDepth], parties[MaxDepth+1]
	last := chain.Hops[len(chain.Hops)-1]
	chain.Hops = append(chain.Hops,
		signHop(t, holder.priv, holder.id, next.id, Grant{Tools: []string{"read"}}, last.Signature))

	keys := &countingRegistry{inner: registry(parties[0], parties[1:]...)}
	if _, _, err := Verify(chain, keys, parties[0].id, time.Now()); !errors.Is(err, ErrTooDeep) {
		t.Fatalf("a chain one hop past the ceiling must be rejected as too deep, got %v", err)
	}
	if keys.lookups != 0 {
		t.Fatalf("rejection resolved %d delegator keys, want 0", keys.lookups)
	}
}

func TestExtendRefusesToPassTheCeiling(t *testing.T) {
	parties := []party{newParty(t, "principal-1")}
	for i := 1; i <= MaxDepth; i++ {
		parties = append(parties, newParty(t, fmt.Sprintf("a%d", i)))
	}
	grants := make([]Grant, MaxDepth)
	for i := range grants {
		grants[i] = Grant{Tools: []string{"read"}}
	}
	chain := buildChain(t, parties, grants)

	if _, err := chain.Extend(parties[MaxDepth].priv, "one-too-many", Grant{Tools: []string{"read"}}); !errors.Is(err, ErrTooDeep) {
		t.Fatalf("Extend past the ceiling must fail with ErrTooDeep, got %v", err)
	}
}

func TestDecodeChainRefusesAnOverLongChain(t *testing.T) {
	// The transport boundary refuses it too, so a header full of hops is not carried further
	// into the pipeline just because some caller forgot to verify it.
	chain := Chain{Hops: make([]Hop, MaxDepth+1)}
	enc, err := EncodeChain(chain)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeChain(enc); !errors.Is(err, ErrTooDeep) {
		t.Fatalf("DecodeChain must refuse an over-long chain, got %v", err)
	}
}

// --- cycles / self-delegation ----------------------------------------------------------

// TestSelfDelegationIsRejected: A -> A is the shape the amplification PoC repeated 4000
// times, and it verified cleanly. The hop here is signed correctly by the real a1 key, so
// nothing but the cycle rule stands between it and acceptance.
func TestSelfDelegationIsRejected(t *testing.T) {
	principal := newParty(t, "principal-1")
	a1 := newParty(t, "a1")
	keys := registry(principal, a1)

	root, err := NewRoot(principal.priv, principal.id, a1.id, Grant{Tools: []string{"read"}})
	if err != nil {
		t.Fatal(err)
	}
	chain := Chain{Hops: append(append([]Hop(nil), root.Hops...),
		signHop(t, a1.priv, a1.id, a1.id, Grant{Tools: []string{"read"}}, root.Hops[0].Signature))}

	_, _, err = Verify(chain, keys, principal.id, time.Now())
	if !errors.Is(err, ErrCycle) {
		t.Fatalf("a self-delegation hop must be rejected as a cycle, got %v", err)
	}
}

// TestCycleBackToAnEarlierPartyIsRejected: a1 -> a2 -> a1 returns authority to a party that
// already holds it. Every hop is honestly signed and every hop attenuates.
func TestCycleBackToAnEarlierPartyIsRejected(t *testing.T) {
	principal := newParty(t, "principal-1")
	a1 := newParty(t, "a1")
	a2 := newParty(t, "a2")
	keys := registry(principal, a1, a2)

	g := Grant{Tools: []string{"read"}}
	root, err := NewRoot(principal.priv, principal.id, a1.id, g)
	if err != nil {
		t.Fatal(err)
	}
	h1 := signHop(t, a1.priv, a1.id, a2.id, g, root.Hops[0].Signature)
	h2 := signHop(t, a2.priv, a2.id, a1.id, g, h1.Signature)

	chain := Chain{Hops: []Hop{root.Hops[0], h1, h2}}
	if _, _, err := Verify(chain, keys, principal.id, time.Now()); !errors.Is(err, ErrCycle) {
		t.Fatalf("a chain that loops back to an earlier party must be rejected, got %v", err)
	}
}

// TestCycleBackToThePrincipalIsRejected: the root delegator counts as a party too.
func TestCycleBackToThePrincipalIsRejected(t *testing.T) {
	principal := newParty(t, "principal-1")
	a1 := newParty(t, "a1")
	keys := registry(principal, a1)

	g := Grant{Tools: []string{"read"}}
	root, err := NewRoot(principal.priv, principal.id, a1.id, g)
	if err != nil {
		t.Fatal(err)
	}
	chain := Chain{Hops: append(append([]Hop(nil), root.Hops...),
		signHop(t, a1.priv, a1.id, principal.id, g, root.Hops[0].Signature))}

	if _, _, err := Verify(chain, keys, principal.id, time.Now()); !errors.Is(err, ErrCycle) {
		t.Fatalf("delegating back to the root principal must be rejected, got %v", err)
	}
}

func TestConstructorsRefuseCycles(t *testing.T) {
	principal := newParty(t, "principal-1")
	a1 := newParty(t, "a1")

	if _, err := NewRoot(principal.priv, principal.id, principal.id, Grant{}); !errors.Is(err, ErrCycle) {
		t.Fatalf("NewRoot must refuse a self-delegation, got %v", err)
	}
	root, err := NewRoot(principal.priv, principal.id, a1.id, Grant{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := root.Extend(a1.priv, a1.id, Grant{}); !errors.Is(err, ErrCycle) {
		t.Fatalf("Extend must refuse a self-delegation, got %v", err)
	}
	if _, err := root.Extend(a1.priv, principal.id, Grant{}); !errors.Is(err, ErrCycle) {
		t.Fatalf("Extend must refuse delegating back to the root principal, got %v", err)
	}
}

// --- capability depth -------------------------------------------------------------------

// TestOverLongCapabilityIsRejectedBeforeAnyBlockIsChecked: block 0 is genuine, every later
// block is junk. If the block loop ran first the error would name block 1's signature; that
// it is ErrTooDeep is the proof that the ceiling is checked before the work.
func TestOverLongCapabilityIsRejectedBeforeAnyBlockIsChecked(t *testing.T) {
	rootPub, rootPriv := rootKeys(t)
	c, _, err := NewCapability(rootPriv, Grant{Tools: []string{"read"}})
	if err != nil {
		t.Fatal(err)
	}
	junkPub, _ := rootKeys(t)
	for len(c.Blocks) <= MaxDepth {
		c.Blocks = append(c.Blocks, Block{Grant: Grant{Tools: []string{"read"}}, NextPub: junkPub, Signature: []byte("junk")})
	}

	_, err = c.Verify(rootPub, time.Now())
	if !errors.Is(err, ErrTooDeep) {
		t.Fatalf("a capability past the ceiling must be rejected as too deep, got %v", err)
	}
	if strings.Contains(err.Error(), "signature") {
		t.Fatalf("the depth check must run before any block signature check, got %v", err)
	}
}

func TestCapabilityAtTheCeilingStillVerifies(t *testing.T) {
	rootPub, rootPriv := rootKeys(t)
	c, secret, err := NewCapability(rootPriv, Grant{Tools: []string{"read", "write"}})
	if err != nil {
		t.Fatal(err)
	}
	for len(c.Blocks) < MaxDepth {
		c, secret, err = c.Attenuate(rootPub, secret, Grant{Tools: []string{"read"}})
		if err != nil {
			t.Fatalf("attenuating to %d blocks: %v", len(c.Blocks)+1, err)
		}
	}
	if len(c.Blocks) != MaxDepth {
		t.Fatalf("expected %d blocks, got %d", MaxDepth, len(c.Blocks))
	}
	g, err := c.Verify(rootPub, time.Now())
	if err != nil {
		t.Fatalf("a capability at the ceiling must verify: %v", err)
	}
	if len(g.Tools) != 1 || g.Tools[0] != "read" {
		t.Fatalf("effective grant = %v", g.Tools)
	}
	if _, _, err := c.Attenuate(rootPub, secret, Grant{Tools: []string{"read"}}); !errors.Is(err, ErrTooDeep) {
		t.Fatalf("Attenuate past the ceiling must fail with ErrTooDeep, got %v", err)
	}
}

// --- the knob -----------------------------------------------------------------------------

// TestWithMaxDepthOnlyTightens: a deployment may refuse chains shorter than the ceiling, but
// nothing it passes can raise the ceiling — that is the DoS bound, not a preference.
func TestWithMaxDepthOnlyTightens(t *testing.T) {
	parties := []party{newParty(t, "principal-1"), newParty(t, "a1"), newParty(t, "a2"), newParty(t, "a3")}
	keys := registry(parties[0], parties[1:]...)
	g := Grant{Tools: []string{"read"}}
	chain := buildChain(t, parties, []Grant{g, g, g})

	if _, _, err := Verify(chain, keys, parties[0].id, time.Now()); err != nil {
		t.Fatalf("3 hops is under the ceiling and must verify: %v", err)
	}
	if _, _, err := Verify(chain, keys, parties[0].id, time.Now(), WithMaxDepth(2)); !errors.Is(err, ErrTooDeep) {
		t.Fatalf("WithMaxDepth(2) must reject a 3-hop chain, got %v", err)
	}
	if _, _, err := Verify(chain, keys, parties[0].id, time.Now(), WithMaxDepth(3)); err != nil {
		t.Fatalf("WithMaxDepth(3) must accept a 3-hop chain: %v", err)
	}

	// Raising is a no-op: the over-long chain is still refused at MaxDepth.
	over := Chain{Hops: make([]Hop, MaxDepth+1)}
	for _, n := range []int{0, -1, MaxDepth + 1, 1 << 20} {
		if _, _, err := Verify(over, keys, parties[0].id, time.Now(), WithMaxDepth(n)); !errors.Is(err, ErrTooDeep) {
			t.Fatalf("WithMaxDepth(%d) must not raise the ceiling, got %v", n, err)
		}
	}
}

// TestStageForwardsTheDepthCeiling: the knob reaches the stage, which is where a deployment
// configures it.
func TestStageForwardsTheDepthCeiling(t *testing.T) {
	parties := []party{newParty(t, "principal-1"), newParty(t, "a1"), newParty(t, "a2")}
	keys := registry(parties[0], parties[1:]...)
	g := Grant{Tools: []string{"read"}}
	chain := buildChain(t, parties, []Grant{g, g})
	newReq := func() *gateway.Request {
		return &gateway.Request{Principal: &types.Principal{ID: parties[0].id}}
	}

	capped := Stage(keys, staticChain(chain, nil), WithVerifyOptions(WithMaxDepth(1)))
	req := newReq()
	if err := capped.Handle(context.Background(), req); !errors.Is(err, ErrTooDeep) {
		t.Fatalf("a stage capped at 1 hop must reject a 2-hop chain, got %v", err)
	}
	if req.Scope.Tools != nil {
		t.Fatalf("a rejected request must carry no scope: %v", req.Scope.Tools)
	}
	if err := Stage(keys, staticChain(chain, nil)).Handle(context.Background(), newReq()); err != nil {
		t.Fatalf("the same chain must pass at the default ceiling: %v", err)
	}
}

func TestDecodeCapabilityRefusesAnOverLongCapability(t *testing.T) {
	c := Capability{Blocks: make([]Block, MaxDepth+1)}
	enc, err := EncodeCapability(c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeCapability(enc); !errors.Is(err, ErrTooDeep) {
		t.Fatalf("DecodeCapability must refuse an over-long capability, got %v", err)
	}
}
