package delegation

import (
	"bytes"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/getsanad/sanad/internal/sigctx"
	"github.com/getsanad/sanad/pkg/types"
)

// buildChain signs a chain through the given ordered grants. parties[0] is the principal
// (root delegator); each subsequent party is the delegate of the prior hop. len(grants)
// must equal len(parties)-1. Returns the signed chain.
func buildChain(t *testing.T, parties []party, grants []Grant) Chain {
	t.Helper()
	if len(grants) != len(parties)-1 {
		t.Fatalf("buildChain: need %d grants for %d parties, got %d", len(parties)-1, len(parties), len(grants))
	}
	chain, err := NewRoot(parties[0].priv, parties[0].id, parties[1].id, grants[0])
	if err != nil {
		t.Fatalf("NewRoot: %v", err)
	}
	for i := 1; i < len(grants); i++ {
		chain, err = chain.Extend(parties[i].priv, parties[i+1].id, grants[i])
		if err != nil {
			t.Fatalf("Extend hop %d: %v", i, err)
		}
	}
	return chain
}

// --- empty / single / deep chains ---------------------------------------------------

func TestVerifyEmptyChainRejected(t *testing.T) {
	if _, _, err := Verify(Chain{}, MemKeyRegistry{}, "principal-1", time.Now()); err == nil {
		t.Fatal("an empty chain must be rejected")
	}
}

func TestDeepChainAllNarrowingVerifies(t *testing.T) {
	// 5 hops, principal -> a1 -> a2 -> a3 -> a4 -> a5, each strictly narrowing.
	now := time.Now()
	parties := []party{
		newParty(t, "principal-1"),
		newParty(t, "a1"), newParty(t, "a2"), newParty(t, "a3"),
		newParty(t, "a4"), newParty(t, "a5"),
	}
	keys := registry(parties[0], parties[1:]...)
	grants := []Grant{
		{Tools: []string{"read", "write", "delete", "list", "stat"}, Servers: []string{"s1", "s2", "s3"}, NotAfter: now.Add(5 * time.Hour), Budget: &types.Budget{Limit: 1000, Unit: "usd"}},
		{Tools: []string{"read", "write", "delete", "list"}, Servers: []string{"s1", "s2"}, NotAfter: now.Add(4 * time.Hour), Budget: &types.Budget{Limit: 800, Unit: "usd"}},
		{Tools: []string{"read", "write", "list"}, Servers: []string{"s1", "s2"}, NotAfter: now.Add(3 * time.Hour), Budget: &types.Budget{Limit: 500, Unit: "usd"}},
		{Tools: []string{"read", "list"}, Servers: []string{"s1"}, NotAfter: now.Add(2 * time.Hour), Budget: &types.Budget{Limit: 200, Unit: "usd"}},
		{Tools: []string{"read"}, Servers: []string{"s1"}, NotAfter: now.Add(time.Hour), Budget: &types.Budget{Limit: 50, Unit: "usd"}},
	}
	chain := buildChain(t, parties, grants)
	if len(chain.Hops) != 5 {
		t.Fatalf("expected 5 hops, got %d", len(chain.Hops))
	}

	eff, acting, err := Verify(chain, keys, parties[0].id, now)
	if err != nil {
		t.Fatalf("deep narrowing chain must verify: %v", err)
	}
	if acting != "a5" {
		t.Fatalf("acting agent = %q, want a5", acting)
	}
	if len(eff.Tools) != 1 || eff.Tools[0] != "read" {
		t.Fatalf("effective tools = %v, want [read]", eff.Tools)
	}
	if eff.Budget == nil || eff.Budget.Limit != 50 {
		t.Fatalf("effective budget = %+v, want limit 50", eff.Budget)
	}
}

// --- wildcard semantics --------------------------------------------------------------

func TestWildcardParentToConcreteChildAllowed(t *testing.T) {
	// Parent (root) grants no tool constraint (wildcard); child narrows to a concrete set.
	principal := newParty(t, "principal-1")
	a1 := newParty(t, "a1")
	a2 := newParty(t, "a2")
	keys := registry(principal, a1, a2)

	chain := buildChain(t, []party{principal, a1, a2}, []Grant{
		{}, // wildcard tools+servers
		{Tools: []string{"read"}, Servers: []string{"s1"}},
	})
	eff, acting, err := Verify(chain, keys, principal.id, time.Now())
	if err != nil {
		t.Fatalf("wildcard parent -> concrete child must verify: %v", err)
	}
	if acting != "a2" || len(eff.Tools) != 1 {
		t.Fatalf("effective grant wrong: agent=%q tools=%v", acting, eff.Tools)
	}
}

func TestConcreteParentToWildcardChildRejected(t *testing.T) {
	// Parent has concrete tools; child clears them back to wildcard -> widening.
	principal := newParty(t, "principal-1")
	a1 := newParty(t, "a1")
	a2 := newParty(t, "a2")
	keys := registry(principal, a1, a2)

	chain := buildChain(t, []party{principal, a1, a2}, []Grant{
		{Tools: []string{"read", "write"}},
		{}, // empty tools = wildcard, widens the concrete parent
	})
	if _, _, err := Verify(chain, keys, principal.id, time.Now()); err == nil {
		t.Fatal("clearing a concrete tool set back to wildcard must be rejected as widening")
	}
}

func TestServerSetSubsetRules(t *testing.T) {
	principal := newParty(t, "principal-1")
	a1 := newParty(t, "a1")
	a2 := newParty(t, "a2")
	keys := registry(principal, a1, a2)

	tests := []struct {
		name      string
		parentSrv []string
		childSrv  []string
		wantErr   bool
	}{
		{"subset allowed", []string{"s1", "s2"}, []string{"s1"}, false},
		{"equal allowed", []string{"s1", "s2"}, []string{"s1", "s2"}, false},
		{"superset rejected", []string{"s1"}, []string{"s1", "s2"}, true},
		{"unrelated rejected", []string{"s1"}, []string{"s9"}, true},
		{"concrete to wildcard rejected", []string{"s1"}, nil, true},
		{"wildcard parent any child", nil, []string{"s1", "s2"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			chain := buildChain(t, []party{principal, a1, a2}, []Grant{
				{Servers: tc.parentSrv},
				{Servers: tc.childSrv},
			})
			_, _, err := Verify(chain, keys, principal.id, time.Now())
			if tc.wantErr && err == nil {
				t.Fatalf("servers %v -> %v should be rejected", tc.parentSrv, tc.childSrv)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("servers %v -> %v should be allowed: %v", tc.parentSrv, tc.childSrv, err)
			}
		})
	}
}

func TestDuplicateToolsInChildAccepted(t *testing.T) {
	// Duplicate entries in the child set are all members of the parent, so they narrow fine.
	principal := newParty(t, "principal-1")
	a1 := newParty(t, "a1")
	a2 := newParty(t, "a2")
	keys := registry(principal, a1, a2)

	chain := buildChain(t, []party{principal, a1, a2}, []Grant{
		{Tools: []string{"read", "write"}},
		{Tools: []string{"read", "read", "read"}},
	})
	if _, _, err := Verify(chain, keys, principal.id, time.Now()); err != nil {
		t.Fatalf("duplicate (but granted) tools should not be rejected: %v", err)
	}
}

// --- budget attenuation through Verify ----------------------------------------------

func TestBudgetEdgeCasesThroughVerify(t *testing.T) {
	principal := newParty(t, "principal-1")
	a1 := newParty(t, "a1")
	a2 := newParty(t, "a2")
	keys := registry(principal, a1, a2)

	tests := []struct {
		name    string
		parent  *types.Budget
		child   *types.Budget
		wantErr bool
	}{
		{"lowered ok", &types.Budget{Limit: 100, Unit: "usd"}, &types.Budget{Limit: 50, Unit: "usd"}, false},
		{"equal ok", &types.Budget{Limit: 100, Unit: "usd"}, &types.Budget{Limit: 100, Unit: "usd"}, false},
		{"raised rejected", &types.Budget{Limit: 100, Unit: "usd"}, &types.Budget{Limit: 200, Unit: "usd"}, true},
		{"removed rejected", &types.Budget{Limit: 100, Unit: "usd"}, nil, true},
		{"unit mismatch rejected", &types.Budget{Limit: 100, Unit: "usd"}, &types.Budget{Limit: 10, Unit: "eur"}, true},
		{"added when parent had none ok", nil, &types.Budget{Limit: 10, Unit: "usd"}, false},
		{"both none ok", nil, nil, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			chain := buildChain(t, []party{principal, a1, a2}, []Grant{
				{Budget: tc.parent},
				{Budget: tc.child},
			})
			_, _, err := Verify(chain, keys, principal.id, time.Now())
			if tc.wantErr && err == nil {
				t.Fatalf("budget %+v -> %+v should be rejected", tc.parent, tc.child)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("budget %+v -> %+v should be allowed: %v", tc.parent, tc.child, err)
			}
		})
	}
}

// --- NotAfter narrowing / widening / boundary ---------------------------------------

func TestNotAfterNarrowingAndWidening(t *testing.T) {
	principal := newParty(t, "principal-1")
	a1 := newParty(t, "a1")
	a2 := newParty(t, "a2")
	keys := registry(principal, a1, a2)
	now := time.Now()

	tests := []struct {
		name    string
		parent  time.Time
		child   time.Time
		wantErr bool
	}{
		{"narrowed earlier ok", now.Add(2 * time.Hour), now.Add(time.Hour), false},
		{"equal ok", now.Add(time.Hour), now.Add(time.Hour), false},
		{"widened later rejected", now.Add(time.Hour), now.Add(2 * time.Hour), true},
		{"child unbounded rejected", now.Add(time.Hour), time.Time{}, true},
		{"parent unbounded child bounded ok", time.Time{}, now.Add(time.Hour), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			chain := buildChain(t, []party{principal, a1, a2}, []Grant{
				{NotAfter: tc.parent},
				{NotAfter: tc.child},
			})
			_, _, err := Verify(chain, keys, principal.id, now)
			if tc.wantErr && err == nil {
				t.Fatalf("NotAfter %v -> %v should be rejected", tc.parent, tc.child)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("NotAfter %v -> %v should be allowed: %v", tc.parent, tc.child, err)
			}
		})
	}
}

func TestExpiryBoundaryIsDenyOnEquality(t *testing.T) {
	// Verify uses !now.Before(NotAfter): exactly at NotAfter is expired (deny-on-boundary).
	principal := newParty(t, "principal-1")
	agent := newParty(t, "a1")
	keys := registry(principal, agent)

	exp := time.Now().Add(time.Hour)
	chain, _ := NewRoot(principal.priv, principal.id, agent.id, Grant{NotAfter: exp})

	if _, _, err := Verify(chain, keys, principal.id, exp.Add(-time.Nanosecond)); err != nil {
		t.Fatalf("just before expiry should verify: %v", err)
	}
	if _, _, err := Verify(chain, keys, principal.id, exp); err == nil {
		t.Fatal("exactly at expiry must be rejected (deny-on-boundary)")
	}
	if _, _, err := Verify(chain, keys, principal.id, exp.Add(time.Nanosecond)); err == nil {
		t.Fatal("after expiry must be rejected")
	}
}

// --- structural attacks: reorder / splice / continuity ------------------------------

func TestHopReorderDetected(t *testing.T) {
	// Swapping two valid hops breaks both signature binding (prevSig) and continuity.
	principal := newParty(t, "principal-1")
	a1 := newParty(t, "a1")
	a2 := newParty(t, "a2")
	keys := registry(principal, a1, a2)

	chain := buildChain(t, []party{principal, a1, a2}, []Grant{
		{Tools: []string{"read", "write"}},
		{Tools: []string{"read"}},
	})
	chain.Hops[0], chain.Hops[1] = chain.Hops[1], chain.Hops[0]

	if _, _, err := Verify(chain, keys, principal.id, time.Now()); err == nil {
		t.Fatal("reordered hops must be rejected")
	}
}

func TestHopSpliceFromOtherChainDetected(t *testing.T) {
	// Take a legitimately signed hop from a second chain and splice it onto the first.
	// Its signature was bound to a different previous signature, so it must fail.
	principal := newParty(t, "principal-1")
	a1 := newParty(t, "a1")
	a2 := newParty(t, "a2")
	keys := registry(principal, a1, a2)

	good := buildChain(t, []party{principal, a1}, []Grant{{Tools: []string{"read"}}})

	// Independent chain whose root hop carries a different grant, so its first signature
	// (and therefore the prevSig that hop 1 is bound to) differs from good.Hops[0].
	other := buildChain(t, []party{principal, a1, a2}, []Grant{
		{Tools: []string{"read", "write"}}, {Tools: []string{"read"}},
	})
	spliced := Chain{Hops: []Hop{good.Hops[0], other.Hops[1]}}

	if _, _, err := Verify(spliced, keys, principal.id, time.Now()); err == nil {
		t.Fatal("a hop spliced from another chain must be rejected (prev-sig binding)")
	}
}

func TestContinuityBreakDelegatorMismatch(t *testing.T) {
	// Forge a middle hop whose Delegator is not the previous hop's Delegate.
	principal := newParty(t, "principal-1")
	a1 := newParty(t, "a1")
	a2 := newParty(t, "a2")
	a3 := newParty(t, "a3")
	keys := registry(principal, a1, a2, a3)

	chain := buildChain(t, []party{principal, a1, a2, a3}, []Grant{
		{Tools: []string{"read"}}, {Tools: []string{"read"}}, {Tools: []string{"read"}},
	})
	// Rewrite hop 2's delegator to a1 (it should be a2). Re-sign with a1's key so the
	// signature itself is valid, isolating the continuity check.
	chain.Hops[2].Delegator = a1.id
	chain.Hops[2].Signature = sigctx.Sign(sigctx.DelegationHop, a1.priv,
		canonical(a1.id, chain.Hops[2].Delegate, chain.Hops[2].Grant, chain.Hops[1].Signature))

	if _, _, err := Verify(chain, keys, principal.id, time.Now()); err == nil {
		t.Fatal("a delegator that does not hold the prior delegation must be rejected")
	}
}

// --- forged / impostor signatures at each position ----------------------------------

func TestForgedSignatureAtEachHop(t *testing.T) {
	for _, pos := range []int{0, 1, 2} {
		pos := pos
		t.Run([]string{"first", "middle", "last"}[pos], func(t *testing.T) {
			principal := newParty(t, "principal-1")
			a1 := newParty(t, "a1")
			a2 := newParty(t, "a2")
			a3 := newParty(t, "a3")
			keys := registry(principal, a1, a2, a3)

			chain := buildChain(t, []party{principal, a1, a2, a3}, []Grant{
				{Tools: []string{"read"}}, {Tools: []string{"read"}}, {Tools: []string{"read"}},
			})
			chain.Hops[pos].Signature[0] ^= 0xFF // corrupt

			if _, _, err := Verify(chain, keys, principal.id, time.Now()); err == nil {
				t.Fatalf("forged signature at hop %d must be rejected", pos)
			}
		})
	}
}

func TestImpostorKeySameIDDifferentKey(t *testing.T) {
	// The registry holds the real principal key; the chain is signed by an impostor
	// holding the same id but a different key. Verify must reject.
	realPrincipal := newParty(t, "principal-1")
	impostor := newParty(t, "principal-1") // same id, different key
	agent := newParty(t, "a1")
	keys := registry(realPrincipal, agent)

	chain, _ := NewRoot(impostor.priv, impostor.id, agent.id, Grant{Tools: []string{"read"}})
	if _, _, err := Verify(chain, keys, "principal-1", time.Now()); err == nil {
		t.Fatal("a hop signed by an impostor key (same id) must be rejected")
	}
}

// --- Extend / NewRoot input validation ----------------------------------------------

func TestExtendEmptyChainErrors(t *testing.T) {
	a := newParty(t, "a1")
	if _, err := (Chain{}).Extend(a.priv, "a2", Grant{}); err == nil {
		t.Fatal("Extend on an empty chain must error")
	}
}

func TestNewRootInvalidKeyErrors(t *testing.T) {
	if _, err := NewRoot(ed25519.PrivateKey{1, 2, 3}, "p", "a", Grant{}); err == nil {
		t.Fatal("NewRoot with an undersized key must error")
	}
}

func TestExtendInvalidHolderKeyErrors(t *testing.T) {
	principal := newParty(t, "principal-1")
	a1 := newParty(t, "a1")
	chain, _ := NewRoot(principal.priv, principal.id, a1.id, Grant{})
	if _, err := chain.Extend(ed25519.PrivateKey{1, 2, 3}, "a2", Grant{}); err == nil {
		t.Fatal("Extend with an undersized holder key must error")
	}
}

// --- ToTypes fidelity ----------------------------------------------------------------

func TestToTypesMappingFidelity(t *testing.T) {
	principal := newParty(t, "principal-1")
	a1 := newParty(t, "a1")
	a2 := newParty(t, "a2")

	budget := &types.Budget{Limit: 100, Unit: "usd"}
	chain := buildChain(t, []party{principal, a1, a2}, []Grant{
		{Tools: []string{"read", "write"}, Servers: []string{"s1"}, Budget: budget},
		{Tools: []string{"read"}, Servers: []string{"s1"}, Budget: &types.Budget{Limit: 50, Unit: "usd"}},
	})

	dc := chain.ToTypes()
	if dc == nil || len(dc.Hops) != 2 {
		t.Fatalf("ToTypes returned %+v, want 2 hops", dc)
	}
	for i, h := range chain.Hops {
		out := dc.Hops[i]
		if out.Delegator != h.Delegator || out.Delegate != h.Delegate {
			t.Fatalf("hop %d ids: got %q->%q, want %q->%q", i, out.Delegator, out.Delegate, h.Delegator, h.Delegate)
		}
		if !bytes.Equal(out.Signature, h.Signature) {
			t.Fatalf("hop %d signature not preserved", i)
		}
		// Scope must carry tools + budget (not servers/NotAfter, by design of Grant.Scope).
		if len(out.Scope.Tools) != len(h.Grant.Tools) {
			t.Fatalf("hop %d tools: got %v, want %v", i, out.Scope.Tools, h.Grant.Tools)
		}
		if (out.Scope.Budget == nil) != (h.Grant.Budget == nil) {
			t.Fatalf("hop %d budget presence mismatch", i)
		}
	}
}

// --- canonical signing independent of tool ordering ---------------------------------

func TestCanonicalIndependentOfToolOrdering(t *testing.T) {
	g1 := Grant{Tools: []string{"read", "write", "delete"}, Servers: []string{"s2", "s1"}}
	g2 := Grant{Tools: []string{"delete", "read", "write"}, Servers: []string{"s1", "s2"}}
	if !bytes.Equal(canonical("p", "a", g1, nil), canonical("p", "a", g2, nil)) {
		t.Fatal("canonical encoding must be independent of tool/server ordering")
	}
}

func TestCanonicalSignatureVerifiesRegardlessOfOrdering(t *testing.T) {
	// A grant signed with tools in one order must verify when re-presented in another.
	principal := newParty(t, "principal-1")
	agent := newParty(t, "a1")
	keys := registry(principal, agent)

	chain, _ := NewRoot(principal.priv, principal.id, agent.id,
		Grant{Tools: []string{"write", "read"}, Servers: []string{"s2", "s1"}})
	// Re-order the stored tool/server slices (an honest re-serialization upstream).
	chain.Hops[0].Grant.Tools = []string{"read", "write"}
	chain.Hops[0].Grant.Servers = []string{"s1", "s2"}

	if _, _, err := Verify(chain, keys, principal.id, time.Now()); err != nil {
		t.Fatalf("signature must verify regardless of tool/server ordering: %v", err)
	}
}
