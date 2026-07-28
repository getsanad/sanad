package passport

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/getsanad/sanad/pkg/types"
)

// realisticChain is what a deployed three-party delegation actually looks like: a did:key
// principal (the longest identifier the system mints), an attested agent instance, and a
// sub-agent, attenuating as it goes.
func realisticChain() *types.DelegationChain {
	const principal = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
	return &types.DelegationChain{Hops: []types.DelegationHop{
		{
			Delegator: principal, Delegate: "agent-7f3a9c2e41b8",
			Scope:     types.Scope{Tools: []string{"search_issues", "get_file", "create_issue"}, Budget: &types.Budget{Limit: 100, Unit: "usd"}},
			Signature: make([]byte, ed25519.SignatureSize),
		},
		{
			Delegator: "agent-7f3a9c2e41b8", Delegate: "subagent-1b4d0e77",
			Scope:     types.Scope{Tools: []string{"search_issues", "get_file"}, Budget: &types.Budget{Limit: 25, Unit: "usd"}},
			Signature: make([]byte, ed25519.SignatureSize),
		},
	}}
}

func realisticPassport() types.Passport {
	chain := realisticChain()
	return types.Passport{
		ID:          "kQ7bXn2ZTQyR4pLmVw8hAg",
		PrincipalID: chain.Hops[0].Delegator,
		AgentID:     "subagent-1b4d0e77",
		Audience:    "github-mcp",
		Scope:       types.Scope{Tools: []string{"search_issues", "get_file"}, Budget: &types.Budget{Limit: 25, Unit: "usd"}},
		Delegation:  chain,
		IssuedAt:    at(2026),
		ExpiresAt:   at(2026).Add(2 * time.Minute),
	}
}

// TestDelegationSurvivesTheCodec is the end-to-end version of the round trip: sign a real
// passport, verify it with the gateway's public key the way a resource server does, and
// check the delegation is still there and still identifies the chain it was minted from.
func TestDelegationSurvivesTheCodec(t *testing.T) {
	pub, priv := newKey(t)
	now := at(2026)
	in := realisticPassport()

	tok, err := Sign(priv, "kid-gw", ToClaims(in, "sanad"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	claims, err := Verify(pub, tok, "github-mcp", now)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	out := claims.ToPassport()
	if out.DelegationRef == nil {
		t.Fatal("the delegation did not survive signing and verification")
	}
	want := []string{in.PrincipalID, "agent-7f3a9c2e41b8", "subagent-1b4d0e77"}
	if strings.Join(out.DelegationRef.Path, ",") != strings.Join(want, ",") {
		t.Fatalf("path = %v, want %v", out.DelegationRef.Path, want)
	}
	if !in.Delegation.Matches(out.DelegationRef) {
		t.Fatal("the verified passport does not commit to the chain it was minted from")
	}
	// The chain is inside the signature, not alongside it: rewriting the path breaks the
	// token, so the path is as trustworthy as `sub` and `agent` are.
	forged := ToClaims(in, "sanad")
	forged.Delegation = &types.DelegationRef{Path: []string{"someone-else"}, Digest: out.DelegationRef.Digest}
	parts := strings.Split(tok, ".")
	pb, _ := json.Marshal(forged)
	if _, err := Verify(pub, parts[0]+"."+b64(pb)+"."+parts[2], "github-mcp", now); err == nil {
		t.Fatal("a rewritten delegation path must break the signature")
	}
}

// TestTokenSizeOnTheHotPath bounds the passport. It is sent on EVERY request, so the claim
// set is a permanent tax on the hot path — this is the assertion that stops a future change
// from quietly making it a large one.
//
// The bound is what forced the delegation to travel as a summary rather than as the chain.
// Measured on the passport below: 508 bytes with no delegation, 735 with the summary (+227),
// and 1280 if the full chain rode along (+772) — 3.4x the delegation cost, for signatures a
// resource server has no keys to check (see types.DelegationRef).
func TestTokenSizeOnTheHotPath(t *testing.T) {
	_, priv := newKey(t)
	p := realisticPassport()

	withChain, err := Sign(priv, "kid-gw", ToClaims(p, "sanad"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	p.Delegation = nil
	p.DelegationRef = nil
	withoutChain, err := Sign(priv, "kid-gw", ToClaims(p, "sanad"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	const maxToken = 800
	const maxDelegationOverhead = 260
	overhead := len(withChain) - len(withoutChain)
	t.Logf("passport: %d bytes with a 3-party chain, %d without (delegation costs %d)",
		len(withChain), len(withoutChain), overhead)

	if len(withChain) > maxToken {
		t.Fatalf("a passport for a realistic 3-party chain is %d bytes, over the %d-byte budget: "+
			"every request pays this", len(withChain), maxToken)
	}
	if overhead > maxDelegationOverhead {
		t.Fatalf("the delegation claim costs %d bytes, over the %d-byte budget: it is meant to be a "+
			"path plus a digest, not the chain", overhead, maxDelegationOverhead)
	}
	// The digest is a fixed cost regardless of chain length; only the path grows. A fourth
	// party must add roughly one identifier, not another signature.
	long := realisticPassport()
	long.Delegation.Hops = append(long.Delegation.Hops, types.DelegationHop{
		Delegator: "subagent-1b4d0e77", Delegate: "subagent-9e2f",
		Scope: types.Scope{Tools: []string{"get_file"}}, Signature: make([]byte, ed25519.SignatureSize),
	})
	longer, _ := Sign(priv, "kid-gw", ToClaims(long, "sanad"))
	if growth := len(longer) - len(withChain); growth > 40 {
		t.Fatalf("a fourth delegation hop added %d bytes; the chain must not scale by its signatures", growth)
	}
}
