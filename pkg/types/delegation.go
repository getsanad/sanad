package types

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"sort"
)

// DelegationHop is one signed link in a delegation chain: who delegated, to whom, the
// granted scope, and the delegator's signature. Forging or extending a chain requires
// the delegator's key (PRD FR-13).
type DelegationHop struct {
	Delegator string // principal/agent ID granting authority
	Delegate  string // principal/agent ID receiving it
	Scope     Scope
	Signature []byte // signed by the delegator's key (PRD FR-13)
}

// DelegationChain is the ordered, attenuating record principal -> agent -> sub-agent
// (PRD FR-10), with every hop's signature. This is the full chain: the gateway verifies
// it (delegation.Verify) and the audit log stores it. It is NOT what travels on a
// passport — see DelegationRef and Ref.
type DelegationChain struct {
	Hops []DelegationHop
}

// Path is the chain as an ordered list of parties: the root delegator (the accountable
// principal) followed by each hop's delegate, so the last element is the acting agent.
// nil for an absent or empty chain.
//
// This is the one derivation of the path in the system: the audit log records it and a
// passport carries it, so "who delegated to whom" reads identically in both places.
func (c *DelegationChain) Path() []string {
	if c == nil || len(c.Hops) == 0 {
		return nil
	}
	path := make([]string, 0, len(c.Hops)+1)
	path = append(path, c.Hops[0].Delegator)
	for _, h := range c.Hops {
		path = append(path, h.Delegate)
	}
	return path
}

// Digest is a SHA-256 commitment to the WHOLE chain — every hop's parties, granted scope
// and signature — over a canonical encoding that does not depend on tool ordering. Two
// chains share a digest only if they are the same chain.
//
// It exists so the compact summary a passport carries (DelegationRef) is still bound to
// exactly one chain: anyone holding the full chain (the audit log, an investigator, the
// delegate itself) can recompute this and confirm the passport was minted from that chain
// and no other. The hop signatures are included precisely because they are what makes the
// chain unforgeable; hashing over them means a chain with a re-signed hop is a different
// chain here too.
func (c *DelegationChain) Digest() []byte {
	if c == nil || len(c.Hops) == 0 {
		return nil
	}
	hops := make([]digestHop, len(c.Hops))
	for i, h := range c.Hops {
		tools := append([]string(nil), h.Scope.Tools...)
		sort.Strings(tools)
		if tools == nil {
			tools = []string{} // nil and empty are the same grant; hash them the same
		}
		hops[i] = digestHop{
			Delegator: h.Delegator, Delegate: h.Delegate,
			Tools: tools, Budget: h.Scope.Budget, Signature: h.Signature,
		}
	}
	// Marshaling a slice of structs is deterministic in Go: fixed field order, no maps.
	b, err := json.Marshal(hops)
	if err != nil {
		return nil // unreachable: every field is a JSON-encodable primitive
	}
	sum := sha256.Sum256(b)
	return sum[:]
}

// digestHop is the canonical hashing form of a hop: a fixed field order, sorted tools, and
// the signature. Kept separate from DelegationHop so a future field on the domain type is a
// deliberate decision about the digest rather than a silent change to it.
type digestHop struct {
	Delegator string   `json:"delegator"`
	Delegate  string   `json:"delegate"`
	Tools     []string `json:"tools"`
	Budget    *Budget  `json:"budget,omitempty"`
	Signature []byte   `json:"sig,omitempty"`
}

// DelegationRef is the delegation chain AS IT TRAVELS ON A PASSPORT (PRD FR-10): the
// ordered path of parties, plus the digest committing to the full signed chain behind it.
//
// It is a summary on purpose. The full chain — n hops of ids, scopes and 64-byte
// signatures — runs to the better part of a kilobyte, and a passport is sent on every
// single request, so carrying it would tax the hot path forever. It would also not buy the
// resource server anything it can act on: verifying a hop needs the delegator's public key,
// and a resource server has no registry of principal/agent keys (that is the gateway's job,
// delegation.Verify). What it can act on is WHO the parties were — and the digest keeps
// that assertion falsifiable rather than merely asserted.
//
// So, precisely: a resource server that verifies a passport learns, under the gateway's
// signature, that the gateway verified a chain rooted at Path[0] (the accountable
// principal, which also equals the `sub` claim) and ending at the last element of Path (the
// acting agent, which equals `agent`), whose full form hashes to Digest; and it learns the
// effective, most-narrowed scope of that chain, because that is the passport's own `scope`.
// It CANNOT itself check the hop signatures or the per-hop attenuation — for those it is
// trusting the gateway, exactly as it already trusts `sub` and `agent` — and it cannot see
// the intermediate grants. An auditor who also holds the full chain can check all of it,
// and can prove the passport belongs to that chain via Digest.
type DelegationRef struct {
	Path   []string `json:"path"`           // principal -> ... -> acting agent
	Digest string   `json:"dgst,omitempty"` // base64url(sha256) of the full signed chain
}

// Ref summarizes the chain into the form a passport carries. nil for an absent or empty
// chain, so an omitempty claim stays absent rather than encoding an empty object.
func (c *DelegationChain) Ref() *DelegationRef {
	if c == nil || len(c.Hops) == 0 {
		return nil
	}
	return &DelegationRef{
		Path:   c.Path(),
		Digest: base64.RawURLEncoding.EncodeToString(c.Digest()),
	}
}

// Matches reports whether ref is the summary of chain c — the check an investigator makes
// to tie a passport to a chain recovered from the audit log. A nil ref matches only a nil
// or empty chain.
func (c *DelegationChain) Matches(ref *DelegationRef) bool {
	got := c.Ref()
	if got == nil || ref == nil {
		return got == nil && ref == nil
	}
	if got.Digest != ref.Digest || len(got.Path) != len(ref.Path) {
		return false
	}
	for i := range got.Path {
		if got.Path[i] != ref.Path[i] {
			return false
		}
	}
	return true
}
