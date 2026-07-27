// Package delegation implements the signed, attenuating delegation chain (PRD FR-10,
// FR-13): the record principal -> agent -> sub-agent where each hop is signed by the
// delegating party and may only narrow the granted authority. Verification (verify.go)
// rejects any forged hop, broken continuity, or scope widening (attenuation-only, FR-11,
// which is issue P2-05).
//
// Each hop is signed over a canonical encoding of (delegator, delegate, grant, previous
// signature). Binding to the previous signature chains the hops so they cannot be
// reordered or spliced. The root delegator must be the accountable principal.
package delegation

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/getsanad/sanad/pkg/types"
)

// Grant is the authority conferred by a hop. Constraints may only tighten down the chain.
// Empty Tools/Servers mean "unconstrained" (a wildcard the next hop may narrow); a zero
// NotAfter means no time bound; a nil Budget means no budget bound.
type Grant struct {
	Tools    []string
	Servers  []string
	NotAfter time.Time
	Budget   *types.Budget
}

// Scope projects the grant onto the passport scope (tools + budget).
func (g Grant) Scope() types.Scope {
	return types.Scope{Tools: g.Tools, Budget: g.Budget}
}

// Hop is one signed link: the delegator grants the delegate the given authority.
type Hop struct {
	Delegator string
	Delegate  string
	Grant     Grant
	Signature []byte
}

// Chain is the ordered delegation record principal -> agent -> sub-agent.
type Chain struct {
	Hops []Hop
}

// KeyRegistry resolves a subject id (principal or agent) to its Ed25519 public key.
// Principal keys come from registration/VCs (P2-08); agent keys from workload credentials
// (P2-01/P2-02). MemKeyRegistry is the in-memory implementation.
type KeyRegistry interface {
	PublicKey(id string) (ed25519.PublicKey, bool)
}

// MemKeyRegistry is an in-memory KeyRegistry.
type MemKeyRegistry map[string]ed25519.PublicKey

// PublicKey implements KeyRegistry.
func (m MemKeyRegistry) PublicKey(id string) (ed25519.PublicKey, bool) {
	k, ok := m[id]
	return k, ok
}

// NewRoot starts a chain: the principal delegates to delegateID under grant g, signing
// with the principal's key.
func NewRoot(principalKey ed25519.PrivateKey, principalID, delegateID string, g Grant) (Chain, error) {
	if len(principalKey) != ed25519.PrivateKeySize {
		return Chain{}, errors.New("delegation: invalid principal key")
	}
	sig := ed25519.Sign(principalKey, canonical(principalID, delegateID, g, nil))
	return Chain{Hops: []Hop{{Delegator: principalID, Delegate: delegateID, Grant: g, Signature: sig}}}, nil
}

// Extend appends a hop: the current holder (the last hop's delegate) delegates onward to
// delegateID under grant g, signing with the holder's key. Attenuation is enforced at
// Verify time; callers should pass a grant that narrows the one they hold.
func (c Chain) Extend(holderKey ed25519.PrivateKey, delegateID string, g Grant) (Chain, error) {
	if len(c.Hops) == 0 {
		return Chain{}, errors.New("delegation: cannot extend an empty chain")
	}
	if len(holderKey) != ed25519.PrivateKeySize {
		return Chain{}, errors.New("delegation: invalid holder key")
	}
	last := c.Hops[len(c.Hops)-1]
	sig := ed25519.Sign(holderKey, canonical(last.Delegate, delegateID, g, last.Signature))
	hops := append(append([]Hop(nil), c.Hops...), Hop{
		Delegator: last.Delegate, Delegate: delegateID, Grant: g, Signature: sig,
	})
	return Chain{Hops: hops}, nil
}

// ToTypes converts the chain to the lightweight representation carried on a passport for
// audit/inspection (PRD FR-10); the cryptographic verification stays gateway-side.
func (c Chain) ToTypes() *types.DelegationChain {
	out := &types.DelegationChain{}
	for _, h := range c.Hops {
		out.Hops = append(out.Hops, types.DelegationHop{
			Delegator: h.Delegator, Delegate: h.Delegate, Scope: h.Grant.Scope(), Signature: h.Signature,
		})
	}
	return out
}

// canonical is the deterministic signing input for a hop. Tools/Servers are sorted so the
// encoding does not depend on caller ordering.
func canonical(delegator, delegate string, g Grant, prevSig []byte) []byte {
	tools := append([]string(nil), g.Tools...)
	sort.Strings(tools)
	servers := append([]string(nil), g.Servers...)
	sort.Strings(servers)
	var notAfter int64
	if !g.NotAfter.IsZero() {
		notAfter = g.NotAfter.Unix()
	}
	b, _ := json.Marshal(struct {
		Delegator string        `json:"delegator"`
		Delegate  string        `json:"delegate"`
		Tools     []string      `json:"tools"`
		Servers   []string      `json:"servers"`
		NotAfter  int64         `json:"not_after"`
		Budget    *types.Budget `json:"budget,omitempty"`
		Prev      []byte        `json:"prev,omitempty"`
	}{delegator, delegate, tools, servers, notAfter, g.Budget, prevSig})
	return b
}
