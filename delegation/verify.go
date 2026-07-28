package delegation

import (
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/getsanad/sanad/internal/sigctx"
)

// Verify checks the whole chain and returns the effective (most-narrowed) grant and the
// acting agent (the final delegate). It first checks the chain's SHAPE — non-empty, within
// the depth ceiling, no party twice (checkShape) — because those cost one pass over a slice
// and the rest of this function costs one Ed25519 verification per hop. Then, for every hop:
//   - the root delegator is the accountable principal (rootPrincipalID);
//   - continuity: each delegator holds the delegation from the previous hop;
//   - a valid signature by the delegator's registered key — resolved in the PRINCIPAL
//     namespace for the root hop and the AGENT namespace for every later one — made under
//     the delegation-hop context (FR-13 — an unverifiable hop is rejected, never trusted,
//     and a signature that key made for some other purpose is not a hop);
//   - attenuation-only against the previous hop (FR-11);
//   - the hop has not expired at now.
func Verify(c Chain, keys KeyRegistry, rootPrincipalID string, now time.Time, opts ...VerifyOption) (Grant, string, error) {
	// Before any cryptography: a chain too long to be honest, or one that loops, is refused
	// here rather than after 4000 signature verifications have been paid for.
	if err := c.checkShape(newVerifyOptions(opts).maxDepth); err != nil {
		return Grant{}, "", err
	}

	var prevSig []byte
	var prevGrant Grant
	for i, hop := range c.Hops {
		if i == 0 {
			if hop.Delegator != rootPrincipalID {
				return Grant{}, "", fmt.Errorf("delegation: chain root %q is not the principal %q", hop.Delegator, rootPrincipalID)
			}
		} else if hop.Delegator != c.Hops[i-1].Delegate {
			return Grant{}, "", fmt.Errorf("delegation: broken chain at hop %d: %q does not hold the delegation from %q", i, hop.Delegator, c.Hops[i-1].Delegate)
		}

		// Which namespace a delegator's key lives in is fixed by the hop's POSITION, not
		// guessed from the id: hop 0 is signed by the accountable principal (just checked to be
		// rootPrincipalID), and every later hop by the agent the previous hop delegated to. So
		// each id is resolved in exactly one namespace. There is no "try principals, then
		// agents" fallback — that would put the two id spaces back into one, and an agent whose
		// id equalled a principal's would once again answer for that principal.
		var pub ed25519.PublicKey
		var ok bool
		kind := "agent"
		if i == 0 {
			kind = "principal"
			pub, ok = keys.PrincipalKey(hop.Delegator)
		} else {
			pub, ok = keys.AgentKey(hop.Delegator)
		}
		if !ok {
			return Grant{}, "", fmt.Errorf("delegation: no registered %s key for delegator %q", kind, hop.Delegator)
		}
		if !sigctx.Verify(sigctx.DelegationHop, pub, canonical(hop.Delegator, hop.Delegate, hop.Grant, prevSig), hop.Signature) {
			return Grant{}, "", fmt.Errorf("delegation: invalid signature at hop %d", i)
		}

		if i > 0 {
			if err := attenuates(prevGrant, hop.Grant); err != nil {
				return Grant{}, "", fmt.Errorf("delegation: hop %d widens scope: %w", i, err)
			}
		}
		if !hop.Grant.NotAfter.IsZero() && !now.Before(hop.Grant.NotAfter) {
			return Grant{}, "", fmt.Errorf("delegation: hop %d has expired", i)
		}

		prevSig = hop.Signature
		prevGrant = hop.Grant
	}

	last := c.Hops[len(c.Hops)-1]
	return last.Grant, last.Delegate, nil
}
