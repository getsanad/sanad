package delegation

import (
	"errors"
	"fmt"
	"time"

	"github.com/getsanad/sanad/internal/sigctx"
)

// Verify checks the whole chain and returns the effective (most-narrowed) grant and the
// acting agent (the final delegate). It enforces, for every hop:
//   - the root delegator is the accountable principal (rootPrincipalID);
//   - continuity: each delegator holds the delegation from the previous hop;
//   - a valid signature by the delegator's registered key, made under the delegation-hop
//     context (FR-13 — an unverifiable hop is rejected, never trusted, and a signature that
//     key made for some other purpose is not a hop);
//   - attenuation-only against the previous hop (FR-11);
//   - the hop has not expired at now.
func Verify(c Chain, keys KeyRegistry, rootPrincipalID string, now time.Time) (Grant, string, error) {
	if len(c.Hops) == 0 {
		return Grant{}, "", errors.New("delegation: empty chain")
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

		pub, ok := keys.PublicKey(hop.Delegator)
		if !ok {
			return Grant{}, "", fmt.Errorf("delegation: no registered key for delegator %q", hop.Delegator)
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
