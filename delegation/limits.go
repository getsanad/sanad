package delegation

import (
	"errors"
	"fmt"
)

// MaxDepth bounds how long a presented delegation may be: hops in a Chain, blocks in a
// Capability. Both units cost the same thing to check — one Ed25519 verification plus one
// attenuation comparison — so one ceiling covers both.
//
// It exists because verification runs BEFORE authorization, on bytes an unauthenticated
// caller chose. Under Go's default 1 MiB MaxHeaderBytes a single X-Agent-Delegation header
// holds ~4000 hops, and checking them measured 113ms of CPU per request on the machine this
// was found on — a ~250x amplification of one request into signature verifications, from a
// caller who has not yet proved anything. A ceiling turns that back into a constant.
//
// 16 is the number because delegation depth is a property of an org chart, not of a
// workload: principal -> agent -> sub-agent -> sub-sub-agent is four, the deepest chain
// anywhere in this repo (docs, tests, the demo) is five, and the PRD's delegation story
// (FR-10, "principal -> agent -> sub-agent…") describes the same shape. 16 leaves 3x
// headroom over the deepest thing anyone has written down while capping the pre-auth work
// at ~0.5ms — small enough that the delegation header stops being an amplifier at all.
// Deployments with a flatter topology should tighten it (WithMaxDepth); nothing can raise
// it, because a configuration mistake must not be able to re-open the amplification window.
const MaxDepth = 16

var (
	// ErrTooDeep is returned when a chain or capability carries more than the ceiling. It is
	// a sentinel so callers (and tests asserting the check runs before the verification loop)
	// can tell "refused for its shape" from "refused for its cryptography".
	ErrTooDeep = errors.New("delegation: too deep")

	// ErrCycle is returned when a party delegates to itself, or back to a party already in
	// the chain. See Chain.checkShape for why neither is legitimate.
	ErrCycle = errors.New("delegation: cyclic chain")
)

// VerifyOption tightens one verification. It is separate from StageOption because Verify and
// Capability.Verify are exported and called directly (cmd/, vc/, workload/ tests); a stage
// forwards these through WithVerifyOptions.
type VerifyOption func(*verifyOptions)

type verifyOptions struct {
	maxDepth int
}

// WithMaxDepth lowers the depth ceiling for this verification to n. It can only TIGHTEN:
// n <= 0, or n above MaxDepth, selects MaxDepth. The ceiling is the DoS bound, so it is not
// a deployment's to raise — see MaxDepth.
func WithMaxDepth(n int) VerifyOption {
	return func(o *verifyOptions) {
		if n > 0 && n < o.maxDepth {
			o.maxDepth = n
		}
	}
}

func newVerifyOptions(opts []VerifyOption) verifyOptions {
	o := verifyOptions{maxDepth: MaxDepth}
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

// checkShape does every check on a chain that needs no cryptography: it is non-empty, within
// the depth ceiling, and no party appears twice.
//
// It runs BEFORE Verify's loop, which is the whole point: an over-long chain costs one pass
// over a slice instead of one Ed25519 verification per hop, so the amplification is refused
// rather than paid for and then reported.
//
// A repeated party is rejected because a delegation can only ever narrow (attenuates), so a
// hop that returns authority to someone already holding it grants strictly nothing — a
// self-delegation A -> A is a signed statement that A may do no more than A already may. The
// only thing such a hop can carry is cost, which is exactly what the amplification PoC used
// it for (A -> A, 4000 times). An agent that wants to narrow ITSELF for one call has the
// offline capability for it (Capability.Attenuate), which names no parties and so has no
// cycle to form. Ids are compared as plain strings, which conflates the principal and agent
// namespaces (KeyRegistry keeps them apart); conflating them here only ever rejects more,
// and the one chain it rejects that namespacing would allow — a principal delegating to an
// agent that shares its id — is the exact confusion P2-08 exists to prevent.
func (c Chain) checkShape(maxDepth int) error {
	if len(c.Hops) == 0 {
		return errors.New("delegation: empty chain")
	}
	if len(c.Hops) > maxDepth {
		return fmt.Errorf("%w: chain has %d hops, the maximum is %d", ErrTooDeep, len(c.Hops), maxDepth)
	}
	// The parties are the root delegator followed by each hop's delegate; continuity (checked
	// in Verify) is what makes that the full list.
	seen := make(map[string]struct{}, len(c.Hops)+1)
	seen[c.Hops[0].Delegator] = struct{}{}
	for i, hop := range c.Hops {
		if hop.Delegator == hop.Delegate {
			return fmt.Errorf("%w: hop %d delegates %q to itself", ErrCycle, i, hop.Delegate)
		}
		if _, dup := seen[hop.Delegate]; dup {
			return fmt.Errorf("%w: hop %d delegates back to %q, which already appears in the chain", ErrCycle, i, hop.Delegate)
		}
		seen[hop.Delegate] = struct{}{}
	}
	return nil
}
