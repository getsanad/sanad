package policy

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/getsanad/sanad/gateway"
	"github.com/getsanad/sanad/pkg/types"
)

// ToolExtractor derives the requested tool/action name from the in-flight request.
// Parsing MCP method/params is refined later; deployments can supply their own. A nil
// extractor yields an empty tool (which a "*" allowlist still permits) and leaves any
// delegated scope on the request untouched.
type ToolExtractor func(req *gateway.Request) string

// Stage returns the gateway policy stage. It builds the PDP input from the verified
// request — including the delegation the delegation stage verified — checks the requested
// tool against that delegation, evaluates the input deny-by-default, routes EffectReview to
// the approver (if any), and fails closed unless the final decision is allow. On allow it
// records the granted scope on the request for the mint stage (P1-04).
//
// The granted scope is an INTERSECTION, never an assignment. Assigning
// types.Scope{Tools: []string{tool}} — as this stage used to — replaced the cryptographically
// attenuated grant the delegation stage had put on the request and dropped its Budget, so a
// minted passport could assert authority the signed chain never conferred (FR-11). The check
// is a denial, not a silent re-scope: a re-scope would turn "you may not do this" into "you
// may do it, narrowly", which is the same escalation with a smaller blast radius.
func Stage(pdp PDP, extract ToolExtractor, approver Approver) gateway.Stage {
	return gateway.NewStage("policy", func(ctx context.Context, req *gateway.Request) error {
		if req.Principal == nil {
			return errors.New("policy: no authenticated principal")
		}

		var tool string
		if extract != nil {
			tool = extract(req)
		}
		// Whatever the delegation stage narrowed the request to (P2-04): the effective
		// grant's scope, or the zero Scope when the principal acts directly.
		delegated := req.Scope

		// The attenuation floor, enforced before the PDP is consulted so that no policy — and
		// no human approver — is ever asked to bless authority the chain does not contain.
		if tool != "" && !granted(delegated.Tools, tool) {
			return deny(req, fmt.Sprintf("tool %q is outside the delegated scope %v", tool, delegated.Tools))
		}

		in := Input{
			Principal: req.Principal, Agent: req.Agent, Server: req.Server, Tool: tool,
			Delegation: req.Delegation, DelegatedScope: delegated,
		}

		d, err := pdp.Evaluate(ctx, in)
		if err != nil {
			return fmt.Errorf("policy: %w", err) // fail closed
		}
		if d.Effect == types.EffectReview {
			if approver == nil {
				return errors.New("policy: action requires approval but no approver is configured")
			}
			if d, err = approver.Decide(ctx, in); err != nil {
				return fmt.Errorf("policy: approval: %w", err)
			}
		}

		req.Decision = &d
		if !d.Allowed() {
			return fmt.Errorf("policy: denied: %s", d.Reason)
		}
		if tool != "" {
			// Narrow to the one tool actually requested — already established to be within the
			// grant, so this can only shrink it — and carry the delegated Budget through, since
			// it is signed authority the request has no standing to drop.
			req.Scope = types.Scope{Tools: []string{tool}, Budget: delegated.Budget}
		}
		return nil
	})
}

// granted reports whether tool is within a delegation-derived tool set. An EMPTY set is the
// unconstrained wildcard — the reading delegation's subset() validated every hop against,
// where a concrete parent may never be widened back to empty. So an empty set reaching here
// is either a chain unconstrained on tools at every hop, or no chain at all (the principal
// acting directly, which delegation.WithRequireChain / PASSPORT_ALLOW_DIRECT_PRINCIPAL is
// what gates); neither has an attenuation to bypass, and denying them would deny every
// direct-principal request. Entries match literally: a grant has no "*" wildcard, so a
// literal "*" in one grants a tool named "*" and nothing else.
func granted(tools []string, tool string) bool {
	return len(tools) == 0 || slices.Contains(tools, tool)
}

// deny records an enforcement denial on the request and returns the stage error, so the
// audit hook sees the decision the gateway actually reached rather than no decision at all.
func deny(req *gateway.Request, reason string) error {
	req.Decision = &types.Decision{Effect: types.EffectDeny, Reason: reason}
	return fmt.Errorf("policy: denied: %s", reason)
}
