package policy

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/getsanad/sanad/gateway"
	"github.com/getsanad/sanad/pkg/types"
)

// ToolExtractor derives the tools an in-flight request asks for: ONE ENTRY PER DECISION the
// request requires, not per distinct tool. For MCP that is one entry per JSON-RPC message in
// the body — "" for a message that invokes no tool of its own (initialize, tools/list, a
// notification) — so a batch is decided element by element rather than on its first element.
// Returning nil, like a nil extractor, yields a single decision with an empty tool (which a
// "*" allowlist still permits) and leaves any delegated scope on the request untouched.
// MCPTools is the default; deployments can supply their own.
type ToolExtractor func(req *gateway.Request) []string

// MCPTools is the default ToolExtractor. It projects the JSON-RPC messages the gateway parsed
// out of the request body (gateway.Request.Calls) onto the tool each one invokes: a tools/call
// contributes its params.name, every other method contributes "".
//
// Protocol methods deliberately map to "" rather than to their method name. Scope.Tools is the
// namespace a delegation chain is signed over, and it names MCP tools; folding "initialize" and
// "tools/list" into it would mean every chain had to grant the protocol handshake alongside the
// work, and a chain attenuated to ["read"] could never open a session at all. They are still
// decided — once each, with an empty tool, exactly as a bodyless request is — so an operator
// policy that wants to gate them can, via the method on Request.Calls.
var MCPTools ToolExtractor = func(req *gateway.Request) []string {
	if req == nil || len(req.Calls) == 0 {
		return nil
	}
	tools := make([]string, len(req.Calls))
	for i, c := range req.Calls {
		tools[i] = c.Tool
	}
	return tools
}

// Stage returns the gateway policy stage. It builds the PDP input from the verified
// request — including the delegation the delegation stage verified — checks each requested
// tool against that delegation, evaluates the input deny-by-default, routes EffectReview to
// the approver (if any), and fails closed unless every decision is allow. On allow it
// records the granted scope on the request for the mint stage (P1-04).
//
// The granted scope is an INTERSECTION, never an assignment. Assigning
// types.Scope{Tools: []string{tool}} — as this stage used to — replaced the cryptographically
// attenuated grant the delegation stage had put on the request and dropped its Budget, so a
// minted passport could assert authority the signed chain never conferred (FR-11). The check
// is a denial, not a silent re-scope: a re-scope would turn "you may not do this" into "you
// may do it, narrowly", which is the same escalation with a smaller blast radius.
//
// A JSON-RPC batch is decided ELEMENT BY ELEMENT and denied whole if any element is denied.
// The gateway forwards the batch as one upstream POST, so partial authorization is not on the
// table: dropping elements would have to rewrite the body and desynchronize the ids the client
// correlates responses by. Of the two all-or-nothing answers, deny is the fail-closed one — the
// alternative lets one permitted element carry a forbidden one through, which is precisely the
// confused-deputy problem the passport exists to prevent. Every element is evaluated, including
// repeats of the same tool, so a stateful PDP (budgets, rate limits) counts what was actually
// asked for and an approver is asked about each invocation rather than about a set.
func Stage(pdp PDP, extract ToolExtractor, approver Approver) gateway.Stage {
	return gateway.NewStage("policy", func(ctx context.Context, req *gateway.Request) error {
		if req.Principal == nil {
			return errors.New("policy: no authenticated principal")
		}

		var tools []string
		if extract != nil {
			tools = extract(req)
		}
		// Whatever the delegation stage narrowed the request to (P2-04): the effective
		// grant's scope, or the zero Scope when the principal acts directly.
		delegated := req.Scope

		// A request that names no tool at all — a GET, a non-JSON-RPC body, no extractor — still
		// gets exactly one decision, with an empty tool, which is the behaviour that predates
		// body parsing. It is one decision, never zero: a request nobody decided is a request
		// nobody authorized.
		decide := tools
		if len(decide) == 0 {
			decide = []string{""}
		}
		for _, tool := range decide {
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
		}

		if requested := distinct(tools); len(requested) > 0 {
			// Narrow to the tools actually requested — each already established to be within the
			// grant, so this can only shrink it — and carry the delegated Budget through, since
			// it is signed authority the request has no standing to drop.
			req.Scope = types.Scope{Tools: requested, Budget: delegated.Budget}
		}
		return nil
	})
}

// distinct returns the non-empty tool names in order, without repeats. Decisions are made per
// element, but the scope minted from them is a set: a batch calling "read" twice is authority
// over "read", and the empty entries the protocol methods contribute are not tools at all.
func distinct(tools []string) []string {
	out := make([]string, 0, len(tools))
	for _, t := range tools {
		if t != "" && !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	return out
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
