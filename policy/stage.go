package policy

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/getsanad/sanad/gateway"
	"github.com/getsanad/sanad/pkg/types"
)

// Action is one unit of authorization: the JSON-RPC method a request element invokes, and the
// tool it names (empty for every method but tools/call, because no other method names one).
// Both travel to the PDP, so a policy can allow "tools/list" while gating "tools/call".
type Action struct {
	Method string
	Tool   string
}

// ActionExtractor derives the actions an in-flight request asks for: ONE ENTRY PER DECISION the
// request requires, not per distinct tool. For MCP that is one entry per JSON-RPC message in
// the body — with an empty Tool for a message that invokes no tool of its own (initialize,
// tools/list, a notification) — so a batch is decided element by element rather than on its
// first element. Returning nil, like a nil extractor, yields a single decision for MethodNone
// and leaves any delegated scope on the request untouched. MCPActions is the default;
// deployments can supply their own.
type ActionExtractor func(req *gateway.Request) []Action

// MCPActions is the default ActionExtractor. It projects the JSON-RPC messages the gateway
// parsed out of the request body (gateway.Request.Calls) onto the action each one takes: its
// method, plus the tool a tools/call names in params.name.
//
// Protocol methods deliberately contribute NO tool rather than their method name as one.
// Scope.Tools is the namespace a delegation chain is signed over, and it names MCP tools;
// folding "initialize" and "tools/list" into it would mean every chain had to grant the
// protocol handshake alongside the work, and a chain attenuated to ["read"] could never open a
// session at all. They are still decided — once each — and now under their own method, so an
// operator policy that wants to gate them can (see AllowList's two namespaces).
var MCPActions ActionExtractor = func(req *gateway.Request) []Action {
	if req == nil || len(req.Calls) == 0 {
		return nil
	}
	actions := make([]Action, len(req.Calls))
	for i, c := range req.Calls {
		actions[i] = Action{Method: c.Method, Tool: c.Tool}
	}
	return actions
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
func Stage(pdp PDP, extract ActionExtractor, approver Approver) gateway.Stage {
	return gateway.NewStage("policy", func(ctx context.Context, req *gateway.Request) error {
		if req.Principal == nil {
			return errors.New("policy: no authenticated principal")
		}

		var actions []Action
		if extract != nil {
			actions = extract(req)
		}
		// Whatever the delegation stage narrowed the request to (P2-04): the effective
		// grant's scope, or the zero Scope when the principal acts directly.
		delegated := req.Scope

		// A request that carries no JSON-RPC call at all — a GET, a non-JSON-RPC body, no
		// extractor — still gets exactly one decision, under MethodNone so that an operator can
		// name it in a policy. It is one decision, never zero: a request nobody decided is a
		// request nobody authorized.
		decide := actions
		if len(decide) == 0 {
			decide = []Action{{Method: MethodNone}}
		}
		for _, act := range decide {
			// The attenuation floor, enforced before the PDP is consulted so that no policy — and
			// no human approver — is ever asked to bless authority the chain does not contain.
			if act.Tool != "" && !granted(delegated.Tools, act.Tool) {
				return deny(req, fmt.Sprintf("tool %q is outside the delegated scope %v", act.Tool, delegated.Tools))
			}

			in := Input{
				Principal: req.Principal, Agent: req.Agent, Server: req.Server,
				Method: act.Method, Tool: act.Tool,
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

		if requested := distinct(actions); len(requested) > 0 {
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
// over "read", and the protocol methods, which name no tool, contribute nothing to it.
func distinct(actions []Action) []string {
	out := make([]string, 0, len(actions))
	for _, a := range actions {
		if a.Tool != "" && !slices.Contains(out, a.Tool) {
			out = append(out, a.Tool)
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
