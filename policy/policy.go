// Package policy is the authorization hook (PRD FR-14..FR-16). Before a passport is
// minted, the gateway asks a pluggable policy decision point (PDP) whether the verified
// principal+agent may perform the requested action. The posture is deny-by-default
// (FR-15): no explicit allow means no passport. We ship the enforcement hook and a
// baseline allowlist PDP — not the customer's business rules (NG1).
//
// The allowlist is configured from a file rather than from Go: see Config (the "policy"
// section of the configuration document the config package loads), which compiles to an
// AllowList. An operator can therefore change authorization without recompiling the gateway.
package policy

import (
	"context"
	"fmt"

	"github.com/getsanad/sanad/pkg/types"
)

// Wildcard is the allowlist entry matching any tool (or any method) on its server. It is the
// operator's own explicit choice, it is per server — a wildcard on one server never leaks to
// another — and a more specific entry always beats it.
const Wildcard = "*"

// MethodNone is the Method of the decision made for a request that carries no JSON-RPC call
// at all: a GET (MCP opens its server->client SSE stream with one), a DELETE that ends a
// session, a POST whose body is not JSON-RPC. Such a request still gets exactly one decision —
// a request nobody decided is a request nobody authorized — so it needs a NAME an operator can
// write in a policy file; without one the only way to permit an MCP session's event stream
// would be a blanket method wildcard. The parentheses keep it outside the JSON-RPC method
// namespace, so it can never collide with a real method.
const MethodNone = "(none)"

// Input is the verified context handed to the PDP.
type Input struct {
	Principal *types.Principal
	Agent     *types.Agent
	Server    string
	// Method is the JSON-RPC method this decision covers — "tools/call", "tools/list",
	// "initialize", "notifications/initialized" — or MethodNone for a request carrying no
	// JSON-RPC call. It is what lets a policy allow the MCP handshake while still gating the
	// work that travels over it: every tool invocation arrives under one method, so a decision
	// keyed only on Tool cannot tell "list the tools" from "run one".
	Method string
	// Tool is the tool the request invokes: params.name of a tools/call. It is EMPTY for every
	// other method, because no other method names a tool — which is also what selects method
	// matching over tool matching in AllowList.
	Tool string
	// DelegatedScope is the authority the request's delegation confers — the effective
	// grant the delegation stage narrowed it to — with an empty Tools reading as
	// unconstrained, exactly as attenuation reads it. Delegation is the verified chain
	// behind it, nil both when the principal acts directly and in the offline capability
	// mode (delegation.CapabilityStage), which carries a grant but no chain, so read the
	// scope for authority and the chain for provenance.
	//
	// The stage already enforces the floor (Tool must be within DelegatedScope), so a PDP
	// that ignores these stays safe; they are supplied so a policy engine can decide AGAINST
	// the grant it is narrowing — route past a Budget to review, refuse a chain beyond some
	// depth — which without them it could not see at all.
	Delegation     *types.DelegationChain
	DelegatedScope types.Scope
}

// PDP evaluates an Input and returns a decision. Implementations must be safe to call on
// the hot path. An error is treated as deny (fail closed) by the gateway stage. An allow is
// permission to mint, not authority to widen: the stage still intersects the decision with
// Input.DelegatedScope, so no PDP can grant past the signed delegation chain.
type PDP interface {
	Evaluate(ctx context.Context, in Input) (types.Decision, error)
}

// Func adapts a function to a PDP.
type Func func(ctx context.Context, in Input) (types.Decision, error)

// Evaluate implements PDP.
func (f Func) Evaluate(ctx context.Context, in Input) (types.Decision, error) { return f(ctx, in) }

// DenyAll denies everything — the safe default before a real policy is configured.
var DenyAll PDP = Func(func(_ context.Context, _ Input) (types.Decision, error) {
	return types.Decision{Effect: types.EffectDeny, Reason: "deny-by-default"}, nil
})

// AllowList is a per-server allowlist of the actions an agent may take (FR-16). A request is
// allowed only if the action it names is listed for its server; everything else is denied.
// Entries marked for review require human-in-the-loop approval and yield EffectReview.
//
// Actions are matched in TWO namespaces, because MCP puts them in two places. A tools/call
// names a tool (params.name) and is matched against the server's TOOL entries; every other
// JSON-RPC message — initialize, tools/list, notifications/* — names no tool and is matched
// against its METHOD entries, as is the MethodNone decision a non-JSON-RPC request makes.
// Keying on the tool alone, as this used to, made "allow tools/list but gate tools/call"
// inexpressible: both arrive with the same shape, and the protocol handshake would have had
// to be permitted by a tool wildcard broad enough to permit every tool with it.
//
// It is the operator's ceiling, deliberately independent of the delegation chain: the stage
// has already rejected anything outside Input.DelegatedScope before this runs, so an
// allowlist entry can only ever subtract from the delegated grant, never add to it.
type AllowList struct {
	servers map[string]*serverRules
}

// serverRules is one server's entries, split by the namespace they match in.
type serverRules struct {
	tools   ruleSet
	methods ruleSet
}

// ruleSet is the allow/review entries of a single namespace.
type ruleSet struct {
	allow  map[string]struct{}
	review map[string]struct{}
}

// decide resolves a name against the set, most specific first and — at equal specificity — to
// the safer effect. Order: exact review, exact allow, wildcard review, wildcard allow, deny.
// An exact entry beating the wildcard is what lets "allow *, review transfer" mean what it
// reads as; review beating allow at the same specificity is the fail-safe tie-break, so a name
// listed on both sides routes to a human rather than straight through.
func (s ruleSet) decide(name string) (types.Effect, bool) {
	if _, ok := s.review[name]; ok {
		return types.EffectReview, true
	}
	if _, ok := s.allow[name]; ok {
		return types.EffectAllow, true
	}
	if _, ok := s.review[Wildcard]; ok {
		return types.EffectReview, false
	}
	if _, ok := s.allow[Wildcard]; ok {
		return types.EffectAllow, false
	}
	return types.EffectDeny, false
}

// NewAllowList returns an empty allowlist (which therefore denies everything).
func NewAllowList() *AllowList {
	return &AllowList{servers: map[string]*serverRules{}}
}

// Allow permits the given tools on a server, i.e. a tools/call naming any of them. Use
// Wildcard to permit any tool. Calling it with no tools still registers the server.
func (a *AllowList) Allow(server string, tools ...string) *AllowList {
	add(&a.rules(server).tools.allow, tools)
	return a
}

// Review marks tools on a server as requiring human approval (FR-16).
func (a *AllowList) Review(server string, tools ...string) *AllowList {
	add(&a.rules(server).tools.review, tools)
	return a
}

// AllowMethods permits JSON-RPC methods that name no tool of their own — "initialize",
// "tools/list", "notifications/initialized" — plus MethodNone for requests carrying no
// JSON-RPC call. Use Wildcard to permit any of them. It does NOT reach tools/call: what a
// tools/call may do is decided by Allow/Review, on the tool it names.
func (a *AllowList) AllowMethods(server string, methods ...string) *AllowList {
	add(&a.rules(server).methods.allow, methods)
	return a
}

// ReviewMethods marks methods on a server as requiring human approval.
func (a *AllowList) ReviewMethods(server string, methods ...string) *AllowList {
	add(&a.rules(server).methods.review, methods)
	return a
}

func (a *AllowList) rules(server string) *serverRules {
	r := a.servers[server]
	if r == nil {
		r = &serverRules{}
		a.servers[server] = r
	}
	return r
}

func add(set *map[string]struct{}, names []string) {
	if *set == nil {
		*set = map[string]struct{}{}
	}
	for _, n := range names {
		(*set)[n] = struct{}{}
	}
}

// Evaluate implements PDP.
func (a *AllowList) Evaluate(_ context.Context, in Input) (types.Decision, error) {
	rules, ok := a.servers[in.Server]
	if !ok {
		return types.Decision{
			Effect: types.EffectDeny,
			Reason: fmt.Sprintf("not allowlisted: no policy for server %q", in.Server),
		}, nil
	}

	// A tools/call is decided on the tool it names; everything else on its method.
	kind, name, set := "tool", in.Tool, rules.tools
	if in.Tool == "" {
		kind, name, set = "method", in.Method, rules.methods
	}

	effect, exact := set.decide(name)
	switch effect {
	case types.EffectAllow:
		return types.Decision{Effect: effect, Reason: allowReason(kind, name, in.Server, exact)}, nil
	case types.EffectReview:
		return types.Decision{Effect: effect, Reason: reviewReason(kind, name, in.Server, exact)}, nil
	default:
		return types.Decision{
			Effect: types.EffectDeny,
			Reason: fmt.Sprintf("not allowlisted: %s %q on server %q", kind, name, in.Server),
		}, nil
	}
}

func allowReason(kind, name, server string, exact bool) string {
	if exact {
		return fmt.Sprintf("allowlisted: %s %q", kind, name)
	}
	return fmt.Sprintf("allowlisted: %s wildcard on server %q", kind, server)
}

func reviewReason(kind, name, server string, exact bool) string {
	if exact {
		return fmt.Sprintf("requires approval: %s %q", kind, name)
	}
	return fmt.Sprintf("requires approval: %s wildcard on server %q", kind, server)
}
