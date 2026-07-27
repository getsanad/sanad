// Package policy is the authorization hook (PRD FR-14..FR-16). Before a passport is
// minted, the gateway asks a pluggable policy decision point (PDP) whether the verified
// principal+agent may perform the requested action. The posture is deny-by-default
// (FR-15): no explicit allow means no passport. We ship the enforcement hook and a
// baseline allowlist PDP — not the customer's business rules (NG1).
package policy

import (
	"context"

	"github.com/getsanad/sanad/pkg/types"
)

// Input is the verified context handed to the PDP.
type Input struct {
	Principal *types.Principal
	Agent     *types.Agent
	Server    string
	Tool      string
	// Delegation context is added in P2-04.
}

// PDP evaluates an Input and returns a decision. Implementations must be safe to call on
// the hot path. An error is treated as deny (fail closed) by the gateway stage.
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

// AllowList is a per-server tool/action allowlist (FR-16). A request is allowed only if
// its tool is listed for its server (or the server lists "*"); everything else is denied.
// Tools marked via Review require human-in-the-loop approval and yield EffectReview.
type AllowList struct {
	allow  map[string]map[string]struct{}
	review map[string]map[string]struct{}
}

// NewAllowList returns an empty allowlist (which therefore denies everything).
func NewAllowList() *AllowList {
	return &AllowList{
		allow:  map[string]map[string]struct{}{},
		review: map[string]map[string]struct{}{},
	}
}

// Allow permits the given tools on a server. Use "*" to permit any tool.
func (a *AllowList) Allow(server string, tools ...string) *AllowList {
	add(a.allow, server, tools)
	return a
}

// Review marks tools on a server as requiring human approval (FR-16).
func (a *AllowList) Review(server string, tools ...string) *AllowList {
	add(a.review, server, tools)
	return a
}

func add(m map[string]map[string]struct{}, server string, tools []string) {
	set := m[server]
	if set == nil {
		set = map[string]struct{}{}
		m[server] = set
	}
	for _, t := range tools {
		set[t] = struct{}{}
	}
}

// Evaluate implements PDP.
func (a *AllowList) Evaluate(_ context.Context, in Input) (types.Decision, error) {
	if _, ok := a.review[in.Server][in.Tool]; ok {
		return types.Decision{Effect: types.EffectReview, Reason: "requires approval"}, nil
	}
	if _, ok := a.allow[in.Server][in.Tool]; ok {
		return types.Decision{Effect: types.EffectAllow, Reason: "allowlisted"}, nil
	}
	if _, ok := a.allow[in.Server]["*"]; ok {
		return types.Decision{Effect: types.EffectAllow, Reason: "wildcard"}, nil
	}
	return types.Decision{Effect: types.EffectDeny, Reason: "not allowlisted"}, nil
}
