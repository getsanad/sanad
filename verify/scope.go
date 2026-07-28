package verify

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/getsanad/sanad/pkg/types"
)

// ErrNoPassport is returned when a scope check runs outside Middleware — no verified
// passport is on the context, so there is nothing to check against and the answer is a
// refusal, not a pass.
var ErrNoPassport = errors.New("verify: no verified passport on the request context")

// ErrOutOfScope is returned when the passport does not grant the tool being invoked. It is
// deliberately distinct from a verification failure: the passport is genuine, the ACTION is
// not permitted, which is a 403 rather than a 401.
var ErrOutOfScope = errors.New("verify: tool is outside the passport scope")

// Allows reports whether the passport's scope permits invoking tool.
//
// An EMPTY tool set is the UNCONSTRAINED WILDCARD, not "nothing allowed". That is the
// reading the rest of the system is built on — delegation's subset() validates every hop
// against it (a concrete parent may never be widened back to empty) and policy's granted()
// applies it at the gateway — and an enforcement point that read it the other way would
// reject every passport minted for a principal acting directly, or for a chain that is
// simply not constrained on tools.
//
// The security consequence is real and worth stating plainly: a passport with no scope is
// accepted here for ANY tool. That is not a hole this check can close, because the passport
// carries no narrower authority to enforce — it is decided upstream, by the gateway policy
// and by whether the deployment allows an unscoped grant at all
// (delegation.WithRequireChain / PASSPORT_ALLOW_DIRECT_PRINCIPAL). A resource server that
// will not serve an unscoped passport under any circumstances says so with
// RequireScopedPassport, which refuses it before this question is ever asked.
//
// Entries match literally: a grant has no "*" wildcard, so a literal "*" in a scope grants a
// tool named "*" and nothing else.
func Allows(p types.Passport, tool string) bool {
	return len(p.Scope.Tools) == 0 || slices.Contains(p.Scope.Tools, tool)
}

// RequireScope checks a tool against the passport Middleware verified onto ctx. It is the
// one-line form for a handler that has already worked out which tool it is about to run:
//
//	if err := verify.RequireScope(r.Context(), name); err != nil {
//		http.Error(w, err.Error(), http.StatusForbidden)
//		return
//	}
//
// Use EnforceScope instead to have the middleware do it for every tools/call in the body.
func RequireScope(ctx context.Context, tool string) error {
	p, ok := FromContext(ctx)
	if !ok {
		return ErrNoPassport
	}
	if !Allows(p, tool) {
		return fmt.Errorf("%w: %q is not in %v", ErrOutOfScope, tool, p.Scope.Tools)
	}
	return nil
}

// DelegationPath returns the accountability path the passport carries — the accountable
// principal, then each delegate in turn, ending at the agent that made this call — and
// whether the passport carried one at all.
//
// See types.DelegationRef for exactly what this is and is not evidence of: it is the
// gateway's signed assertion about a chain it verified, not a chain this server can verify
// hop by hop.
func DelegationPath(p types.Passport) ([]string, bool) {
	if p.DelegationRef == nil || len(p.DelegationRef.Path) == 0 {
		return nil, false
	}
	return p.DelegationRef.Path, true
}
