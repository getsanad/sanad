package delegation

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/getsanad/sanad/gateway"
	"github.com/getsanad/sanad/pkg/types"
)

// ChainExtractor pulls a delegation chain from the in-flight request (e.g. from a header
// the SDK sets). It returns present=false when the request carries no delegation, in which
// case the principal acts directly. Transport encoding is deployment-specific.
type ChainExtractor func(req *gateway.Request) (chain Chain, present bool, err error)

// StageOption configures Stage or CapabilityStage.
type StageOption func(*stageOptions)

type stageOptions struct{ requireChain bool }

// WithRequireChain makes the stage fail closed when the request carries no delegation,
// instead of letting the principal act directly. Without it delegation is opt-in per
// request, so a delegate holding a chain attenuated to e.g. ["read"] can simply omit the
// chain and be minted a passport with NO scope at all — an empty scope is unconstrained
// (see Grant), hence strictly wider than the chain it actually holds. Deployments where
// every caller is a delegate should always set this.
func WithRequireChain() StageOption { return func(o *stageOptions) { o.requireChain = true } }

func newStageOptions(opts []StageOption) stageOptions {
	var o stageOptions
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

// Stage returns the gateway delegation stage. When a chain is present it verifies it
// against the authenticated principal (fail-closed on any error), narrows the request
// scope to the effective grant, records the verified chain for minting/audit, and sets the
// acting agent to the final delegate. A request with no chain lets the principal act
// directly unless WithRequireChain is set, which rejects it.
//
// Live wiring needs agent keys in the KeyRegistry (from workload credentials, P2-01/P2-02);
// until then this stage is exercised via tests with an in-memory registry.
func Stage(keys KeyRegistry, extract ChainExtractor, opts ...StageOption) gateway.Stage {
	o := newStageOptions(opts)
	return gateway.NewStage("delegation", func(_ context.Context, req *gateway.Request) error {
		if req.Principal == nil {
			return errors.New("delegation: no authenticated principal")
		}
		chain, present, err := extract(req)
		if err != nil {
			return fmt.Errorf("delegation: %w", err)
		}
		if !present {
			if o.requireChain {
				return errors.New("delegation: no delegation chain presented (a chain is required)")
			}
			return nil
		}
		grant, actingAgent, err := Verify(chain, keys, req.Principal.ID, time.Now())
		if err != nil {
			return err // fail closed
		}
		// Bind the chain to the authenticated instance: if an instance was authenticated
		// (P2-02), it must be the party the chain actually ends at.
		if req.Agent != nil && req.Agent.ID != actingAgent {
			return fmt.Errorf("delegation: chain ends at %q but the authenticated instance is %q", actingAgent, req.Agent.ID)
		}
		if err := checkServer(grant, req); err != nil {
			return err // fail closed
		}
		req.Scope = grant.Scope()
		req.Delegation = chain.ToTypes()
		if req.Agent == nil {
			req.Agent = &types.Agent{ID: actingAgent, PrincipalID: req.Principal.ID}
		}
		return nil
	})
}

// checkServer binds the effective grant's Servers constraint to the server the request is
// actually headed for. Grant.Scope() projects only tools+budget, so without this the server
// constraint — signed by the principal, transported and attenuation-checked — would never
// reach a decision, and a chain granting only "reports" would authorize "payments".
//
// The semantics are the ones subset (attenuation.go) already validated every hop against:
// an EMPTY list is the wildcard "any server", and entries are matched literally. A grant has
// no "*" wildcard — attenuates treats "*" as an ordinary server id — so a literal "*" here
// matches only a server registered under that id.
func checkServer(g Grant, req *gateway.Request) error {
	if len(g.Servers) == 0 {
		return nil // unconstrained, as attenuation reads it
	}
	// Target is the resolved server the gateway will proxy to, so it is what must be
	// checked; req.Server is the id it was resolved from, for pipelines wired by hand.
	target := req.Server
	if req.Target != nil {
		target = req.Target.ID
	}
	if target == "" {
		return errors.New("delegation: the delegation is limited to named servers but the request has no target server")
	}
	for _, s := range g.Servers {
		if s == target {
			return nil
		}
	}
	return fmt.Errorf("delegation: the delegation grants servers %v but the request targets %q", g.Servers, target)
}
