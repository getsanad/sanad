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
		req.Scope = grant.Scope()
		req.Delegation = chain.ToTypes()
		if req.Agent == nil {
			req.Agent = &types.Agent{ID: actingAgent, PrincipalID: req.Principal.ID}
		}
		return nil
	})
}
