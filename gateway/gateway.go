// Package gateway is the policy enforcement point (PEP): an identity-aware reverse
// proxy in front of registered MCP servers so no agent reaches a protected server
// directly (PRD §6). It resolves the target server, runs an ordered decision pipeline,
// and only on success forwards upstream — any unknown server or stage error fails
// closed (NFR-3). Concrete decision stages arrive in P1-03/P1-04/P1-06.
package gateway

import (
	"context"
	"net/http"

	"github.com/getsanad/sanad/pkg/types"
)

// Request is the in-flight, identity-enriched request moving through the pipeline.
// Successive stages populate its identity fields (principal auth, policy, mint).
type Request struct {
	Server     string                 // target protected MCP server ID
	Target     *Server                // resolved server (nil if unknown)
	HTTP       *http.Request          // the inbound request stages may inspect
	Principal  *types.Principal       // set by the principal-auth stage (P1-03)
	Agent      *types.Agent           // set by instance auth (P2-02) or delegation (P2-04)
	Decision   *types.Decision        // set by the policy stage (P1-06)
	Scope      types.Scope            // granted scope (policy P1-06 / delegation P2-04); consumed by mint
	Delegation *types.DelegationChain // verified chain set by the delegation stage (P2-04)
	Passport   *types.Passport        // set by the minting stage (P1-04)
}

// Stage is one step in the gateway decision pipeline:
//
//	authn(instance) -> authn(principal) -> policy(PDP) -> mint(passport)
//
// A stage returns an error to fail the request closed (PRD NFR-3); no stage may
// silently allow a request to proceed. Forwarding and audit happen after a clean run.
type Stage interface {
	Name() string
	Handle(ctx context.Context, req *Request) error
}

// NewStage adapts a named function into a Stage, for wiring pipelines concisely.
func NewStage(name string, fn func(ctx context.Context, req *Request) error) Stage {
	return stageFunc{name: name, fn: fn}
}

type stageFunc struct {
	name string
	fn   func(ctx context.Context, req *Request) error
}

func (s stageFunc) Name() string                                 { return s.name }
func (s stageFunc) Handle(ctx context.Context, r *Request) error { return s.fn(ctx, r) }

// Pipeline runs stages in order, stopping at the first error (fail-closed).
type Pipeline struct {
	Stages []Stage
}

// Run executes each stage in order. Any error aborts the request without proceeding.
func (p Pipeline) Run(ctx context.Context, req *Request) error {
	for _, s := range p.Stages {
		if err := s.Handle(ctx, req); err != nil {
			return err
		}
	}
	return nil
}
