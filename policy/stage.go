package policy

import (
	"context"
	"errors"
	"fmt"

	"github.com/getsanad/sanad/gateway"
	"github.com/getsanad/sanad/pkg/types"
)

// ToolExtractor derives the requested tool/action name from the in-flight request.
// Parsing MCP method/params is refined later; deployments can supply their own. A nil
// extractor yields an empty tool (which a "*" allowlist still permits).
type ToolExtractor func(req *gateway.Request) string

// Stage returns the gateway policy stage. It builds the PDP input from the verified
// request, evaluates it deny-by-default, routes EffectReview to the approver (if any),
// and fails closed unless the final decision is allow. On allow it records the granted
// scope on the request for the mint stage (P1-04).
func Stage(pdp PDP, extract ToolExtractor, approver Approver) gateway.Stage {
	return gateway.NewStage("policy", func(ctx context.Context, req *gateway.Request) error {
		if req.Principal == nil {
			return errors.New("policy: no authenticated principal")
		}

		var tool string
		if extract != nil {
			tool = extract(req)
		}
		in := Input{Principal: req.Principal, Agent: req.Agent, Server: req.Server, Tool: tool}

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
			req.Scope = types.Scope{Tools: []string{tool}}
		}
		return nil
	})
}
