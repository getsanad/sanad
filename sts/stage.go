package sts

import (
	"context"
	"errors"

	"github.com/getsanad/sanad/gateway"
)

// MintStage returns a gateway pipeline stage that mints a passport for the verified
// request and enforces token isolation (PRD FR-8): it strips any inbound caller
// credentials and forwards ONLY the freshly minted passport as a Bearer token. It fails
// closed if no principal was established by an earlier stage.
//
// The requested scope is supplied by the policy decision point in P1-06; until then the
// passport binds identity + audience, which is what enforces SEC-2.
func MintStage(issuer Issuer) gateway.Stage {
	return gateway.NewStage("mint", func(ctx context.Context, req *gateway.Request) error {
		if req.Principal == nil {
			return errors.New("sts: no authenticated principal to mint for")
		}

		audience := req.Server
		if req.Target != nil {
			audience = req.Target.ID
		}

		m, err := issuer.Issue(ctx, IssueRequest{
			Principal:  req.Principal,
			Agent:      req.Agent,
			Audience:   audience,
			Scope:      req.Scope,      // granted by the policy stage (P1-06)
			Delegation: req.Delegation, // verified chain (P2-04), if any
		})
		if err != nil {
			return err
		}
		req.Passport = &m.Passport

		// Token isolation (FR-8): the inbound principal/agent credentials are never
		// forwarded; the upstream sees only the minted passport.
		if req.HTTP != nil {
			req.HTTP.Header.Del("Authorization")
			req.HTTP.Header.Del("Proxy-Authorization")
			req.HTTP.Header.Set("Authorization", "Bearer "+m.Token)
		}
		return nil
	})
}
