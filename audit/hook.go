package audit

import (
	"context"
	"log"
	"time"

	"github.com/getsanad/sanad/gateway"
)

// GatewayHook adapts an audit Log to the gateway's audit seam (gateway.AuditFunc),
// recording every allow/deny decision with its principal/agent/server attribution
// (PRD FR-22). Append failures are logged, not propagated — auditing must not break the
// request path. (A write-ahead "audit before forward" guarantee is a later refinement.)
func GatewayHook(l Log) gateway.AuditFunc {
	return func(req *gateway.Request, allowed bool, reason string) {
		action := "deny"
		if allowed {
			action = "allow"
		}
		e := Entry{
			At:       time.Now().UTC(),
			Action:   action,
			Reason:   reason,
			Server:   req.Server,
			Decision: req.Decision,
		}
		if req.Principal != nil {
			e.Principal = req.Principal.ID
		}
		if req.Agent != nil {
			e.Agent = req.Agent.ID
		}
		if req.Passport != nil {
			e.PassportID = req.Passport.ID
		}
		if req.Delegation != nil && len(req.Delegation.Hops) > 0 {
			path := []string{req.Delegation.Hops[0].Delegator}
			for _, h := range req.Delegation.Hops {
				path = append(path, h.Delegate)
			}
			e.Delegation = path
		}
		if err := l.Append(context.Background(), e); err != nil {
			log.Printf("audit: append failed: %v", err)
		}
	}
}
