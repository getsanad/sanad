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
		// Same derivation the passport's `dlg` claim uses, so the path in the log and the
		// path the resource server was handed are the same string by construction.
		e.Delegation = req.Delegation.Path()
		if err := l.Append(context.Background(), e); err != nil {
			log.Printf("audit: append failed: %v", err)
		}
	}
}
