package audit

import (
	"context"
	"log"
	"time"

	"github.com/getsanad/sanad/tooldefs"
)

// ToolDefsHook adapts an audit Log to the tool-definition guard's event seam
// (tooldefs.AuditFunc), so drift lands in the same tamper-evident chain as every allow and
// deny (PRD FR-21..FR-23, SEC-3) — attributed to the principal and agent whose request
// surfaced it, which is where an investigation starts.
//
// Drift is recorded under its own action rather than folded into "deny", because the two answer
// different questions. A deny is "this caller was not allowed to do that"; a drift is "this
// SERVER is no longer the one that was approved", which is true regardless of who asked and
// stays true for every caller after them. A SIEM rule wants to alert on the second immediately
// even when the mode is "warn" and nothing was blocked at all.
func ToolDefsHook(l Log) tooldefs.AuditFunc {
	return func(ev tooldefs.Event) {
		at := ev.At
		if at.IsZero() {
			at = time.Now().UTC()
		}
		action := "tooldefs"
		if ev.Status == tooldefs.Drifted {
			action = "drift"
		}
		e := Entry{
			At:         at,
			Action:     action,
			Reason:     ev.Reason,
			Server:     ev.Server,
			Principal:  ev.Principal,
			Agent:      ev.Agent,
			PassportID: ev.PassportID,
			Delegation: ev.Delegation,
			Drift: &Drift{
				Status:   ev.Status.String(),
				Mode:     string(ev.Mode),
				Blocked:  ev.Blocked,
				Approved: ev.Approved,
				Observed: ev.Observed,
				Tools:    ev.Tools,
				Page:     ev.Page,
			},
		}
		if err := l.Append(context.Background(), e); err != nil {
			log.Printf("audit: append failed: %v", err)
		}
	}
}
