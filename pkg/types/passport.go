package types

import "time"

// Budget bounds what a delegated action may consume. Constraints may only narrow as
// they pass down a delegation chain (PRD FR-10, FR-11).
type Budget struct {
	Limit int64
	Unit  string
}

// Scope is the set of permissions/tasks a Passport grants on a single target server.
type Scope struct {
	Tools  []string // allowed tool/action names (PRD FR-16 allowlist)
	Budget *Budget  // optional spend/usage limit
}

// Passport is the short-lived, audience-bound, task-scoped credential the gateway
// mints after verification and the MCP server ultimately trusts (PRD FR-7, SEC-2).
// It is the only credential forwarded upstream; principal/agent tokens never are (FR-8).
type Passport struct {
	ID          string // jti
	PrincipalID string
	AgentID     string
	Audience    string // single target MCP server (audience-restricted, SEC-2)
	Scope       Scope
	Delegation  *DelegationChain // empty in P1; populated in P2-04 (PRD FR-10)
	IssuedAt    time.Time
	ExpiresAt   time.Time
}

// Expired reports whether the passport is at or past its expiry at time t.
func (p Passport) Expired(t time.Time) bool { return !t.Before(p.ExpiresAt) }
