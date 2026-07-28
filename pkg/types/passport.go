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
	// Delegation is the FULL verified chain, hop signatures and all. It is set gateway-side
	// (the delegation stage puts it here on the way to minting) and recorded in the audit
	// log; it is deliberately not what the token carries — see DelegationRef.
	Delegation *DelegationChain
	// DelegationRef is the delegation as it travels on the wire (PRD FR-10): the ordered
	// path of parties plus a digest of the full chain. This is the field a resource server
	// reads back off a verified passport, and the one the codec round-trips.
	DelegationRef *DelegationRef
	IssuedAt      time.Time
	ExpiresAt     time.Time
}

// Expired reports whether the passport is at or past its expiry at time t.
func (p Passport) Expired(t time.Time) bool { return !t.Before(p.ExpiresAt) }
