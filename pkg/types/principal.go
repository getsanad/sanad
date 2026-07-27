package types

import "time"

// AssuranceLevel expresses how strongly a Principal's identity has been verified.
// The required minimum is per-deployment policy (PRD FR-2, R4); enforcement lands in P1-06.
type AssuranceLevel string

const (
	AssuranceUnverified AssuranceLevel = "unverified"
	AssuranceIndividual AssuranceLevel = "individual" // a verified individual
	AssuranceOrg        AssuranceLevel = "org"        // verified org / domain / KYC
)

// Principal is the accountable human or organization behind an agent (PRD FR-2, FR-6).
// In P1 the Subject is an IdP subject; P2-08 adds W3C VC / DID-based principals.
type Principal struct {
	ID        string
	Subject   string // IdP subject (P1) or DID (P2-08)
	Assurance AssuranceLevel
	Disabled  bool // tripped by the kill-switch / IdP disable (PRD FR-18, FR-19)
	CreatedAt time.Time
}
