// Package audit records every verification decision, passport issuance, and forwarded
// action in an append-only, tamper-evident log and streams it to a SIEM (PRD
// FR-21..FR-23). Implemented in issue P1-08; the Merkle/transparency-log upgrade is P3-02.
package audit

import (
	"context"
	"time"

	"github.com/getsanad/sanad/pkg/types"
)

// Entry is a single append-only audit record, attributable to a principal and agent
// (PRD FR-22).
type Entry struct {
	At         time.Time
	Action     string // "allow" | "deny" | "drift" | "tooldefs" (extended as more events are logged)
	Reason     string
	Server     string
	Principal  string
	Agent      string
	PassportID string   // jti of the issued passport (for the investigation view, FR-24)
	Delegation []string // delegation path principal -> ... -> agent, if any (FR-10)
	Decision   *types.Decision
	// Drift is the detail of a tool-definition event (SEC-3), nil on every other entry.
	Drift *Drift
	// PrevHash/Hash form the tamper-evident hash chain (HashChainLog); they are the
	// foundation for the P3-02 Merkle transparency log.
	PrevHash []byte
	Hash     []byte
}

// Drift is what a tool-definition drift entry has to carry for the alert to be actionable
// without going back to the wire. "Server X drifted" is not investigable; the approved digest,
// the one the upstream actually served, the tools it advertised, and whether the request was
// stopped or merely noted, are. Every field is covered by the entry's chain hash, so the record
// of what was seen cannot be quietly edited afterwards.
type Drift struct {
	Status   string   `json:"status"`             // "drifted" | "ok" | "unknown"
	Mode     string   `json:"mode,omitempty"`     // configured failure mode: "deny" | "warn"
	Blocked  bool     `json:"blocked"`            // the response was refused / the request denied
	Approved string   `json:"approved,omitempty"` // the pinned fingerprint
	Observed string   `json:"observed,omitempty"` // the fingerprint the upstream served
	Tools    []string `json:"tools,omitempty"`    // tool names observed, sorted
	Page     bool     `json:"page,omitempty"`     // the observation covered one page of a paginated list
}

// Log is an append-only audit log. Entries cannot be silently edited or deleted.
type Log interface {
	Append(ctx context.Context, e Entry) error
}

// Sink receives each appended entry for near-real-time streaming to a SIEM/monitoring
// endpoint (PRD FR-23). It is downstream of the system of record (the Log), so a sink
// failure never loses the recorded entry.
type Sink interface {
	Write(e Entry) error
}
