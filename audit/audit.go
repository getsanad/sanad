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
	Action     string // "allow" | "deny" (extended as more event types are logged)
	Reason     string
	Server     string
	Principal  string
	Agent      string
	PassportID string   // jti of the issued passport (for the investigation view, FR-24)
	Delegation []string // delegation path principal -> ... -> agent, if any (FR-10)
	Decision   *types.Decision
	// PrevHash/Hash form the tamper-evident hash chain (HashChainLog); they are the
	// foundation for the P3-02 Merkle transparency log.
	PrevHash []byte
	Hash     []byte
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
