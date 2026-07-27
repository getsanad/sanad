// Package tooldefs detects tool-definition drift (PRD SEC-3): a protected MCP server's
// advertised tools are fingerprinted against an approved baseline, so a silently changed
// or poisoned tool surface is caught. Higher-assurance servers can treat drift as a hard
// deny; others as a flag.
package tooldefs

import (
	"crypto/sha256"
	"sync"
)

// Status is the result of comparing observed tool definitions to the approved baseline.
type Status int

const (
	// OK means the observed definitions match the approved baseline.
	OK Status = iota
	// Drifted means the definitions changed from the approved baseline.
	Drifted
	// Unknown means no baseline has been approved for this server yet.
	Unknown
)

func (s Status) String() string {
	switch s {
	case OK:
		return "ok"
	case Drifted:
		return "drifted"
	default:
		return "unknown"
	}
}

// Hash fingerprints a server's tool definitions (the raw bytes the server advertises).
func Hash(defs []byte) [32]byte { return sha256.Sum256(defs) }

// Approved holds the approved tool-definition fingerprint per server.
type Approved struct {
	mu     sync.RWMutex
	hashes map[string][32]byte
}

// New returns an empty baseline registry.
func New() *Approved { return &Approved{hashes: map[string][32]byte{}} }

// Approve pins the current definitions as the baseline for a server.
func (a *Approved) Approve(server string, defs []byte) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.hashes[server] = Hash(defs)
}

// Check compares observed definitions to the approved baseline.
func (a *Approved) Check(server string, defs []byte) Status {
	a.mu.RLock()
	defer a.mu.RUnlock()
	want, ok := a.hashes[server]
	if !ok {
		return Unknown
	}
	if want == Hash(defs) {
		return OK
	}
	return Drifted
}
