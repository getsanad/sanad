// Package revoke implements the kill-switch / deny-list (PRD FR-18). Revocation is
// primarily by non-renewal (FR-17): because passports are short-lived, simply ceasing to
// issue them lets access self-terminate within the configured window. The kill-switch
// makes that immediate by causing the gateway to stop minting for a specific principal,
// agent, or blueprint at once. Combined with short TTLs this meets the ≤60s revocation
// target (NFR-4).
//
// The store is consulted in-process on the mint path — there is no external real-time
// status lookup that could "soft-fail open" (FR-20). A durable, cached backing store
// (Postgres + in-process cache) arrives with ADR-004 wiring; MemStore is the default.
package revoke

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/getsanad/sanad/gateway"
)

// Checker is the read side of the kill-switch consulted on the hot path: it must be a fast,
// local, non-failing lookup (no network call that could soft-fail open, FR-20). Both
// MemStore and the multi-replica CachedStore satisfy it.
type Checker interface {
	Revoked(id string) bool
}

// FreshnessChecker is the optional companion to Checker for implementations that answer
// from a periodically refreshed snapshot rather than from authoritative local state. Revoked
// returns a bool, which has no way to say "I don't know" — so the freshness of the snapshot
// behind it is asked separately, here. Stage consults it before trusting any Revoked answer;
// a Checker that cannot go stale (MemStore) simply does not implement it.
type FreshnessChecker interface {
	// CheckFresh returns nil while the local view is recent enough to be trusted, and an
	// error describing the staleness once it is not.
	CheckFresh() error
}

// Store is the kill-switch / deny-list. Revoking an id immediately stops issuance for it.
type Store interface {
	Checker
	Revoke(id string)
	Restore(id string)
	List() []string
}

// MemStore is an in-process kill-switch. Its Revoked method also satisfies the
// principal.StatusChecker interface, so the same store enforces principal revocation at
// authentication time and principal/agent/blueprint revocation at mint time.
type MemStore struct {
	mu      sync.RWMutex
	revoked map[string]struct{}
}

// NewMemStore returns an empty kill-switch.
func NewMemStore() *MemStore {
	return &MemStore{revoked: map[string]struct{}{}}
}

// Revoke adds an id (principal, agent, or blueprint) to the deny list.
func (m *MemStore) Revoke(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.revoked[id] = struct{}{}
}

// Restore removes an id from the deny list.
func (m *MemStore) Restore(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.revoked, id)
}

// Revoked reports whether an id is on the deny list.
func (m *MemStore) Revoked(id string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.revoked[id]
	return ok
}

// List returns the revoked ids in sorted order (for the admin console, P1-10).
func (m *MemStore) List() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]string, 0, len(m.revoked))
	for id := range m.revoked {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// Stage returns a gateway stage that rejects the request if the principal, agent, or the
// agent's blueprint is on the kill-switch. It runs after identity is established and
// before minting, so a revoked party can never obtain a passport. It needs only a Checker,
// so it works with the in-process MemStore or the multi-replica CachedStore.
//
// When the Checker is snapshot-backed (FreshnessChecker) the stage first asks whether that
// snapshot can still be trusted, and denies the request outright if it cannot. That is the
// fail-closed direction and the reason this check lives here rather than inside Revoked:
// a stale kill-switch cannot rule anyone out, so it must stop everyone — including
// principals that authenticated cleanly, since principal.StatusChecker consults the same
// snapshot and gets the same unknowable answer (NFR-4).
func Stage(c Checker) gateway.Stage {
	return gateway.NewStage("revocation", func(_ context.Context, req *gateway.Request) error {
		if f, ok := c.(FreshnessChecker); ok {
			if err := f.CheckFresh(); err != nil {
				return fmt.Errorf("revocation: %w", err)
			}
		}
		if req.Principal != nil && c.Revoked(req.Principal.ID) {
			return fmt.Errorf("revocation: principal %q is revoked", req.Principal.ID)
		}
		if req.Agent != nil {
			if c.Revoked(req.Agent.ID) {
				return fmt.Errorf("revocation: agent %q is revoked", req.Agent.ID)
			}
			if req.Agent.BlueprintID != "" && c.Revoked(req.Agent.BlueprintID) {
				return fmt.Errorf("revocation: blueprint %q is revoked", req.Agent.BlueprintID)
			}
		}
		return nil
	})
}
