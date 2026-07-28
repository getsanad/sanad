package admin

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"sort"
	"sync"

	"github.com/getsanad/sanad/audit"
	"github.com/getsanad/sanad/gateway"
	"github.com/getsanad/sanad/pkg/types"
	"github.com/getsanad/sanad/revoke"
)

// Service is the in-memory control plane. It owns principal/agent records and drives the
// shared gateway registry (protected servers) and kill-switch (revocation).
type Service struct {
	mu         sync.RWMutex
	principals map[string]types.Principal
	agents     map[string]types.Agent
	blueprints map[string]Blueprint

	registry *gateway.Registry
	kill     revoke.Store
	audit    *audit.HashChainLog // optional, enables the investigation view (P2-09)
	reviews  Reviews             // optional, enables the human-approval queue (FR-16)
}

// Option configures a Service.
type Option func(*Service)

// WithAuditLog enables the investigation view backed by the given audit log.
func WithAuditLog(l *audit.HashChainLog) Option {
	return func(s *Service) { s.audit = l }
}

// NewService returns a Service backed by the given gateway registry and kill-switch.
func NewService(registry *gateway.Registry, kill revoke.Store, opts ...Option) *Service {
	s := &Service{
		principals: map[string]types.Principal{},
		agents:     map[string]types.Agent{},
		blueprints: map[string]Blueprint{},
		registry:   registry,
		kill:       kill,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// RegisterPrincipal records an accountable principal (FR-2).
func (s *Service) RegisterPrincipal(_ context.Context, p types.Principal) error {
	if p.ID == "" {
		return errors.New("admin: principal id required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.principals[p.ID] = p
	return nil
}

// RegisterAgent records an agent bound to an existing principal (FR-1, FR-2).
func (s *Service) RegisterAgent(_ context.Context, a types.Agent) error {
	if a.ID == "" {
		return errors.New("admin: agent id required")
	}
	if a.PrincipalID == "" {
		return errors.New("admin: agent must reference a principal")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.principals[a.PrincipalID]; !ok {
		return fmt.Errorf("admin: unknown principal %q", a.PrincipalID)
	}
	s.agents[a.ID] = a
	return nil
}

// RegisterServer adds a protected MCP server to the gateway registry.
func (s *Service) RegisterServer(id, upstream string) error {
	if id == "" {
		return errors.New("admin: server id required")
	}
	if upstream == "" {
		return errors.New("admin: server upstream URL required")
	}
	u, err := url.Parse(upstream)
	if err != nil {
		return fmt.Errorf("admin: bad upstream URL: %w", err)
	}
	return s.registry.Register(&gateway.Server{ID: id, Upstream: u})
}

// StoreError reports that a control-plane write did not reach the durable kill-switch — its
// Postgres source is unreachable, say. It is not the caller's mistake, so the HTTP layer
// answers 5xx rather than 4xx, and it separates two audiences: Err is the underlying cause,
// for the server log only (it can carry a DSN, host, or driver detail), while Op, IDs and
// Applied are the caller-safe account of what did and did not take effect.
type StoreError struct {
	Op      string   // "revoke" or "restore"
	IDs     []string // every id the operation was meant to cover
	Applied []string // the ids the store confirms are now in the requested state
	Err     error    // underlying cause — logged, never sent to the caller
}

func (e *StoreError) Error() string {
	return fmt.Sprintf("admin: %s %v failed against the durable kill-switch (applied: %v): %v",
		e.Op, e.IDs, e.Applied, e.Err)
}

func (e *StoreError) Unwrap() error { return e.Err }

// Failed returns the ids whose new state the store does NOT confirm. They are the ones the
// operator must assume are still as they were, and retry.
func (e *StoreError) Failed() []string {
	out := make([]string, 0, len(e.IDs))
	for _, id := range e.IDs {
		if !slices.Contains(e.Applied, id) {
			out = append(out, id)
		}
	}
	return out
}

// Public is the caller-facing summary: what happened, with no internal detail.
func (e *StoreError) Public() string {
	return fmt.Sprintf("%s failed: the kill-switch could not be written to its durable store; "+
		"treat the listed ids as unchanged and retry", e.Op)
}

// Revoke adds an id to the kill-switch and marks the matching record disabled (FR-18).
// Revoking a principal CASCADES (FR-19): every agent rooted at that principal is also
// added to the kill-switch and disabled, so no descendant can keep operating. Revoking a
// blueprint cascades to its instances the same way (FR-3).
//
// The whole cascade goes to the kill-switch in ONE call, which Store applies atomically:
// either the target and every descendant are durably revoked, or nothing is. A half-applied
// cascade would leave agents operating while the operator had been told their principal was
// cut off. If the write fails, nothing is marked disabled — the in-memory view never claims
// a revocation the durable store does not have — and the failure is returned as a
// *StoreError, which the HTTP layer answers with 5xx rather than a reassuring 200.
func (s *Service) Revoke(_ context.Context, id string) error {
	if id == "" {
		return errors.New("admin: id required")
	}

	// The whole operation runs under the lock so the cascade is computed and written against
	// one view of the registry: an agent registered mid-revocation cannot slip past it.
	s.mu.Lock()
	defer s.mu.Unlock()

	ids := s.cascade(id)
	if err := s.kill.Revoke(ids...); err != nil {
		return &StoreError{Op: "revoke", IDs: ids, Applied: s.confirmRevoked(ids), Err: err}
	}

	// The durable write landed; the in-memory bookkeeping that follows cannot fail.
	if p, ok := s.principals[id]; ok {
		p.Disabled = true
		s.principals[id] = p
	}
	for _, aid := range ids {
		if a, ok := s.agents[aid]; ok {
			a.Disabled = true
			s.agents[aid] = a
		}
	}
	return nil
}

// cascade returns id followed by every agent that hangs off it — rooted at it as a principal
// (FR-19) or instantiated from it as a blueprint (FR-3) — sorted after the target so the set
// is deterministic in responses and logs. Callers must hold s.mu.
func (s *Service) cascade(id string) []string {
	var agents []string
	for aid, a := range s.agents {
		if aid != id && (a.PrincipalID == id || a.BlueprintID == id) {
			agents = append(agents, aid)
		}
	}
	sort.Strings(agents)
	return append([]string{id}, agents...)
}

// confirmRevoked returns the subset of ids the kill-switch reports as revoked. It is used
// only on Revoke's failure path: the operator's next question after "the write failed" is
// "so what is in effect right now?", and that is answered by asking the store rather than by
// assuming the write was atomic. Asking is safe in this direction only — a store that is
// failing its writes may be failing its reads too, and an unreadable store answers "not
// revoked", so a bad read can only understate what is in effect, never overstate it. (That
// is why Restore does not do the same read-back: there, an unreadable store would look like
// a successful restore.)
func (s *Service) confirmRevoked(ids []string) []string {
	var out []string
	for _, id := range ids {
		if s.kill.Revoked(id) {
			out = append(out, id)
		}
	}
	return out
}

// Investigate returns the accountability report for a passport id (FR-24). Requires an
// audit log (WithAuditLog).
func (s *Service) Investigate(passportID string) (audit.Report, error) {
	if s.audit == nil {
		return audit.Report{}, errors.New("admin: audit log not configured")
	}
	return s.audit.Investigate(passportID)
}

// HasAudit reports whether the investigation view is available.
func (s *Service) HasAudit() bool { return s.audit != nil }

// Restore removes an id from the kill-switch and clears its disabled flag. Restoring a
// principal reverses the cascade (FR-19): its agents are taken off the kill-switch and
// re-enabled too, so a revoke/restore pair is symmetric — including in its failure handling,
// which mirrors Revoke: one atomic write, and on failure a *StoreError and no record change,
// so the console never shows an agent as enabled while the kill-switch still denies it.
func (s *Service) Restore(id string) error {
	if id == "" {
		return errors.New("admin: id required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	ids := s.cascade(id)
	if err := s.kill.Restore(ids...); err != nil {
		// Applied stays empty on purpose: see confirmRevoked. Nothing is claimed restored
		// unless the write said so, so the operator's fallback assumption is "still revoked".
		return &StoreError{Op: "restore", IDs: ids, Err: err}
	}

	if p, ok := s.principals[id]; ok {
		p.Disabled = false
		s.principals[id] = p
	}
	for _, aid := range ids {
		if a, ok := s.agents[aid]; ok {
			a.Disabled = false
			s.agents[aid] = a
		}
	}
	return nil
}

// Revocations lists the ids currently on the kill-switch.
func (s *Service) Revocations() []string { return s.kill.List() }

// Principals returns all registered principals, sorted by id.
func (s *Service) Principals() []types.Principal {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]types.Principal, 0, len(s.principals))
	for _, p := range s.principals {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Agents returns all registered agents, sorted by id.
func (s *Service) Agents() []types.Agent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]types.Agent, 0, len(s.agents))
	for _, a := range s.agents {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
