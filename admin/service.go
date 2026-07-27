package admin

import (
	"context"
	"errors"
	"fmt"
	"net/url"
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

// Revoke adds an id to the kill-switch and marks the matching record disabled (FR-18).
// Revoking a principal CASCADES (FR-19): every agent rooted at that principal is also
// added to the kill-switch and disabled, so no descendant can keep operating.
func (s *Service) Revoke(_ context.Context, id string) error {
	if id == "" {
		return errors.New("admin: id required")
	}
	s.kill.Revoke(id)

	s.mu.Lock()
	defer s.mu.Unlock()
	if p, ok := s.principals[id]; ok {
		p.Disabled = true
		s.principals[id] = p
	}
	if a, ok := s.agents[id]; ok {
		a.Disabled = true
		s.agents[id] = a
	}
	// Cascade to agents rooted at this principal (FR-19) or instantiated from this
	// blueprint (FR-3): disable them and add them to the kill-switch.
	for aid, a := range s.agents {
		if a.PrincipalID == id || a.BlueprintID == id {
			a.Disabled = true
			s.agents[aid] = a
			s.kill.Revoke(aid)
		}
	}
	return nil
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
// re-enabled too, so a revoke/restore pair is symmetric.
func (s *Service) Restore(id string) {
	s.kill.Restore(id)

	s.mu.Lock()
	defer s.mu.Unlock()
	if p, ok := s.principals[id]; ok {
		p.Disabled = false
		s.principals[id] = p
	}
	if a, ok := s.agents[id]; ok {
		a.Disabled = false
		s.agents[id] = a
	}
	for aid, a := range s.agents {
		if a.PrincipalID == id || a.BlueprintID == id {
			a.Disabled = false
			s.agents[aid] = a
			s.kill.Restore(aid)
		}
	}
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
