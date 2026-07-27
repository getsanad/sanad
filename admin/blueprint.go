package admin

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/getsanad/sanad/pkg/types"
)

// Blueprint defines an agent type once so an org can instantiate many short-lived
// instances under it, inheriting its governance (PRD FR-3). Revoking a blueprint cascades
// to all of its instances (kill-switch by BlueprintID, enforced at the gateway and in
// Service.Revoke).
type Blueprint struct {
	ID          string   `json:"id"`
	PrincipalID string   `json:"principalId"` // owning accountable principal
	Tier        string   `json:"tier"`        // assurance tier inherited by instances
	Servers     []string `json:"servers"`     // governance: allowed servers
	Tools       []string `json:"tools"`       // governance: default tools
}

// RegisterBlueprint stores a blueprint under an existing principal.
func (s *Service) RegisterBlueprint(_ context.Context, bp Blueprint) error {
	if bp.ID == "" {
		return errors.New("admin: blueprint id required")
	}
	if bp.PrincipalID == "" {
		return errors.New("admin: blueprint must reference a principal")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.principals[bp.PrincipalID]; !ok {
		return fmt.Errorf("admin: unknown principal %q", bp.PrincipalID)
	}
	s.blueprints[bp.ID] = bp
	return nil
}

// InstantiateAgent creates an agent under a blueprint, inheriting its principal (FR-3).
func (s *Service) InstantiateAgent(_ context.Context, blueprintID, agentID string) (types.Agent, error) {
	if agentID == "" {
		return types.Agent{}, errors.New("admin: agent id required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	bp, ok := s.blueprints[blueprintID]
	if !ok {
		return types.Agent{}, fmt.Errorf("admin: unknown blueprint %q", blueprintID)
	}
	a := types.Agent{ID: agentID, PrincipalID: bp.PrincipalID, BlueprintID: blueprintID}
	s.agents[agentID] = a
	return a, nil
}

// Blueprints returns all registered blueprints, sorted by id.
func (s *Service) Blueprints() []Blueprint {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Blueprint, 0, len(s.blueprints))
	for _, bp := range s.blueprints {
		out = append(out, bp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
