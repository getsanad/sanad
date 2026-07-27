package types

import "time"

// Agent is a registered agent bound to exactly one accountable Principal (PRD FR-1, FR-2).
// BlueprintID is optional and set when the agent is instantiated from a blueprint (P2-03).
type Agent struct {
	ID          string
	PrincipalID string
	BlueprintID string // optional; populated in P2-03 (PRD FR-3)
	Disabled    bool   // tripped by the kill-switch (PRD FR-18)
	CreatedAt   time.Time
}
