# P2-03 — Agent blueprint/template model

- **Phase:** P2 — Instance identity + delegation
- **Status:** Done (Blueprint type + register/instantiate; revoking a blueprint cascades to
  its instances)
- **PRD refs:** FR-3
- **Depends on:** P2-01
- **Blocks:** —

## Goal
Let an org define an agent **type once** (blueprint) and instantiate many short-lived instances under it, inheriting governance from the blueprint.

## Scope (in)
- Blueprint entity: default scope, allowed servers, budget/time constraints, assurance tier.
- Instance creation references a blueprint and inherits its governance; kill-switch (P1-07) can target a blueprint.
- Admin console (P1-10) gains blueprint management.

## Acceptance criteria
- An org defines a blueprint and spins up multiple instances under it.
- Revoking a blueprint stops issuance for all its instances.

## Open questions
- Which constraints are blueprint-fixed vs. per-instance-narrowable (ties to attenuation, P2-05).
