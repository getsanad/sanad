# P2-05 — Attenuation-only enforcement

- **Phase:** P2 — Instance identity + delegation
- **Status:** Done
- **PRD refs:** FR-11
- **Depends on:** P2-04
- **Blocks:** —

## Goal
Guarantee each delegation hop can only **narrow** permissions, never widen them.

## Scope (in)
- Scope/constraint comparison logic: reject any hop whose scope, budget, time, or server set exceeds what it was granted.
- Applies across scope, budget, expiry, and allowed-server dimensions.
- Violations rejected and logged with a clear reason.

## Acceptance criteria
- A hop attempting to widen any dimension is rejected.
- Valid narrowing across all dimensions is accepted; the issued passport reflects the narrowest effective scope.

## Open questions
- Canonical scope algebra so "narrower" is unambiguous across dimensions.
