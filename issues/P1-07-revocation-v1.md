# P1-07 — Revocation v1: non-renewal + kill-switch

- **Phase:** P1 — MVP
- **Status:** Done
- **PRD refs:** FR-17, FR-18, FR-20, NFR-4 (≤60s)
- **Depends on:** P1-04
- **Blocks:** P1-10, P2-09

## Goal
Make cutting off an agent or principal fast and reliable without depending on a fragile real-time external status lookup that soft-fails open.

## Scope (in)
- **Non-renewal as primary mechanism** (FR-17): short passport TTLs mean access self-terminates within the configured window once issuance stops.
- **Kill-switch** (FR-18): a deny list / status list the gateway consults at mint time to immediately stop issuing for a specific agent, blueprint, or principal.
- **Effective-revocation budget** (NFR-4): kill + max TTL ≤ ~60s end-to-end; make this measurable.
- Ensure the design does **not** rely on the protected server doing an external status check that fails open (FR-20).

## Out of scope
- Principal→agent cascade (P2-09); blueprint model (P2-03) — kill-switch keys on ids that exist now.

## Acceptance criteria
- Adding an agent/principal to the kill-switch stops new passport issuance immediately.
- Existing access ends within the configured window; measured end-to-end ≤60s with default TTLs.
- Revocation path has no soft-fail-open dependency (verified by design review + test).

## Open questions
- Kill-switch storage and propagation latency across multiple gateway replicas (relates to NFR-2 horizontal scale).
