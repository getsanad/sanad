# P2-04 — Delegation chain data model (signed, attenuating)

- **Phase:** P2 — Instance identity + delegation
- **Status:** Done (lib + stage + live gateway wiring via the workload KeyStore, P2-02)
- **PRD refs:** FR-10, FR-13
- **Depends on:** P1-04
- **Blocks:** P2-05, P2-06, P2-07, P2-09

## Goal
Represent delegation as a signed chain (principal → agent → sub-agent…), where each entry names the delegate, granted scope, and constraints (budget, time, allowed servers), and cannot be forged without the delegating party's key.

## Scope (in)
- Chain data model + serialization; each hop signed by the delegating key.
- Gateway verifies every signature and that the root principal is accountable/not revoked.
- Anti-impersonation (FR-13): extending a chain requires the delegating key; unsigned "rogue" use rejected and logged.
- Populate the `delegation_chain` claim in the passport (P1-04) and audit attribution (P1-08).

## Acceptance criteria
- A multi-hop chain verifies end-to-end at the gateway.
- A chain extension without the delegating key is rejected and logged.

## Open questions
- Token encoding for chain entries (feeds ADR-002 and the offline mode, P2-07).
