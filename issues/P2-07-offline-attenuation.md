# P2-07 — Offline attenuation mode (macaroon/Biscuit)

- **Phase:** P2 — Instance identity + delegation
- **Status:** Done (Biscuit-style capability: offline attenuation, offline verify vs root key,
  holder proof, recipient-can't-broaden; + CapabilityStage)
- **PRD refs:** FR-12 (mode b), §11 (macaroon/Biscuit)
- **Depends on:** P2-04
- **Blocks:** —

## Goal
Support offline attenuation via capability-style tokens a holder can narrow without contacting the issuer — lower latency, works across trust boundaries.

## Scope (in)
- Capability-token format: **Biscuit** (decided in ADR-002 — public-key, so offline
  verification works across trust boundaries without a shared secret), supporting
  holder-side caveat addition (narrowing only).
- Gateway verifies the attenuated token offline against P2-05 rules.
- Selectable per deployment vs. centralized mode (P2-06).

## Acceptance criteria
- A holder narrows a capability token offline and the gateway honors the reduced scope.
- Any attempt to broaden via caveats fails verification.

## Open questions
- Mid-chain revocation is harder offline (PRD R5) — pair with short TTLs and kill-switch (P1-07); document the trade-off.
