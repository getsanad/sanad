# P2-06 — Centralized delegation mode (token exchange)

- **Phase:** P2 — Instance identity + delegation
- **Status:** Done (ExchangeAuthority: online down-scoping with attenuation + ancestry-based
  mid-chain revocation)
- **PRD refs:** FR-12 (mode a), §11 (OAuth token exchange)
- **Depends on:** P2-04
- **Blocks:** —

## Goal
Support centralized down-scoping via an online token-exchange step — tighter control and easy mid-chain revocation, at one round-trip per hop.

## Scope (in)
- OAuth 2.0 token-exchange endpoint that issues a narrowed delegation token per hop after verifying attenuation (P2-05).
- Selectable per deployment (vs. offline mode, P2-07).
- Each exchange is audited (P1-08).

## Acceptance criteria
- A sub-agent obtains a narrowed token via online exchange; widening is refused.
- Revoking mid-chain immediately stops further exchanges down that branch.

## Open questions
- Default mode per deployment (PRD R5) — centralized favors control, offline favors latency.
