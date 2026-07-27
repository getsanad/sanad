# P1-03 — Principal authentication via IdP (OAuth 2.1 / OIDC)

- **Phase:** P1 — MVP
- **Status:** Done
- **PRD refs:** FR-6, §11 (OAuth 2.1/OIDC)
- **Depends on:** P1-02
- **Blocks:** P1-04, P1-10

## Goal
Verify the accountable **principal** (human/org) behind a call using the customer's existing IdP, and confirm the principal is currently valid (not revoked/disabled).

## Scope (in)
- OIDC relying-party integration (`go-oidc` or equivalent): discovery, JWKS, token validation (issuer, audience, expiry, signature).
- Map a validated principal token → internal `Principal` record.
- Check principal status against the kill-switch/deny-list interface (consumed from P1-07; stub until then).
- Configurable **assurance level** field on the principal (e.g., verified-domain/org vs. individual) — recorded now, enforced by policy in P1-06. Full VC-based principal identity is P2-08.

## Out of scope
- Verifiable-Credential principals (P2-08); instance identity (P2-02).

## Acceptance criteria
- A valid principal token is accepted and resolved to a `Principal`.
- Expired, wrong-audience, bad-signature, or revoked principal tokens are rejected and logged.
- IdP config is per-deployment (issuer URL, client, audience).

## Open questions
- Default minimum assurance level per deployment (PRD R4) — surface as config with a sane default.
