# P1-04 — Passport issuance service (STS) + token isolation

- **Phase:** P1 — MVP
- **Status:** Done
- **PRD refs:** FR-7, FR-8, SEC-2
- **Depends on:** P1-02, P1-03
- **Blocks:** P1-05, P1-06, P1-07, P1-09, P1-12, P2-04

## Goal
Mint short-lived, audience-bound, task-scoped **passports** — the only credential the MCP server sees — and guarantee the original principal/agent tokens are never forwarded upstream.

## Scope (in)
- **STS** that signs a passport (JWT for v1 per ADR-002) carrying: `principal`, `agent` id, `scope`/task, `aud` = target server, short `exp` (seconds–minutes, configurable), `iat`, unique `jti`.
- **Token isolation** (FR-8): strip all inbound `Authorization`/principal/agent credentials before forwarding; attach only the minted passport.
- Configurable passport TTL per server/tier.
- Signing key fetched from KMS interface (stub until P1-12).
- Delegation claim placeholder in the passport for P2 (`delegation_chain`), empty in P1.

## Out of scope
- Offline verification by the server (P1-05); delegation chain contents (P2-04).

## Acceptance criteria
- A passport is minted with correct claims for an authenticated principal + registered server.
- Inbound principal/agent tokens are verifiably absent from the upstream request (test asserts).
- A passport with `aud` = server A is rejected when presented to server B (audience binding).
- TTL is enforced; expired passports rejected.

## Open questions
- ~~JWT vs CWT for v1~~ — **resolved (ADR-002):** hardened **JWT/JWS, EdDSA (Ed25519)**,
  algorithm pinned, no `alg` agility, no in-band keys (ECDSA P-256 only for FIPS). The
  delegation chain uses **Biscuit** (P2-04/P2-07), not the passport format.
- Signing keys are KMS/HSM-backed in P1-12; until then a local dev key (ADR-004 covers storage).
