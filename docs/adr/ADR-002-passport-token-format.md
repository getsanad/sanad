# ADR-002 — Passport token format: JWT for v1

- **Status:** Accepted
- **Date:** 2026-06-16
- **Deciders:** Security Eng, Platform

## Context
The passport (PRD FR-7) is the only credential the MCP server sees. It must be short-lived, audience-bound (SEC-2), task-scoped, and **verifiable offline** by the server with no callback to the gateway on the common path (FR-9). It must also be able to carry a delegation chain claim later (FR-10) and, for some deployments, support offline holder-side attenuation (FR-12b).

## Decision
Use **JWT** (JWS) for the v1 passport, **hardened** so JOSE's well-known footguns are
designed out. Claims: `jti`, `iss`, `sub` (principal), `aud` (single target server),
`iat`, `exp`, plus custom `agent`, `scope`, and (empty in P1) `delegation`. Keys
published via JWKS for offline verification (consumed by P1-05); keys move to KMS/HSM
in P1-12.

### Mandatory hardening (these are requirements, not options)
- **EdDSA / Ed25519 only.** A single asymmetric algorithm; **ECDSA P-256** is the only
  permitted alternative, enabled solely for FIPS-constrained deployments (regulated
  customers). No others.
- **No algorithm agility.** The verifier pins the expected algorithm and ignores the
  token's `alg` header for the decision. `alg: none` and any HMAC/symmetric algorithm
  (`HS*`) are rejected outright — this closes `alg:none` and the RS256↔HS256
  confusion class.
- **No in-band keys.** Embedded `jwk`/`x5c` headers are never trusted; `kid` resolves
  only against the pinned, operator-controlled JWKS.
- **Short TTL + `aud` binding + `jti`** are mandatory on every passport (SEC-2), so a
  stolen or replayed passport is useless at another server and self-expires fast.
- Use a single vetted JOSE library wrapped behind our own `Sign`/`Verify` so these
  constraints can't be bypassed per-call.

## Alternatives considered
- **PASETO v4.public** — strictly more secure *by construction*: versioned, with no
  in-band algorithm negotiation, so `alg:none` and algorithm-confusion are impossible
  rather than merely mitigated. Rejected as the base passport because MCP servers verify
  the passport and the **MCP authorization spec is OAuth 2.1 / bearer-token (JWT) based**;
  a JWT lets us complement the server's own resource-server checks rather than force our
  verify library on every server (NG4, §11). The hardening above gives us PASETO's safety
  properties on the JWT we actually ship. Revisit if MCP/OAuth interop stops mattering.
- **CWT (CBOR)** — more compact for constrained transports; revisit if payload size matters at the edge. Not needed for HTTP-based MCP in v1.
- **Macaroons / Biscuit** — Ed25519 capability tokens supporting *offline attenuation* (FR-12b).
  This **is** the chosen format for the **delegation chain** (P2-04/P2-07): narrowing-only
  is native, and it verifies offline across trust boundaries. Decision: keep the
  server-facing *passport* a hardened JWT and use **Biscuit for the delegation chain**,
  rather than forcing one format to do both jobs. Biscuit (public-key) is preferred over
  classic macaroons (symmetric root key) so offline verification works without sharing a
  secret.

## Consequences
- Ubiquitous library support; trivial offline verification via JWKS (FR-9).
- `aud` gives us audience binding for free (SEC-2): a passport for server A fails at server B.
- Short `exp` is the primary revocation lever (FR-17) — non-renewal self-terminates access.
- The delegation chain uses **Biscuit** (P2-04/P2-07); the passport's `delegation` claim
  references the verified chain, keeping the base passport format stable.
- Hardening is enforced in one wrapped `Sign`/`Verify` path, so no individual call site
  can re-introduce an `alg:none`/confusion bug.
