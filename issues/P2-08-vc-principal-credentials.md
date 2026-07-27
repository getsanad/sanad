# P2-08 — VC-based principal credentials (did:web / did:key)

- **Phase:** P2 — Instance identity + delegation
- **Status:** Done (W3C VC + did:key + principal-auth integration that auto-registers the
  principal key for delegation; did:web resolution is a follow-up)
- **PRD refs:** FR-2, §11 (W3C VCs, non-blockchain DIDs)
- **Depends on:** P1-03
- **Blocks:** —

## Goal
Bind each agent to exactly one accountable principal verified to a configurable assurance level, using W3C Verifiable Credentials with non-blockchain identifier methods.

## Scope (in)
- Accept/verify W3C VCs for principal/org identity using `did:web` / `did:key` (no blockchain — PRD §12).
- Configurable assurance levels (org KYC / verified domain vs. verified individual — FR-2).
- Coexist with the P1 IdP/OIDC principal path; deployments choose per assurance tier.

## Acceptance criteria
- A principal presents a VC; the gateway verifies issuer/subject/assurance and binds the agent to it.
- Below-threshold assurance is rejected per policy.

## Open questions
- Trusted VC issuers and how org KYC maps to assurance levels (PRD R4).
