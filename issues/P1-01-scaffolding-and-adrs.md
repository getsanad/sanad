# P1-01 — Tech stack, repo scaffolding & ADRs

- **Phase:** P1 — MVP
- **Status:** Done
- **PRD refs:** §6 (architecture), §11 (standards & interop)
- **Depends on:** —
- **Blocks:** everything

## Goal
Lock the foundational technical decisions and stand up a repo skeleton so all subsequent issues build on a stable base.

## Scope (in)
- **Stack decision (ADR).** Recommendation: **Go** — strongest fit for the mTLS/TLS gateway, proxy ecosystem, native SPIFFE/SPIRE and `go-oidc` libraries, and easy self-hosted single-binary distribution (NFR-6). Alternatives (Rust, TS) recorded with trade-offs.
- **Monorepo layout** with module skeletons that compile:
  - `gateway/` (PEP + request pipeline)
  - `sts/` (passport issuance)
  - `verify/` (offline verification library + MCP adapter)
  - `sdk/` (agent SDK)
  - `admin/` (control plane API + console)
  - `audit/` (append-only log + SIEM export)
  - `pkg/` (shared types: Principal, Agent, Passport, DelegationChain, Decision)
- **ADR template** + initial ADRs:
  - ADR-001 implementation language/stack
  - ADR-002 passport token format (recommend **JWT** for v1; leave **CWT/biscuit** as future for FR-12b)
  - ADR-003 audit store choice (append-only; path to Merkle/transparency log in P3-02)
- CI scaffolding (build, lint, unit test) and a `make`/task runner.

## Out of scope
- Any real auth, crypto, or business logic (later issues).

## Acceptance criteria
- Repo builds green in CI; module skeletons compile and expose stub interfaces.
- ADR-001/002/003 merged and referenced from this issue.
- Shared `pkg/` types defined for Principal, Agent, Passport, Decision.

## Open questions
- Managed-service vs. self-hosted-first as the primary distribution shape — affects packaging (relates to NFR-6). Default: self-hostable single binary first.
