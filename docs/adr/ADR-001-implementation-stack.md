# ADR-001 — Implementation stack: Go

- **Status:** Accepted
- **Date:** 2026-06-16
- **Deciders:** Platform, Security Eng

## Context
Sanad is, at its core, a high-throughput TLS/mTLS reverse proxy (the gateway/PEP) plus supporting services (STS, audit, admin, SDK). Hard constraints from the PRD: low hot-path latency (NFR-1: p95 ≤ ~50ms cached, ≤ ~200ms cold), horizontal scale with no single bottleneck (NFR-2), self-hostable in the customer's environment with no external hot-path dependency (NFR-6), and first-class mTLS / workload-identity / OAuth ecosystem support (§11: SPIFFE/SPIRE, OAuth 2.1/OIDC).

## Decision
Implement the gateway and core services in **Go**, as a single module monorepo. Distribute as static single binaries for easy self-hosting.

## Alternatives considered
- **Rust** — best raw performance and memory safety, but slower iteration for an early-stage codebase and a thinner OAuth/OIDC + SPIFFE ecosystem. Revisit for hot-path components if profiling demands it.
- **TypeScript/Node** — fastest for the admin UI and SDKs and closest to many agent developers, but a weaker fit for a latency-sensitive mTLS proxy. We will still ship SDKs in TS (and Python) per P1-09; the *gateway* stays Go.
- **Java/Kotlin** — strong enterprise crypto/identity libraries, heavier runtime and footprint for a self-hosted single-binary edge proxy.

## Consequences
- Native fit for mTLS, `crypto/*`, `net/http`, reverse proxying, SPIFFE/SPIRE, and `go-oidc`; aligns with §11.
- Single static binaries satisfy the self-hosting/data-residency requirement (NFR-6).
- Agent-facing SDKs may be polyglot (TS/Python) even though the control/data plane is Go.
- Monorepo (one `go.mod`) keeps shared `pkg/types` consistent across gateway, STS, verify, SDK, admin, and audit.
