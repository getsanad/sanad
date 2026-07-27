# ADR-004 — Data storage: Postgres control plane + abstract audit sink

- **Status:** Accepted
- **Date:** 2026-06-16
- **Deciders:** Platform, Security Eng, Compliance

## Context
Two very different persistence needs:
1. **Control plane** — principals, agents, blueprints, protected servers, policy, the
   kill-switch/deny-list, and the only place we hold PII. Low-to-moderate volume, needs
   strong consistency, transactions, and — for data-subject rights (PRD PRIV-2) —
   **deletion/rectification**.
2. **Audit log** — every decision, issuance, and forwarded action. High-volume,
   append-only, queried for the investigation view (FR-24) and dashboards (FR-28).

Hard constraints: the gateway hot path must add ≤ ~50ms p95 (NFR-1) with **no external
call on the hot-path decision** (NFR-6); revocation must take effect ≤60s (NFR-4);
tamper-evidence is cryptographic (FR-21), not a property of the database.

## Decision
- **Control plane → PostgreSQL** (with **SQLite** as the option for small self-hosted
  single-binary deployments). System of record for identities, policy, and the
  kill-switch; PII lives here so it can be erased (PRIV-2).
- **Hot path → no per-request DB call.** Passport verification is offline (signature).
  The kill-switch is served from an **in-process cache** with a short TTL refreshed from
  Postgres (optionally fanned out via Redis for multi-replica propagation, but never a
  blocking network hop in the verify path). Bounded cache staleness + short passport TTL
  is what delivers ≤60s revocation (NFR-4) without soft-fail-open lookups (FR-20).
- **Audit log → backend kept abstract** behind the `audit.Log` interface; the concrete
  store is chosen when **P1-08** is implemented. **Leading candidate: ClickHouse** —
  columnar, high append-only ingest, fast analytics for FR-24/FR-28 — with **PII kept
  out** (principal/agent IDs + hashes only, per PRIV-1) so erasure stays in Postgres.
  SQLite/Postgres remain acceptable for small deployments; SIEM streaming (FR-23) happens
  regardless of the local store.

## Alternatives considered
- **One Postgres for everything** — simplest; fine at low/medium volume, but audit
  analytics at high action volume will strain it. Still the default for small self-hosts.
- **Audit only in the customer's SIEM** — couples the investigation view to their tooling;
  we keep a local queryable store and *also* stream to the SIEM.
- **Blockchain / immutable ledger** — rejected (Appendix B, PRIV-2): too slow/costly for
  the volume and incompatible with erasure rights. Integrity comes from the hash-chain →
  Merkle log + witnesses (ADR-003), layered above whatever store.

## Consequences
- Splitting **erasable PII (Postgres)** from **high-volume append-only events (audit
  sink)** satisfies PRIV-1 and PRIV-2 at the same time.
- `audit.Log` stays backend-agnostic, so adopting ClickHouse later is additive — no schema
  migration forced now (matches the "keep the sink abstract for now" decision).
- The hot path stays DB-free, protecting NFR-1 and NFR-6.
