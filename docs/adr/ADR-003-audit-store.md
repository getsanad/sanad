# ADR-003 — Audit store: hash-chained append-only log now, Merkle transparency log later

- **Status:** Accepted
- **Date:** 2026-06-16
- **Deciders:** Security Eng, Compliance

## Context
Every decision, issuance, and forwarded action must be recorded in an append-only, tamper-evident log attributable to a responsible principal (PRD FR-21, FR-22), streamed to a SIEM (FR-23), and eventually support inclusion/consistency proofs with independent witnesses (FR-25, P3-02/P3-03). Privacy law requires data-subject rights, so the system of record is an operator-controlled log — **never a public blockchain** (PRIV-2, §12, Appendix B). No personal data goes on any external anchor; anchors carry hashes only (PRIV-1).

## Decision
P1 (issue P1-08): a **hash-chained append-only log** — each entry carries `PrevHash`/`Hash` so silent edits/deletes are detectable — persisted in operator-controlled storage, with near-real-time SIEM streaming in a standard format. The schema is designed so P3-02 layers a **Merkle transparency log** (inclusion + consistency proofs) and P3-03 adds **independent witnesses** over the same entries without a data migration.

## Alternatives considered
- **Plain RDBMS audit table** — simple but not inherently tamper-evident; we add the hash chain on top of normal storage.
- **Blockchain / public ledger** — rejected: seconds-to-minutes latency and per-write cost are disqualifying for the action volume, and immutability conflicts with erasure rights (Appendix B). A narrow cross-org *hash-only* anchor remains a gated P4 possibility (P4-01), never the primary store.
- **Managed CT-style log from day one** — more than P1 needs; deferred to P3-02 to keep the MVP lean.

## Consequences
- P1 gets tamper-evidence (hash chain) + SIEM streaming without heavy infrastructure.
- The entry schema (see `audit/audit.go`) reserves `PrevHash`/`Hash`, so the P3 Merkle/witness upgrade is additive.
- Storage backend stays operator-controlled to honor data residency (NFR-6) and data-subject rights (PRIV-2).
