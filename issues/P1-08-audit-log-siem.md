# P1-08 — Append-only audit log + SIEM streaming

- **Phase:** P1 — MVP
- **Status:** Done
- **PRD refs:** FR-21, FR-22, FR-23, PRIV-1/2/3
- **Depends on:** P1-02
- **Blocks:** P3-02

## Goal
Record every verification decision, passport issuance, and forwarded action in an append-only log attributable to a responsible party, and stream it to the customer's SIEM in near-real-time.

## Scope (in)
- **Append-only store** (v1): entries cannot be silently edited/deleted; per-entry hash-chaining as the foundation for P3-02's Merkle/transparency upgrade.
- **Attribution** (FR-22): each entry references the agent instance (id now, full instance identity in P2), delegation context (stub until P2-04), and responsible principal.
- **SIEM streaming** (FR-23): export in a standard format (e.g., CEF/JSON over syslog or an OTLP/webhook sink), near-real-time.
- **Privacy** (PRIV-1/2/3): store only what accountability needs; log is operator-controlled and access-controlled; access to the audit log is itself logged.

## Out of scope
- Merkle inclusion/consistency proofs and external witnesses (P3-02/P3-03).

## Acceptance criteria
- Decisions, issuances, and forwarded actions are persisted with principal/agent attribution.
- Tampering with a past entry is detectable via the hash chain.
- Events stream to a configured SIEM sink in a documented standard format.
- Audit-log reads are themselves recorded (PRIV-3).

## Open questions
- Default standard export format for the beachhead SIEMs (confirm against design-partner tooling).
