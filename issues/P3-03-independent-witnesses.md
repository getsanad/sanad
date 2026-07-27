# P3-03 — Independent witnesses (signed checkpoints)

- **Phase:** P3 — High assurance
- **Status:** Done (Witness co-signs checkpoints only after a consistency check; rejects
  rewrites/forks/shrinks)
- **PRD refs:** FR-25
- **Depends on:** P3-02
- **Blocks:** P4-01

## Goal
Publish periodic signed checkpoints of the audit log to one or more independent witnesses so external parties can verify the log hasn't been rewritten.

## Scope (in)
- Witness protocol: submit signed tree heads to independent witnesses that co-sign.
- Verification path for external parties to check witness co-signatures against the operator's checkpoints.
- Witnesses receive commitments only — never personal data (PRIV-1).

## Acceptance criteria
- Checkpoints are co-signed by ≥1 independent witness and externally verifiable.
- A rewritten log fails witness-based verification.

## Open questions
- Who runs witnesses for the beachhead (customer consortium vs. neutral third parties).
