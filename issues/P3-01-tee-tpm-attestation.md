# P3-01 — TEE/TPM remote attestation (RATS)

- **Phase:** P3 — High assurance
- **Status:** Done (RATS-style MeasuredAttestor: approved-build measurement + freshness +
  trusted attestation key; plugs into the workload Authority for the high-assurance tier)
- **PRD refs:** FR-26, §11 (IETF RATS), R3
- **Depends on:** P2-01
- **Blocks:** —

## Goal
For designated high-assurance servers, require a hardware-backed attestation that the agent runs an approved build before issuing a passport; reject stale or unrecognized measurements.

## Scope (in)
- IETF RATS-style remote attestation (TEE/TPM): collect evidence, verify against an approved-build appraisal policy.
- Gate passport issuance for designated servers on a fresh, recognized measurement.
- Reject stale/unknown measurements (fail-closed).

## Acceptance criteria
- A regulated-data server can require approved-build proof; non-matching/stale builds are denied.

## Open questions
- Required assurance level per tier and root-of-trust (PRD R3): attestation proves which binary runs, not source match unless reproducibly built.
