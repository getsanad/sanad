# P3-02 — Transparency-log audit (Merkle inclusion/consistency proofs)

- **Phase:** P3 — High assurance
- **Status:** Done (RFC 6962-style Merkle log: inclusion + consistency proofs, signed
  checkpoints; truncation/rewrite detectable — fixes the hash-chain tail-truncation gap)
- **PRD refs:** FR-21, FR-25, NFR-5, §11 (CT-style logs), Appendix B
- **Depends on:** P1-08
- **Blocks:** P3-03

## Goal
Upgrade the append-only audit log (P1-08) to a Certificate-Transparency-style Merkle log supporting inclusion and consistency proofs, with bounded proof sizes at full action volume.

## Scope (in)
- Merkle tree over audit entries; inclusion proofs (entry is in the log) and consistency proofs (log wasn't rewritten).
- Periodic signed checkpoints (tree heads).
- Sustains full action volume with verifiable integrity and bounded proof sizes (NFR-5).
- No personal data on any external anchor — hashes/commitments only (PRIV-1, Appendix B).

## Acceptance criteria
- Any entry yields a verifiable inclusion proof; consistency proofs detect rewriting.
- Throughput sustains target action volume with bounded proof sizes.

## Open questions
- Log implementation (build on Trillian-style infra vs. bespoke).
