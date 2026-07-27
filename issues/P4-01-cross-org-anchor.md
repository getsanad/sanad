# P4-01 — Cross-org shared anchor (conditional, hashes only)

- **Phase:** P4 — Cross-org (conditional)
- **Status:** Not started — **gated**
- **PRD refs:** §12 (conditional future exception), §13, Appendix B
- **Depends on:** P3-03
- **Blocks:** —

## Goal
*If and only if justified*, provide a minimal shared anchor for cross-organization revocation/audit commitments across mutually distrusting organizations.

## Gate (must pass before any work starts)
- A concrete cross-org adversary is **documented** that a transparency log with independent witnesses (P3-03) cannot satisfy.
- If that specific adversary can't be named, **do not build this** (PRD §12).

## Scope (in, only if gate passes)
- Minimal multi-witness / anchored revocation + audit **commitments** — hashes only, never personal data (PRIV-1).
- No per-request on-chain operations; nothing on the hot path (NG3, §12).

## Acceptance criteria
- A documented cross-org adversary justifies the anchor.
- Cross-org revocation/audit commitments are verifiable across orgs using hashes only.

## Notes
- Default expectation per the PRD is that this is **not built**. Keep as a placeholder unless the gate is met.
