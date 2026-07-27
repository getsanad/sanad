# P2-09 — Principal revocation cascade + investigation view

- **Phase:** P2 — Instance identity + delegation
- **Status:** Done
- **PRD refs:** FR-19, FR-24
- **Depends on:** P1-07, P2-04
- **Blocks:** —

## Goal
Make revoking a principal cascade to all agents and chains rooted in it, and provide an investigation view that returns the full chain from any action back to the accountable principal.

## Scope (in)
- **Cascade** (FR-19): revoking a principal invalidates all dependent agents, blueprints, and delegation chains via the kill-switch (P1-07).
- **Investigation view** (FR-24): given an action/incident, traverse the audit log (P1-08) + delegation chain (P2-04) and return the responsible principal with the full path.
- Surfaced in the admin console (P1-10).

## Acceptance criteria
- Revoking a principal stops issuance for every dependent agent/chain.
- Given an action id, the system returns the complete chain back to the accountable principal.

## Open questions
- Performance of cascade + investigation traversal at scale (relates to NFR-5).
