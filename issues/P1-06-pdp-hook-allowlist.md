# P1-06 — PDP hook: deny-by-default, allowlist, optional HITL

- **Phase:** P1 — MVP
- **Status:** Done
- **PRD refs:** FR-14, FR-15, FR-16, NG1 (we provide hooks, not policy)
- **Depends on:** P1-04
- **Blocks:** —

## Goal
Before minting a passport, call a pluggable **policy decision point** with verified identity + context as inputs; enforce deny-by-default; support per-server tool/action allowlists and optional human-in-the-loop approval. We ship the *enforcement hook*, not the customer's business rules.

## Scope (in)
- **PDP interface**: synchronous decision call receiving `{principal, agent, server, requested scope/tool, delegation context}` → `allow | deny`. Pluggable (built-in simple engine + external PDP via HTTP).
- **Deny-by-default** (FR-15): no explicit allow ⇒ no passport.
- **Per-server tool/action allowlist** (FR-16) as a built-in baseline policy.
- **Human-in-the-loop** (FR-16): designated sensitive actions enter a `pending` state; mint only after approve; deny/expire on timeout.

## Out of scope
- Shipping any specific customer policy (NG1); delegation context is stubbed until P2-04.

## Acceptance criteria
- A request with no allow decision is denied and logged (deny-by-default verified).
- Allowlisted tool/action passes; non-allowlisted is denied with a reason.
- A HITL-designated action pauses until an approver acts; approval ⇒ passport, denial/timeout ⇒ no passport.

## Open questions
- Reference external PDP to document against (e.g., OPA/Cedar) — pick one for the example; keep the interface engine-agnostic.
