# P1-10 — Admin console v1

- **Phase:** P1 — MVP
- **Status:** Done (API; web UI deferred)
- **PRD refs:** FR-27
- **Depends on:** P1-03, P1-07
- **Blocks:** —

## Goal
Provide a control-plane API + minimal console to register/disable principals, agents, and protected servers, view live sessions, and trigger revocation.

## Scope (in)
- **Control-plane API** (the console is a thin client over it): CRUD for principals, agents, protected servers.
- **Disable / revoke** actions wired to the kill-switch (P1-07).
- **Live sessions** view: currently active agents / recent passport issuance.
- **Minimal web UI** over the API; RBAC on admin access; admin actions audited (ties to P1-08).

## Out of scope
- Blueprints (P2-03) and delegation views (P2-09) — added when those land.

## Acceptance criteria
- Operator can register and disable a principal, agent, and protected server via the console.
- Triggering revocation from the console takes effect through the kill-switch.
- Live sessions are visible; all admin actions are recorded in the audit log.

## Open questions
- Console scope for v1 — API-first with a thin UI is the default; confirm how much UI design partners actually need vs. API + CLI.
