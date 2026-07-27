# P1-02 — Gateway core: identity-aware reverse proxy (PEP)

- **Phase:** P1 — MVP
- **Status:** Done
- **PRD refs:** §6 (architecture), FR-5, NFR-3 (fail closed)
- **Depends on:** P1-01
- **Blocks:** P1-03, P1-04, P1-08, P1-11, P3-04

## Goal
Stand up the enforcement point (PEP): a reverse proxy that sits in front of registered MCP servers so no agent reaches a protected server directly, with a pluggable request pipeline for later stages.

## Scope (in)
- **Server registry**: config of protected MCP servers (id, upstream URL, transport, assurance tier).
- **Transport support** for MCP: HTTP + SSE / streamable-HTTP; pass through request/response faithfully to the upstream.
- **Request pipeline** with ordered, pluggable stages — stubs wired now, filled by later issues:
  `authn(instance) → authn(principal) → policy(PDP) → mint(passport) → forward → audit`.
- **Fail-closed default** (NFR-3): any stage error or missing decision ⇒ request denied, never silently allowed.
- Health/readiness endpoints.

## Out of scope
- Instance mTLS (P2-02), principal auth (P1-03), passport minting (P1-04) — only the hooks/stubs here.

## Acceptance criteria
- A request to a registered MCP server is proxied through the gateway to its upstream.
- A request to an unregistered server, or any pipeline-stage failure, is rejected (fail-closed) — verified by test.
- Pipeline middleware interface exists and is unit-tested with no-op stages.

## Open questions
- Which MCP transport(s) to support first — default to streamable-HTTP + SSE; confirm against target design-partner servers.
