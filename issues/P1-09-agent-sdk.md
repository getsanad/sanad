# P1-09 — Agent SDK (register + obtain passport)

- **Phase:** P1 — MVP
- **Status:** Done
- **PRD refs:** FR-1, FR-29, R6 (adoption friction)
- **Depends on:** P1-04
- **Blocks:** —

## Goal
Give agent developers a simple SDK to register an agent under a principal/blueprint and obtain passports at runtime with minimal friction.

## Scope (in)
- **Registration** flow: register an agent under a verified principal; receive SDK config (no embedded long-lived secret — FR-1).
- **Runtime client**: transparently obtains a passport and routes calls through the gateway to a protected MCP server.
- Sensible defaults, clear errors (denied vs. expired vs. unregistered), retry/refresh on TTL expiry.
- Quickstart + example agent.

## Out of scope
- Workload credential via attestation (P2-01) — v1 registration uses the IdP-backed principal flow; SDK API is designed so attestation slots in without breaking callers.
- Creating delegation entries (P2-04/P2-07).

## Acceptance criteria
- A developer can register an agent and make an authorized call to a protected MCP server end-to-end using only the SDK.
- No long-lived shared secret is embedded in the agent (FR-1).
- Passport refresh on expiry is handled by the SDK.

## Open questions
- First SDK language(s) — align with design-partner stacks (likely TS + Python); flag as assumption.
