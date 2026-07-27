# P1-05 — Offline passport verification library + MCP server adapter

- **Phase:** P1 — MVP
- **Status:** Done
- **PRD refs:** FR-9, FR-29, R6 (adoption friction)
- **Depends on:** P1-04
- **Blocks:** —

## Goal
Let MCP server owners verify passports **offline** (signature + claims, no callback to the gateway on the common path) and drop protection in with minimal code.

## Scope (in)
- **Verification library**: validates passport signature, `aud`, `exp`, `scope`; fetches/caches gateway signing keys via JWKS.
- **Thin MCP server adapter**: middleware that gates an MCP server using the library; a passport-less or invalid request is rejected.
- Worked example: protect a sample MCP server in a handful of lines.
- Clear key-rotation handling (cache + refresh) so offline verification keeps working across rotation (coordinates with P1-12).

## Out of scope
- Gateway-side minting (P1-04); delegation verification (P2).

## Acceptance criteria
- A sample MCP server validates a real gateway-issued passport fully offline.
- Wrong-audience, expired, and forged/altered passports are rejected.
- Adapter integration is documented and demonstrably small (<~20 lines for the reference server).

## Open questions
- Languages to ship first. Start with the gateway's language; flag others (TS, Python) as follow-ups driven by design-partner stacks.
