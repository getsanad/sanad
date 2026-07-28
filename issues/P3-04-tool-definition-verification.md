# P3-04 — Tool-definition hashing/verification (drift detection)

- **Phase:** P3 — High assurance (can pull earlier — security hardening)
- **Status:** Done and wired. `tooldefs` fingerprints a canonical form of a server's tool
  definitions and the gateway checks every `tools/list` **response** from a pinned server
  against it (`gateway.ResponseInspector` → `ModifyResponse`). Pins live in the `tooldefs`
  section of the configuration document; drift refuses the response (`deny`, default) or
  records it (`warn`), quarantines the server, audits under the `drift` action and exports
  `agentpassport_tooldefs_quarantined_servers`.
- **PRD refs:** SEC-3 (tool definition drift)
- **Depends on:** P1-02
- **Blocks:** —

## Goal
Defend against tool-definition drift: hash and verify MCP tool definitions so a silently changed/poisoned tool surface is detected.

## Scope (in)
- Capture and hash each protected server's tool definitions at registration / known-good time.
- Verify current tool definitions against the approved hash on the gateway path; flag/deny on mismatch per server tier.
- Surface drift events to audit (P1-08) and observability (P1-11).

## Acceptance criteria
- A changed tool definition vs. the approved baseline is detected and handled (flag or fail-closed by tier).

## Notes
- This addresses a documented MCP threat (SEC-3) and could be promoted into P1/P2 if a design partner needs it sooner — it depends only on the gateway (P1-02).
- Known gaps, deliberate: drift on a server nobody lists through the gateway is never seen (an
  out-of-band poller would close this, at the cost of being a distinguishable client a hostile
  server can serve a clean list to); a poisoned list delivered over SSE is detected and
  quarantines the server but cannot be withheld, because those bytes are already on the wire; a
  paginated `tools/list` cannot be compared against a whole-list pin and is treated as
  unverifiable rather than passed.
