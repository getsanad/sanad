# P3-04 — Tool-definition hashing/verification (drift detection)

- **Phase:** P3 — High assurance (can pull earlier — security hardening)
- **Status:** Done (tooldefs: approved-baseline fingerprint + drift/unknown detection;
  live ModifyResponse wiring is a follow-up)
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
