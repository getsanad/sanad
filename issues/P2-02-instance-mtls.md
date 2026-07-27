# P2-02 — Instance authentication via mTLS at the gateway

- **Phase:** P2 — Instance identity + delegation
- **Status:** Done (workload credential + proof-of-possession instance auth, wired live with
  delegation; production would channel-bind this to mTLS / issue X.509 SVIDs)
- **PRD refs:** FR-5
- **Depends on:** P2-01
- **Blocks:** —

## Goal
Authenticate the agent **instance** on each sensitive request via mutual TLS using its workload credential, filling the `authn(instance)` stage stubbed in P1-02.

## Scope (in)
- mTLS termination at the gateway validating the workload credential from P2-01.
- Bind the verified instance identity into the request context, passport claims (P1-04), and audit attribution (P1-08).
- Reject unknown/expired/untrusted instance credentials (fail-closed).

## Acceptance criteria
- A request without a valid workload credential is rejected at mTLS.
- Verified instance identity flows into the passport and audit log.

## Open questions
- Coexistence with the P1 principal-only path during migration (support both, gate by server tier).
