# P1-12 — KMS/HSM key management + NFR hardening

- **Phase:** P1 — MVP
- **Status:** Done. Persistent signer (`LoadSigner` from a stable seed) + KMS/HSM seam
  (`passport.SignWith` / `sts.RemoteSigner`, key never in-process); shared multi-replica
  kill-switch (`revoke.Source` + `CachedStore`: hot-path-local cache, write-through,
  background refresh, cross-replica propagation). The **Postgres `Source`** is now
  implemented (`revoke/postgres`, advisory-lock migration) and wired into both the gateway
  (via `CachedStore`) and the admin plane (via `revoke.SyncStore`); validated end-to-end on
  the docker-compose stack — an admin revoke propagates to a separate gateway process and it
  fails closed. Remaining deploy-time adapters: the concrete **KMS client** (drops into the
  `RemoteSigner` seam) and a real **load test** (a deploy-time activity). A Redis `Source` is
  an optional alternative to Postgres.
- **PRD refs:** SEC-4, NFR-1, NFR-2, NFR-3, NFR-6
- **Depends on:** P1-04
- **Blocks:** P2-01

## Goal
Manage signing keys properly in an HSM/KMS with rotation and recovery, and harden the gateway against the core non-functional requirements before P1 exit.

## Scope (in)
- **KMS/HSM integration** (SEC-4): passport signing keys live in KMS/HSM; replace the P1-04 stub. Rotation + recovery procedures defined; no single lost key permanently bricks a principal.
- **Key rotation** that keeps offline verification (P1-05) working (overlapping keys in JWKS).
- **NFR hardening**:
  - Fail-closed for sensitive servers under degraded mode (NFR-3).
  - Horizontal scale: stateless hot path, no single bottleneck (NFR-2).
  - No external network call on the hot-path decision (NFR-6); hot-path latency budget met (NFR-1).
- **Self-hostability** packaging check (NFR-6): runs in the customer's environment for data residency.

## Out of scope
- Workload-credential CA (P2-01) — this issue covers passport signing keys; that one adds the instance-credential authority.

## Acceptance criteria
- Passport signing uses KMS/HSM; key rotation completes with zero verification downtime.
- Documented key recovery procedure; no single-key permanent lockout.
- Load test shows horizontal scaling and hot-path p95 within NFR-1; degraded mode fails closed for sensitive servers.

## Open questions
- KMS targets to support first (cloud KMS vs. on-prem HSM) — driven by self-hosting design partners.
