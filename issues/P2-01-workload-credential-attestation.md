# P2-01 — Workload credential issuance via attestation (SPIFFE/SPIRE)

- **Phase:** P2 — Instance identity + delegation
- **Status:** Done (Ed25519 credential + pluggable attestor + KeyStore; X.509 SVID / real SPIRE
  and hardware attestation are P3-01 / future)
- **PRD refs:** FR-1, FR-4, SEC-1, §11 (SPIFFE/SPIRE, WIMSE)
- **Depends on:** P1-12
- **Blocks:** P2-02, P2-03, P3-01

## Goal
Issue a per-instance workload credential via runtime attestation — no embedded long-lived secret — short-lived and auto-rotating.

## Scope (in)
- Workload-identity authority (SPIFFE/SPIRE-style) issuing per-instance SVIDs/credentials via node/workload attestation.
- Short lifetimes (default ≤1h, configurable to minutes — FR-4) with auto-rotation before expiry.
- No long-lived shared secret; identity derives from attestation (SEC-1).

## Acceptance criteria
- An agent instance obtains a unique workload credential through attestation with no pre-shared secret.
- Credentials expire on schedule and auto-rotate without manual intervention.

## Open questions
- SPIRE vs. building on a lighter attestation primitive; node-attestation methods per target environment (cloud, k8s, on-prem).
