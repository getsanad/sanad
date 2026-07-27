# Sanad — Engineering Issues & Roadmap

This folder breaks the [PRD](../Sanad-PRD.md) into discrete, workable issues, ordered so they can be picked up step by step. Each issue has its own file with goal, scope, PRD references, dependencies, and acceptance criteria.

> **GTM work lives separately** in [`../gtm/`](../gtm/) and is owned by a different workstream. Nothing in this folder concerns positioning, pricing, or launch.

## How to use this

- Issues are numbered by phase (`P1`, `P2`, `P3`, `P4`) matching PRD §13.
- Work top-to-bottom within a phase; respect the **Depends on** field for cross-issue ordering.
- Status legend: `Not started` · `In progress` · `Blocked` · `Done`.
- P1 issues have full detail (this is the near-term work). P2–P4 are scoped here in the table and broken into their own files; depth will increase as we approach each phase.

## Suggested execution order (the critical path)

```
P1-01 scaffolding
   └─▶ P1-02 gateway core ──▶ P1-03 principal auth ──▶ P1-04 passport STS
                                                          ├─▶ P1-05 offline verify + adapter
                                                          ├─▶ P1-06 PDP hook + allowlist
                                                          └─▶ P1-07 revocation v1
        P1-02 ──▶ P1-08 audit log + SIEM
        P1-04 ──▶ P1-09 agent SDK
   P1-02..09 ──▶ P1-10 admin console ─ P1-11 observability ─ P1-12 KMS + NFR hardening
```
**P1 exit criteria (PRD §13):** can authenticate principal + agent and kill access in <1 min.

## Phase 1 — MVP: smart gateway + short-lived passports

| ID | Title | PRD refs | Depends on |
|---|---|---|---|
| [P1-01](P1-01-scaffolding-and-adrs.md) | Tech stack, repo scaffolding & ADRs | §6, §11 | — |
| [P1-02](P1-02-gateway-core-pep.md) | Gateway core: identity-aware reverse proxy (PEP) | §6, FR-5, NFR-3 | P1-01 |
| [P1-03](P1-03-principal-auth-idp.md) | Principal authentication via IdP (OAuth 2.1/OIDC) | FR-6, §11 | P1-02 |
| [P1-04](P1-04-passport-issuance-sts.md) | Passport issuance service (STS) + token isolation | FR-7, FR-8, SEC-2 | P1-02, P1-03 |
| [P1-05](P1-05-offline-verify-and-adapter.md) | Offline passport verification lib + MCP server adapter | FR-9, FR-29 | P1-04 |
| [P1-06](P1-06-pdp-hook-allowlist.md) | PDP hook: deny-by-default, allowlist, optional HITL | FR-14, FR-15, FR-16 | P1-04 |
| [P1-07](P1-07-revocation-v1.md) | Revocation v1: non-renewal + kill-switch | FR-17, FR-18, FR-20, NFR-4 | P1-04 |
| [P1-08](P1-08-audit-log-siem.md) | Append-only audit log + SIEM streaming | FR-21, FR-22, FR-23 | P1-02 |
| [P1-09](P1-09-agent-sdk.md) | Agent SDK (register + obtain passport) | FR-1, FR-29 | P1-04 |
| [P1-10](P1-10-admin-console.md) | Admin console v1 | FR-27 | P1-03, P1-07 |
| [P1-11](P1-11-observability.md) | Observability: metrics & dashboards | FR-28, §14 | P1-02 |
| [P1-12](P1-12-kms-and-nfr-hardening.md) | KMS/HSM key management + NFR hardening | SEC-4, NFR-1/2/3/6 | P1-04 |

## Phase 2 — Instance identity + delegation

| ID | Title | PRD refs | Depends on |
|---|---|---|---|
| [P2-01](P2-01-workload-credential-attestation.md) | Workload credential issuance via attestation (SPIFFE/SPIRE) | FR-1, FR-4, SEC-1 | P1-12 |
| [P2-02](P2-02-instance-mtls.md) | Instance authentication via mTLS at the gateway | FR-5 | P2-01 |
| [P2-03](P2-03-agent-blueprints.md) | Agent blueprint/template model | FR-3 | P2-01 |
| [P2-04](P2-04-delegation-chain-model.md) | Delegation chain data model (signed, attenuating) | FR-10, FR-13 | P1-04 |
| [P2-05](P2-05-attenuation-enforcement.md) | Attenuation-only enforcement | FR-11 | P2-04 |
| [P2-06](P2-06-centralized-delegation.md) | Centralized delegation mode (token exchange) | FR-12a | P2-04 |
| [P2-07](P2-07-offline-attenuation.md) | Offline attenuation mode (macaroon/Biscuit) | FR-12b | P2-04 |
| [P2-08](P2-08-vc-principal-credentials.md) | VC-based principal credentials (did:web/did:key) | FR-2, §11 | P1-03 |
| [P2-09](P2-09-revocation-cascade-and-investigation.md) | Principal revocation cascade + investigation view | FR-19, FR-24 | P1-07, P2-04 |

## Phase 3 — High assurance

| ID | Title | PRD refs | Depends on |
|---|---|---|---|
| [P3-01](P3-01-tee-tpm-attestation.md) | TEE/TPM remote attestation (RATS) | FR-26 | P2-01 |
| [P3-02](P3-02-transparency-log-audit.md) | Transparency-log audit (Merkle inclusion/consistency proofs) | FR-21, FR-25, NFR-5 | P1-08 |
| [P3-03](P3-03-independent-witnesses.md) | Independent witnesses (signed checkpoints) | FR-25 | P3-02 |
| [P3-04](P3-04-tool-definition-verification.md) | Tool-definition hashing/verification (drift detection) | SEC-3 | P1-02 |

## Phase 4 — Cross-org (conditional)

| ID | Title | PRD refs | Depends on |
|---|---|---|---|
| [P4-01](P4-01-cross-org-anchor.md) | Cross-org shared anchor (conditional, hashes only) | §12, §13 | P3-03 |

> **P4 gate (PRD §12/§13):** build only if a concrete cross-org adversary is documented that a transparency log with independent witnesses cannot satisfy. Hashes only, never personal data.
