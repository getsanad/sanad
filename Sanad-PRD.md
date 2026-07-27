# Sanad — Product Requirements Document

| | |
|---|---|
| **Product** | Sanad (working name) |
| **Component** | Agent Identity Gateway + Passport issuance/verification |
| **Version** | 0.1 — Draft |
| **Status** | For review |
| **Date** | June 15, 2026 |
| **Owner** | _[you]_ |
| **Reviewers** | Security Eng, Platform, Compliance, Legal/Privacy |

---

## 1. One-line summary

A security checkpoint and credential system that verifies *who an agent is and who is accountable for it* before that agent is allowed to talk to important MCP servers — and that issues short-lived, single-purpose "passports" instead of long-lived keys.

## 2. Problem

AI agents are increasingly calling MCP servers that touch real systems — code, money, customer data, internal tools. Today most of that access is governed by long-lived API keys or bearer tokens that:

- don't prove which **human or organization** is actually behind the agent,
- don't prove the agent is the **specific program** it claims to be (not an impostor or a tampered copy),
- carry **no record of who delegated what** to whom,
- are **slow and unreliable to revoke** when something goes wrong, and
- leave a **weak audit trail** when you need to trace an action back to a responsible party.

Field data underlines the gap: independent scans in 2025–2026 found large numbers of internet-exposed MCP servers with no authentication at all (one research team found every server in its verified sample exposed its tool list without any auth; a registry audit found roughly 41% of listed servers had no protocol-level auth). As agents proliferate, "an agent showed up with a key" is not a sufficient basis for trust.

## 3. Goals & non-goals

### Goals
- **G1 — Authenticate the agent and the principal.** Establish, on every sensitive interaction, both *which agent instance* is calling and *which accountable human/organization* stands behind it.
- **G2 — Verify the delegation chain.** Make the path principal → agent → sub-agent cryptographically verifiable, where each hop can only *narrow* permissions, never widen them.
- **G3 — Issue short-lived, scoped passports.** Replace long-lived secrets with passes that expire in minutes and are valid only for a specific server and task.
- **G4 — Make revocation fast and reliable.** Cutting off an agent or principal should take effect within ~1 minute, without depending on fragile real-time status checks.
- **G5 — Produce a tamper-evident audit trail.** Every decision and action is recorded in an append-only log that can be traced back to a responsible party and can't be quietly altered.
- **G6 — Be a clean choke point.** Provide a single, central place to enforce identity policy in front of many MCP servers, with minimal integration work for agent developers and server owners.

### Non-goals
- **NG1 — Not an authorization policy engine.** Detailed "who-can-do-what" rules are inherently per-organization. We standardize the *inputs* (verified identities, delegation context) and provide enforcement hooks, but we do not ship the customer's business rules.
- **NG2 — Not a model/behavior safety system.** We govern identity and access, not whether the agent's outputs are safe or correct (prompt-injection mitigation is supported via guardrail hooks but is not the core promise).
- **NG3 — Not blockchain-based on the hot path.** No per-request on-chain operations, and no personal data on any ledger (see §12 and §13).
- **NG4 — Not a replacement for the MCP server's own OAuth resource-server checks.** We complement the MCP authorization spec, we don't bypass it.

## 4. Target users

| Persona | Role | What they need from us |
|---|---|---|
| **Platform / Security Engineer** | Buys, deploys, and operates the gateway | Easy deployment, central policy, strong defaults, observability, fast kill-switch |
| **Agent Developer** | Builds agents that must reach MCP servers | A simple SDK to register an agent and obtain passports; minimal friction |
| **Principal owner (human/org)** | The accountable party behind agents | Confidence that no one can run an agent in their name without a trace; ability to revoke |
| **MCP Server Owner** | Operates a sensitive MCP server | Assurance that only verified, authorized agents reach them; audit-able access |
| **Compliance / Audit Officer** | Investigates incidents, proves controls | Complete, tamper-evident trail tying actions to responsible parties |

## 5. Key concepts (glossary)

The product is precise about binding **four different things**. Conflating them is the root of most identity failures.

- **Code/model identity** — *what software is this?* Provenance and (optionally) a hardware attestation that the running code matches an approved build.
- **Instance identity** — *is this the specific running agent it claims to be?* A per-workload credential, not a shared secret.
- **Principal identity** — *who is accountable?* The verified human or organization behind the agent.
- **Session/task identity** — *this one delegated action,* with its scope, budget, and expiry.
- **Passport** — a short-lived, audience-bound, task-scoped credential the gateway issues after verification; the only thing the MCP server ultimately trusts.
- **Delegation chain** — the signed, attenuating record of who authorized whom (principal → agent → sub-agent…).
- **Gateway** — the enforcement point (PEP) that intercepts agent→MCP traffic; works with a decision point (PDP) for policy.

## 6. Scope & high-level architecture

The gateway sits in front of registered MCP servers. No agent reaches a protected server directly. Conceptually, a sensitive call passes four stages:

1. **Instance check** — the agent presents a per-workload credential over mutual TLS; the gateway verifies it. For high-assurance servers, optionally require a hardware attestation that the code matches an approved build.
2. **Principal + delegation check** — the agent presents its delegation chain (principal credential → agent → any sub-agents). The gateway verifies every signature, confirms each hop only narrows scope, and confirms the root principal is accountable and not revoked.
3. **Passport issuance** — the gateway mints a short-lived, single-server, task-scoped passport carrying the verified principal, agent identity, delegation path, and limits (scope, budget, expiry). This is the only credential the MCP server sees.
4. **Decision + audit** — a policy decision point evaluates the request against the customer's rules; the decision and the resulting action are written to the tamper-evident audit log and streamed to the customer's monitoring/SIEM.

```
  Agent ──(mTLS + delegation chain)──▶  ┌───────────────────────────┐
                                        │      Agent Identity        │
  Principal credential ───────────────▶ │         Gateway            │──▶  Protected
  (verified org/human)                  │  PEP │ Verifier │ STS │ PDP │     MCP Server
                                        └──────────┬────────────────┘
                                                   │ writes
                                                   ▼
                                        Tamper-evident audit log ──▶ SIEM
```

## 7. Functional requirements

### 7.1 Identity & registration
- **FR-1.** Agent developers can register an agent and receive a per-instance workload credential issued via runtime attestation (no embedded long-lived secret).
- **FR-2.** Each registered agent is bound to exactly one accountable principal (human or organization) whose identity has been verified to a configurable assurance level (e.g., org KYC / verified domain for organizations; verified identity for individuals).
- **FR-3.** The system supports an agent "blueprint/template" so an org can define an agent type once and instantiate many short-lived instances under it, with governance inherited from the blueprint.
- **FR-4.** Workload credentials are short-lived (default ≤1 hour, configurable to minutes) and auto-rotate before expiry.

### 7.2 Authentication & passport issuance
- **FR-5.** On each sensitive request, the gateway authenticates the agent **instance** via mutual TLS using its workload credential.
- **FR-6.** The gateway verifies the **principal** credential and that it is currently valid (not revoked/disabled).
- **FR-7.** The gateway issues a **passport** that is: (a) short-lived (seconds–minutes, configurable), (b) bound to a single target MCP server (audience-restricted), and (c) scoped to the specific task/permissions requested.
- **FR-8.** The original principal/agent tokens are **never passed through** to the MCP server; only the minted passport is forwarded.
- **FR-9.** Passports are verifiable offline by the MCP server (signature + claims), with no callback to the gateway required for the common path.

### 7.3 Delegation chain
- **FR-10.** The system represents delegation as a signed chain (principal → agent → sub-agent…), where each entry names the delegate, the granted scope, and constraints (e.g., budget, time, allowed servers).
- **FR-11.** The gateway rejects any chain where a hop attempts to **widen** scope beyond what it was granted (attenuation-only enforcement).
- **FR-12.** Support two delegation modes, selectable per deployment: (a) **centralized** down-scoping via an online token-exchange step (tighter control, one round-trip per hop), and (b) **offline attenuation** via capability-style tokens that a holder can narrow without contacting the issuer (lower latency, works across trust boundaries).
- **FR-13.** A principal cannot be impersonated: creating or extending a chain requires possession of the delegating party's key; "rogue" use in a principal's name without a verifiable signature is rejected and logged.

### 7.4 Authorization hooks (enforcement, not policy)
- **FR-14.** Before issuing a passport, the gateway calls a pluggable **policy decision point** with the verified identity + delegation context as inputs; deployments supply their own policy engine/rules.
- **FR-15.** Default posture is **deny-by-default**: no passport unless an explicit allow decision is returned.
- **FR-16.** Support a per-server **tool/action allowlist** and optional **human-in-the-loop approval** for designated sensitive actions.

### 7.5 Revocation
- **FR-17.** Primary revocation is by **non-renewal**: stop issuing/refreshing credentials and passports; because lifetimes are short, access self-terminates within the configured window (target ≤1 minute).
- **FR-18.** Provide an explicit **kill-switch** (status list / deny list) the gateway consults to immediately stop minting for a specific agent, blueprint, or principal.
- **FR-19.** Revoking a **principal** cascades to all agents and chains rooted in that principal.
- **FR-20.** Revocation must not depend on the protected server performing a fragile real-time external status lookup that "soft-fails" open.

### 7.6 Audit & accountability
- **FR-21.** Every verification decision, passport issuance, and forwarded action is recorded in an **append-only, tamper-evident log** (entries cannot be silently edited or deleted; the log supports inclusion/consistency proofs).
- **FR-22.** Each log entry is attributable to the agent instance, the delegation chain, and the responsible principal.
- **FR-23.** Logs stream in near-real-time to the customer's SIEM/monitoring in a standard format.
- **FR-24.** Provide an investigation view: given an action or incident, return the full chain back to the accountable principal.
- **FR-25.** (Optional, high-assurance) Publish periodic signed checkpoints of the audit log to one or more independent witnesses so external parties can verify the log hasn't been rewritten.

### 7.7 Code attestation (optional, high-assurance tier)
- **FR-26.** For designated servers, require a hardware-backed attestation that the agent is running an approved build before a passport is issued; reject stale or unrecognized measurements.

### 7.8 Administration & observability
- **FR-27.** Admin console to register/disable principals, agents, blueprints, and protected servers; view live sessions; trigger revocation.
- **FR-28.** Metrics and dashboards for auth volume, decision latency, denial reasons, revocation events, and anomalies.
- **FR-29.** SDKs/libraries for agent developers and a thin adapter for MCP server owners, minimizing custom code.

## 8. Key user flows

1. **Onboard an agent.** Developer registers an agent under a verified principal/blueprint → receives SDK config → first run obtains a workload credential via attestation. *(FR-1–4)*
2. **Runtime call to a protected MCP server.** Agent connects → gateway verifies instance + principal + chain → mints a short-lived passport → forwards to the MCP server → logs the decision and action. *(FR-5–9, 21–23)*
3. **Delegate to a sub-agent.** Agent creates an attenuated delegation entry (narrower scope/budget) → sub-agent presents the extended chain → gateway verifies attenuation-only and issues a correspondingly limited passport. *(FR-10–13)*
4. **Revoke fast.** Operator hits kill-switch for an agent or principal → gateway stops minting immediately and existing passports expire within the window → cascade applied to dependent chains. *(FR-17–20)*
5. **Investigate an incident.** Auditor searches an action → system returns the tamper-evident trail tying it to the responsible principal, with proof the record is intact. *(FR-24–25)*

## 9. Non-functional requirements

- **NFR-1 — Latency.** Added p95 latency for a cached/common-path verification + passport issuance ≤ ~50 ms; cold path (full chain verification) ≤ ~200 ms. (Hard requirement: no consensus/ledger wait on the hot path.)
- **NFR-2 — Throughput.** Scale horizontally to the customer's peak agent call volume; the gateway must not become a single bottleneck.
- **NFR-3 — Availability.** ≥ 99.9% for the gateway; degraded-mode behavior must **fail closed** for sensitive servers (no passport ⇒ no access).
- **NFR-4 — Revocation window.** Default effective revocation ≤ 60 seconds end-to-end.
- **NFR-5 — Scalability of audit.** Audit log sustains the full action volume with verifiable integrity and bounded proof sizes.
- **NFR-6 — Deployability.** Self-hostable in the customer's environment (data residency) and/or managed; no hard dependency on any external network call during a hot-path decision.

## 10. Security & privacy requirements

- **SEC-1.** No long-lived shared secrets for agent instances; identity derives from attestation, not stored keys.
- **SEC-2.** All credentials are audience-bound and scoped; a passport for server A is useless at server B.
- **SEC-3.** Defense against the documented MCP threats — token passthrough/theft (mitigated by FR-8), confused-deputy (scoping + allowlists + optional human approval), tool definition drift (hash/verify tool definitions), and exposed/unauthenticated servers (gateway is mandatory front door).
- **SEC-4.** Keys are managed in an HSM/KMS; key rotation and recovery procedures are defined; no single lost key permanently bricks a principal.
- **PRIV-1.** Minimize personal data; store only what's needed for accountability. No personal data is ever written to any external/immutable ledger — audit anchors carry only hashes/commitments.
- **PRIV-2.** Support data-subject rights (erasure/rectification) on stored records — which is why the immutable system of record is an append-only log under the operator's control, **not** a public blockchain.
- **PRIV-3.** Audit logs themselves are access-controlled and their access is logged.

## 11. Standards & interoperability

Build on existing, maturing standards rather than inventing credentials:
- **Authorization plumbing:** OAuth 2.1 / OpenID Connect; audience-bound tokens; protected-resource metadata discovery; token exchange for centralized delegation. Align with the **MCP authorization spec** so we complement (not replace) the MCP server's resource-server checks.
- **Workload identity:** SPIFFE/SPIRE-style instance credentials over mTLS; WIMSE direction for agent identifiers.
- **Delegation/capabilities:** capability-style attenuable tokens (macaroon/Biscuit family) for offline mode.
- **Credentials/identifiers:** W3C Verifiable Credentials for principal/org credentials, using non-blockchain identifier methods (e.g., `did:web`, `did:key`).
- **Tamper-evident audit:** Certificate-Transparency-style Merkle/append-only logs with optional independent witnesses.
- **Attestation:** IETF RATS-style remote attestation (TEE/TPM) for the optional high-assurance tier.

## 12. Explicitly out of scope / "not building"

- Per-request on-chain operations or any blockchain dependency on the authentication hot path (too slow, too costly, privacy-incompatible).
- Personal/principal data stored on any public ledger.
- The customer's business authorization rules (we provide the decision hook and inputs, not the policy).
- General agent output-safety / content moderation.

> **Conditional future exception (not in scope for v1):** a *minimal* shared anchor for cross-organization revocation/audit commitments **may** be considered later — and only if there is a concrete need for a tamper-proof record across mutually distrusting organizations that a transparency log with independent witnesses cannot satisfy. Even then: hashes only, never personal data. If that specific adversary can't be named, we don't add it.

## 13. Phased delivery

| Phase | Theme | Includes | Exit criteria |
|---|---|---|---|
| **P1 — MVP** | Smart gateway + short-lived passports | Identity-aware proxy; principal auth via existing IdP; audience-bound, minutes-long passports; never pass tokens through; append-only audit to SIEM | Can authenticate principal + agent and kill access in <1 min |
| **P2 — Instance + delegation** | Per-workload identity + chains | Workload credentials via attestation (mTLS, ≤1h); delegation chains (centralized **and** offline-attenuation modes); VC-based principal credentials | Multi-hop delegation verified end-to-end; attenuation-only enforced |
| **P3 — High assurance** | Code attestation + verifiable audit | TEE/TPM attestation for designated servers; transparency-log audit with independent witnesses | Regulated-data servers can require approved-build proof; audit independently verifiable |
| **P4 — Cross-org (conditional)** | Shared anchor *if justified* | Minimal multi-witness/anchored revocation+audit commitments (hashes only) | Only if a concrete cross-org adversary is documented |

## 14. Success metrics

- **Adoption:** number of protected MCP servers behind the gateway; number of registered agents/principals; share of sensitive traffic flowing through the gateway (target: 100% for protected servers).
- **Security outcome:** time-to-revoke (target p95 ≤ 60s); number of unauthenticated/direct accesses to protected servers (target: 0); reduction in long-lived secrets in use.
- **Performance:** hot-path added latency (p95 ≤ 50 ms); gateway availability (≥ 99.9%).
- **Accountability:** share of actions with a complete, verifiable trail to a responsible principal (target: 100%); mean time to attribute an incident.
- **Developer experience:** median integration time for a new agent / new server (target: < 1 day).

## 15. Risks & open questions

- **R1 — Standards still moving.** Several relevant specs (agent-auth, workload identity extensions, transaction tokens) are drafts. *Mitigation:* build on the stable cores (OAuth 2.1, mTLS, VCs, transparency logs) and treat the newer pieces as swappable.
- **R2 — Gateway as bottleneck / single point of failure.** *Mitigation:* horizontal scale, offline-verifiable passports, fail-closed for sensitive servers, regional deployment.
- **R3 — Attestation roots of trust.** Hardware attestation ties you to CPU-vendor trust and proves *which binary runs*, not that it matches audited source unless reproducibly built. *Open question:* required assurance level per tier.
- **R4 — Principal verification rigor.** How strongly must individuals vs. orgs be verified at the root? Per-deployment policy, but needs sane defaults.
- **R5 — Offline vs. centralized delegation tradeoff.** Offline attenuation reduces latency but makes instant mid-chain revocation harder. *Open question:* default mode per deployment.
- **R6 — Adoption friction.** Server owners must put the gateway in front of their MCP servers. *Mitigation:* thin adapters, drop-in proxy, clear migration path.

## 16. Dependencies

- A certificate/identity authority for issuing workload credentials (self-hostable).
- The customer's existing IdP for principal authentication.
- A policy engine for the authorization decision hook.
- KMS/HSM for key management.
- SIEM/monitoring endpoint for audit streaming.

---

### Appendix A — Binding-to-primitive map

| Concept | Primitive | Revocation model |
|---|---|---|
| Code/model | Hardware remote attestation | Reject stale/unknown measurements |
| Instance | Per-workload credential over mTLS | Short TTL + stop issuance |
| Principal | Verified org/human credential (VC/OIDC) | Status list / IdP disable (cascades) |
| Session/task | Short-lived audience-bound passport | Seconds-scale expiry |

### Appendix B — Why not blockchain (summary)
Tamper-evidence, public verifiability, and append-only history — the properties usually wanted from a ledger here — are delivered by transparency logs with lower latency, lower cost, and no conflict with data-erasure law. On-chain writes are seconds-to-minutes slow and cost real money per operation, which is disqualifying for a real-time auth gate. A ledger is reserved, if ever, for a narrow cross-org anchor with hashes only.
