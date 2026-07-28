# Deployment

Sanad is a few small, stateless Go services plus a shared database. This guide
covers running it locally for validation (docker-compose) and the shape of a production
deployment (e.g. AWS ECS). It also lists the deploy-time seams that swap dev stubs for
real infrastructure.

## Components

| Service | Binary | Port | Role |
|---|---|---|---|
| **Gateway** (PEP) | `cmd/gateway` | 8080 | The hot path. Authenticates callers, checks the kill-switch + policy, mints passports, proxies to upstreams. Stateless — scale horizontally. |
| **Authority** | `cmd/authority` | 8082 | Issues short-lived workload credentials after attestation (enrollment). |
| **Admin** | `cmd/admin` | 8081 | Control plane: register/disable principals & agents, drive the kill-switch, investigation view. |
| **Postgres** | — | 5432 | Shared durable state (currently the kill-switch; control-plane records per ADR-004). |
| Demo upstream | `cmd/echomcp` | 9090 | Local stand-in for a protected MCP server. **Not for production.** |

The agent side runs the `passport` CLI sidecar or a language SDK (`sdks/`) — those live with
the agent, not in this deployment.

## Local validation (docker-compose)

```bash
# 1. Generate throwaway dev secrets/identities (writes deploy/.env + deploy/secrets/).
go run ./cmd/devsecrets --out deploy      # or: make devsecrets

# 2. Bring up gateway + authority + admin + Postgres + demo upstream.
cd deploy && docker compose up --build    # or, from repo root: make compose-up

# 3. From the repo root, enroll an agent and route a call through the gateway.
go run ./cmd/passport enroll --authority http://localhost:8082 --token dev-token \
  --key agent.key --out cred.json

PASSPORT_PRINCIPAL_TOKEN=$(cat deploy/secrets/principal.token) \
  go run ./cmd/passport proxy --gateway http://localhost:8080 \
    --principal-key deploy/secrets/principal.key \
    --key agent.key --credential cred.json --delegation deploy/secrets/delegation.json &

curl -s localhost:7070/servers/demo/tools/list | jq .
# The upstream echoes back the freshly-minted passport — note it is NOT your principal token.
```

The compose stack runs the **real** authenticated path (VC principal + workload-attested
instance + delegation + shared Postgres kill-switch), so it is a faithful mirror of
production minus the seams below. `PASSPORT_ALLOW_ALL=1` is set for the demo so the policy
engine permits everything; remove it and configure policy for anything real.

To see the shared kill-switch cross a process boundary: `POST /admin/revoke {"ID": "<principal-did>"}`
to `:8081` (bearer `PASSPORT_ADMIN_TOKEN` from `deploy/.env`); within one refresh interval the
gateway starts denying that principal.

## Production shape (ECS / Kubernetes)

```
                    ┌───────────── Load balancer (TLS) ─────────────┐
   agents ──mTLS──▶ │  gateway x N (stateless, autoscaled)          │ ──▶ upstream MCP servers
                    └───────┬──────────────────────┬────────────────┘
                            │                       │
                     Postgres (RDS)          KMS / HSM (signing key)
                            │
        admin (1–2)  ◀──────┘        authority (1–2, attestation)
```

- **Gateway**: 2+ replicas behind an ALB/NLB. Stateless; the only shared state is the
  kill-switch, read from a local cache (no DB call on the decision path — FR-20, NFR-1).
  Scale on CPU/RPS.
- **Postgres**: managed (RDS/Cloud SQL). One instance shared by all gateway replicas and the
  admin plane. This is how a revocation written anywhere reaches every replica (NFR-2).
- **Authority & Admin**: 1–2 replicas each; not on the request hot path.
- Put **TLS** at the load balancer and **mTLS** between agents and the gateway (the instance
  proof is designed to be channel-bound to it — see `workload/instance.go`).

### ECS Fargate notes
- The `Dockerfile` produces static, non-root distroless images that run as-is on Fargate.
- One task definition per service (gateway/authority/admin), each overriding the container
  `command` to select its binary (`/usr/local/bin/gateway`, `.../authority`, `.../admin`).
- Inject config via task-definition environment; inject secrets from **AWS Secrets Manager /
  SSM** (never bake them into the image). See the env tables in each `cmd/*/main.go` header.
- Health check: `GET /metrics` on the gateway, `GET /healthz` on the authority.

## Deploy-time seams (swap dev stubs for real infra)

Everything below is already abstracted in code; deploying means providing the concrete
adapter, not writing new core logic.

| Seam | Dev default | Production |
|---|---|---|
| **Passport signing key** | `PASSPORT_SIGNING_KEY` seed (env) | KMS/HSM via `sts.NewRemoteSigner` (key never in-process) — SEC-4 |
| **Workload attestation** | bootstrap tokens (`TokenAttestor`) | TEE/TPM measured attestation (`workload.MeasuredAttestor`) — P3-01 |
| **Kill-switch store** | in-memory | shared Postgres (`PASSPORT_REVOCATION_DSN`) — this release |
| **Audit sink** | JSON lines to stdout | SIEM / transparency log + witness (`audit/`) — P3-02/03 |
| **Principal auth** | — | OIDC (`PASSPORT_PRINCIPAL_MODE=oidc`) or VC (`=vc`) |
| **Transport auth** | proof-over-bearer | mTLS at the LB, proof channel-bound to it |

## Key configuration (env)

Gateway (full list in `cmd/gateway/main.go`):

| Var | Purpose |
|---|---|
| `PASSPORT_SERVERS` | `id=url,id2=url2` protected MCP servers |
| `PASSPORT_POLICY_FILE` | path to the configuration document (see the README). The `policy` section says, per server, which JSON-RPC methods and tools are allowed and which need a human; the optional `tooldefs` section pins each server's approved tool definitions, so a silently rewritten tool description is refused rather than shown to the agent (SEC-3). Unset = deny everything and pin nothing. A file that does not parse, or whose rules or pins do not validate, is a **fatal startup error** naming the offending entry — never a partial load |
| `PASSPORT_APPROVAL_TIMEOUT` | how long an action held for human approval waits before it is denied (default `2m`; `0` = until the caller disconnects) |
| `PASSPORT_ADMIN_TOKEN` | bearer token for the review API (`/admin/reviews`) on the gateway. **Unset = the review API is not mounted**, and anything routed to review times out and denies |
| `PASSPORT_PRINCIPAL_MODE` | `oidc` (default) or `vc` |
| `PASSPORT_SIGNING_KEY` | base64url 32-byte seed (stable across replicas) |
| `PASSPORT_WORKLOAD_CA` | base64url Ed25519 CA pubkey; enables instance auth + delegation |
| `PASSPORT_ALLOW_DIRECT_PRINCIPAL` | `1` accepts requests carrying no delegation chain; by default (delegation enabled) they are rejected, so omitting the chain cannot escape its scope |
| `PASSPORT_FORWARD_HEADERS` | comma-separated extra inbound headers to forward upstream; by default only the minted passport plus a minimal MCP transport set survives (token isolation, FR-8) |
| `PASSPORT_MAX_REQUEST_BODY` | bytes of MCP request body buffered so the tool being called can be authorized (default 1 MiB); a larger body is refused with `413` rather than forwarded undecided |
| `PASSPORT_REVOCATION_DSN` | Postgres DSN for the shared kill-switch (empty = in-memory) |
| `PASSPORT_REVOCATION_REFRESH` | cache refresh interval (default 2s) — keep well under your revocation SLA |
| `PASSPORT_REVOCATION_MAX_STALENESS` | snapshot age past which revocation checks **deny** and `/readyz` reports unready (default 60s, the NFR-4 target); must exceed the refresh interval |
| `PASSPORT_ALLOW_ALL` | `1` permits everything (**dev only**) |
| `PASSPORT_DEV_NO_AUTH` | `1` starts without principal auth (**dev only**); otherwise a missing principal authenticator is a fatal startup error |

The `PASSPORT_REVOCATION_DSN` must point every gateway replica **and** the admin service at
the same database for the kill-switch to be global.

If that database becomes unreachable, each replica keeps serving its last snapshot — but
only for `PASSPORT_REVOCATION_MAX_STALENESS`. During the outage the gateway logs the failure
(first occurrence, the moment the bound is crossed, then a heartbeat), exports the age as
`agentpassport_revocation_snapshot_age_seconds`, and once the bound is crossed it denies
every request and fails `/readyz`. That is deliberate: past the bound the gateway can no
longer promise a revocation has reached it (NFR-4), and a kill-switch that cannot see its
deny list must stop traffic rather than wave it through. **Alert on the gauge approaching
the bound** — it goes off long before any request is denied.

### Tool-definition drift

If the configuration document carries a `tooldefs` section (see the README), the gateway checks
every `tools/list` response from a pinned server against its approved fingerprint. A mismatch is
audited under the `drift` action — with both fingerprints, the tools observed and the principal
whose request surfaced it — logged, and exported as
`agentpassport_tooldefs_quarantined_servers`. **Alert on that gauge being non-zero**: it means a
protected server is advertising tools nobody approved, and under the default `deny` mode its
tool calls are already being refused. Take it to zero by reviewing the diff and either rolling
the server back or re-pinning it; the quarantine lifts by itself on the first `tools/list` that
matches again, with no restart.

The write side is just as blunt: if `POST /admin/revoke` (or `/admin/restore`) cannot reach
that database, it answers **503**, never a reassuring 200, with a body naming the ids that
did and did not take effect — `{"error": ..., "op": "revoke", "applied": [], "failed":
["p1","a1"]}`. A cascade (a principal plus its agents) is written as one transaction, so a
failure leaves nothing half-applied; retry it. The underlying cause goes to the admin log
only, so it never leaks the DSN to the caller. **Treat a 5xx here as "the agent is still
live"** and escalate.

## Human-in-the-loop approvals across replicas

An action a policy marks `review` blocks the caller's HTTP request until an operator resolves
it over `/admin/reviews` on the gateway. **That queue is per-process and in-memory** — a pending
review is a blocked request inside one replica, not a row in a database — with two consequences
for a multi-replica deployment:

- Only the replica holding the request can resolve it. Any other replica answers `404`
  ("already resolved, expired, or held by another gateway replica"). Reach the replicas
  individually (a headless service / per-pod address), or run approvals against a
  single-replica deployment, until the durable queue lands (Phase 3).
- A replica restart or rollout drops every review it was holding. That fails in the safe
  direction — the held requests fail closed rather than being let through — but the operator's
  console will simply stop showing them.

`PASSPORT_APPROVAL_TIMEOUT` bounds how long each held request occupies a connection. Reviews are
resolved by exactly one winner: an operator told "approved" has approved the decision the
requester actually received, and an approval that arrives after the timeout answers `404`
rather than reporting a success nobody acted on.
