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
| `PASSPORT_PRINCIPAL_MODE` | `oidc` (default) or `vc` |
| `PASSPORT_SIGNING_KEY` | base64url 32-byte seed (stable across replicas) |
| `PASSPORT_WORKLOAD_CA` | base64url Ed25519 CA pubkey; enables instance auth + delegation |
| `PASSPORT_REVOCATION_DSN` | Postgres DSN for the shared kill-switch (empty = in-memory) |
| `PASSPORT_REVOCATION_REFRESH` | cache refresh interval (default 2s) — keep well under your revocation SLA |
| `PASSPORT_ALLOW_ALL` | `1` permits everything (**dev only**) |

The `PASSPORT_REVOCATION_DSN` must point every gateway replica **and** the admin service at
the same database for the kill-switch to be global.
