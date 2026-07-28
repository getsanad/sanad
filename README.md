# Sanad

A security checkpoint and credential system that verifies *who an agent is and who is
accountable for it* before it can talk to sensitive MCP servers — issuing short-lived,
single-purpose **passports** instead of long-lived keys.

> **Why "Sanad"?** In classical scholarship, a *sanad* (سند) is the verified chain of
> transmission that makes a claim trustworthy — who heard it from whom, all the way back
> to the source. Sanad builds the same thing for AI agents: a signed, verifiable chain
> from the accountable human, through every delegation hop, to the action taken.

See [`Sanad-PRD.md`](Sanad-PRD.md) for the full product spec.

> **New to the concepts?** [`docs/CONCEPTS.md`](docs/CONCEPTS.md) explains everything
> (agents, passports, delegation, the crypto) in plain English with analogies.

## Try it in 30 seconds

```sh
make demo     # or: go run ./cmd/demo
```

A self-contained, narrated run of the whole flow: it creates a VC principal, an
attested agent instance, and a delegation chain; sends a real request through the
gateway (showing the minted passport with scope `[read]`, and the caller's credential
being stripped); then revokes the principal and shows the next request fail closed; then
prints the tamper-evident audit log and an investigation. No external setup needed.

## Repository layout

| Path | What it is |
|---|---|
| `pkg/types/`, `pkg/passport/` | Shared domain types + the hardened EdDSA passport codec |
| `gateway/` | Policy enforcement point (PEP): identity-aware reverse proxy + pipeline |
| `principal/` | Principal authentication via OIDC |
| `vc/` | Principal authentication via W3C Verifiable Credentials (`did:key`) |
| `workload/` | Per-instance workload credentials + attestation (incl. measured/TEE) |
| `delegation/` | Delegation: signed chains, centralized exchange, offline capability |
| `policy/` | Authorization hook (deny-by-default allowlist + human-in-the-loop) |
| `config/` | The configuration document (`PASSPORT_POLICY_FILE`) and its validation |
| `revoke/` | Kill-switch / revocation |
| `sts/` | Security token service: mints passports |
| `verify/` | Offline passport verification library + MCP server adapter |
| `audit/` | Tamper-evident log: hash chain → Merkle transparency log + witnesses |
| `metrics/`, `jwks/`, `tooldefs/` | Metrics, JWKS publication, tool-definition drift |
| `sdk/` | Go agent-developer SDK |
| `sdks/` | Client SDKs for other languages: `typescript/`, `python/` |
| `skills/` | Agent-onboarding skill (`sanad`) for AI coding agents |
| `admin/` | Control-plane API |
| `revoke/postgres/` | Durable shared kill-switch backed by Postgres |
| `cmd/` | Binaries: `gateway`, `admin`, `authority`, `sts`, `demo`, `passport` (agent-side CLI/sidecar), `devsecrets` (dev bootstrap), `echomcp` (demo upstream) |
| `deploy/` | `docker-compose.yml` for the full local stack |
| `docs/`, `issues/` | Concepts + ADRs + deployment guide, and the engineering roadmap |

> **Status:** P1 (MVP), P2 (instance identity + delegation), and P3 (high assurance) are
> implemented and tested (320+ tests). The kill-switch now has a durable shared **Postgres**
> backing (ADR-004); the audit sink stays abstract and P4 (cross-org) is intentionally gated.

## Running it

The **gateway** is a long-running HTTP server you put *in front of* your MCP servers; no
agent reaches a protected server except through it. The **admin** API is a separate
control-plane service.

```
agents ──HTTP──▶  gateway (this server)  ──▶  your protected MCP servers
                       │ writes
                       ▼
                  audit log → SIEM
```

```sh
# Gateway (dev: allow-all policy, PASSPORT_DEV_NO_AUTH=1). Exposes /healthz, /metrics,
# /.well-known/jwks.json. Without principal auth configured startup is fatal unless
# PASSPORT_DEV_NO_AUTH=1 — and then every proxied request is denied.
make run
#   PASSPORT_GATEWAY_ADDR        listen address (default :8080)
#   PASSPORT_SERVERS             "id=https://upstream,..." protected MCP servers
#   PASSPORT_POLICY_FILE         authorization rules (see below); unset = deny everything
#   PASSPORT_APPROVAL_TIMEOUT    how long a held action waits for a human (default 2m)
#   PASSPORT_ADMIN_TOKEN         bearer token for the review API at /admin/reviews
#   PASSPORT_PRINCIPAL_MODE      "oidc" (default) or "vc"
#   PASSPORT_OIDC_ISSUER/_CLIENT_ID   (oidc mode)
#   PASSPORT_VC_TRUSTED_ISSUERS  comma-separated trusted issuer DIDs (vc mode)
#   PASSPORT_WORKLOAD_CA         base64url Ed25519 CA pubkey → enables instance auth + delegation
#   PASSPORT_ALLOW_DIRECT_PRINCIPAL  1 = accept requests with no delegation chain (default: reject)
#   PASSPORT_FORWARD_HEADERS     extra inbound headers forwarded upstream, comma-separated
#   PASSPORT_MAX_REQUEST_BODY    bytes of MCP request body buffered per request (default 1 MiB)
#   PASSPORT_DEV_NO_AUTH         1 = start without principal auth (dev only)

# Admin control plane (set PASSPORT_ADMIN_TOKEN to require auth).
make run-admin

# Credential authority (issues workload credentials; prints the CA pubkey to give the gateway).
make run-authority
```

For real deployment: `go build ./cmd/gateway` produces a single static binary — run it on
a VM/container/Kubernetes next to your MCP servers (it's self-hostable for data residency;
see ADR-004/NFR-6). Put it on the network path so agents target the gateway URL.

## Authorizing actions (policy file)

The gateway denies everything until you tell it otherwise. `PASSPORT_POLICY_FILE` points at a
JSON document (see [`config/`](config/config.go) for why JSON and not YAML) that says, per
protected server, which JSON-RPC **methods** and which **tools** an agent may use — and which
need a human first:

```json
{
  "version": 1,
  "policy": {
    "servers": {
      "github": {
        "note": "read-only research bot; issue creation needs a human",
        "allow":  {"methods": ["initialize", "notifications/initialized", "tools/list", "(none)"],
                   "tools":   ["search_issues", "get_file"]},
        "review": {"tools": ["create_issue"]}
      }
    }
  }
}
```

- **`tools`** match the tool a `tools/call` names (`params.name`). **`methods`** match every
  other JSON-RPC message — the MCP handshake, `tools/list`, notifications — plus `"(none)"` for
  a request carrying no JSON-RPC call at all (the `GET` that opens the event stream). Splitting
  them is what lets you allow *listing* the tools while gating *running* one.
- `"*"` is the wildcard for one list on one server; an exact entry always beats it, and a
  `review` entry beats an `allow` entry.
- Anything not listed is denied. Anything under `review` is held until an operator answers.
- `note` is where comments go, since JSON has none. Unknown keys are a **startup error**, so a
  typo can never quietly become a missing rule; so is a malformed file, a duplicate entry, or an
  entry listed as both allowed and reviewed.
- `PASSPORT_ALLOW_ALL=1` (dev) refuses to start alongside a policy file, rather than silently
  overriding it.

**Human-in-the-loop.** A `review` action blocks the caller's request while an operator decides.
Set `PASSPORT_ADMIN_TOKEN` to expose the review API on the gateway (without it the endpoints are
absent and every held action times out and is denied):

```sh
curl -H "Authorization: Bearer $PASSPORT_ADMIN_TOKEN" localhost:8080/admin/reviews
# [{"id":"qFsLUZ…","server":"github","method":"tools/call","tool":"create_issue","principal":"…"}]
curl -H "Authorization: Bearer $PASSPORT_ADMIN_TOKEN" -X POST \
  localhost:8080/admin/reviews/approve -d '{"id":"qFsLUZ…"}'      # …or /deny with a "reason"
```

The pending queue lives **in the gateway process that took the request** — it is a blocked
request, not a database row — so with multiple replicas an operator must reach the replica
holding it, and an id is unknown anywhere else. A shared, durable approval queue is Phase 3.

## The full stack locally (Docker)

To run the gateway, authority, admin, a shared **Postgres** kill-switch, and a demo upstream
together — a faithful mirror of production:

```sh
make devsecrets     # generate throwaway dev identities → deploy/.env + deploy/secrets/
make compose-up     # docker compose up --build   (Ctrl-C to stop; make compose-down to clean)
```

Then enroll an agent and route a call through the gateway (the upstream echoes back the
minted passport — note it is **not** your principal token):

```sh
go run ./cmd/passport enroll --authority http://localhost:8082 --token dev-token \
  --key agent.key --out cred.json
PASSPORT_PRINCIPAL_TOKEN=$(cat deploy/secrets/principal.token) \
  go run ./cmd/passport proxy --gateway http://localhost:8080 \
    --key agent.key --credential cred.json --delegation deploy/secrets/delegation.json &
curl -s localhost:7070/servers/demo/tools/list | jq .
```

Revoke through the admin API (`POST :8081/admin/revoke`) and the gateway starts denying that
principal within one cache-refresh interval — the kill-switch is shared across processes via
Postgres. Full walkthrough and the ECS/production shape: [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md).

## Integrating an agent

An agent reaches a protected server by calling the gateway with three things on the
request: the **principal credential** (`Authorization: Bearer …`), its **workload
credential** + proof (`X-Agent-Credential` / `X-Agent-Proof`), and its **delegation chain**
(`X-Agent-Delegation`). The gateway authenticates, mints a passport, and forwards only that
passport plus a minimal transport allowlist — every other inbound header (those credentials,
cookies, API keys) is dropped, so a semi-trusted MCP server gets nothing it could replay
(`PASSPORT_FORWARD_HEADERS` widens the allowlist). Once delegation is enabled a request with
no chain is rejected — omitting it must not be a way to escape the chain's scope — unless
the deployment sets `PASSPORT_ALLOW_DIRECT_PRINCIPAL=1` to let a principal act directly.

- **Easiest (any language, zero code changes): enroll once, then run the `passport` sidecar.**
  The agent points its MCP client at a local proxy that injects all the credentials for it:
  ```sh
  # operator runs the authority (issues credentials):  make run-authority
  passport enroll --authority https://authority.example.com --token <bootstrap-token>
  passport proxy  --gateway   https://gw.example.com --key agent.key --credential cred.json \
                  --delegation chain.json   # agent now calls http://127.0.0.1:7070/servers/<id>/...
  ```
- **Go agents:** use the `sdk` package (`sdk.New(gatewayURL, tokenSource).Call(...)`).
- **TypeScript / Python agents:** use the client SDKs in [`sdks/`](sdks/) — same enroll →
  request flow as the sidecar, in-process (`npm i @getsanad/sdk` / `pip install sanad-sdk`).
- **AI coding agents:** the [`skills/sanad`](skills/sanad/SKILL.md) skill
  walks an agent through enrolling and routing its MCP traffic through the gateway.
- **Manual / other languages:** it's just HTTP — set the headers yourself (see `cmd/demo`).
  Verifying passports on the MCP-server side is the `verify` package (a few lines).
- See [`docs/CONCEPTS.md`](docs/CONCEPTS.md) for what each piece means.

## Development

```sh
make check   # build + vet + test (the gates CI runs)
make race    # go test -race ./...
make bench   # latency benchmarks
```

Requires Go 1.25+.

## Architecture decisions
- [ADR-001](docs/adr/ADR-001-implementation-stack.md) — implementation stack (Go)
- [ADR-002](docs/adr/ADR-002-passport-token-format.md) — passport token format (hardened JWT / EdDSA; Biscuit for delegation)
- [ADR-003](docs/adr/ADR-003-audit-store.md) — audit store (hash-chained log → Merkle transparency log)
- [ADR-004](docs/adr/ADR-004-data-storage.md) — data storage (Postgres control plane; abstract audit sink, ClickHouse leading)

## Roadmap
Phased per PRD §13 — see [`issues/README.md`](issues/README.md). P1 (MVP) exits at:
*authenticate principal + agent and kill access in under a minute.*
