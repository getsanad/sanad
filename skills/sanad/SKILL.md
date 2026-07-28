---
name: sanad
description: Route an AI agent's calls to protected MCP servers through a Sanad gateway. Use when a tool/MCP server sits behind a Sanad gateway (calls return 401/403 "passport"/"revocation"/"missing instance credential"), or when onboarding a new agent that must authenticate with a workload credential + principal token. Covers enrollment and both the zero-code sidecar and the in-process SDK.
---

# Onboarding an agent to Sanad

Sanad is an identity-aware gateway in front of MCP servers. Instead of holding a
long-lived API key, your agent presents **who it is** on each call and the gateway mints a
short-lived, task-scoped **passport** for the upstream. Your agent never sees or forwards the
upstream's real credential.

You attach the following to every request; the gateway checks them and fails closed if any
is missing or wrong:

| Header | What it is |
|---|---|
| `Authorization: Bearer <principal-token>` | the accountable human/org (an OIDC token or a VC), given to you by your operator |
| `X-Agent-Credential` | your short-lived workload credential, obtained by enrolling |
| `X-Agent-Proof` | a signature proving you hold the instance key the credential is bound to |
| `X-Principal-Proof` *(VC mode)* | a signature proving you hold the principal's `did:key` — a VC is not a bearer token, so a copy of the credential is not an identity |
| `X-Agent-Delegation` *(optional)* | a signed chain narrowing what you're allowed to do |

You do **not** build these by hand. Use one of the two paths below.

## What you need from the operator
- **Gateway URL** (e.g. `https://gw.example.com`)
- **Authority URL** for enrollment (e.g. `https://authority.example.com`)
- **Bootstrap token** — proves to the authority which agent id you are. It is **single-use and
  expiring**: one token buys one enrollment (unless your operator says otherwise), inside a
  short window. Ask for it as a **file**, and never put it on a command line — argv is readable
  by every process on the host and your shell writes it to history.
- **Principal token** — the caller identity you act on behalf of (OIDC bearer, or a VC token)
- **Principal key** — with a VC, the `did:key` private key of the credential's subject. The
  gateway requires a per-request proof of possession of it; without the key the credential
  authenticates nothing.
- The **server id** of the protected MCP server you need (the gateway routes `/servers/<id>/…`)

## Path A — sidecar (zero code changes, recommended first)

Run the `passport` CLI as a local proxy and point your MCP client at it. Nothing about your
agent's request-building changes.

```bash
# 1. Enroll: generate an instance key and exchange the bootstrap token for a credential.
#    Run this ONCE — the token is single-use. Pass it by file (or `--token-file -` to pipe it
#    in, or $PASSPORT_BOOTSTRAP_TOKEN); there is no --token flag.
passport enroll --authority "$AUTHORITY_URL" --token-file bootstrap.token \
  --key agent.key --out cred.json

# 2. Run the sidecar. It injects the headers above and forwards to the gateway.
export PASSPORT_PRINCIPAL_TOKEN="$PRINCIPAL_TOKEN"
passport proxy --gateway "$GATEWAY_URL" --key agent.key --credential cred.json
# in VC mode add:  --principal-key principal.key
# (optional) add:  --delegation delegation.json
```

Now point your MCP client's base URL at the sidecar:

```
http://127.0.0.1:7070/servers/<server-id>/
```

That's it — every call through `127.0.0.1:7070` is authenticated. If you don't have the
`passport` binary, build it from the repo: `go build -o passport ./cmd/passport`, or run it
via `go run ./cmd/passport …`.

## Path B — in-process SDK (when you can't run a sidecar)

Use the TypeScript or Python SDK to attach the headers yourself. Same wire protocol.

**Python** (`pip install sanad-sdk`):
```python
from sanad import generate_instance_key, enroll, PassportClient

key = generate_instance_key()                      # {"private_key","public_key"}
cred = enroll(AUTHORITY_URL, BOOTSTRAP_TOKEN, key["public_key"])
client = PassportClient(GATEWAY_URL, key["private_key"], cred["credential"],
                        principal_key=PRINCIPAL_KEY)   # VC mode only

resp = client.request("my-server", "/tools/list", principal_token=PRINCIPAL_TOKEN)
print(resp.status, resp.body)
```

**TypeScript** (`npm i @getsanad/sdk`):
```ts
import { generateInstanceKey, enroll, PassportClient } from "@getsanad/sdk";

const key = generateInstanceKey();
const { credential } = await enroll({ authorityUrl: AUTHORITY_URL, bootstrapToken: BOOTSTRAP_TOKEN, publicKey: key.publicKey });
// principalKey is required in VC mode, omitted in OIDC mode.
const client = new PassportClient({ gatewayUrl: GATEWAY_URL, instanceKey: key.privateKey, credential, principalKey: PRINCIPAL_KEY });

const resp = await client.request("my-server", "/tools/list", { principalToken: PRINCIPAL_TOKEN });
console.log(resp.status, await resp.text());
```

Persist `agent.key` / the private key and re-enroll when the credential nears expiry (they're
short-lived by design). Re-enrolling needs budget on your bootstrap token — ask your operator
for one with enough uses to cover your restart and renewal rate, or for a fresh token each
time. Don't paper over `bootstrap token … is spent` by retrying; it will not start working.

## Troubleshooting (the gateway fails closed, so a rejection is normal and informative)
- **`401/403 … missing instance credential` or `bad credential signature`** — enroll again; the
  credential may be expired or the gateway trusts a different CA than issued it.
- **`enrollment denied: … bootstrap token … is spent` / `… expired`** — the token authorized a
  bounded number of enrollments inside a bounded window and you are past one of them. This is
  not transient: ask the operator for a fresh token (or, on a local stack, restart the
  authority — the budget lives in that process).
- **`429 … enrollment rate limit exceeded`** — the authority rate-limits enrollment. Honour the
  `Retry-After` header and back off; do not retry in a tight loop.
- **`… instance proof of possession failed`** — the `agent.key` you're signing with doesn't
  match the credential's public key. Re-run enroll so the key and credential are a matched pair.
- **`revocation: … is revoked`** — your principal, agent, or blueprint is on the kill-switch.
  This is intentional; contact the operator.
- **`principal … is not trusted` / token invalid** — the principal token is wrong for this
  gateway (wrong issuer/audience). Get a fresh one from the operator.
- **`vc: principal holder proof failed` / `expected exactly one X-Principal-Proof header`** —
  the gateway is in VC mode and you presented the credential without proving you hold its
  subject key. Supply the principal key (`--principal-key`, `principal_key=`, `principalKey`).
- **404 for the path** — check the server id; the route is `/servers/<id>/<upstream-path>`.

## Notes
- Never forward the upstream's minted passport anywhere; it's scoped to that one call.
- The instance key is a secret — treat `agent.key` like a private key (mode 0600).
- The whole thing runs locally too: `go run ./cmd/devsecrets --out deploy && (cd deploy && docker compose up --build)` stands up a full stack you can point this skill at.
