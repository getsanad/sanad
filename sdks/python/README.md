# sanad (Python SDK)

Python client SDK for **Sanad**. It lets an AI agent authenticate to the
Sanad gateway: (1) **enroll** to obtain a short-lived workload
credential, then (2) attach the correct headers to each MCP request routed
through the gateway.

This mirrors the Go sidecar `passport proxy` (`cmd/passport`). Wire formats match
the Go implementation byte-for-byte: all base64 is RFC 4648 URL-safe with **no
padding** (Go's `base64.RawURLEncoding`), and cryptography is **Ed25519**.

## Install

Requires Python 3.9+ and the [`cryptography`](https://pypi.org/project/cryptography/)
package (HTTP uses the stdlib `urllib`, so there is no `requests` dependency).

```bash
pip install cryptography
# then install this SDK (from sdks/python/):
pip install .
```

## Quickstart

```python
from sanad import generate_instance_key, enroll, PassportClient

# 1) Generate an Ed25519 instance key.
#    key["private_key"] is base64url(seed||pub) — interchangeable with the Go
#    `passport keygen` key file. Keep it secret.
key = generate_instance_key()

# 2) Enroll: present the bootstrap token + public key, get a workload credential.
result = enroll(
    "https://authority.example.com",
    bootstrap_token="my-bootstrap-token",
    public_key=key["public_key"],
)
print(result["agent_id"], result["not_after"])
credential = result["credential"]  # raw JSON text, kept verbatim

# 3) Make authenticated requests through the gateway.
client = PassportClient(
    gateway_url="https://gw.example.com",
    instance_key=key["private_key"],
    credential=credential,
    # principal_key="<principal did:key private key>",  # required in VC mode
    # delegation="<delegation chain JSON>",             # optional
)

resp = client.request(
    "example-server",              # server_id registered at the gateway
    "/mcp",                        # upstream path (must start with "/")
    principal_token="<principal bearer token>",
    method="POST",
    body=b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}',
    headers={"Content-Type": "application/json"},
)
print(resp.status, resp.text())
```

See [`examples/quickstart.py`](examples/quickstart.py) for a runnable version.

## Enrollment

Enrollment is two requests to the authority:

1. `POST {authority_url}/enroll/nonce` → `{"nonce": base64url(bytes), "expires_in": <seconds>}`.
   Single-use and short-lived.
2. `POST {authority_url}/enroll` with `{"nonce": ..., "evidence": ..., "public_key": ...}`,
   all base64url. The 200 body is the credential JSON.

The evidence must cryptographically cover **both** the nonce and the public key, or the
authority refuses it — so an enrollment captured off the wire cannot be replayed with a
different key. `enroll()` does both legs for you.

## What it sends

Requests go to `${gateway_url}/servers/${server_id}${path}`. On every request the
client sets:

| Header | Value |
| --- | --- |
| `Authorization` | `Bearer <principal_token>` (you supply the token) |
| `X-Agent-Credential` | base64url(utf8(credential JSON text)) — encoded verbatim, never re-serialized |
| `X-Agent-Proof` | `base64url(payload).base64url(Ed25519_sign(instance_priv, sigctx_message("sanad/instance-proof/v2", payload)))`, bound to this request — see `proof` below |
| `X-Principal-Proof` | the same payload signed with the **principal's** `did:key` under `sanad/vc-holder-proof/v1` — only if a `principal_key` was provided, and **required** by gateways in VC mode |
| `X-Agent-Delegation` | base64url(utf8(delegation chain text)) — only if a delegation chain was provided |

A gateway in VC mode (`PASSPORT_PRINCIPAL_MODE=vc`) will not accept the principal
credential on its own. The credential proves a trusted issuer vouched for a `did:key`;
`X-Principal-Proof` proves the caller actually holds that key, on this request. Without it
the credential would be worth exactly as much as a copy of it — which is what anything that
sees one request's headers gets for free.

The credential's embedded signature would break if the JSON were re-serialized, so
the SDK encodes the **exact bytes** returned by enrollment.

## API

- `generate_instance_key() -> dict` — `{"private_key": base64url(seed||pub), "public_key": base64url(pub)}`.
- `public_key_of(private_key: str) -> str` — accepts a 32-byte seed or 64-byte `seed||pub` (base64url).
- `proof(private_key, method, target, principal_token, body=None, iat=None, jti=None) -> str` —
  the `X-Agent-Proof` value for **one request**. It is the DPoP construction (RFC 9449) in
  Sanad's signature format: `base64url(payload) "." base64url(signature)`, where the payload
  is compact JSON `{"ath","bh","htm","htu","iat","jti"}` — `ath` is
  `base64url(sha256(principal_token))`, `bh` is `base64url(sha256(body))` (the hash of zero
  bytes when there is none), and the signature is made under
  `sanad/instance-proof/v2`. The gateway checks every claim against the request in front of
  it, requires the proof to be seconds old, and spends the `jti` on first use. **Do not
  cache it** — a proof that is the same bytes twice is a bearer token, and the second
  request is rejected. Two departures from RFC 9449: the serialization is not a JWT (the key
  already arrives in a CA-signed workload credential, and a parsed `alg` field is the root
  of the JWT confusion family), and the body IS covered, which §11.7 explicitly does not do
  — in MCP streamable HTTP every JSON-RPC message is POSTed to one endpoint, so method and
  path are identical for `tools/list` and for a `tools/call` of any tool.
- `capability_holder_proof(holder_secret, method, target, principal_token, body=None, ...) -> str` —
  the `X-Agent-Capability-Proof` value: the same payload under
  `sanad/capability-holder-proof/v2`.
- `principal_holder_proof(principal_key, method, target, principal_token, body=None, ...) -> str` —
  the `X-Principal-Proof` value: the same payload under `sanad/vc-holder-proof/v1`, signed
  with the private key of the credential **subject** (not the instance key, not the
  issuer's). `principal_token` must be the credential string exactly as sent, since the
  proof commits to it via `ath`.
- `proof_target(url) -> str` — the `htu` value: the origin-form target (path plus query).
  The authority is deliberately absent, because the gateway sits behind TLS terminators,
  ingresses and the `passport proxy` sidecar, any of which can rewrite scheme or Host.
- `proof_binding(...) -> dict` / `proof_payload(binding) -> bytes` — the claim set and its
  canonical bytes, for callers that want to inspect or pin them.
- `sigctx_message(ctx: str, message: bytes) -> bytes` — the domain-separated signing input
  Go's `sigctx.Message` produces: `uint64be(len(ctx)) || utf8(ctx) || message`. Every
  signature commits to a context label saying what it is, because the instance key signs
  more than one kind of thing — it proves possession here and authenticates the delegation
  hops the agent signs. The 8-byte length prefix fixes exactly where the label ends, so a
  signature made for one purpose cannot verify for another. **Signing the bare token is
  rejected by the gateway.**
- `bootstrap_evidence(bootstrap_token, nonce: bytes, public_key: bytes) -> bytes` — the
  attestation evidence a Go `workload.TokenAttestor` accepts: HMAC-SHA256 keyed by the
  bootstrap token over the nonce and the key being enrolled. The token never leaves the
  process, and the result only enrolls *that* key against *that* nonce.
- `request_nonce(authority_url) -> bytes` — the single-use enrollment challenge.
- `enroll(authority_url, bootstrap_token, public_key) -> dict` — `{"credential": <raw text>, "agent_id", "not_after"}`.
- `class PassportClient(gateway_url, instance_key, credential, delegation=None, principal_key=None)`
  - `.headers(server_id, path, principal_token, method="GET", body=None) -> dict` — the
    headers for **that request**; the proof is bound to its method, target and body.
  - `.url(server_id, path) -> str`
  - `.request(server_id, path, principal_token, method="GET", body=None, headers=None) -> Response`
- `Response(status: int, headers: dict, body: bytes)` with `.text()` and `.json()` helpers. A non-2xx
  gateway response is returned as a `Response` (with its status), not raised.

`instance_key` accepts either the base64url private-key string or the dict from
`generate_instance_key()`; `credential` accepts either the raw JSON text or the
dict from `enroll()`; `principal_key` is a base64url private key (seed or `seed||pub`).

## Interop with the Go CLI

- `generate_instance_key()["private_key"]` is byte-compatible with a key written by
  `passport keygen` (base64url of `seed(32) || pub(32)`).
- `enroll()` speaks the same two-leg wire protocol as `workload.Enroll`, and
  `bootstrap_evidence()` reproduces `workload.BootstrapEvidence` byte-for-byte.
- The credential text returned by `enroll()` is the authority's response body verbatim;
  store it as-is (`passport enroll` saves an indented copy of the same credential).

## Tests

Interop tests lock the fixed byte vectors from the Go code:

```bash
python -m venv .venv
.venv/bin/pip install cryptography
.venv/bin/python -m unittest discover -s tests -v
```
