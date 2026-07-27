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
    # delegation="<delegation chain JSON>",  # optional
)

resp = client.request(
    "example-server",              # server_id registered at the gateway
    "/mcp",                        # upstream path (must start with "/")
    principal_token="<opaque principal bearer token>",
    method="POST",
    body=b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}',
    headers={"Content-Type": "application/json"},
)
print(resp.status, resp.text())
```

See [`examples/quickstart.py`](examples/quickstart.py) for a runnable version.

## What it sends

Requests go to `${gateway_url}/servers/${server_id}${path}`. On every request the
client sets:

| Header | Value |
| --- | --- |
| `Authorization` | `Bearer <principal_token>` (you supply the opaque token) |
| `X-Agent-Credential` | base64url(utf8(credential JSON text)) — encoded verbatim, never re-serialized |
| `X-Agent-Proof` | base64url(Ed25519_sign(instance_priv, utf8(principal_token))) |
| `X-Agent-Delegation` | base64url(utf8(delegation chain text)) — only if a delegation chain was provided |

The credential's embedded signature would break if the JSON were re-serialized, so
the SDK encodes the **exact bytes** returned by enrollment.

## API

- `generate_instance_key() -> dict` — `{"private_key": base64url(seed||pub), "public_key": base64url(pub)}`.
- `public_key_of(private_key: str) -> str` — accepts a 32-byte seed or 64-byte `seed||pub` (base64url).
- `proof(private_key: str, principal_token: str) -> str`.
- `enroll(authority_url, bootstrap_token, public_key) -> dict` — `{"credential": <raw text>, "agent_id", "not_after"}`.
- `class PassportClient(gateway_url, instance_key, credential, delegation=None)`
  - `.headers(principal_token) -> dict`
  - `.request(server_id, path, principal_token, method="GET", body=None, headers=None) -> Response`
- `Response(status: int, headers: dict, body: bytes)` with `.text()` and `.json()` helpers. A non-2xx
  gateway response is returned as a `Response` (with its status), not raised.

`instance_key` accepts either the base64url private-key string or the dict from
`generate_instance_key()`; `credential` accepts either the raw JSON text or the
dict from `enroll()`.

## Interop with the Go CLI

- `generate_instance_key()["private_key"]` is byte-compatible with a key written by
  `passport keygen` (base64url of `seed(32) || pub(32)`).
- The credential text returned by `enroll()` is byte-identical to what
  `passport enroll` saves; store it verbatim.

## Tests

Interop tests lock the fixed byte vectors from the Go code:

```bash
python -m venv .venv
.venv/bin/pip install cryptography
.venv/bin/python -m unittest discover -s tests -v
```
