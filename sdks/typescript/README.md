# @getsanad/sdk

TypeScript/Node client SDK for **Sanad**. It lets an AI agent authenticate to
the Sanad gateway with minimal effort:

1. **Enroll** to obtain a short-lived, CA-signed workload credential.
2. **Attach the correct headers** to every MCP request routed through the gateway.

This is the programmatic equivalent of the Go `passport proxy` sidecar
(`cmd/passport/main.go`): it injects the principal bearer token, the workload
credential, a proof of possession of the instance key, and an optional delegation
chain, then forwards to the gateway — without your agent having to build any of those
headers itself.

- **Zero runtime dependencies** — only Node.js built-ins (`node:crypto`, global `fetch`).
- **Node >= 18** (global `fetch`). Ed25519 is provided by `node:crypto`.
- Wire format matches the Go implementation **byte-for-byte** (Ed25519; RFC 4648
  URL-safe base64, no padding).

## Install

```sh
npm install @getsanad/sdk
```

## Quickstart

```ts
import { generateInstanceKey, enroll, PassportClient } from '@getsanad/sdk';

// 1. Generate an Ed25519 instance key. `privateKey` is the base64url of the 64-byte
//    seed||pub form — byte-for-byte interchangeable with `passport keygen`.
const key = generateInstanceKey();
//    Persist key.privateKey somewhere safe (e.g. a file, mode 0600).

// 2. Enroll: present a bootstrap token + your public key, get a workload credential.
const { credential, agentId, notAfter } = await enroll({
  authorityUrl: 'https://authority.example.com',
  bootstrapToken: process.env.PASSPORT_BOOTSTRAP_TOKEN!,
  publicKey: key.publicKey,
});
//    Store `credential` verbatim — it is the raw JSON text and must NOT be
//    reformatted or re-serialized (the gateway verifies an embedded signature).

// 3. Make gateway requests. Passport headers are injected for you.
const client = new PassportClient({
  gatewayUrl: 'https://gw.example.com',
  instanceKey: key.privateKey,
  credential,
  // delegation: delegationChainJsonText, // optional
});

const resp = await client.request('my-server', '/tools/list', {
  principalToken: process.env.PASSPORT_PRINCIPAL_TOKEN!,
  method: 'POST',
  body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
  headers: { 'Content-Type': 'application/json' },
});
console.log(resp.status, await resp.text());
```

See [`examples/quickstart.ts`](./examples/quickstart.ts) for a runnable end-to-end
demo (it uses an in-process fake authority + gateway when no real endpoints are set).

## API

### `generateInstanceKey(): { privateKey: string; publicKey: string }`
Generate a fresh Ed25519 instance keypair. `privateKey` is base64url of the 64-byte
`seed(32) || publicKey(32)` form (interchangeable with the Go CLI's key file);
`publicKey` is base64url of the 32-byte public key.

### `publicKeyOf(privateKey: string): string`
Return the base64url 32-byte public key for an instance private key. Accepts either a
32-byte seed or a 64-byte `seed||pub` key (uses the first 32 bytes as the seed).

### `proof(privateKey: string, input: ProofInput): string`
The `X-Agent-Proof` value for **one request**. `input` is
`{ method, target, principalToken, body?, iat?, jti? }`; `iat` and `jti` default to now
and to 128 fresh random bits and exist only for tests and pinned vectors.

It is the DPoP construction (RFC 9449) in Sanad's signature format:

```
base64url(payload) "." base64url(ed25519_sign(instanceKey, sigctxMessage(ctx, payload)))
```

where `ctx` is `sanad/instance-proof/v2` and `payload` is compact JSON with the keys in
this order:

| Claim | Value |
| --- | --- |
| `ath` | `base64url(sha256(principalToken))` — RFC 9449 §4.2 |
| `bh` | `base64url(sha256(body))`, the hash of zero bytes when there is none |
| `htm` | the HTTP method |
| `htu` | the origin-form target (see `proofTarget`) |
| `iat` | creation time, Unix seconds |
| `jti` | unique per proof |

The gateway checks every claim against the request in front of it, requires the proof to
be seconds old, and spends the `jti` on first use. **Do not cache the result** — a proof
that is the same bytes twice is a bearer token, and the second request is rejected.

Two departures from RFC 9449: the serialization is not a JWT (the key already arrives in
a CA-signed workload credential, so DPoP's self-asserted `jwk` would be strictly weaker,
and a parsed `alg` field is the root of the JWT confusion family); and the body IS
covered, which §11.7 explicitly does not do — in MCP streamable HTTP every JSON-RPC
message is POSTed to one endpoint, so method and path are identical for `tools/list` and
for a `tools/call` of any tool.

### `capabilityHolderProof(holderSecret: string, input: ProofInput): string`
The `X-Agent-Capability-Proof` value: the same payload signed under
`sanad/capability-holder-proof/v2`. Mirrors Go's `delegation.HolderProof`.

### `proofTarget(url: string): string`
The `htu` value for a URL: the origin-form target (path plus query), which is what both
ends can compute identically. The authority is deliberately absent — the gateway sits
behind TLS terminators, ingresses and the `passport proxy` sidecar, any of which can
rewrite the scheme or the Host header. The query IS included, where RFC 9449 drops it.

### `proofBinding(input) / proofPayload(binding)`
The claim set and its canonical bytes, exposed so a caller can inspect or pin them.

### `sigctxMessage(ctx: string, message): Buffer`
The domain-separated signing input Go's `sigctx.Message` produces:
`uint64be(ctx.length) || utf8(ctx) || message`. Every signature in Sanad commits to a
context label saying what it is, because the instance key signs more than one kind of
thing — it proves possession here and authenticates the delegation hops the agent
signs. The 8-byte length prefix fixes exactly where the label ends, so the bytes parse
back to one `(ctx, message)` pair and a signature made for one purpose cannot verify
for another. **Signing the bare token is rejected by the gateway.**

### `bootstrapEvidence(bootstrapToken, nonce, publicKey): Buffer`
The attestation evidence a Go `workload.TokenAttestor` accepts: HMAC-SHA256, keyed by
the bootstrap token, over the authority-issued nonce and the public key being enrolled
(mirrors Go's `workload.BootstrapEvidence`). The bootstrap token never leaves the
process, and the result only enrolls *that* key against *that* nonce — so an enrollment
captured off the wire cannot be replayed with somebody else's key.

### `requestNonce(authorityUrl, fetch?): Promise<Buffer>`
`POST`s to `${authorityUrl}/enroll/nonce` and returns the decoded single-use challenge.
This is the RATS freshness nonce (carried as EAT `eat_nonce`): the authority accepts it
exactly once, within a short window.

### `enroll(opts): Promise<{ credential; agentId?; notAfter? }>`
`opts`: `{ authorityUrl, bootstrapToken, publicKey, fetch? }`. Two requests: fetch a
nonce from `${authorityUrl}/enroll/nonce`, then `POST`
`{ nonce, evidence, public_key }` to `${authorityUrl}/enroll`, where `evidence` covers
both the nonce and the public key. On HTTP 200 returns the **raw credential JSON text**
in `credential` (plus `agentId` / `notAfter` parsed out for convenience). Throws on any
non-200, including the status and response body.

### `class PassportClient`
Constructed with `{ gatewayUrl, instanceKey, credential, delegation?, fetch? }`.

- `headers(serverId, path, opts): Record<string,string>` — builds the passport headers
  for **that request** (the proof is bound to its method, target and body):
  - `Authorization: Bearer <opts.principalToken>`
  - `X-Agent-Credential: base64url(utf8(credential))`
  - `X-Agent-Proof` — see `proof` above
  - `X-Agent-Delegation: base64url(utf8(delegation))` — **only** when a delegation
    chain was provided.
- `url(serverId, path): string` — `${gatewayUrl}/servers/${serverId}${path}`.
- `request(serverId, path, opts): Promise<Response>` — `opts`:
  `{ principalToken, method?, body?, headers? }`. Performs the fetch to the gateway
  with passport headers injected; extra `headers` override the injected ones on conflict.
  `path` must begin with `/` (e.g. `/tools/list`).

## Wire protocol

Everything below matches the Go implementation exactly.

- **Base64**: RFC 4648 URL-safe, **no padding** (Go `base64.RawURLEncoding`, Node
  `buf.toString('base64url')`). Decoding tolerates missing padding.
- **Crypto**: Ed25519.
- **Instance key**: the persisted private key is `base64url(seed(32) || publicKey(32))`.
- **Enrollment** is two requests, both `Content-Type: application/json`:
  1. `POST ${authorityUrl}/enroll/nonce` with body `{}` → `{"nonce": base64url(bytes),
     "expires_in": <seconds>}`. Single-use, short-lived.
  2. `POST ${authorityUrl}/enroll` with body `{"nonce": base64url(nonce), "evidence":
     base64url(evidence), "public_key": base64url(pub32)}`. The 200 response body is
     the credential JSON, stored as raw text.

  The evidence must cryptographically cover **both** the nonce and the public key, or
  the authority refuses it — a quote captured from one enrollment cannot be re-presented
  with a different key. For the bootstrap (dev) attestor the evidence is
  `HMAC-SHA256(bootstrapToken, canonicalJSON({ctx, nonce, pub}))`, where `ctx` is
  `"sanad/bootstrap-evidence/v1"` and `nonce`/`pub` are **standard, padded** base64
  (Go's `encoding/json` rendering of `[]byte`). The bootstrap token itself is never sent.
- **Request URL**: `${gatewayUrl}/servers/${serverId}${path}`.
- **Credential header**: base64url of the *exact* credential bytes — never
  JSON.parse-then-stringify, which would break the credential's embedded signature.

## Developing / testing

The SDK source is TypeScript. Tests use the built-in `node:test` runner and run
directly on Node >= 22.6, which strips the TypeScript types automatically — no build
step or extra tooling required:

```sh
npm test          # node --test test/   (runs the interop + behavior tests)
```

Optional, if you have the dev dependencies installed (`npm install`):

```sh
npm run typecheck  # tsc -p tsconfig.test.json  (type-checks src + tests + examples)
npm run build      # tsc -p tsconfig.json       (emits dist/ JS + .d.ts)
npm run test:strict # typecheck, then run tests
```

If no TypeScript toolchain is available at all, you can still verify the crypto/wire
vectors against the Go implementation with a plain-Node script (no tsc/tsx needed):

```sh
node test/vectors.mjs
```

### Interop vectors

The tests lock these fixed vectors (generated from the Go code) for the 32-byte seed
`0x01..0x20` (base64url `AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA`):

| Value | Expected |
| --- | --- |
| `publicKeyOf(seed)` | `ebVWLo_mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ` |
| 64-byte `seed\|\|pub` form | `AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyB5tVYuj-ZU-UB4sRLoqYunkB-FOuaVvtfg45ELrQSWZA` |
| `ath` for `"test-principal-token"` | `eaVdc24MF5rbKpTXWDI5W-tXHNfA1-qvFjwQ4GIhjlI` |
| `bh` for an empty body | `47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU` |
| `proof(seed, VECTOR_INPUT)` (see `test/vectors.mjs` for the pinned request, `iat` and `jti`) | `eyJhdGgiOiJlYVZkYzI0TUY1cmJLcFRYV0RJNVctdFhITmZBMS1xdkZqd1E0R0loamxJIiwiYmgiOiJxWERiYlNiQUlBcXRUcF9wYUZURDVHSzNGcERQVXlNZmR3M00tQmVXcFd3IiwiaHRtIjoiUE9TVCIsImh0dSI6Ii9zZXJ2ZXJzL2RlbW8vbWNwIiwiaWF0IjoxNzY3MjI1NjAwLCJqdGkiOiJBQUVDQXdRRkJnY0lDUW9MREEwT0R3In0.xDlJ_BHqkqNCj1L4e4RqJsHSO_DE71uRiqALR6CRFdMSC-ICPY8rojK3uyy_coSbhDFQBT1mpL0ECFk8sIlpBw` |
| `bootstrapEvidence("boot-token", nonce, pub)` where nonce is `0x00..0x1f` | `umfR1kxOzPGX1ZFOK5pgnnRtnxSm-q3nE-Qx6DPsI1o` |
