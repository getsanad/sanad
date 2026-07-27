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

### `proof(privateKey: string, principalToken: string): string`
base64url of the Ed25519 signature, made with the instance key, over the UTF-8 bytes
of the principal token. This is the proof-of-possession sent as `X-Agent-Proof`.

### `enroll(opts): Promise<{ credential; agentId?; notAfter? }>`
`opts`: `{ authorityUrl, bootstrapToken, publicKey, fetch? }`. `POST`s
`{ evidence: base64url(utf8(bootstrapToken)), public_key }` to `${authorityUrl}/enroll`.
On HTTP 200 returns the **raw credential JSON text** in `credential` (plus `agentId` /
`notAfter` parsed out for convenience). Throws on any non-200, including the status and
response body.

### `class PassportClient`
Constructed with `{ gatewayUrl, instanceKey, credential, delegation?, fetch? }`.

- `headers(principalToken): Record<string,string>` — builds the passport headers:
  - `Authorization: Bearer <principalToken>`
  - `X-Agent-Credential: base64url(utf8(credential))`
  - `X-Agent-Proof: base64url(ed25519_sign(instanceKey, utf8(principalToken)))`
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
- **Enrollment**: `POST ${authorityUrl}/enroll`, `Content-Type: application/json`,
  body `{"evidence": base64url(utf8(bootstrapToken)), "public_key": base64url(pub32)}`.
  The 200 response body is the credential JSON, stored as raw text.
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
| `proof(seed, "test-principal-token")` | `vS7aSzPmJd-D-AEAgbkw6oFU_0KU4rvei6aUlpCbrGn-nGkfVoqrvrV695SwkzT-id_8nXu18uleQye60FhWCQ` |
