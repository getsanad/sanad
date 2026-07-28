/**
 * @getsanad/sdk
 *
 * TypeScript/Node client SDK for Sanad. It lets an AI agent authenticate
 * to the Sanad gateway with minimal effort:
 *
 *   1. `enroll()` to obtain a short-lived workload credential, and
 *   2. attach the correct headers to every MCP request routed through the gateway.
 *
 * This mirrors the Go sidecar (`passport proxy`, see cmd/passport/main.go): it
 * injects the principal bearer token, the workload credential, a proof of
 * possession of the instance key, a proof of possession of the principal's
 * `did:key` when one is configured, and an optional delegation chain.
 *
 * Wire format notes (must match the Go implementation byte-for-byte):
 *   - All base64 is RFC 4648 URL-safe with NO padding (Go's base64.RawURLEncoding,
 *     Node's `buf.toString('base64url')`). Decoding tolerates missing padding.
 *   - Cryptography is Ed25519.
 *   - Every signature is domain-separated: it is made over
 *     `uint64be(ctx.length) || ctx || message`, where `ctx` names what is being signed
 *     (see `sigctxMessage`). Signing the bare message is NOT accepted by the gateway.
 *   - The proof of possession is bound to ONE request. It is the DPoP construction
 *     (RFC 9449) in Sanad's signature format: a payload naming the method (`htm`), the
 *     target (`htu`), a hash of the principal token (`ath`), a hash of the body (`bh`),
 *     a creation time (`iat`) and a unique id (`jti`), signed under the instance-proof
 *     context. See `proof` for why the body is covered when DPoP leaves it out.
 *     A proof therefore CANNOT be computed once and reused — that is the whole point,
 *     and a client that caches one will be denied on its second request.
 *   - A gateway in VC mode expects TWO proofs on each request: one from the agent instance
 *     (`X-Agent-Proof`) and one from the principal whose credential is being presented
 *     (`X-Principal-Proof`). A principal credential is not a bearer token — see
 *     `principalHolderProof` and the `principalKey` client option.
 *   - Enrolling is two requests: fetch a single-use nonce from the authority, then
 *     present attestation evidence covering both that nonce and the public key being
 *     enrolled. That binding is what stops an enrollment captured off the wire from
 *     being replayed with somebody else's key.
 *
 * Zero runtime dependencies: only Node.js built-ins (`node:crypto`, global fetch).
 * Requires Node >= 18 (global fetch). Ed25519 support in `node:crypto` requires a
 * reasonably recent Node; Node >= 18 is fine.
 */

import {
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  sign,
  type KeyObject,
} from 'node:crypto';

/** DER prefix for a PKCS#8-wrapped Ed25519 private key. Followed by the 32-byte seed. */
const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

const ED25519_SEED_LEN = 32;
const ED25519_PUBLIC_LEN = 32;
const ED25519_PRIVATE_LEN = 64; // Go's form: seed(32) || publicKey(32)

/** Header names, matching workload.HeaderCredential / HeaderProof and delegation.HeaderDelegation. */
export const HEADER_CREDENTIAL = 'X-Agent-Credential';
export const HEADER_PROOF = 'X-Agent-Proof';
export const HEADER_DELEGATION = 'X-Agent-Delegation';
/** Matches Go's `vc.HeaderPrincipalProof`. Sent only when a principal key is configured. */
export const HEADER_PRINCIPAL_PROOF = 'X-Principal-Proof';

// ---------------------------------------------------------------------------
// base64url helpers
// ---------------------------------------------------------------------------

/** Encode bytes as RFC 4648 URL-safe base64 with no padding. */
function b64url(data: Buffer | Uint8Array): string {
  return Buffer.from(data).toString('base64url');
}

/** Decode RFC 4648 URL-safe base64; tolerant of missing padding. */
function b64urlDecode(s: string): Buffer {
  return Buffer.from(s, 'base64url');
}

/** Encode a UTF-8 string as base64url. */
function b64urlUtf8(s: string): string {
  return Buffer.from(s, 'utf8').toString('base64url');
}

// ---------------------------------------------------------------------------
// Domain separation
// ---------------------------------------------------------------------------

/**
 * Context label for an instance proof of possession. Mirrors Go's
 * `sigctx.InstanceProof`.
 *
 * `v2` because the proof changed meaning: `v1` signed the bare principal token, `v2`
 * signs a request binding. The label moved so a `v1` proof cannot be replayed against
 * the new semantics — it now verifies under no context at all.
 */
export const CTX_INSTANCE_PROOF = 'sanad/instance-proof/v2';

/**
 * Context label for a capability holder proof (Go's `sigctx.CapabilityHolderProof`).
 * The payload is the same shape as an instance proof; only the label differs, and that
 * is what stops one from being presented as the other when both are signed by keys that
 * can coincide.
 */
export const CTX_CAPABILITY_HOLDER_PROOF = 'sanad/capability-holder-proof/v2';

/**
 * Context label for a principal holder proof (Go's `sigctx.VCHolderProof`): the presenter of
 * a W3C-style principal credential proving possession of the credential subject's `did:key`
 * private key. Again the same payload shape, and again the label is the only thing keeping
 * one kind of signature from being read as another — a principal's `did:key` also signs
 * delegation hops and, if it is an issuer, credentials.
 */
export const CTX_VC_HOLDER_PROOF = 'sanad/vc-holder-proof/v1';

/**
 * Build the domain-separated signing input Go's `sigctx.Message` produces:
 *
 *     uint64be(ctx.length) || utf8(ctx) || message
 *
 * The 8-byte big-endian length prefix is what makes the encoding unambiguous — it
 * fixes exactly where the label ends, so the bytes parse back to one (ctx, message)
 * pair and no label can be read as the head of a message. The instance key signs
 * more than one kind of thing (it proves possession here, and authenticates the
 * delegation hops the agent signs), and the label is what keeps a signature made
 * for one from being accepted as the other.
 */
export function sigctxMessage(ctx: string, message: Buffer | Uint8Array): Buffer {
  const label = Buffer.from(ctx, 'utf8');
  const prefix = Buffer.alloc(8);
  prefix.writeBigUInt64BE(BigInt(label.length));
  return Buffer.concat([prefix, label, Buffer.from(message)]);
}

// ---------------------------------------------------------------------------
// Ed25519 key handling
// ---------------------------------------------------------------------------

/**
 * Decode a caller-supplied instance private key (base64url) into its 32-byte Ed25519
 * seed. Accepts either the 32-byte seed form or Go's 64-byte `seed || publicKey`
 * form; in both cases the first 32 bytes are the seed.
 */
function seedFromPrivateKey(privateKey: string): Buffer {
  const raw = b64urlDecode(privateKey);
  if (raw.length !== ED25519_SEED_LEN && raw.length !== ED25519_PRIVATE_LEN) {
    throw new Error(
      `sanad: instance private key must decode to ${ED25519_SEED_LEN} or ${ED25519_PRIVATE_LEN} bytes, got ${raw.length}`,
    );
  }
  return raw.subarray(0, ED25519_SEED_LEN);
}

/** Wrap a raw 32-byte Ed25519 seed as a KeyObject usable by `node:crypto`. */
function privateKeyObjectFromSeed(seed: Buffer): KeyObject {
  const der = Buffer.concat([PKCS8_ED25519_PREFIX, seed]);
  return createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
}

/** Derive the raw 32-byte Ed25519 public key from a private KeyObject. */
function rawPublicKey(priv: KeyObject): Buffer {
  // SPKI DER for Ed25519 is a fixed 12-byte prefix (302a300506032b6570032100)
  // followed by the 32-byte public key.
  const spki = createPublicKey(priv).export({ format: 'der', type: 'spki' });
  return spki.subarray(spki.length - ED25519_PUBLIC_LEN);
}

// ---------------------------------------------------------------------------
// Public key / signing primitives
// ---------------------------------------------------------------------------

/** An Ed25519 instance keypair, encoded to be interchangeable with the Go CLI. */
export interface InstanceKey {
  /** base64url of the 64-byte `seed(32) || publicKey(32)` form (matches `passport keygen`). */
  privateKey: string;
  /** base64url of the 32-byte public key. */
  publicKey: string;
}

/**
 * Generate a fresh Ed25519 instance key. The returned `privateKey` is the base64url
 * of the 64-byte `seed || publicKey` form, byte-for-byte interchangeable with the
 * key file written by the Go `passport keygen` command.
 */
export function generateInstanceKey(): InstanceKey {
  const { privateKey } = generateKeyPairSync('ed25519');
  // PKCS#8 DER = 16-byte prefix || 32-byte seed. Extract the seed to build the Go form.
  const der = privateKey.export({ format: 'der', type: 'pkcs8' });
  const seed = der.subarray(der.length - ED25519_SEED_LEN);
  const pub = rawPublicKey(privateKey);
  return {
    privateKey: b64url(Buffer.concat([seed, pub])),
    publicKey: b64url(pub),
  };
}

/** Return the base64url 32-byte public key for a given instance private key. */
export function publicKeyOf(privateKey: string): string {
  const priv = privateKeyObjectFromSeed(seedFromPrivateKey(privateKey));
  return b64url(rawPublicKey(priv));
}

// ---------------------------------------------------------------------------
// Request-bound proof of possession (DPoP, RFC 9449)
// ---------------------------------------------------------------------------

/** base64url(SHA-256(data)) — the digest form both `ath` and `bh` use. */
function sha256b64(data: Uint8Array | string): string {
  const buf = typeof data === 'string' ? Buffer.from(data, 'utf8') : Buffer.from(data);
  return b64url(createHash('sha256').update(buf).digest());
}

/**
 * The claims a proof commits to. Mirrors Go's `pop.Binding`; the key order here IS the
 * canonical encoding order and must not be changed.
 */
export interface ProofBinding {
  ath: string;
  bh: string;
  htm: string;
  htu: string;
  iat: number;
  jti: string;
}

/** What a caller supplies to build a proof for one request. */
export interface ProofInput {
  /** HTTP method, exactly as it will be sent (e.g. `POST`). */
  method: string;
  /** Origin-form request target: path plus `?` and the query. No scheme or host — see `proofTarget`. */
  target: string;
  /** The principal bearer token this request carries. */
  principalToken: string;
  /** The request body bytes, if any. Omit for a request that carries none. */
  body?: string | Uint8Array;
  /** Creation time, Unix SECONDS. Defaults to now; set it only for tests and vectors. */
  iat?: number;
  /** Unique proof id. Defaults to 128 fresh random bits; set it only for tests and vectors. */
  jti?: string;
}

/**
 * The `htu` value for a URL: the origin-form request target the gateway will see, which
 * is what both ends can compute identically. Mirrors Go's `pop.Target`.
 *
 * The authority is deliberately absent: the gateway sits behind TLS terminators, ingresses
 * and the `passport proxy` sidecar, any of which can rewrite the scheme or the Host header,
 * so binding a value the two ends compute differently buys an outage rather than security.
 * The query IS included, where RFC 9449 drops it — nothing between an agent and the gateway
 * rewrites query strings, and covering it is strictly stronger.
 *
 * Accepts an absolute URL or a bare path.
 */
export function proofTarget(url: string): string {
  const u = new URL(url, 'http://sanad.invalid');
  return (u.pathname || '/') + u.search;
}

/** Build the claim set for one request, filling in `iat` and `jti` when not supplied. */
export function proofBinding(input: ProofInput): ProofBinding {
  return {
    ath: sha256b64(Buffer.from(input.principalToken, 'utf8')),
    bh: sha256b64(input.body === undefined ? Buffer.alloc(0) : input.body),
    htm: input.method,
    htu: input.target,
    iat: input.iat ?? Math.floor(Date.now() / 1000),
    // 128 bits, above the 96 RFC 9449 §4.2 asks for.
    jti: input.jti ?? b64url(randomBytes(16)),
  };
}

/**
 * The canonical payload bytes: compact JSON with the keys in `ProofBinding` order.
 * `JSON.stringify` matches Go's `pop.Encode` (an encoder with HTML escaping off) and
 * Python's `json.dumps(..., separators=(",", ":"), ensure_ascii=False)`.
 */
export function proofPayload(binding: ProofBinding): Buffer {
  return Buffer.from(
    JSON.stringify({
      ath: binding.ath,
      bh: binding.bh,
      htm: binding.htm,
      htu: binding.htu,
      iat: binding.iat,
      jti: binding.jti,
    }),
    'utf8',
  );
}

/**
 * Sign a request binding under an arbitrary context label, returning the header value
 * `base64url(payload) "." base64url(signature)`. Mirrors Go's `pop.Sign`.
 *
 * The signature covers the payload bytes as transmitted, so the gateway never re-encodes
 * what it is checking and the three SDK languages cannot disagree about JSON details.
 */
export function requestProof(ctx: string, privateKey: string, input: ProofInput): string {
  const priv = privateKeyObjectFromSeed(seedFromPrivateKey(privateKey));
  const payload = proofPayload(proofBinding(input));
  const sig = sign(null, sigctxMessage(ctx, payload), priv);
  return `${b64url(payload)}.${b64url(sig)}`;
}

/**
 * Produce the `X-Agent-Proof` value for one request. Matches Go's `workload.Proof`.
 *
 * The proof commits to the method, the target, a hash of the principal token (`ath`) and a
 * hash of the body (`bh`), plus a creation time and a unique id. A gateway checks each
 * against the request in front of it, requires the proof to be seconds old, and spends the
 * `jti` on first use.
 *
 * Two departures from RFC 9449 are worth knowing about. The serialization is not a JWT:
 * the key is already carried in a CA-signed workload credential, so DPoP's `jwk` header
 * would be strictly weaker, and a parsed `alg` field is the root of the whole JWT confusion
 * family. And the body IS covered, which RFC 9449 §11.7 explicitly does not do: in MCP
 * streamable HTTP every JSON-RPC message is POSTed to one endpoint, so method and path are
 * identical for `tools/list` and for a `tools/call` of any tool — a proof that stopped at
 * the URL would leave a captured header bundle usable to invoke anything.
 *
 * Do NOT cache the result. Calling this once and reusing the value is precisely the bug
 * this construction fixes, and the gateway will reject the second request.
 */
export function proof(privateKey: string, input: ProofInput): string {
  return requestProof(CTX_INSTANCE_PROOF, privateKey, input);
}

/**
 * Produce the `X-Agent-Capability-Proof` value for one request: the same binding as
 * `proof`, signed under the capability holder context. Matches Go's
 * `delegation.HolderProof`.
 */
export function capabilityHolderProof(holderSecret: string, input: ProofInput): string {
  return requestProof(CTX_CAPABILITY_HOLDER_PROOF, holderSecret, input);
}

/**
 * Produce the `X-Principal-Proof` value for one request. Matches Go's `vc.HolderProof`.
 *
 * A gateway in VC mode (`PASSPORT_PRINCIPAL_MODE=vc`) does not treat the principal
 * credential as a bearer token: the credential proves that a trusted issuer vouched for a
 * `did:key`, and this proves that the caller actually holds that key, on this request. Both
 * are required. Without it the credential would be exactly as good as a copy of it, which is
 * what anything that sees one request's headers gets for free.
 *
 * `principalKey` is the base64url `did:key` private key of the credential SUBJECT — not the
 * instance key, and not the issuer's key. `principalToken` must be the credential string
 * exactly as it is sent in the Authorization header, since the proof commits to it (`ath`).
 */
export function principalHolderProof(principalKey: string, input: ProofInput): string {
  return requestProof(CTX_VC_HOLDER_PROOF, principalKey, input);
}

// ---------------------------------------------------------------------------
// Enrollment
// ---------------------------------------------------------------------------

export interface EnrollOptions {
  /** Authority base URL. A trailing slash is trimmed before appending `/enroll`. */
  authorityUrl: string;
  /**
   * Bootstrap attestation token (dev/self-host attestor). Single-use and expiring: it
   * authorizes a bounded number of enrollments (one, by default) inside a bounded window.
   * Read it from a file or the environment — never a command-line argument, which is
   * readable by every process on the host.
   */
  bootstrapToken: string;
  /** base64url of the 32-byte instance public key (from `generateInstanceKey`/`publicKeyOf`). */
  publicKey: string;
  /** Optional fetch implementation (for testing / custom transports). Defaults to global fetch. */
  fetch?: typeof fetch;
}

export interface EnrollResult {
  /**
   * The raw credential JSON text exactly as returned by the authority. Store this
   * verbatim — do NOT reformat or re-serialize it; the gateway verifies an embedded
   * signature over the credential fields and re-encoding could reorder/reshape it.
   */
  credential: string;
  /** Convenience: the AgentID parsed out of the credential, if present. */
  agentId?: string;
  /** Convenience: the NotAfter (expiry) parsed out of the credential, if present. */
  notAfter?: string;
}

/**
 * Build the attestation evidence a Go `workload.TokenAttestor` accepts: an HMAC-SHA256,
 * keyed by the bootstrap token, over the authority-issued nonce and the public key being
 * enrolled. Mirrors Go's `workload.BootstrapEvidence` byte-for-byte.
 *
 * The bootstrap token never leaves the process, and the result only enrolls this key
 * against this nonce — so an enrollment captured off the wire cannot be replayed with
 * somebody else's key.
 */
export function bootstrapEvidence(
  bootstrapToken: string,
  nonce: Buffer | Uint8Array,
  publicKey: Buffer | Uint8Array,
): Buffer {
  // The MAC input is the canonical JSON Go signs over: {"ctx","nonce","pub"} in that
  // field order, with nonce/pub as standard (padded) base64 — Go's encoding of []byte.
  const msg = JSON.stringify({
    ctx: 'sanad/bootstrap-evidence/v1',
    nonce: Buffer.from(nonce).toString('base64'),
    pub: Buffer.from(publicKey).toString('base64'),
  });
  return createHmac('sha256', Buffer.from(bootstrapToken, 'utf8')).update(msg).digest();
}

/**
 * Fetch a single-use enrollment nonce from the authority's `POST /enroll/nonce`.
 * Mirrors Go's `workload.RequestNonce`.
 *
 * The nonce is the RATS freshness challenge (carried as EAT `eat_nonce`): the authority
 * accepts it exactly once, within a short window, so an attestation built over it cannot
 * be replayed.
 */
export async function requestNonce(
  authorityUrl: string,
  doFetch: typeof fetch = fetch,
): Promise<Buffer> {
  const url = authorityUrl.replace(/\/+$/, '') + '/enroll/nonce';
  const resp = await doFetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: '{}',
  });
  const text = await resp.text();
  if (resp.status !== 200) {
    throw new Error(`enroll: ${resp.status} ${resp.statusText}: ${text.trim()}`);
  }
  const parsed = JSON.parse(text) as { nonce?: unknown };
  if (typeof parsed.nonce !== 'string' || parsed.nonce === '') {
    throw new Error('enroll: authority returned an unusable nonce');
  }
  return b64urlDecode(parsed.nonce);
}

/**
 * Obtain a short-lived workload credential. Mirrors the client side of Go's
 * `workload.Enroll`, which is two requests:
 *
 *   1. `POST /enroll/nonce` for a single-use challenge, then
 *   2. `POST /enroll` with that nonce, evidence covering it and the instance public key,
 *      and the public key itself.
 *
 * On HTTP 200 the response body is kept as the raw credential text. On any non-200
 * status this throws an Error including the status and response body.
 *
 * Call it once, at startup, and persist the credential: the bootstrap token is single-use
 * and expiring. A 403 naming a spent or expired token is permanent — a retry cannot fix it,
 * only a fresh token can. A 429 is the authority's enrollment rate limit and carries a
 * `Retry-After`; wait that long rather than retrying immediately.
 */
export async function enroll(opts: EnrollOptions): Promise<EnrollResult> {
  const doFetch = opts.fetch ?? fetch;
  const pub = b64urlDecode(opts.publicKey);
  if (pub.length !== ED25519_PUBLIC_LEN) {
    throw new Error(`enroll: instance public key must be ${ED25519_PUBLIC_LEN} bytes`);
  }

  const nonce = await requestNonce(opts.authorityUrl, doFetch);
  const url = opts.authorityUrl.replace(/\/+$/, '') + '/enroll';
  const body = JSON.stringify({
    nonce: b64url(nonce),
    evidence: b64url(bootstrapEvidence(opts.bootstrapToken, nonce, pub)),
    public_key: opts.publicKey,
  });

  const resp = await doFetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body,
  });

  const text = await resp.text();
  if (resp.status !== 200) {
    throw new Error(`enroll: ${resp.status} ${resp.statusText}: ${text.trim()}`);
  }

  const result: EnrollResult = { credential: text };
  try {
    const parsed = JSON.parse(text) as { AgentID?: unknown; NotAfter?: unknown };
    if (typeof parsed.AgentID === 'string') result.agentId = parsed.AgentID;
    if (typeof parsed.NotAfter === 'string') result.notAfter = parsed.NotAfter;
  } catch {
    // Non-JSON body: keep the raw credential text without convenience fields.
  }
  return result;
}

// ---------------------------------------------------------------------------
// PassportClient
// ---------------------------------------------------------------------------

export interface PassportClientOptions {
  /** Gateway base URL. A trailing slash is trimmed before appending `/servers/...`. */
  gatewayUrl: string;
  /** Instance private key, base64url (32-byte seed or 64-byte seed||pub). */
  instanceKey: string;
  /** Raw workload credential JSON text, exactly as returned by `enroll`. */
  credential: string;
  /**
   * The principal's `did:key` private key, base64url (32-byte seed or 64-byte seed||pub).
   * REQUIRED by gateways in VC mode, where the principal credential is not a bearer token and
   * each request carries a proof of possession of this key (see `principalHolderProof`).
   * Omit it in OIDC mode, where the principal has no such key.
   */
  principalKey?: string;
  /** Optional delegation chain JSON text. When present, sent as X-Agent-Delegation. */
  delegation?: string;
  /** Optional fetch implementation. Defaults to global fetch. */
  fetch?: typeof fetch;
}

export interface RequestOptions {
  /**
   * The principal bearer token; sent as `Authorization: Bearer <token>` and hashed into the
   * proofs. Opaque to the SDK — an OIDC ID token, or a principal credential in VC mode, where
   * it must be paired with the `principalKey` that credential's subject holds.
   */
  principalToken: string;
  /** HTTP method (default GET). */
  method?: string;
  /**
   * Optional request body forwarded to the gateway. Narrowed to bytes the SDK can hash:
   * the proof commits to a digest of the body, so a stream or a `FormData` — which cannot
   * be read twice — could not be bound, and sending one unbound would leave the gateway
   * authorizing bytes no proof covered.
   */
  body?: string | Uint8Array;
  /** Extra headers merged onto the injected passport headers (extras win on conflict). */
  headers?: Record<string, string>;
}

/**
 * PassportClient attaches passport authentication headers to requests routed through
 * the gateway. It is the programmatic equivalent of the `passport proxy` sidecar.
 */
export class PassportClient {
  private readonly gatewayUrl: string;
  private readonly instanceKey: string;
  private readonly principalKey?: string;
  private readonly credentialHeader: string;
  private readonly delegationHeader?: string;
  private readonly fetchImpl: typeof fetch;

  constructor(opts: PassportClientOptions) {
    this.gatewayUrl = opts.gatewayUrl.replace(/\/+$/, '');
    this.instanceKey = opts.instanceKey;
    this.principalKey = opts.principalKey;
    // Encode the raw credential bytes once. Encoding the exact bytes (not a
    // re-serialization) preserves the signature the gateway verifies.
    this.credentialHeader = b64urlUtf8(opts.credential);
    this.delegationHeader =
      opts.delegation !== undefined ? b64urlUtf8(opts.delegation) : undefined;
    this.fetchImpl = opts.fetch ?? fetch;
  }

  /**
   * Build the passport headers for ONE request: Authorization plus X-Agent-Credential and
   * X-Agent-Proof, X-Principal-Proof when a principal key was configured, and
   * X-Agent-Delegation when a delegation chain was.
   *
   * It takes the request — server, path, method and body — because the proofs are bound to
   * all of them. The returned headers are good for that request and no other; building
   * them once and reusing them across calls is the bug this construction exists to fix.
   */
  headers(serverId: string, path: string, opts: RequestOptions): Record<string, string> {
    const input: ProofInput = {
      method: opts.method ?? 'GET',
      target: proofTarget(this.url(serverId, path)),
      principalToken: opts.principalToken,
      body: opts.body,
    };
    const h: Record<string, string> = {
      Authorization: `Bearer ${opts.principalToken}`,
      [HEADER_CREDENTIAL]: this.credentialHeader,
      [HEADER_PROOF]: proof(this.instanceKey, input),
    };
    // The same `input` for both: it carries no `iat` or `jti`, so each call fills in its own.
    if (this.principalKey !== undefined) {
      h[HEADER_PRINCIPAL_PROOF] = principalHolderProof(this.principalKey, input);
    }
    if (this.delegationHeader !== undefined) {
      h[HEADER_DELEGATION] = this.delegationHeader;
    }
    return h;
  }

  /** Build the full gateway URL: `${gatewayUrl}/servers/${serverId}${path}`. */
  url(serverId: string, path: string): string {
    return `${this.gatewayUrl}/servers/${serverId}${path}`;
  }

  /**
   * Perform a request to `${gatewayUrl}/servers/${serverId}${path}` with the passport
   * headers injected. `path` must begin with `/` (e.g. `/tools/list`). Extra headers
   * override the injected ones on conflict.
   */
  async request(serverId: string, path: string, opts: RequestOptions): Promise<Response> {
    const init: RequestInit = {
      method: opts.method ?? 'GET',
      headers: { ...this.headers(serverId, path, opts), ...(opts.headers ?? {}) },
    };
    if (opts.body !== undefined) init.body = opts.body;
    return this.fetchImpl(this.url(serverId, path), init);
  }
}
