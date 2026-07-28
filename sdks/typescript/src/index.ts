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
 * possession of the instance key, and an optional delegation chain.
 *
 * Wire format notes (must match the Go implementation byte-for-byte):
 *   - All base64 is RFC 4648 URL-safe with NO padding (Go's base64.RawURLEncoding,
 *     Node's `buf.toString('base64url')`). Decoding tolerates missing padding.
 *   - Cryptography is Ed25519.
 *   - Every signature is domain-separated: it is made over
 *     `uint64be(ctx.length) || ctx || message`, where `ctx` names what is being signed
 *     (see `sigctxMessage`). Signing the bare message is NOT accepted by the gateway.
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
  createHmac,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
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
 */
export const CTX_INSTANCE_PROOF = 'sanad/instance-proof/v1';

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

/**
 * Produce the proof of possession for a principal token: base64url of the Ed25519
 * signature, made with the instance private key, over the domain-separated signing
 * input for the token under `CTX_INSTANCE_PROOF`. Matches Go's `workload.Proof`.
 *
 * Signing the bare token — as this SDK did before the context was introduced — turns
 * the instance key into a signing oracle for anything else that key authenticates,
 * so the gateway rejects such a signature.
 */
export function proof(privateKey: string, principalToken: string): string {
  const priv = privateKeyObjectFromSeed(seedFromPrivateKey(privateKey));
  const msg = sigctxMessage(CTX_INSTANCE_PROOF, Buffer.from(principalToken, 'utf8'));
  const sig = sign(null, msg, priv);
  return b64url(sig);
}

// ---------------------------------------------------------------------------
// Enrollment
// ---------------------------------------------------------------------------

export interface EnrollOptions {
  /** Authority base URL. A trailing slash is trimmed before appending `/enroll`. */
  authorityUrl: string;
  /** Bootstrap attestation token (dev/self-host attestor). */
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
  /** Optional delegation chain JSON text. When present, sent as X-Agent-Delegation. */
  delegation?: string;
  /** Optional fetch implementation. Defaults to global fetch. */
  fetch?: typeof fetch;
}

export interface RequestOptions {
  /** Opaque principal bearer token; sent as `Authorization: Bearer <token>` and signed for the proof. */
  principalToken: string;
  /** HTTP method (default GET). */
  method?: string;
  /** Optional request body forwarded to the gateway. */
  body?: RequestInit['body'];
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
  private readonly credentialHeader: string;
  private readonly delegationHeader?: string;
  private readonly fetchImpl: typeof fetch;

  constructor(opts: PassportClientOptions) {
    this.gatewayUrl = opts.gatewayUrl.replace(/\/+$/, '');
    this.instanceKey = opts.instanceKey;
    // Encode the raw credential bytes once. Encoding the exact bytes (not a
    // re-serialization) preserves the signature the gateway verifies.
    this.credentialHeader = b64urlUtf8(opts.credential);
    this.delegationHeader =
      opts.delegation !== undefined ? b64urlUtf8(opts.delegation) : undefined;
    this.fetchImpl = opts.fetch ?? fetch;
  }

  /**
   * Build the passport headers for a given principal token: Authorization plus
   * X-Agent-Credential and X-Agent-Proof, and X-Agent-Delegation only when a
   * delegation chain was configured.
   */
  headers(principalToken: string): Record<string, string> {
    const h: Record<string, string> = {
      Authorization: `Bearer ${principalToken}`,
      [HEADER_CREDENTIAL]: this.credentialHeader,
      [HEADER_PROOF]: proof(this.instanceKey, principalToken),
    };
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
      headers: { ...this.headers(opts.principalToken), ...(opts.headers ?? {}) },
    };
    if (opts.body !== undefined) init.body = opts.body;
    return this.fetchImpl(this.url(serverId, path), init);
  }
}
