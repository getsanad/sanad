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
 *
 * Zero runtime dependencies: only Node.js built-ins (`node:crypto`, global fetch).
 * Requires Node >= 18 (global fetch). Ed25519 support in `node:crypto` requires a
 * reasonably recent Node; Node >= 18 is fine.
 */

import {
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
 * signature, made with the instance private key, over the UTF-8 bytes of the token.
 * Matches Go's `workload.Proof`.
 */
export function proof(privateKey: string, principalToken: string): string {
  const priv = privateKeyObjectFromSeed(seedFromPrivateKey(privateKey));
  const sig = sign(null, Buffer.from(principalToken, 'utf8'), priv);
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
 * Present a bootstrap token plus the instance public key to the authority's
 * `POST /enroll` endpoint and receive a short-lived workload credential. Mirrors the
 * client side of Go's `workload.Enroll`.
 *
 * On HTTP 200 the response body is kept as the raw credential text. On any non-200
 * status this throws an Error including the status and response body.
 */
export async function enroll(opts: EnrollOptions): Promise<EnrollResult> {
  const doFetch = opts.fetch ?? fetch;
  const url = opts.authorityUrl.replace(/\/+$/, '') + '/enroll';
  const body = JSON.stringify({
    evidence: b64urlUtf8(opts.bootstrapToken),
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
