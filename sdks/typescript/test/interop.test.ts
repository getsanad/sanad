/**
 * Interop tests. These lock the byte formats against fixed vectors generated from the
 * Go implementation, so any drift in the wire format is caught immediately.
 *
 * Run with:  node --test test/        (Node >= 22.6 strips the TS types automatically)
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  generateInstanceKey,
  publicKeyOf,
  proof,
  enroll,
  PassportClient,
  HEADER_CREDENTIAL,
  HEADER_PROOF,
  HEADER_DELEGATION,
} from '../src/index.ts';

// The 32-byte seed 0x01..0x20, base64url-encoded.
const SEED_B64URL = 'AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA';
// Its 64-byte Go form (seed || pub).
const FULL_B64URL =
  'AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyB5tVYuj-ZU-UB4sRLoqYunkB-FOuaVvtfg45ELrQSWZA';
const EXPECTED_PUB = 'ebVWLo_mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ';
const EXPECTED_PROOF =
  'vS7aSzPmJd-D-AEAgbkw6oFU_0KU4rvei6aUlpCbrGn-nGkfVoqrvrV695SwkzT-id_8nXu18uleQye60FhWCQ';

const CRED_TEXT =
  '{"AgentID":"agent-1","PublicKey":"3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29","IssuedAt":"2026-07-10T00:00:00Z","NotAfter":"2026-07-10T01:00:00Z","KeyID":"ca-1","Signature":"AA=="}';
const EXPECTED_CRED_HEADER =
  'eyJBZ2VudElEIjoiYWdlbnQtMSIsIlB1YmxpY0tleSI6IjNiNmEyN2JjY2ViNmE0MmQ2MmEzYThkMDJhNmYwZDczNjUzMjE1NzcxZGUyNDNhNjNhYzA0OGExOGI1OWRhMjkiLCJJc3N1ZWRBdCI6IjIwMjYtMDctMTBUMDA6MDA6MDBaIiwiTm90QWZ0ZXIiOiIyMDI2LTA3LTEwVDAxOjAwOjAwWiIsIktleUlEIjoiY2EtMSIsIlNpZ25hdHVyZSI6IkFBPT0ifQ';

function b64urlUtf8(s: string): string {
  return Buffer.from(s, 'utf8').toString('base64url');
}

test('publicKeyOf matches the fixed vector', () => {
  assert.equal(publicKeyOf(SEED_B64URL), EXPECTED_PUB);
});

test('proof matches the fixed vector', () => {
  assert.equal(proof(SEED_B64URL, 'test-principal-token'), EXPECTED_PROOF);
});

test('base64url(utf8(credential)) matches the fixed vector', () => {
  assert.equal(b64urlUtf8(CRED_TEXT), EXPECTED_CRED_HEADER);
});

test('64-byte private input and its 32-byte seed prefix agree', () => {
  assert.equal(publicKeyOf(FULL_B64URL), EXPECTED_PUB);
  assert.equal(publicKeyOf(FULL_B64URL), publicKeyOf(SEED_B64URL));
  assert.equal(
    proof(FULL_B64URL, 'test-principal-token'),
    proof(SEED_B64URL, 'test-principal-token'),
  );
});

test('the 64-byte form of the seed key equals the fixed vector', () => {
  // Build the 64-byte form from the SEED by round-tripping through publicKeyOf.
  const seed = Buffer.from(SEED_B64URL, 'base64url');
  const pub = Buffer.from(publicKeyOf(SEED_B64URL), 'base64url');
  assert.equal(Buffer.concat([seed, pub]).toString('base64url'), FULL_B64URL);
});

test('generate -> publicKeyOf round-trips', () => {
  const key = generateInstanceKey();
  // The reported publicKey must equal the one derived from the private key.
  assert.equal(publicKeyOf(key.privateKey), key.publicKey);
  // The private key must decode to the 64-byte Go form (seed || pub).
  const raw = Buffer.from(key.privateKey, 'base64url');
  assert.equal(raw.length, 64);
  // Its trailing 32 bytes are exactly the public key.
  assert.equal(raw.subarray(32).toString('base64url'), key.publicKey);
  // A signature made with this key is verifiable via a proof round-trip: the proof
  // for a token is deterministic for Ed25519, so it must be stable.
  const p1 = proof(key.privateKey, 'hello');
  const p2 = proof(raw.subarray(0, 32).toString('base64url'), 'hello');
  assert.equal(p1, p2);
});

test('PassportClient.headers builds the 3 base headers (no delegation)', () => {
  const client = new PassportClient({
    gatewayUrl: 'https://gw.example.com',
    instanceKey: SEED_B64URL,
    credential: CRED_TEXT,
  });
  const h = client.headers('test-principal-token');
  assert.equal(h['Authorization'], 'Bearer test-principal-token');
  assert.equal(h[HEADER_CREDENTIAL], EXPECTED_CRED_HEADER);
  assert.equal(h[HEADER_PROOF], EXPECTED_PROOF);
  assert.equal(h[HEADER_DELEGATION], undefined);
  assert.equal(Object.prototype.hasOwnProperty.call(h, HEADER_DELEGATION), false);
});

test('PassportClient.headers includes X-Agent-Delegation when configured', () => {
  const chain = '{"hops":[]}';
  const client = new PassportClient({
    gatewayUrl: 'https://gw.example.com/',
    instanceKey: SEED_B64URL,
    credential: CRED_TEXT,
    delegation: chain,
  });
  const h = client.headers('test-principal-token');
  assert.equal(h[HEADER_DELEGATION], b64urlUtf8(chain));
});

test('PassportClient.url trims trailing slash and joins /servers/{id}{path}', () => {
  const client = new PassportClient({
    gatewayUrl: 'https://gw.example.com/',
    instanceKey: SEED_B64URL,
    credential: CRED_TEXT,
  });
  assert.equal(
    client.url('demo', '/tools/list'),
    'https://gw.example.com/servers/demo/tools/list',
  );
});

test('PassportClient.request injects headers, method, body and forwards to the gateway', async () => {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const fakeFetch = (async (url: string | URL | Request, init?: RequestInit) => {
    calls.push({ url: String(url), init: init ?? {} });
    return new Response('{"ok":true}', { status: 200 });
  }) as unknown as typeof fetch;

  const client = new PassportClient({
    gatewayUrl: 'https://gw.example.com',
    instanceKey: SEED_B64URL,
    credential: CRED_TEXT,
    fetch: fakeFetch,
  });

  const resp = await client.request('demo', '/tools/call', {
    principalToken: 'test-principal-token',
    method: 'POST',
    body: '{"name":"echo"}',
    headers: { 'Content-Type': 'application/json' },
  });

  assert.equal(resp.status, 200);
  assert.equal(calls.length, 1);
  const call = calls[0]!;
  assert.equal(call.url, 'https://gw.example.com/servers/demo/tools/call');
  assert.equal(call.init.method, 'POST');
  assert.equal(call.init.body, '{"name":"echo"}');
  const headers = call.init.headers as Record<string, string>;
  assert.equal(headers['Authorization'], 'Bearer test-principal-token');
  assert.equal(headers[HEADER_CREDENTIAL], EXPECTED_CRED_HEADER);
  assert.equal(headers[HEADER_PROOF], EXPECTED_PROOF);
  assert.equal(headers['Content-Type'], 'application/json');
});

test('enroll posts the right body and returns the raw credential + parsed fields', async () => {
  const captured: { url: string; init: RequestInit }[] = [];
  const fakeFetch = (async (url: string | URL | Request, init?: RequestInit) => {
    captured.push({ url: String(url), init: init ?? {} });
    return new Response(CRED_TEXT, {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  }) as unknown as typeof fetch;

  const result = await enroll({
    authorityUrl: 'https://authority.example.com/',
    bootstrapToken: 'boot-tok',
    publicKey: EXPECTED_PUB,
    fetch: fakeFetch,
  });

  // Raw credential text is preserved verbatim.
  assert.equal(result.credential, CRED_TEXT);
  assert.equal(result.agentId, 'agent-1');
  assert.equal(result.notAfter, '2026-07-10T01:00:00Z');

  assert.equal(captured.length, 1);
  const call = captured[0]!;
  assert.equal(call.url, 'https://authority.example.com/enroll');
  assert.equal(call.init.method, 'POST');
  const sentHeaders = call.init.headers as Record<string, string>;
  assert.equal(sentHeaders['Content-Type'], 'application/json');
  const parsedBody = JSON.parse(String(call.init.body)) as {
    evidence: string;
    public_key: string;
  };
  // evidence is base64url(utf8(bootstrapToken))
  assert.equal(parsedBody.evidence, Buffer.from('boot-tok', 'utf8').toString('base64url'));
  assert.equal(parsedBody.public_key, EXPECTED_PUB);
});

test('enroll throws with status and body on non-200', async () => {
  const fakeFetch = (async () =>
    new Response('enrollment denied: attestation rejected', {
      status: 403,
      statusText: 'Forbidden',
    })) as unknown as typeof fetch;

  await assert.rejects(
    () =>
      enroll({
        authorityUrl: 'https://authority.example.com',
        bootstrapToken: 'nope',
        publicKey: EXPECTED_PUB,
        fetch: fakeFetch,
      }),
    /403.*attestation rejected/,
  );
});

test('rejects a private key of the wrong length', () => {
  const bad = Buffer.alloc(16, 7).toString('base64url');
  assert.throws(() => publicKeyOf(bad), /must decode to 32 or 64 bytes/);
});
