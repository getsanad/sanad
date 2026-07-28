// Plain-Node (no TypeScript toolchain required) proof that the SDK's crypto/wire
// vectors match the Go implementation byte-for-byte. Run with:  node test/vectors.mjs
//
// This mirrors the logic in src/index.ts using only node:crypto so the fixed vectors
// can be verified in any environment, even without tsc/tsx installed. The same values are
// pinned Go-side in workload/interop_test.go — update all three suites together.
import crypto from 'node:crypto';
import assert from 'node:assert/strict';

const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

function seedFromPrivateKey(b64) {
  const raw = Buffer.from(b64, 'base64url');
  if (raw.length !== 32 && raw.length !== 64) {
    throw new Error(`key must be 32 or 64 bytes, got ${raw.length}`);
  }
  return raw.subarray(0, 32);
}
function privObj(seed) {
  return crypto.createPrivateKey({
    key: Buffer.concat([PKCS8_ED25519_PREFIX, seed]),
    format: 'der',
    type: 'pkcs8',
  });
}
function rawPub(priv) {
  const spki = crypto.createPublicKey(priv).export({ format: 'der', type: 'spki' });
  return spki.subarray(spki.length - 32);
}
function publicKeyOf(b64) {
  return rawPub(privObj(seedFromPrivateKey(b64))).toString('base64url');
}
// Domain-separated signing input, matching Go's sigctx.Message:
// uint64be(ctx.length) || ctx || message. The length prefix fixes where the label ends,
// so no label can be read as the head of a message (or the reverse).
function sigctxMessage(ctx, message) {
  const label = Buffer.from(ctx, 'utf8');
  const prefix = Buffer.alloc(8);
  prefix.writeBigUInt64BE(BigInt(label.length));
  return Buffer.concat([prefix, label, Buffer.from(message)]);
}
const CTX_INSTANCE_PROOF = 'sanad/instance-proof/v2';
const CTX_CAPABILITY_HOLDER_PROOF = 'sanad/capability-holder-proof/v2';

function sha256b64(data) {
  return crypto.createHash('sha256').update(Buffer.from(data)).digest().toString('base64url');
}
// The origin-form request target the gateway sees: path plus query, no scheme or host.
function proofTarget(url) {
  const u = new URL(url, 'http://sanad.invalid');
  return (u.pathname || '/') + u.search;
}
// The canonical proof payload: compact JSON, keys in this order, no HTML escaping. Matches
// Go's pop.Encode and Python's json.dumps(separators=(",",":"), ensure_ascii=False).
function proofPayload({ token, method, target, body, iat, jti }) {
  return Buffer.from(
    JSON.stringify({
      ath: sha256b64(Buffer.from(token, 'utf8')),
      bh: sha256b64(body === undefined ? Buffer.alloc(0) : Buffer.from(body)),
      htm: method,
      htu: target,
      iat,
      jti,
    }),
    'utf8',
  );
}
// The request-bound proof of possession (DPoP, RFC 9449, in Sanad's signature format):
// base64url(payload) "." base64url(Ed25519 signature over the domain-separated payload).
function requestProof(ctx, b64, input) {
  const payload = proofPayload(input);
  const sig = crypto.sign(null, sigctxMessage(ctx, payload), privObj(seedFromPrivateKey(b64)));
  return `${payload.toString('base64url')}.${sig.toString('base64url')}`;
}
function proof(b64, input) {
  return requestProof(CTX_INSTANCE_PROOF, b64, input);
}
// The evidence a Go workload.TokenAttestor accepts: HMAC-SHA256 keyed by the bootstrap
// token over the canonical JSON of {ctx, nonce, pub}, with the byte fields in standard
// (padded) base64 — how Go's encoding/json renders []byte.
function bootstrapEvidence(token, nonce, pub) {
  const msg = JSON.stringify({
    ctx: 'sanad/bootstrap-evidence/v1',
    nonce: Buffer.from(nonce).toString('base64'),
    pub: Buffer.from(pub).toString('base64'),
  });
  return crypto.createHmac('sha256', Buffer.from(token, 'utf8')).update(msg).digest();
}

const SEED = 'AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA';
const FULL = 'AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyB5tVYuj-ZU-UB4sRLoqYunkB-FOuaVvtfg45ELrQSWZA';
const PUB = 'ebVWLo_mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ';
// The request the vector proof is bound to, with the two per-proof random inputs pinned.
const VECTOR_INPUT = {
  token: 'test-principal-token',
  method: 'POST',
  target: '/servers/demo/mcp',
  body: '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read"}}',
  iat: 1767225600, // 2026-01-01T00:00:00Z
  jti: 'AAECAwQFBgcICQoLDA0ODw',
};
const ATH = 'eaVdc24MF5rbKpTXWDI5W-tXHNfA1-qvFjwQ4GIhjlI';
const BH = 'qXDbbSbAIAqtTp_paFTD5GK3FpDPUyMfdw3M-BeWpWw';
const BH_EMPTY = '47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU';
const PAYLOAD =
  '{"ath":"eaVdc24MF5rbKpTXWDI5W-tXHNfA1-qvFjwQ4GIhjlI","bh":"qXDbbSbAIAqtTp_paFTD5GK3FpDPUyMfdw3M-BeWpWw","htm":"POST","htu":"/servers/demo/mcp","iat":1767225600,"jti":"AAECAwQFBgcICQoLDA0ODw"}';
const PROOF =
  'eyJhdGgiOiJlYVZkYzI0TUY1cmJLcFRYV0RJNVctdFhITmZBMS1xdkZqd1E0R0loamxJIiwiYmgiOiJxWERiYlNiQUlBcXRUcF9wYUZURDVHSzNGcERQVXlNZmR3M00tQmVXcFd3IiwiaHRtIjoiUE9TVCIsImh0dSI6Ii9zZXJ2ZXJzL2RlbW8vbWNwIiwiaWF0IjoxNzY3MjI1NjAwLCJqdGkiOiJBQUVDQXdRRkJnY0lDUW9MREEwT0R3In0.xDlJ_BHqkqNCj1L4e4RqJsHSO_DE71uRiqALR6CRFdMSC-ICPY8rojK3uyy_coSbhDFQBT1mpL0ECFk8sIlpBw';
const HOLDER_PROOF =
  'eyJhdGgiOiJlYVZkYzI0TUY1cmJLcFRYV0RJNVctdFhITmZBMS1xdkZqd1E0R0loamxJIiwiYmgiOiJxWERiYlNiQUlBcXRUcF9wYUZURDVHSzNGcERQVXlNZmR3M00tQmVXcFd3IiwiaHRtIjoiUE9TVCIsImh0dSI6Ii9zZXJ2ZXJzL2RlbW8vbWNwIiwiaWF0IjoxNzY3MjI1NjAwLCJqdGkiOiJBQUVDQXdRRkJnY0lDUW9MREEwT0R3In0.y-dA1G8M220lQyMubM0EyB8V2qAfznj-PA2WWHMYvmmgye7iNT60q4xXJW73e5hux4niRagPGEYNDYz7HQ5DAw';
// The signing input the proof covers, as hex: 8-byte length || context || payload.
const PROOF_INPUT_HEX = '000000000000001773616e61642f696e7374616e63652d70726f6f662f76327b22617468223a22656156646332344d463572624b70545857444935572d7458484e6641312d7176466a7751344749686a6c49222c226268223a2271584462625362414941717454705f706146544435474b334670445055794d666477334d2d426557705777222c2268746d223a22504f5354222c22687475223a222f736572766572732f64656d6f2f6d6370222c22696174223a313736373232353630302c226a7469223a2241414543417751464267634943516f4c4441304f4477227d';
const CRED = '{"AgentID":"agent-1","PublicKey":"3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29","IssuedAt":"2026-07-10T00:00:00Z","NotAfter":"2026-07-10T01:00:00Z","KeyID":"ca-1","Signature":"AA=="}';
const CRED_HEADER = 'eyJBZ2VudElEIjoiYWdlbnQtMSIsIlB1YmxpY0tleSI6IjNiNmEyN2JjY2ViNmE0MmQ2MmEzYThkMDJhNmYwZDczNjUzMjE1NzcxZGUyNDNhNjNhYzA0OGExOGI1OWRhMjkiLCJJc3N1ZWRBdCI6IjIwMjYtMDctMTBUMDA6MDA6MDBaIiwiTm90QWZ0ZXIiOiIyMDI2LTA3LTEwVDAxOjAwOjAwWiIsIktleUlEIjoiY2EtMSIsIlNpZ25hdHVyZSI6IkFBPT0ifQ';
const NONCE = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8';
const EVIDENCE = 'umfR1kxOzPGX1ZFOK5pgnnRtnxSm-q3nE-Qx6DPsI1o';

const results = [
  ['publicKeyOf(seed)', publicKeyOf(SEED), PUB],
  ['64-byte form b64url', Buffer.concat([Buffer.from(SEED, 'base64url'), Buffer.from(PUB, 'base64url')]).toString('base64url'), FULL],
  ['publicKeyOf(64-byte form)', publicKeyOf(FULL), PUB],
  ['proofTarget(absolute URL)', proofTarget('https://gw.example.com/servers/demo/mcp'), '/servers/demo/mcp'],
  ['proofTarget(path + query)', proofTarget('/servers/demo/mcp?cursor=abc'), '/servers/demo/mcp?cursor=abc'],
  ['ath = sha256(principal token)', sha256b64(Buffer.from(VECTOR_INPUT.token, 'utf8')), ATH],
  ['bh = sha256(body)', sha256b64(Buffer.from(VECTOR_INPUT.body)), BH],
  ['bh = sha256(empty body)', sha256b64(Buffer.alloc(0)), BH_EMPTY],
  ['canonical proof payload', proofPayload(VECTOR_INPUT).toString('utf8'), PAYLOAD],
  ['sigctxMessage(instance-proof, payload)', sigctxMessage(CTX_INSTANCE_PROOF, proofPayload(VECTOR_INPUT)).toString('hex'), PROOF_INPUT_HEX],
  ['proof(seed, request)', proof(SEED, VECTOR_INPUT), PROOF],
  ['proof(64-byte form) == proof(seed)', proof(FULL, VECTOR_INPUT), PROOF],
  ['capability holder proof over the same payload', requestProof(CTX_CAPABILITY_HOLDER_PROOF, SEED, VECTOR_INPUT), HOLDER_PROOF],
  ['base64url(utf8(credential))', Buffer.from(CRED, 'utf8').toString('base64url'), CRED_HEADER],
  ['bootstrapEvidence("boot-token", nonce, pub)', bootstrapEvidence('boot-token', Buffer.from(NONCE, 'base64url'), Buffer.from(PUB, 'base64url')).toString('base64url'), EVIDENCE],
];

let ok = true;
for (const [name, got, want] of results) {
  const pass = got === want;
  ok = ok && pass;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) console.log(`        got:  ${got}\n        want: ${want}`);
}
for (const [name, got, want] of results) assert.equal(got, want, name);
console.log(ok ? '\nAll vectors match the Go implementation.' : '\nVECTOR MISMATCH');
process.exit(ok ? 0 : 1);
