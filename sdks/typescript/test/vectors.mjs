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
const CTX_INSTANCE_PROOF = 'sanad/instance-proof/v1';

function proof(b64, token) {
  const msg = sigctxMessage(CTX_INSTANCE_PROOF, Buffer.from(token, 'utf8'));
  return crypto.sign(null, msg, privObj(seedFromPrivateKey(b64))).toString('base64url');
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
const PROOF = '_xyI6J0jruF9VJx5RZimoWtBtrH_7lFTueCgCdeSllnwDcTP5bxCQ9ponOj9OZSbidfO-89TiuC8QYwKBYmlDw';
// The signing input the proof covers, as hex: 8-byte length || context || token.
const PROOF_INPUT_HEX = '000000000000001773616e61642f696e7374616e63652d70726f6f662f7631746573742d7072696e636970616c2d746f6b656e';
const CRED = '{"AgentID":"agent-1","PublicKey":"3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29","IssuedAt":"2026-07-10T00:00:00Z","NotAfter":"2026-07-10T01:00:00Z","KeyID":"ca-1","Signature":"AA=="}';
const CRED_HEADER = 'eyJBZ2VudElEIjoiYWdlbnQtMSIsIlB1YmxpY0tleSI6IjNiNmEyN2JjY2ViNmE0MmQ2MmEzYThkMDJhNmYwZDczNjUzMjE1NzcxZGUyNDNhNjNhYzA0OGExOGI1OWRhMjkiLCJJc3N1ZWRBdCI6IjIwMjYtMDctMTBUMDA6MDA6MDBaIiwiTm90QWZ0ZXIiOiIyMDI2LTA3LTEwVDAxOjAwOjAwWiIsIktleUlEIjoiY2EtMSIsIlNpZ25hdHVyZSI6IkFBPT0ifQ';
const NONCE = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8';
const EVIDENCE = 'umfR1kxOzPGX1ZFOK5pgnnRtnxSm-q3nE-Qx6DPsI1o';

const results = [
  ['publicKeyOf(seed)', publicKeyOf(SEED), PUB],
  ['64-byte form b64url', Buffer.concat([Buffer.from(SEED, 'base64url'), Buffer.from(PUB, 'base64url')]).toString('base64url'), FULL],
  ['publicKeyOf(64-byte form)', publicKeyOf(FULL), PUB],
  ['sigctxMessage(instance-proof, token)', sigctxMessage(CTX_INSTANCE_PROOF, Buffer.from('test-principal-token', 'utf8')).toString('hex'), PROOF_INPUT_HEX],
  ['proof(seed, "test-principal-token")', proof(SEED, 'test-principal-token'), PROOF],
  ['proof(64-byte form) == proof(seed)', proof(FULL, 'test-principal-token'), PROOF],
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
