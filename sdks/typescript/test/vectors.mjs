// Plain-Node (no TypeScript toolchain required) proof that the SDK's crypto/wire
// vectors match the Go implementation byte-for-byte. Run with:  node test/vectors.mjs
//
// This mirrors the logic in src/index.ts using only node:crypto so the fixed vectors
// can be verified in any environment, even without tsc/tsx installed.
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
function proof(b64, token) {
  return crypto.sign(null, Buffer.from(token, 'utf8'), privObj(seedFromPrivateKey(b64))).toString('base64url');
}

const SEED = 'AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA';
const FULL = 'AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyB5tVYuj-ZU-UB4sRLoqYunkB-FOuaVvtfg45ELrQSWZA';
const PUB = 'ebVWLo_mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ';
const PROOF = 'vS7aSzPmJd-D-AEAgbkw6oFU_0KU4rvei6aUlpCbrGn-nGkfVoqrvrV695SwkzT-id_8nXu18uleQye60FhWCQ';
const CRED = '{"AgentID":"agent-1","PublicKey":"3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29","IssuedAt":"2026-07-10T00:00:00Z","NotAfter":"2026-07-10T01:00:00Z","KeyID":"ca-1","Signature":"AA=="}';
const CRED_HEADER = 'eyJBZ2VudElEIjoiYWdlbnQtMSIsIlB1YmxpY0tleSI6IjNiNmEyN2JjY2ViNmE0MmQ2MmEzYThkMDJhNmYwZDczNjUzMjE1NzcxZGUyNDNhNjNhYzA0OGExOGI1OWRhMjkiLCJJc3N1ZWRBdCI6IjIwMjYtMDctMTBUMDA6MDA6MDBaIiwiTm90QWZ0ZXIiOiIyMDI2LTA3LTEwVDAxOjAwOjAwWiIsIktleUlEIjoiY2EtMSIsIlNpZ25hdHVyZSI6IkFBPT0ifQ';

const results = [
  ['publicKeyOf(seed)', publicKeyOf(SEED), PUB],
  ['64-byte form b64url', Buffer.concat([Buffer.from(SEED, 'base64url'), Buffer.from(PUB, 'base64url')]).toString('base64url'), FULL],
  ['publicKeyOf(64-byte form)', publicKeyOf(FULL), PUB],
  ['proof(seed, "test-principal-token")', proof(SEED, 'test-principal-token'), PROOF],
  ['proof(64-byte form) == proof(seed)', proof(FULL, 'test-principal-token'), PROOF],
  ['base64url(utf8(credential))', Buffer.from(CRED, 'utf8').toString('base64url'), CRED_HEADER],
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
