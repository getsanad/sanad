/**
 * End-to-end quickstart for @getsanad/sdk.
 *
 * Run directly on Node >= 22.6 (TypeScript types are stripped automatically):
 *
 *     node examples/quickstart.ts
 *
 * With no arguments it runs a self-contained demo against an in-process fake
 * authority + gateway so you can see the full flow without any servers. To point
 * at real services, set the environment variables described below.
 *
 * Real usage:
 *     PASSPORT_AUTHORITY=https://authority.example.com \
 *     PASSPORT_GATEWAY=https://gw.example.com \
 *     PASSPORT_BOOTSTRAP_TOKEN=<your bootstrap token> \
 *     PASSPORT_PRINCIPAL_TOKEN=<your principal bearer token> \
 *     node examples/quickstart.ts
 */
import {
  generateInstanceKey,
  publicKeyOf,
  enroll,
  PassportClient,
} from '../src/index.ts';

async function main(): Promise<void> {
  // 1. Generate (or load) an Ed25519 instance key. `privateKey` is interchangeable
  //    with the file written by `passport keygen`.
  const key = generateInstanceKey();
  console.log('instance public key:', key.publicKey);
  console.log('derived again      :', publicKeyOf(key.privateKey));

  const authorityUrl = process.env.PASSPORT_AUTHORITY;
  const gatewayUrl = process.env.PASSPORT_GATEWAY;
  const bootstrapToken = process.env.PASSPORT_BOOTSTRAP_TOKEN ?? 'demo-bootstrap-token';
  const principalToken = process.env.PASSPORT_PRINCIPAL_TOKEN ?? 'demo-principal-token';

  // Use in-process fakes unless real endpoints are provided.
  const useFakes = !authorityUrl || !gatewayUrl;
  const fakeFetch = useFakes ? makeFakeFetch(key.publicKey) : undefined;

  // 2. Enroll: present the bootstrap token + public key, receive a workload credential.
  const { credential, agentId, notAfter } = await enroll({
    authorityUrl: authorityUrl ?? 'https://authority.local',
    bootstrapToken,
    publicKey: key.publicKey,
    fetch: fakeFetch,
  });
  console.log('enrolled as       :', agentId, '(expires', notAfter + ')');

  // 3. Build a client and make gateway requests. Headers are injected automatically.
  const client = new PassportClient({
    gatewayUrl: gatewayUrl ?? 'https://gw.local',
    instanceKey: key.privateKey,
    credential,
    fetch: fakeFetch,
  });

  const resp = await client.request('demo', '/tools/list', {
    principalToken,
    method: 'POST',
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
    headers: { 'Content-Type': 'application/json' },
  });
  console.log('gateway response  :', resp.status, await resp.text());
}

/**
 * A tiny fake authority+gateway so the example runs with no external services.
 * It is NOT a real Sanad server; it just echoes plausible responses.
 */
function makeFakeFetch(publicKeyB64: string): typeof fetch {
  return (async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    if (url.endsWith('/enroll/nonce')) {
      // First leg of enrollment: the single-use challenge the evidence must cover.
      const nonce = Buffer.alloc(32, 7).toString('base64url');
      return new Response(JSON.stringify({ nonce, expires_in: 120 }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }
    if (url.endsWith('/enroll')) {
      const cred = JSON.stringify({
        AgentID: 'agent-demo',
        PublicKey: Buffer.from(publicKeyB64, 'base64url').toString('hex'),
        IssuedAt: new Date().toISOString(),
        NotAfter: new Date(Date.now() + 3600_000).toISOString(),
        KeyID: 'ca-demo',
        Signature: 'AA==',
      });
      return new Response(cred, { status: 200, headers: { 'Content-Type': 'application/json' } });
    }
    // Gateway: echo back the passport headers it received.
    const headers = new Headers(init?.headers);
    const seen = {
      authorization: headers.get('Authorization'),
      credentialPresent: headers.has('X-Agent-Credential'),
      proofPresent: headers.has('X-Agent-Proof'),
    };
    return new Response(JSON.stringify({ received: seen }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  }) as unknown as typeof fetch;
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
