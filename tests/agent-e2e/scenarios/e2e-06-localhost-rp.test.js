'use strict';
const { scenario, assert } = require('../lib/scenario');
const { authenticate, assertVerifiedAssertion, assertInterceptionActive, assertAgentAllowed, extensionEndpoint, FramedClient, signRequest, waitFor, TRANSPORT_LOG, logMatches } = require('../lib/helpers');
const { stopExtensionWorker } = require('../lib/browser');

// Catalogue: an `http://localhost` RP works (R15: exact `localhost` rules accept `http://localhost[:port]` origins).
//
// Step 1 (daemon only): a `get` sent straight to the sign socket over the wire protocol, with the extension's own
// bearer, is signed for rp_id `localhost` / origin `http://localhost:<port>`. The worker is stopped first: the daemon
// keeps one connection per bearer, so a live worker and this client would supersede each other.
// Step 2 (page): the full path. The page's request wakes the stopped worker (plan D1), which reconnects and relays it.
scenario({ id: 'E2E-06', title: 'http://localhost RP works', ci: true }, async ctx => {
  const stack = await ctx.stack({
    rps: { local: { host: 'localhost' } },
    profiles: { agent: { mode: 'same-user', rules: [{ rp: 'localhost', authenticate: 'allow', register: 'deny' }] } },
  });
  const rp = stack.rp.local;
  await stack.seedHuman(rp, 'alice');
  const b = await stack.open('agent', `${rp.origin}/sw`);
  assertInterceptionActive(b);

  // Step 1.
  const endpoint = await extensionEndpoint(b);
  await stopExtensionWorker(b.browser);
  await waitFor('the daemon to see the worker connection close', () => logMatches(stack.daemon.log(), TRANSPORT_LOG.closed).length >= 1);
  const client = await FramedClient.connect(endpoint.socketPath);
  try {
    const ack = await client.hello(endpoint);
    assert.equal(ack.type, 'hello', `hello refused: ${JSON.stringify(ack)}`);
    const result = await client.request(1, 'get', signRequest({ origin: rp.origin, rpId: 'localhost' }));
    assert.equal(result.ok, true, `the daemon must sign for rp_id localhost / origin ${rp.origin}: ${JSON.stringify(result)}`);
    const credential = JSON.parse(result.body);
    const authData = Buffer.from(credential.response.authenticatorData, 'base64url');
    assert.equal(authData[32] & 0x05, 0x05, 'agent evidence: UP and UV are set');
    const clientData = JSON.parse(Buffer.from(credential.response.clientDataJSON, 'base64url').toString('utf8'));
    assert.equal(clientData.origin, rp.origin, 'the daemon builds clientDataJSON with the browser-supplied origin');
    assert.equal(clientData.type, 'webauthn.get');
  } finally { client.close(); }
  await assertAgentAllowed(stack, { rpId: 'localhost', n: 1 });

  // Step 2.
  const res = await authenticate(b.page, { username: 'alice' });
  assertVerifiedAssertion(rp, res, { username: 'alice' });
  await assertAgentAllowed(stack, { rpId: 'localhost', n: 2 });
});
