'use strict';
const { scenario, assert } = require('../lib/scenario');
const { authenticate, assertVerifiedAssertion, assertInterceptionActive, assertAgentAllowed, waitFor, TRANSPORT_LOG, logMatches, HUMAN_CTAP_LOG } = require('../lib/helpers');
const { stopExtensionWorker, extensionWorkerTargets } = require('../lib/browser');

// Catalogue: the service worker is stopped between requests (CDP `Target.closeTarget` on the worker target, plan V-L6;
// the way Chromium stops an idle worker). Its native port closes, so the relay exits and the daemon sees the connection
// end. The next request wakes the worker (its proxy listeners are registered synchronously at top level and the
// attachment is browser-side state, spike Q2): it says hello again on a new connection and the ceremony succeeds.
scenario({ id: 'E2E-18', title: 'worker stopped between requests: the next request wakes it, reconnects and succeeds' }, async ctx => {
  const stack = await ctx.stack({
    rps: { a: { host: 'rp-a.test' } },
    profiles: { agent: { mode: 'same-user', rules: [{ rp: 'rp-a.test', authenticate: 'allow', register: 'deny' }] } },
  });
  const rp = stack.rp.a;
  await stack.seedHuman(rp, 'alice');
  const b = await stack.open('agent', `${rp.origin}/raw`);
  assertInterceptionActive(b);
  const logBefore = stack.daemon.log().length;

  assertVerifiedAssertion(rp, await authenticate(b.page, { username: 'alice' }), { username: 'alice' });
  const hellos = () => logMatches(stack.daemon.log(), TRANSPORT_LOG.hello);
  assert.equal(hellos().length, 1, 'one worker connection so far');

  await stopExtensionWorker(b.browser);
  await waitFor('the daemon to see the worker connection close', () => logMatches(stack.daemon.log(), TRANSPORT_LOG.closed).length >= 1);
  assert.deepEqual(await extensionWorkerTargets(b.browser), [], 'the worker is stopped');

  assertVerifiedAssertion(rp, await authenticate(b.page, { username: 'alice' }), { username: 'alice' });
  const workers = await extensionWorkerTargets(b.browser);
  assert.equal(workers.length, 1, 'the request woke the worker');
  // (Chromium keeps the worker's target ID across a restart, so the new instance shows in the daemon's hellos.)
  assert.deepEqual(hellos().map(h => h[1]), ['true', 'true'], 'the daemon saw a second hello (attached) from the new worker instance');
  assert.notEqual(hellos()[0][0], hellos()[1][0], 'on a new connection');

  await assertAgentAllowed(stack, { rpId: 'rp-a.test', n: 2 });
  assert.doesNotMatch(stack.daemon.log().slice(logBefore), HUMAN_CTAP_LOG, 'the human authenticator handled a request');
});
