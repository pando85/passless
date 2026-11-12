'use strict';
const { scenario, assert } = require('../lib/scenario');
const { policyEvents, extensionEndpoint, FramedClient, registerRequest, waitFor, assertNoNotification, TRANSPORT_LOG, logMatches } = require('../lib/helpers');
const { stopExtensionWorker } = require('../lib/browser');

// Catalogue: registration after browser exit using the old bearer is refused (ADR 0014 §9: browser exit and lease
// revocation revoke both sign and registration bearers; the refusal is audited).
//
// The bearer is the one the managed browser's extension holds, used over the daemon's wire protocol (hello, then
// request frames). The extension's worker is stopped first so that this client is the bearer's only connection (the
// daemon keeps one per bearer). While the browser lives the bearer registers (positive control, so the later
// refusals can only be the revocation). After the browser is killed and the daemon has revoked the lease:
//   - a `create` on the connection that is still open is answered `unauthorized` (the bearer is re-validated per
//     request; the connection is not dropped) and audited `policy.deny(reason=bearer_revoked, rp_id=rp-a.test)`;
//   - a new connection's `hello` with the old bearer is refused `unauthorized` and closed, and audited
//     `policy.deny(reason=bearer_revoked)` with an unknown RP ID (a hello names none) and the `authenticate` action
//     (the revoked sign bearer is looked up first; the hello names no action).
// No credential is created after the exit.
//
// The profile also carries a legacy `[device]` table: it must be warned about and ignored (R6, B6).
// Port-only: reads the extension's bearer and stops its worker over CDP; the extension worker is hidden from the agent in pipe mode by design (ADR 0014 §4.3, E2E-52).
scenario({ id: 'E2E-11', title: 'registration after browser exit with the old bearer is refused', ci: true }, async ctx => {
  const stack = await ctx.stack({
    rps: { a: { host: 'rp-a.test' } },
    profiles: { iso: { mode: 'isolated', legacyDevice: true, rules: [{ rp: 'rp-a.test', register: 'allow', authenticate: 'deny' }] } },
  });
  const rp = stack.rp.a;
  const humanBefore = stack.daemon.humanStore();

  assert.match(stack.daemon.log(), /\[device\] table is deprecated and ignored/, 'the legacy [device] key must be warned about');

  const b = await stack.open('iso', `${rp.origin}/sw`);
  const endpoint = await extensionEndpoint(b);
  await stopExtensionWorker(b.browser);
  await waitFor('the daemon to see the worker connection close', () => logMatches(stack.daemon.log(), TRANSPORT_LOG.closed).length >= 1);

  const client = await FramedClient.connect(endpoint.socketPath);
  try {
    const ack = await client.hello(endpoint);
    assert.equal(ack.type, 'hello', `the live bearer must be accepted: ${JSON.stringify(ack)}`);

    // Positive control: the live bearer registers.
    const live = await client.request(1, 'create', registerRequest(rp, { username: 'dora' }));
    assert.equal(live.ok, true, `a live bearer must register: ${JSON.stringify(live)}`);
    assert.equal(stack.daemon.profileStore('iso').length, 1, 'the credential lands in the isolated profile store');

    // The browser exits; wait until the daemon has noticed and revoked the lease.
    stack.env.killTree(b.lease.pid);
    await waitFor('the daemon to record the browser exit', async () =>
      (await stack.daemon.audit()).some(e => (e.event || e).kind === 'browser_lease.crash'));

    // The still-open connection: the request is refused, the connection stays.
    const late = await client.request(2, 'create', registerRequest(rp, { username: 'eve' }));
    assert.equal(late.type, 'result', `the refusal must be a result on the open connection: ${JSON.stringify(late)}`);
    assert.equal(late.ok, false, `the old bearer must be refused: ${JSON.stringify(late)}`);
    assert.equal(late.error.code, 'unauthorized', JSON.stringify(late));
    assert.equal(late.error.dom, 'NotAllowedError', JSON.stringify(late));
  } finally { client.close(); }

  // A new connection with the old bearer is refused at hello.
  const again = await FramedClient.connect(endpoint.socketPath);
  try {
    const refused = await again.hello(endpoint);
    assert.deepEqual(refused, { type: 'error', code: 'unauthorized' }, 'a hello with the revoked bearer');
    assert.equal((await again.next(() => false, 5000)).type, 'eof', 'the daemon closes the connection after refusing the hello');
  } finally { again.close(); }

  assert.equal(stack.daemon.profileStore('iso').length, 1, 'no credential may be created after the exit');
  assert.deepEqual(stack.daemon.humanStore(), humanBefore, 'the human store must be untouched');

  const audit = await stack.daemon.audit();
  // A hello names no action: the daemon audits it against the revoked sign bearer (checked first), so it carries
  // `authenticate`; the refused `create` request is audited as `register`.
  const refusals = policyEvents(audit, 'policy.deny').filter(e => e.profile_id === 'iso');
  assert.deepEqual(refusals.map(e => [e.action, e.reason, e.rp_id]),
    [['register', 'bearer_revoked', 'rp-a.test'], ['authenticate', 'bearer_revoked', 'unknown']],
    `expected the request and the hello refusals, audit: ${JSON.stringify(audit.map(e => (e.event || e).kind))}`);
  assert.equal(policyEvents(audit, 'policy.allow').filter(e => e.action === 'register').length, 1, 'only the live registration was allowed');
  assertNoNotification(stack);
});
