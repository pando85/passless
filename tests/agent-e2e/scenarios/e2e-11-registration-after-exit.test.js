'use strict';
const { scenario, assert } = require('../lib/scenario');
const { policyEvents, extensionEndpoint, postToDaemon, registerRequest, waitFor, assertNoNotification } = require('../lib/helpers');

// Catalogue: registration after browser exit using the old bearer is refused (ADR 0014 §9: browser exit and lease
// revocation revoke both sign and registration bearers; the refusal is audited).
//
// The bearer is the one the managed browser's extension holds. While the browser lives it registers (positive control,
// so the later refusal can only be the revocation); after the browser is killed, the daemon revokes the lease and the
// same bearer must be refused: HTTP 401, no credential created, one audited `policy.deny(reason=bearer_revoked)`.
//
// The profile also carries a legacy `[device]` table: it must be warned about and ignored (R6, B6).
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

  // Positive control: the live bearer registers.
  const live = await postToDaemon(endpoint, '/register', registerRequest(rp, { username: 'dora' }));
  assert.equal(live.status, 200, `a live bearer must register: ${live.status} ${live.body}`);
  assert.equal(stack.daemon.profileStore('iso').length, 1, 'the credential lands in the isolated profile store');

  // The browser exits; wait until the daemon has noticed and revoked the lease.
  stack.env.killTree(b.lease.pid);
  await waitFor('the daemon to record the browser exit', async () =>
    (await stack.daemon.audit()).some(e => (e.event || e).kind === 'browser_lease.crash'));

  const late = await postToDaemon(endpoint, '/register', registerRequest(rp, { username: 'eve' }));
  assert.equal(late.status, 401, `the old bearer must be refused: ${late.status} ${late.body}`);
  assert.equal(stack.daemon.profileStore('iso').length, 1, 'no credential may be created after the exit');
  assert.deepEqual(stack.daemon.humanStore(), humanBefore, 'the human store must be untouched');

  const audit = await stack.daemon.audit();
  const refused = policyEvents(audit, 'policy.deny').filter(e => e.profile_id === 'iso' && e.action === 'register');
  assert.equal(refused.length, 1, `expected one audited registration refusal, audit: ${JSON.stringify(audit.map(e => (e.event || e).kind))}`);
  assert.equal(refused[0].reason, 'bearer_revoked');
  assert.equal(refused[0].rp_id, 'rp-a.test');
  assert.equal(policyEvents(audit, 'policy.allow').filter(e => e.action === 'register').length, 1, 'only the live registration was allowed');
  assertNoNotification(stack);
});
