'use strict';
const { scenario, assert } = require('../lib/scenario');
const { assertInterceptionActive, escalationEvents, grantedRuleEvents, denyReasons, grantsStore, waitFor } = require('../lib/helpers');

// Catalogue: page `timeout` 3 min with nobody answering the notification: the ceremony fails at about 3 min and the
// notification is withdrawn. Chromium clamps the page timeout to at least 3 min and cancels the request at its own deadline
// (the daemon may see the abort a moment before or after its own deadline: an abort within 2 s of the ceremony deadline counts
// as the timeout), so the audit says `escalation.expired` with `reason = timeout` and the page sees NotAllowedError.
const PAGE_TIMEOUT_MS = 180000;

scenario({
  id: 'E2E-21', title: 'page timeout 3 min without approval: fails at about 3 min, notification withdrawn, expired(timeout)',
  timeoutMs: 360000,
}, async ctx => {
  const stack = await ctx.stack({
    rps: { a: { host: 'rp-a.test' } },
    profiles: { agent: { mode: 'same-user', rules: [{ rp: 'rp-a.test', authenticate: 'request', register: 'deny' }] } },
    notify: { script: ['ignore'] },
  });
  const rp = stack.rp.a;
  await stack.seedHuman(rp, 'alice');
  const b = await stack.open('agent', `${rp.origin}/raw`);
  assertInterceptionActive(b);
  await b.page.waitForFunction(() => window.e2e);
  const key = await b.page.evaluate(t => window.e2e.start('authenticate', { username: 'alice', timeout: t }), PAGE_TIMEOUT_MS);
  assert.ok(await stack.notify.waitForNotify(1), 'an escalation notification is shown');
  await new Promise(r => setTimeout(r, 4000));
  let peek = await b.page.evaluate(k => window.e2e.peek(k), key);
  assert.equal(peek.settled, false, `the escalation is pending: ${JSON.stringify(peek.result)}`);

  const res = await b.page.evaluate(k => window.e2e.result(k), key);
  peek = await b.page.evaluate(k => window.e2e.peek(k), key);
  assert.equal(res.ok, false);
  assert.equal(res.name, 'NotAllowedError', JSON.stringify(res));
  assert.ok(peek.elapsedMs >= 170000 && peek.elapsedMs <= 200000, `fails at about 3 min (${peek.elapsedMs} ms)`);
  await waitFor('the notification to be withdrawn', () => stack.notify.closes().length >= 1);
  assert.equal(stack.notify.notifications().length, 1);
  await waitFor('the escalation to expire in the audit', async () => escalationEvents(await stack.daemon.audit(), 'expired').length === 1, { timeoutMs: 15000 });
  const audit = await stack.daemon.audit();
  assert.deepEqual(escalationEvents(audit, 'expired').map(e => e.reason), ['timeout'], JSON.stringify(escalationEvents(audit)));
  assert.equal(escalationEvents(audit, 'approved').length, 0);
  assert.equal(grantedRuleEvents(audit, 'add').length, 0);
  assert.equal(grantsStore(stack).grants.length, 0);
  assert.deepEqual(denyReasons(audit, { rpId: 'rp-a.test' }), ['escalation_expired']);
  assert.equal(rp.authentications.length, 0);
});
