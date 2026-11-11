'use strict';
const { scenario, assert } = require('../lib/scenario');
const { assertInterceptionActive } = require('../lib/helpers');

// Catalogue: page `timeout` 3 min with no approval: the ceremony fails at about 3 min (Chromium clamps the page timeout
// to at least 3 min) and the escalation notification is withdrawn. Escalation arrives in P7; until then a `request`
// rule is denied at once (`escalation_unavailable`), which is what the xfail matches.
const PAGE_TIMEOUT_MS = 180000;

scenario({
  id: 'E2E-21', title: 'page timeout 3 min without approval: fails at about 3 min, notification withdrawn',
  xfailUntil: 'P7', xfailMatch: /escalation is not pending/, xfailReason: 'escalation (request rules) arrives in P7; until then a request rule is denied immediately',
  timeoutMs: 360000,
}, async ctx => {
  const stack = await ctx.stack({
    rps: { a: { host: 'rp-a.test' } },
    profiles: { agent: { mode: 'same-user', rules: [{ rp: 'rp-a.test', authenticate: 'request', register: 'deny' }] } },
  });
  const rp = stack.rp.a;
  await stack.seedHuman(rp, 'alice');
  const b = await stack.open('agent', `${rp.origin}/raw`);
  assertInterceptionActive(b);
  await b.page.waitForFunction(() => window.e2e);
  const key = await b.page.evaluate(t => window.e2e.start('authenticate', { username: 'alice', timeout: t }), PAGE_TIMEOUT_MS);
  await new Promise(r => setTimeout(r, 5000));
  let peek = await b.page.evaluate(k => window.e2e.peek(k), key);
  if (peek.settled) throw new Error(`escalation is not pending: the ceremony settled after ${peek.elapsedMs} ms with ${JSON.stringify(peek.result)}`);
  assert.ok(await stack.notify.waitForNotify(1), 'an escalation notification is shown');
  const res = await b.page.evaluate(k => window.e2e.result(k), key);
  peek = await b.page.evaluate(k => window.e2e.peek(k), key);
  assert.equal(res.ok, false);
  assert.equal(res.name, 'NotAllowedError');
  assert.ok(peek.elapsedMs >= 170000 && peek.elapsedMs <= 200000, `fails at about 3 min (${peek.elapsedMs} ms)`);
  assert.ok(stack.notify.closes().length >= 1, 'the notification is withdrawn');
  assert.equal(rp.authentications.length, 0);
});
