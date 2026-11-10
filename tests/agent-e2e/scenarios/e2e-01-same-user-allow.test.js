'use strict';
const { scenario, assert } = require('../lib/scenario');
const { authenticate, policyEvents, assertVerifiedAssertion, assertInterceptionActive, assertNoNotification } = require('../lib/helpers');

// Catalogue: same-user `allow`, authenticate at rp-a (SimpleWebAuthn). RP verifies signature, UP=1, UV=1,
// counter increments; audit shows `agent` evidence.
scenario({ id: 'E2E-01', title: 'same-user allow: authenticate at rp-a (SimpleWebAuthn)', ci: true }, async ctx => {
  const stack = await ctx.stack({
    rps: { a: { host: 'rp-a.test' } },
    profiles: { agent: { mode: 'same-user', rules: [{ rp: 'rp-a.test', authenticate: 'allow', register: 'deny' }] } },
  });
  const rp = stack.rp.a;
  await stack.seedHuman(rp, 'alice');

  const b = await stack.open('agent', `${rp.origin}/sw`);
  assertInterceptionActive(b);

  const first = assertVerifiedAssertion(rp, await authenticate(b.page, { username: 'alice' }), { username: 'alice' });
  const second = assertVerifiedAssertion(rp, await authenticate(b.page, { username: 'alice' }), { username: 'alice' });
  assert.ok(second.counter > first.counter, `counter must increase across assertions (${first.counter} -> ${second.counter})`);

  const audit = await stack.daemon.audit();
  const allows = policyEvents(audit, 'policy.allow').filter(e => e.profile_id === 'agent' && e.action === 'authenticate' && e.rp_id === 'rp-a.test');
  assert.equal(allows.length, 2, 'one policy.allow per ceremony');
  for (const e of allows) {
    assert.equal(e.user_presence, 'agent');
    assert.equal(e.user_verification, 'agent');
  }
  assertNoNotification(stack);
});
