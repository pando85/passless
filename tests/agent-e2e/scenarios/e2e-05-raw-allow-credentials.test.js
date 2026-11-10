'use strict';
const { scenario, assert } = require('../lib/scenario');
const { assertVerifiedAssertion, assertInterceptionActive, assertAgentAllowed } = require('../lib/helpers');

// Catalogue: raw navigator.credentials page with `allowCredentials`: the correct credential is selected.
scenario({ id: 'E2E-05', title: 'raw navigator.credentials page with allowCredentials selects the right credential' }, async ctx => {
  const stack = await ctx.stack({
    rps: { a: { host: 'rp-a.test' } },
    profiles: { agent: { mode: 'same-user', rules: [{ rp: 'rp-a.test', authenticate: 'allow', register: 'deny' }] } },
  });
  const rp = stack.rp.a;
  await stack.seedHuman(rp, 'alice');
  await stack.seedHuman(rp, 'bob');
  const bobId = rp.credentialsOf('bob')[0];
  const aliceId = rp.credentialsOf('alice')[0];
  assert.ok(bobId && aliceId && bobId !== aliceId);

  const b = await stack.open('agent', `${rp.origin}/raw`);
  assertInterceptionActive(b);
  await b.page.waitForFunction(() => window.e2e);

  for (const [name, id] of [['bob', bobId], ['alice', aliceId]]) {
    const res = await b.page.evaluate(o => window.e2e.authenticate(o), { allowCredentials: [id], timeout: 20000 });
    const ev = assertVerifiedAssertion(rp, res, { username: name });
    assert.equal(ev.credentialId, id, `assertion must be made with ${name}'s credential`);
    assert.equal(res.received.type, 'public-key');
  }
  await assertAgentAllowed(stack, { rpId: 'rp-a.test', n: 2 });
});
