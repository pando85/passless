'use strict';
const { scenario, assert } = require('../lib/scenario');
const { authenticate, policyEvents, assertVerifiedAssertion, assertInterceptionActive, assertNoNotification } = require('../lib/helpers');

// Catalogue: isolated `allow`: register then authenticate. The credential lands in the profile store,
// not in the human store.
//
// Baseline (today's code) fails in three independent ways, all found by this scenario:
//  1. registration needs an operator-minted one-shot enrollment grant even for `register = allow`
//     (policy.deny reason=grant_not_found)  -> removed in P3
//  2. the daemon's /register answers with a bare credential but worker.js requires
//     `create_attestation_result` (page sees NotAllowedError, credential is stored anyway)  -> P6
//  3. the registration authenticator data holds a raw EC point instead of a COSE key, so a real RP
//     rejects it ("Leftover bytes detected while parsing authenticator data")  -> not in the plan
scenario({
  id: 'E2E-02', title: 'isolated allow: register then authenticate', ci: true,
  xfailUntil: 'P6', xfailMatch: /registration failed:.*NotAllowedError/s, xfailReason: 'registration needs a minted grant, extension rejects the /register response shape, and daemon emits an invalid COSE key',
}, async ctx => {
  const stack = await ctx.stack({
    rps: { a: { host: 'rp-a.test' } },
    profiles: { iso: { mode: 'isolated', rules: [{ rp: 'rp-a.test', register: 'allow', authenticate: 'allow' }] } },
  });
  const rp = stack.rp.a;
  const humanBefore = stack.daemon.humanStore();

  const b = await stack.open('iso', `${rp.origin}/sw`);
  assertInterceptionActive(b);

  await b.page.waitForFunction(() => window.e2e);
  const reg = await b.page.evaluate(() => window.e2e.register({ username: 'carol', userVerification: 'preferred', timeout: 20000 }));
  assert.equal(reg.ok, true, `registration failed: ${JSON.stringify(reg)}`);
  assert.equal(reg.rpIdHashOk, true);

  const auth = await authenticate(b.page, { username: 'carol' });
  assertVerifiedAssertion(rp, auth, { username: 'carol' });

  assert.equal(stack.daemon.profileStore('iso').length, 1, 'credential must be in the isolated profile store');
  assert.deepEqual(stack.daemon.humanStore(), humanBefore, 'the human store must be untouched');

  const audit = await stack.daemon.audit();
  assert.ok(policyEvents(audit, 'policy.allow').some(e => e.action === 'register' && e.profile_id === 'iso'), 'register allowed in audit');
  assert.ok(policyEvents(audit, 'policy.allow').some(e => e.action === 'authenticate' && e.profile_id === 'iso'), 'authenticate allowed in audit');
  assertNoNotification(stack);
});
