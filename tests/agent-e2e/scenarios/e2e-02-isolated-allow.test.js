'use strict';
const { scenario, assert } = require('../lib/scenario');
const { authenticate, policyEvents, assertVerifiedAssertion, assertInterceptionActive, assertNoNotification } = require('../lib/helpers');

// Catalogue: isolated `allow`: register then authenticate. The credential lands in the profile store, not in the human
// store. Both ceremonies go through @simplewebauthn/browser and are verified by @simplewebauthn/server, so a bad
// COSE_Key or attestation object (defect B3) or a response the page cannot consume fails here.
scenario({ id: 'E2E-02', title: 'isolated allow: register then authenticate', ci: true }, async ctx => {
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
  assert.equal(reg.origin, rp.origin, 'origin in the verified clientDataJSON');
  assert.equal(reg.flags.uv, true, 'UV flag in the verified registration');
  assert.equal(stack.daemon.profileStore('iso').length, 1, 'credential must be in the isolated profile store');

  const auth = await authenticate(b.page, { username: 'carol' });
  assertVerifiedAssertion(rp, auth, { username: 'carol' });
  assert.equal(auth.credentialId, reg.credentialId, 'the new credential authenticates');

  assert.equal(stack.daemon.profileStore('iso').length, 1, 'still exactly one credential in the isolated profile store');
  assert.deepEqual(stack.daemon.humanStore(), humanBefore, 'the human store must be untouched');

  const audit = await stack.daemon.audit();
  assert.equal(policyEvents(audit, 'policy.allow').filter(e => e.action === 'register' && e.profile_id === 'iso').length, 1, 'register allowed in audit');
  assert.equal(policyEvents(audit, 'policy.allow').filter(e => e.action === 'authenticate' && e.profile_id === 'iso').length, 1, 'authenticate allowed in audit');
  assert.equal(policyEvents(audit, 'policy.deny').length, 0, 'nothing denied');
  assertNoNotification(stack);
});
