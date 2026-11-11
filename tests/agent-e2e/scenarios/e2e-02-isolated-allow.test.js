'use strict';
const { scenario, assert } = require('../lib/scenario');
const { authenticate, policyEvents, assertVerifiedAssertion, assertInterceptionActive, assertNoNotification } = require('../lib/helpers');

// Catalogue: isolated `allow`: register then authenticate. The credential lands in the profile store,
// not in the human store.
//
// P3 removed the minted enrollment grant (registration is authorised by `register = "allow"` alone) and fixed the
// COSE_Key in the attested credential data (unit-tested in register.rs). What still fails is only the page-facing
// half: the extension rejects the daemon's `/register` response shape (it requires `create_attestation_result`)
// and the page sees NotAllowedError although the credential was created. That is P6. The scenario therefore proves
// the daemon side first (credential in the profile store, human store untouched, audited allow) and only then
// raises the one error the xfail matches, so any other failure stays a FAIL.
const EXTENSION_SHAPE = 'extension rejected the daemon /register response shape (P6)';
scenario({
  id: 'E2E-02', title: 'isolated allow: register then authenticate', ci: true,
  xfailUntil: 'P6', xfailMatch: /extension rejected the daemon \/register response shape/,
  xfailReason: 'the extension rejects the /register response shape (needs create_attestation_result); daemon side is complete',
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
  if (!reg.ok) {
    // Daemon side must be complete before the page-side failure is accepted as the known P6 gap.
    assert.equal(reg.name, 'NotAllowedError', `registration failed unexpectedly: ${JSON.stringify(reg)}`);
    assert.equal(stack.daemon.profileStore('iso').length, 1, `the daemon must have created the credential: ${JSON.stringify(reg)}`);
    assert.deepEqual(stack.daemon.humanStore(), humanBefore, 'the human store must be untouched');
    const early = await stack.daemon.audit();
    assert.ok(policyEvents(early, 'policy.allow').some(e => e.action === 'register' && e.profile_id === 'iso'), 'register allowed in audit');
    assert.equal(policyEvents(early, 'policy.deny').length, 0, 'no denial: the failure is only the response shape');
    assert.fail(EXTENSION_SHAPE);
  }
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
