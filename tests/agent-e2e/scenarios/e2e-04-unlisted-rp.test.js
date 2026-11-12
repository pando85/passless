'use strict';
const { scenario, assert } = require('../lib/scenario');
const { authenticate, policyEvents, storeFingerprint, assertInterceptionActive, assertNoNotification } = require('../lib/helpers');

// Catalogue: unlisted RP, no wildcard: NotAllowedError, no prompt.
scenario({ id: 'E2E-04', exposeModes: ['port', 'pipe'], title: 'unlisted RP without wildcard: NotAllowedError, no prompt', ci: true }, async ctx => {
  const stack = await ctx.stack({
    rps: { a: { host: 'rp-a.test' }, b: { host: 'rp-b.test' } },
    // Only rp-a is listed. rp-b has a credential in the human store but no rule.
    profiles: { agent: { mode: 'same-user', rules: [{ rp: 'rp-a.test', authenticate: 'allow', register: 'deny' }] } },
  });
  const rpB = stack.rp.b;
  await stack.seedHuman(rpB, 'alice');
  const storeBefore = storeFingerprint(stack.daemon);

  const b = await stack.open('agent', `${rpB.origin}/sw`, { startUrl: false }); // an unlisted RP is no admissible start URL
  assertInterceptionActive(b);
  const res = await authenticate(b.page, { username: 'alice' });

  assert.equal(res.ok, false, `unlisted RP must not authenticate: ${JSON.stringify(res)}`);
  assert.equal(res.name, 'NotAllowedError');
  assert.equal(rpB.authentications.length, 0, 'the unlisted RP must never receive an assertion');
  assert.equal(storeFingerprint(stack.daemon), storeBefore, 'no key use');
  assertNoNotification(stack);
  const audit = await stack.daemon.audit();
  assert.equal(policyEvents(audit, 'policy.allow').length, 0, 'nothing may be allowed for an unlisted RP');
  // The request must have reached the daemon and been denied there (not merely failed in the page).
  const denies = policyEvents(audit, 'policy.deny').filter(e => e.profile_id === 'agent' && e.action === 'authenticate' && e.rp_id === 'rp-b.test');
  assert.equal(denies.length, 1, `expected one audited deny for rp-b.test, audit: ${JSON.stringify(audit.map(e => e.event.kind))}`);
});
