'use strict';
const { scenario, assert } = require('../lib/scenario');
const { authenticate, policyEvents, storeFingerprint, assertInterceptionActive, assertNoNotification } = require('../lib/helpers');

// Catalogue: `deny` rule: NotAllowedError; no prompt; no key use; audit deny.
scenario({ id: 'E2E-03', title: 'deny rule: NotAllowedError, no prompt, no key use', ci: true }, async ctx => {
  const stack = await ctx.stack({
    rps: { a: { host: 'rp-a.test' } },
    // Baseline finding: a profile whose rules are ALL deny does not start ("invalid policy: allowed_actions
    // must not be empty"), so another RP is allowed to keep the profile valid. rp-a is explicitly denied.
    profiles: { agent: { mode: 'same-user', rules: [
      { rp: 'rp-a.test', authenticate: 'deny', register: 'deny' },
      { rp: 'other.test', authenticate: 'allow', register: 'deny' },
    ] } },
  });
  const rp = stack.rp.a;
  await stack.seedHuman(rp, 'alice'); // a credential exists, so a leak to the human path would succeed
  const storeBefore = storeFingerprint(stack.daemon);
  const assertionsBefore = rp.authentications.length;

  const b = await stack.open('agent', `${rp.origin}/sw`);
  assertInterceptionActive(b);
  const res = await authenticate(b.page, { username: 'alice' });

  assert.equal(res.ok, false, `denied ceremony must not succeed: ${JSON.stringify(res)}`);
  assert.equal(res.name, 'NotAllowedError');
  assert.equal(rp.authentications.length, assertionsBefore, 'the RP must never receive an assertion');
  assert.equal(storeFingerprint(stack.daemon), storeBefore, 'no key use: store (incl. counters) unchanged');
  assertNoNotification(stack);

  const audit = await stack.daemon.audit();
  assert.ok(policyEvents(audit, 'policy.deny').some(e => e.profile_id === 'agent' && e.action === 'authenticate' && e.rp_id === 'rp-a.test'),
    'audit must record the deny');
  assert.equal(policyEvents(audit, 'policy.allow').length, 0);
});
