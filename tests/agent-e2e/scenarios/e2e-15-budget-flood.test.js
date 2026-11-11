'use strict';
const { scenario, assert } = require('../lib/scenario');
const { authenticate, policyEvents, storeFingerprint, assertVerifiedAssertion, assertInterceptionActive, assertNoNotification } = require('../lib/helpers');

const MAX_OPERATIONS = 3;
const FLOOD = 10;

// Catalogue: evil.test floods denied requests; the budget stays intact for rp-a. ADR 0014 section 9 (R4): `max_operations`
// is claimed only by a fresh replay key AFTER origin validation and policy resolution, so rejected requests (here an
// unlisted RP) never consume budget. Once the budget is really used up the daemon answers `operation_budget_exhausted`
// (the page sees NotAllowedError) and signs nothing.
scenario({ id: 'E2E-15', title: 'Budget: evil.test floods denied requests', ci: true }, async ctx => {
  const stack = await ctx.stack({
    rps: { a: { host: 'rp-a.test' }, evil: { host: 'evil.test' } },
    // Only rp-a.test is listed; evil.test resolves to no rule (default deny).
    profiles: { agent: { mode: 'same-user', max_operations: MAX_OPERATIONS, rules: [{ rp: 'rp-a.test', authenticate: 'allow', register: 'deny' }] } },
  });
  const rp = stack.rp.a;
  const evil = stack.rp.evil;
  await stack.seedHuman(rp, 'alice');
  const storeSeeded = storeFingerprint(stack.daemon);

  // Flood from evil.test, in the same browser (same bearer session) that is used for rp-a afterwards.
  const b = await stack.open('agent', `${evil.origin}/raw`);
  assertInterceptionActive(b);
  for (let i = 0; i < FLOOD; i++) {
    const res = await authenticate(b.page, { timeout: 20000 }); // each call gets fresh options (a new challenge) with rpId evil.test
    assert.equal(res.ok, false, `flood request ${i} must not succeed: ${JSON.stringify(res)}`);
    assert.equal(res.name, 'NotAllowedError', `flood request ${i}: ${JSON.stringify(res)}`);
  }
  assert.equal(evil.authentications.length, 0, 'evil.test must never receive an assertion');
  assert.equal(storeFingerprint(stack.daemon), storeSeeded, 'no key use for the flood');

  // The budget is intact: exactly max_operations successful authentications at rp-a, each verified by the RP.
  await b.page.goto(`${rp.origin}/sw`);
  assertInterceptionActive({ ...b, injected: await b.page.evaluate(() => document.documentElement.hasAttribute('data-passless-agent-broker')) });
  let last;
  for (let i = 1; i <= MAX_OPERATIONS; i++) {
    last = assertVerifiedAssertion(rp, await authenticate(b.page, { username: 'alice' }), { username: 'alice' });
    assert.equal(rp.authentications.length, i);
  }
  const storeAtBudget = storeFingerprint(stack.daemon);
  assert.notEqual(storeAtBudget, storeSeeded, 'the successful ceremonies signed');

  // One more with a new challenge: budget exhausted. NotAllowedError, no signature, nothing reaches the RP.
  const over = await authenticate(b.page, { username: 'alice' });
  assert.equal(over.ok, false, `over-budget ceremony must not succeed: ${JSON.stringify(over)}`);
  assert.equal(over.name, 'NotAllowedError');
  assert.equal(rp.authentications.length, MAX_OPERATIONS, 'the RP must see no authentication beyond the budget');
  assert.equal(rp.lastAuth().counter, last.counter, 'no further counter movement at the RP');
  assert.equal(storeFingerprint(stack.daemon), storeAtBudget, 'no signature: store (incl. counters) unchanged');
  assertNoNotification(stack);

  const audit = await stack.daemon.audit();
  const denies = policyEvents(audit, 'policy.deny').filter(e => e.profile_id === 'agent' && e.action === 'authenticate');
  const evilDenies = denies.filter(e => e.rp_id === 'evil.test');
  assert.equal(evilDenies.length, FLOOD, `one policy.deny per flood request, denies: ${JSON.stringify(denies)}`);
  const budgetDenies = denies.filter(e => e.rp_id === 'rp-a.test');
  assert.equal(budgetDenies.length, 1, `exactly one deny at rp-a.test, denies: ${JSON.stringify(denies)}`);
  assert.equal(budgetDenies[0].reason, 'budget_exhausted', 'the over-budget ceremony is denied for the budget');
  for (const e of evilDenies) assert.notEqual(e.reason, 'budget_exhausted', 'a flood request must be rejected before it claims budget');
  const allows = policyEvents(audit, 'policy.allow').filter(e => e.profile_id === 'agent' && e.action === 'authenticate' && e.rp_id === 'rp-a.test');
  assert.equal(allows.length, MAX_OPERATIONS, 'one policy.allow per budgeted ceremony');
  assert.equal(policyEvents(audit, 'policy.allow').length, MAX_OPERATIONS, 'nothing else may be allowed');
});
