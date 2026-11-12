'use strict';
const { scenario, assert } = require('../lib/scenario');
const { authenticate, policyEvents, storeFingerprint, assertVerifiedAssertion, assertInterceptionActive, assertNoNotification } = require('../lib/helpers');
const { parseAuthData } = require('../lib/rp-server');

// Catalogue: replay, page resubmits identical options (Kanidm pattern). ADR 0014 section 9: per bearer session the
// replay key is SHA-256(action | rp_id | origin | top_origin | challenge). An identical request never signs twice:
// a duplicate in flight joins the first; after completion it gets the original result for 120 s.
scenario({ id: 'E2E-14', exposeModes: ['port', 'pipe'], title: 'Replay: page resubmits identical options (Kanidm pattern)', ci: true }, async ctx => {
  const stack = await ctx.stack({
    rps: { a: { host: 'rp-a.test' } },
    profiles: { agent: { mode: 'same-user', rules: [{ rp: 'rp-a.test', authenticate: 'allow', register: 'deny' }] } },
  });
  const rp = stack.rp.a;
  await stack.seedHuman(rp, 'alice');
  const seededCounter = rp.users.get('alice').credentials[0].counter;
  const storeSeeded = storeFingerprint(stack.daemon);

  const b = await stack.open('agent', `${rp.origin}/raw`); // raw navigator.credentials page
  assertInterceptionActive(b);
  await b.page.waitForFunction(() => window.e2e, null, { timeout: 15000 });

  // One set of options (one challenge), used for every call below.
  const options = await b.page.evaluate(o => window.e2e.authOptions(o), { username: 'alice', userVerification: 'preferred', timeout: 20000 });
  assert.ok(options.challenge, 'RP issued options');

  // (a) two identical calls started together, from two tabs of the same origin (Chromium allows one pending WebAuthn
  // request per tab: a second one in the same tab fails with OperationError "A request is already pending").
  const twin = await b.context.newPage();
  await twin.goto(`${rp.origin}/raw`);
  await twin.waitForFunction(() => window.e2e, null, { timeout: 15000 });
  await b.page.bringToFront();
  const concurrent = (await Promise.all([b.page, twin].map(p => p.evaluate(o => window.e2e.getIdentical(o, { count: 1 }), options)))).flat();
  assert.equal(concurrent.length, 2);
  for (const r of concurrent) assert.equal(r.ok, true, `concurrent duplicate failed: ${JSON.stringify(r)}`);
  const storeAfterConcurrent = storeFingerprint(stack.daemon);
  assert.notEqual(storeAfterConcurrent, storeSeeded, 'the first request must have signed (store counter changed)');
  const first = concurrent[0].json;
  assert.deepEqual(concurrent[1].json, first, 'concurrent duplicate must receive the same result as the first call');
  const counterAfterFirst = parseAuthData(Buffer.from(first.response.authenticatorData, 'base64url')).counter;
  assert.equal(counterAfterFirst, seededCounter + 1, `exactly one signature: counter ${seededCounter} -> ${counterAfterFirst}`);

  // (b) once more after both resolved: served from the completed-result cache, byte for byte.
  const later = await b.page.evaluate(o => window.e2e.getIdentical(o, { count: 1 }), options);
  assert.equal(later.length, 1);
  assert.equal(later[0].ok, true, `sequential duplicate failed: ${JSON.stringify(later[0])}`);
  assert.deepEqual(later[0].json, first, 'sequential duplicate must return the original result (credential id, authenticatorData, signature, clientDataJSON)');
  assert.equal(storeFingerprint(stack.daemon), storeAfterConcurrent, 'a duplicate must not sign: store (incl. counters) unchanged');

  // The RP verifies one of the identical results and records exactly one authentication for the challenge.
  const verification = await b.page.evaluate(r => window.e2e.verifyAuth(r), first);
  const ev = assertVerifiedAssertion(rp, verification, { username: 'alice' });
  assert.equal(ev.counter, seededCounter + 1);
  assert.equal(rp.authentications.length, 1, 'the RP records exactly one authentication');

  // Exactly one policy.allow for this ceremony (three calls, one signature).
  let audit = await stack.daemon.audit();
  let allows = policyEvents(audit, 'policy.allow').filter(e => e.profile_id === 'agent' && e.action === 'authenticate' && e.rp_id === 'rp-a.test');
  assert.equal(allows.length, 1, `identical requests must be allowed (and signed) once, got ${allows.length}`);
  assert.equal(policyEvents(audit, 'policy.deny').length, 0, 'a duplicate is not a denial');

  // A fresh ceremony (new challenge) signs again: counter increments by one more.
  const second = assertVerifiedAssertion(rp, await authenticate(b.page, { username: 'alice' }), { username: 'alice' });
  assert.equal(second.counter, seededCounter + 2, 'a fresh ceremony increments the counter once more');
  assert.notEqual(storeFingerprint(stack.daemon), storeAfterConcurrent, 'the fresh ceremony signed');
  assert.equal(rp.authentications.length, 2);

  audit = await stack.daemon.audit();
  allows = policyEvents(audit, 'policy.allow').filter(e => e.profile_id === 'agent' && e.action === 'authenticate' && e.rp_id === 'rp-a.test');
  assert.equal(allows.length, 2, 'one policy.allow per distinct ceremony');
  assertNoNotification(stack);
});
