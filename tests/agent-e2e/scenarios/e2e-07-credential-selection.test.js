'use strict';
const { scenario, assert } = require('../lib/scenario');
const { authenticate, policyEvents, assertVerifiedAssertion, assertInterceptionActive, assertAgentAllowed } = require('../lib/helpers');

const sleep = ms => new Promise(r => setTimeout(r, ms));
// "newest" compares creation timestamps (whole seconds, ties broken by credential id), so ordering is made
// explicit instead of assumed: wait just until the next wall-clock second after alice was created, then
// assert the RP-side registration times really are in different seconds.
const untilNextSecondAfter = async t => { const target = (Math.floor(t / 1000) + 1) * 1000 + 50; while (Date.now() < target) await sleep(target - Date.now()); };

// Catalogue: multi-account RP with `single` / `newest` / `credential:<ref>`: deterministic selection;
// `single` errors on ambiguity. Authentication is discoverable (no username, no allowCredentials), so the
// daemon's selection policy decides.
scenario({ id: 'E2E-07', exposeModes: ['port', 'pipe'], title: 'multi-account RP: single / newest / credential:<ref> selection' }, async ctx => {
  const rule = [{ rp: 'rp-a.test', authenticate: 'allow', register: 'deny' }];
  const stack = await ctx.stack({
    rps: { a: { host: 'rp-a.test' } },
    profiles: { single: { mode: 'same-user', rules: rule } },
  });
  const rp = stack.rp.a;
  await stack.seedHuman(rp, 'alice');
  await untilNextSecondAfter(Date.now());
  await stack.seedHuman(rp, 'bob');
  const [aliceReg, bobReg] = rp.registrations.filter(r => r.ok);
  assert.equal(aliceReg.username, 'alice');
  assert.ok(Math.floor(bobReg.ts / 1000) > Math.floor(aliceReg.ts / 1000), 'bob must be created in a later second than alice');

  // A credential reference only exists once the credential does, so the pinned profile is added by restart.
  const { credentials } = await stack.daemon.adminJson('credential', 'list');
  const aliceRef = credentials.find(c => c.user_name === 'alice').credential_ref;
  await stack.restartDaemon({
    single: { mode: 'same-user', credential_selection: 'single', rules: rule },
    newest: { mode: 'same-user', credential_selection: 'newest', rules: rule },
    pinned: { mode: 'same-user', credential_selection: `credential:${aliceRef}`, rules: rule },
  });

  const discoverable = async profile => {
    const b = await stack.open(profile, `${rp.origin}/sw`);
    assertInterceptionActive(b);
    return { b, res: await authenticate(b.page, { timeout: 20000 }) };
  };

  // single: two eligible credentials -> must fail closed.
  const before = rp.authentications.length;
  const single = await discoverable('single');
  assert.equal(single.res.ok, false, `single must fail on ambiguity: ${JSON.stringify(single.res)}`);
  assert.equal(single.res.name, 'NotAllowedError');
  assert.equal(rp.authentications.length, before, 'no assertion may reach the RP on ambiguity');

  // newest: bob, every time.
  const newest = await discoverable('newest');
  assertVerifiedAssertion(rp, newest.res, { username: 'bob' });
  assertVerifiedAssertion(rp, await authenticate(newest.b.page, { timeout: 20000 }), { username: 'bob' });

  // credential:<ref> pinned to alice.
  const pinned = await discoverable('pinned');
  assertVerifiedAssertion(rp, pinned.res, { username: 'alice' });

  const audit = await stack.daemon.audit();
  assert.ok(policyEvents(audit, 'policy.deny').some(e => e.profile_id === 'single' && e.action === 'authenticate'), 'single: ambiguity must be an audited deny');
  await assertAgentAllowed(stack, { profile: 'newest', rpId: 'rp-a.test', n: 2 });
  await assertAgentAllowed(stack, { profile: 'pinned', rpId: 'rp-a.test', n: 1 });
});
