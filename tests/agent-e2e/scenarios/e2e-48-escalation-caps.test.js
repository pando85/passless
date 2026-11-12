'use strict';
const { scenario, assert } = require('../lib/scenario');
const { denyReasons, escalationEvents, policyEvents, assertVerifiedAssertion, assertInterceptionActive, authenticate } = require('../lib/helpers');
const { requestProfile, start, settle, peek, abort } = require('../lib/escalation');

const HOSTS = ['rp-a.test', 'rp-b.test', 'rp-c.test', 'rp-d.test', 'rp-e.test'];
const rps = Object.fromEntries('abcde'.split('').map(c => [c, { host: `rp-${c}.test` }]));

// Escalation waiters are capped per bearer session (4), per profile (16) and globally (64). Parked ceremonies hold no request
// slots, so these are the limits that apply. Five RPs in one browser (one bearer session): the first four park, the fifth is
// refused `escalation_waiter_cap` before any prompt, and a second profile (its own session, its own prompt queue and a plain
// `allow` rule) is unaffected.
scenario({ id: 'E2E-48', exposeModes: ['port', 'pipe'], title: 'five RPs in one session: the fifth is denied escalation_waiter_cap while another profile still works', ci: true }, async ctx => {
  const stack = await ctx.stack({
    rps,
    profiles: {
      agent: requestProfile(HOSTS),
      other: { mode: 'same-user', rules: [{ rp: 'rp-a.test', authenticate: 'allow', register: 'deny' }] },
    },
    notify: { script: ['ignore'] },
  });
  for (const c of 'abcde') await stack.seedHuman(stack.rp[c], 'alice');

  const b = await stack.open('agent', `${stack.rp.a.origin}/raw`);
  assertInterceptionActive(b);
  const pages = [b.page];
  for (const c of 'bcde') {
    const p = await b.context.newPage();
    await p.goto(`${stack.rp[c].origin}/raw`);
    pages.push(p);
  }

  // Four escalations park (a ceremony is one waiter; the first one shows its prompt, the others queue behind it).
  const keys = [];
  for (let i = 0; i < 4; i++) keys.push(await start(pages[i], 'authenticate', { username: 'alice' }));
  assert.ok(await stack.notify.waitForNotify(1), 'the first escalation prompts');
  for (let i = 0; i < 4; i++) assert.equal((await peek(pages[i], keys[i])).settled, false, `escalation ${i + 1} is parked`);
  assert.equal(stack.notify.notifications().length, 1, 'one prompt at a time: the other three wait in the queue');

  // The fifth is refused at once, without a prompt.
  const fifth = await settle(pages[4], await start(pages[4], 'authenticate', { username: 'alice' }));
  assert.equal(fifth.ok, false, JSON.stringify(fifth));
  assert.equal(fifth.name, 'NotAllowedError');
  assert.deepEqual(denyReasons(await stack.daemon.audit(), { rpId: 'rp-e.test' }), ['escalation_waiter_cap']);
  assert.equal(stack.notify.notifications().length, 1, 'a refused request does not prompt');

  // The other profile has its own session: its allow ceremony succeeds while four escalations are parked.
  const other = await stack.open('other', `${stack.rp.a.origin}/sw`);
  assertInterceptionActive(other);
  assertVerifiedAssertion(stack.rp.a, await authenticate(other.page, { username: 'alice' }), { username: 'alice' });
  const audit = await stack.daemon.audit();
  assert.equal(policyEvents(audit, 'policy.allow').filter(e => e.profile_id === 'other').length, 1);
  for (let i = 0; i < 4; i++) assert.equal((await peek(pages[i], keys[i])).settled, false, `escalation ${i + 1} is still parked`);

  for (let i = 0; i < 4; i++) { await abort(pages[i], keys[i]); assert.equal((await settle(pages[i], keys[i])).name, 'AbortError'); }
  assert.equal(escalationEvents(await stack.daemon.audit(), 'approved').length, 0);
});
