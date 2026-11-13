'use strict';
const { scenario, assert } = require('../lib/scenario');
const { policyEvents, escalationEvents, grantedRuleEvents, denyReasons, grantsStore, auditEvents, waitFor, assertInterceptionActive } = require('../lib/helpers');
const { REGISTER_SUMMARY } = require('../lib/escalation');

// ADR 0014 amendment section 2.2 items 4 and 5: the hard cap (`max_wildcard_registrations`) and the daily prompt limit
// (`wildcard_registration_prompts_per_day`), each with a NON-default value so that the scenario cannot pass on a default.
//
//   daily   cap 8 (default 4), 2 prompts per day (default 3): two approved registrations, the third is refused without a
//           prompt, `wildcard_registration_rate`
//   capped  cap 2 (default 4), 6 prompts per day (default 3): two approved registrations, the third is refused without a
//           prompt, `wildcard_registration_cap`; revoking one grant frees a slot, and the next registration prompts and
//           is approved; the one after that is refused again
//
// A grant revocation bumps the global revocation epoch and the daemon terminates every browser, so the `capped` part
// runs last and relaunches its browser after the revoke. The notification script is consumed in arrival order, so it
// lists the five approvals the scenario expects, and the assertions count prompts.
const WILDCARD = { rp: '*', authenticate: 'request', register: 'request' };
const PROFILES = {
  daily: { mode: 'same-user', rules: [WILDCARD], extra: { max_wildcard_registrations: 8, wildcard_registration_prompts_per_day: 2 } },
  capped: { mode: 'same-user', rules: [WILDCARD], extra: { max_wildcard_registrations: 2, wildcard_registration_prompts_per_day: 6 } },
};
const pidAlive = pid => { try { process.kill(pid, 0); return true; } catch (e) { return e.code === 'EPERM'; } };

scenario({ id: 'E2E-60', exposeModes: ['port', 'pipe'], title: 'wildcard registration limits: cap and daily limit refuse without a prompt, revoking a grant frees a cap slot', ci: true, timeoutMs: 360000 }, async ctx => {
  const stack = await ctx.stack({
    rps: Object.fromEntries('abcd'.split('').map(c => [c, { host: `rp-${c}.test` }])),
    profiles: PROFILES,
    notify: { script: Array(5).fill('approve:1500') },
  });
  const rp = Object.fromEntries('abcd'.split('').map(c => [c, stack.rp[c]]));
  const prompts = () => stack.notify.notifications().length;

  /** Register `username` at the RP `key` (`a`, `b`, ...) through browser `b`. */
  async function registerAt(b, key, username) {
    await b.page.goto(`${rp[key].origin}/raw`);
    await b.page.waitForFunction(() => window.e2e);
    return b.page.evaluate(u => window.e2e.register({ username: u, userVerification: 'preferred', timeout: 30000 }), username);
  }
  const grantsOf = async profile => (await stack.daemon.adminJson('grants', 'list', '--profile', profile)).profiles[0].rules;

  // ---- daily: the third prompt of a rolling 24 hours is refused without one.
  const daily = await stack.open('daily', `${rp.a.origin}/raw`);
  assertInterceptionActive(daily);
  assert.equal((await registerAt(daily, 'a', 'dora-a')).ok, true);
  assert.equal((await registerAt(daily, 'b', 'dora-b')).ok, true);
  assert.equal(prompts(), 2);
  const rate = await registerAt(daily, 'c', 'dora-c');
  assert.equal(rate.ok, false, `the third prompt of the day is refused: ${JSON.stringify(rate)}`);
  assert.equal(rate.name, 'NotAllowedError');
  assert.equal(prompts(), 2, 'refused without a prompt');
  assert.equal(rp.c.registrations.filter(r => r.ok).length, 0, 'nothing was created at the refused site');
  assert.equal((await grantsOf('daily')).length, 2, 'two grants, well under the cap of 8');

  // ---- capped: the cap of 2 refuses the third registration; a revoked grant frees a slot.
  let capped = await stack.open('capped', `${rp.a.origin}/raw`);
  assertInterceptionActive(capped);
  assert.equal((await registerAt(capped, 'a', 'cass-a')).ok, true);
  assert.equal((await registerAt(capped, 'b', 'cass-b')).ok, true);
  assert.equal(prompts(), 4);
  const full = await registerAt(capped, 'c', 'cass-c');
  assert.equal(full.ok, false, `at the cap the registration is refused: ${JSON.stringify(full)}`);
  assert.equal(full.name, 'NotAllowedError');
  assert.equal(prompts(), 4, 'refused without a prompt');
  assert.equal(rp.c.registrations.filter(r => r.ok).length, 0);
  assert.deepEqual((await grantsOf('capped')).map(g => [g.rp_id, g.kind, g.rule]), [['rp-a.test', 'registration', '*'], ['rp-b.test', 'registration', '*']]);

  // Revoke rp-a's grant: a slot is free (the credential stays until `credential delete`). The revocation ends every browser.
  const revoked = await stack.daemon.adminJson('grants', 'revoke', '--profile', 'capped', '--rp', 'rp-a.test', '--confirm');
  assert.equal(revoked.revoked, 1, JSON.stringify(revoked));
  await waitFor('the daemon to terminate the capped browser', () => !pidAlive(capped.lease.pid));
  assert.equal(stack.daemon.humanStore().filter(f => f.file.startsWith('rp-a.test/')).length, 2, 'the credentials of both profiles are still in the store (dora-a and cass-a)');
  capped = await stack.open('capped', `${rp.c.origin}/raw`);
  assertInterceptionActive(capped);
  await capped.page.waitForFunction(() => window.e2e);
  const freed = await capped.page.evaluate(u => window.e2e.register({ username: u, userVerification: 'preferred', timeout: 30000 }), 'cass-c');
  assert.equal(freed.ok, true, `the freed slot allows one more registration: ${JSON.stringify(freed)}`);
  assert.equal(prompts(), 5, 'the registration prompted');
  assert.deepEqual((await grantsOf('capped')).map(g => g.rp_id).sort(), ['rp-b.test', 'rp-c.test']);
  const again = await registerAt(capped, 'd', 'cass-d');
  assert.equal(again.ok, false, `the cap holds again: ${JSON.stringify(again)}`);
  assert.equal(prompts(), 5, 'refused without a prompt');

  // ---- audit: the refusals say why, the prompts and grants are exactly the approved ones.
  const audit = await stack.daemon.audit();
  assert.deepEqual(denyReasons(audit, { profile: 'daily', action: 'register' }), ['wildcard_registration_rate']);
  assert.deepEqual(denyReasons(audit, { profile: 'capped', action: 'register' }), ['wildcard_registration_cap', 'wildcard_registration_cap']);
  assert.equal(policyEvents(audit, 'policy.deny').find(e => e.reason === 'wildcard_registration_cap').rule, '*');
  assert.deepEqual(escalationEvents(audit, 'requested').map(e => [e.profile_id, e.rp_id, e.rule]), [
    ['daily', 'rp-a.test', '*'], ['daily', 'rp-b.test', '*'],
    ['capped', 'rp-a.test', '*'], ['capped', 'rp-b.test', '*'],
    ['capped', 'rp-c.test', '*'],
  ]);
  assert.deepEqual(grantedRuleEvents(audit, 'add').map(e => [e.profile_id, e.rp_id, e.rule, e.grant_kind]), [
    ['daily', 'rp-a.test', '*', 'registration'], ['daily', 'rp-b.test', '*', 'registration'],
    ['capped', 'rp-a.test', '*', 'registration'], ['capped', 'rp-b.test', '*', 'registration'],
    ['capped', 'rp-c.test', '*', 'registration'],
  ]);
  assert.deepEqual(grantedRuleEvents(audit, 'revoke').map(e => [e.profile_id, e.rp_id]), [['capped', 'rp-a.test']]);
  for (const n of stack.notify.notifications()) assert.equal(n.summary, REGISTER_SUMMARY);
  assert.deepEqual(grantsStore(stack, 'capped').grants.map(g => g.rp_id).sort(), ['rp-b.test', 'rp-c.test']);
  assert.ok(auditEvents(audit).every(e => e.kind !== 'policy.allow' || e.action !== 'register' || ['daily', 'capped'].includes(e.profile_id)));
});
