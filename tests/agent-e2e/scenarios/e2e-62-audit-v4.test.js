'use strict';
const { scenario, assert } = require('../lib/scenario');
const { authenticate, auditEvents, policyEvents, escalationEvents, grantedRuleEvents, denyReasons, assertInterceptionActive } = require('../lib/helpers');
const { section12, missingFields } = require('../lib/audit-fields');

// ADR 0014 amendment section 8 (audit schema version 4) for what E2E-58 to E2E-61 exercise, in one run:
//   - every record is schema version 4;
//   - every operation record (reservation, refusal, terminal) carries `credential_scope`, always present: `pinned` (exact
//     rule with profile pins), `discovered` (`*`, or an exact rule without pins), `registration_pinned` (`*` at a site where
//     the agent registered), null before a candidate set exists (a refusal ahead of selection, and a registration);
//     a terminal record repeats its reservation's scope;
//   - the new `policy.deny` reasons: wildcard_registration_cap, wildcard_registration_rate, wildcard_registration_cooldown;
//   - escalation records of a wildcard registration carry rule `*` and action `register`, and the grants they persist are
//     `registration` grants with rule `*`.
//
// Three profiles share the stack; the notification script is consumed in arrival order:
//   coding  pins [alice@rp-a], cap 1:   sign at rp-a (pinned); register at rp-c (prompt 1, approved); sign at rp-c
//                                       (registration_pinned); register at rp-d (cap); sign at rp-b through `*` request
//                                       (prompt 2, approved; discovered)
//   rated   1 prompt per day:           register at rp-a (prompt 3, approved); register at rp-b (rate)
//   cooled  defaults:                   register at rp-a (prompt 4, denied); register at rp-b (profile-wide cooldown)
const WILD = { rp: '*', authenticate: 'request', register: 'request' };
const PROFILES = pins => ({
  coding: { mode: 'same-user', rules: [{ rp: 'rp-a.test', authenticate: 'allow', register: 'deny' }, WILD], extra: { credential_refs: pins, max_wildcard_registrations: 1 } },
  rated: { mode: 'same-user', rules: [WILD], extra: { wildcard_registration_prompts_per_day: 1 } },
  cooled: { mode: 'same-user', rules: [WILD] },
});

scenario({ id: 'E2E-62', exposeModes: ['port', 'pipe'], title: 'audit schema 4: credential_scope on every operation record, the wildcard registration deny reasons, rule `*` on escalations and grants', ci: true, timeoutMs: 360000 }, async ctx => {
  const stack = await ctx.stack({
    rps: Object.fromEntries('abcd'.split('').map(c => [c, { host: `rp-${c}.test` }])),
    profiles: PROFILES([]),
    notify: { script: ['approve:1500', 'approve:1500', 'approve:1500', 'deny:1500'] },
  });
  const rp = Object.fromEntries('abcd'.split('').map(c => [c, stack.rp[c]]));
  await stack.seedHuman(rp.a, 'alice');
  await stack.seedHuman(rp.a, 'bob');
  await stack.seedHuman(rp.b, 'carol');
  const aliceRef = (await stack.daemon.adminJson('credential', 'list', '--domain', 'rp-a.test')).credentials.find(c => c.user_name === 'alice').credential_ref;
  await stack.restartDaemon(PROFILES([aliceRef]));

  const register = (b, key, username) => b.page.goto(`${rp[key].origin}/raw`)
    .then(() => b.page.waitForFunction(() => window.e2e))
    .then(() => b.page.evaluate(u => window.e2e.register({ username: u, userVerification: 'preferred', timeout: 30000 }), username));
  const signIn = async (b, key) => { await b.page.goto(`${rp[key].origin}/sw`); return authenticate(b.page, {}); };

  // coding
  const coding = await stack.open('coding', `${rp.a.origin}/sw`);
  assertInterceptionActive(coding);
  assert.equal((await authenticate(coding.page, {})).ok, true, 'pinned sign-in at rp-a');
  assert.equal((await register(coding, 'c', 'cora')).ok, true, 'approved wildcard registration at rp-c');
  assert.equal((await signIn(coding, 'c')).ok, true, 'sign-in at rp-c with the registered passkey, no prompt');
  assert.equal((await register(coding, 'd', 'dan')).ok, false, 'the cap of 1 refuses the second wildcard registration');
  assert.equal((await signIn(coding, 'b')).ok, true, 'sign-in at rp-b through `*` request, approved');
  assert.equal(stack.notify.notifications().length, 2);

  // rated
  const rated = await stack.open('rated', `${rp.a.origin}/raw`);
  assert.equal((await register(rated, 'a', 'rita')).ok, true, 'the one prompt of the day');
  assert.equal((await register(rated, 'b', 'ron')).ok, false, 'the second prompt of the day is refused');
  assert.equal(stack.notify.notifications().length, 3);

  // cooled
  const cooled = await stack.open('cooled', `${rp.a.origin}/raw`);
  assert.equal((await register(cooled, 'a', 'cy')).ok, false, 'denied by the human');
  assert.equal((await register(cooled, 'b', 'cleo')).ok, false, 'refused by the profile-wide cooldown');
  assert.equal(stack.notify.notifications().length, 4);

  const audit = await stack.daemon.audit();
  const all = auditEvents(audit);
  const fields = section12();

  // Every record is schema version 4.
  assert.deepEqual([...new Set(all.map(e => e.v))], [4], 'every record carries schema version 4');

  // credential_scope on every operation record, present even when null.
  const operations = all.filter(e => fields.operationKinds.includes(e.kind));
  assert.ok(operations.length >= 12, `operation records: ${operations.length}`);
  for (const record of operations) assert.deepEqual(missingFields(record, fields.operation), [], `${record.kind} lacks a canonical field: ${JSON.stringify(record)}`);
  assert.ok(operations.every(e => 'credential_scope' in e && (e.credential_scope === null || ['pinned', 'discovered', 'registration_pinned'].includes(e.credential_scope))));

  // The scope of each reservation, and the terminal that repeats it.
  const reservations = policyEvents(audit, 'policy.allow');
  const scopes = reservations.map(e => [e.profile_id, e.action, e.rp_id, e.rule, e.credential_scope]);
  assert.deepEqual(scopes, [
    ['coding', 'authenticate', 'rp-a.test', 'exact', 'pinned'],
    ['coding', 'register', 'rp-c.test', '*', null],
    ['coding', 'authenticate', 'rp-c.test', '*', 'registration_pinned'],
    ['coding', 'authenticate', 'rp-b.test', '*', 'discovered'],
    ['rated', 'register', 'rp-a.test', '*', null],
  ], JSON.stringify(scopes));
  for (const reservation of reservations) {
    const terminal = policyEvents(audit, 'operation.terminal').find(e => e.request_id === reservation.request_id);
    assert.ok(terminal, `a terminal record closes ${reservation.request_id}`);
    assert.equal(terminal.credential_scope, reservation.credential_scope, 'the terminal record repeats the reservation\'s scope');
    assert.equal(terminal.result, 'success');
  }

  // The new refusal reasons, ahead of selection (scope null), each without a prompt.
  assert.deepEqual(denyReasons(audit, { profile: 'coding', action: 'register' }), ['wildcard_registration_cap']);
  assert.deepEqual(denyReasons(audit, { profile: 'rated', action: 'register' }), ['wildcard_registration_rate']);
  assert.deepEqual(denyReasons(audit, { profile: 'cooled', action: 'register' }), ['escalation_denied', 'wildcard_registration_cooldown']);
  for (const e of policyEvents(audit, 'policy.deny').filter(e => /^wildcard_registration_/.test(e.reason))) {
    assert.equal(e.credential_scope, null, `${e.reason} comes before any candidate set`);
    assert.equal(e.rule, '*');
    assert.equal(e.action, 'register');
  }

  // Escalations and grants of the wildcard registrations.
  const requested = escalationEvents(audit, 'requested').map(e => [e.profile_id, e.action, e.rp_id, e.rule]);
  assert.deepEqual(requested, [
    ['coding', 'register', 'rp-c.test', '*'],
    ['coding', 'authenticate', 'rp-b.test', '*'],
    ['rated', 'register', 'rp-a.test', '*'],
    ['cooled', 'register', 'rp-a.test', '*'],
  ], JSON.stringify(requested));
  const added = grantedRuleEvents(audit, 'add').map(e => [e.profile_id, e.rp_id, e.grant_kind, e.rule, !!e.credential_ref]);
  assert.deepEqual(added, [
    ['coding', 'rp-c.test', 'registration', '*', true],
    ['coding', 'rp-b.test', 'escalation', '*', false],
    ['rated', 'rp-a.test', 'registration', '*', true],
  ], JSON.stringify(added));
});
