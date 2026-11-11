'use strict';
const { scenario, assert } = require('../lib/scenario');
const { authenticate, policyEvents, escalationEvents, assertVerifiedAssertion, assertInterceptionActive } = require('../lib/helpers');

// Catalogue: a wildcard `request` rule plus an exact `allow` (ADR 0014 sections 6.2 and 6.3). The exact rule wins at
// rp-a (allowed autonomously, no escalation); an RP that only the wildcard covers resolves through `*` and `request`
// (denied with audit `escalation_unavailable` until P7 implements escalation). A wildcard rule requires the profile in
// `agents.acknowledge_global_same_user`, which lib/daemon.js writes for every `*` rule.
const NOTIFY = { script: ['deny:500'] };
const PROFILES = {
  agent: {
    mode: 'same-user',
    rules: [
      { rp: 'rp-a.test', authenticate: 'allow', register: 'deny' },
      { rp: '*', authenticate: 'request', register: 'deny' },
    ],
  },
};

scenario({ id: 'E2E-12', title: 'exact allow beats wildcard request', ci: true }, async ctx => {
  const stack = await ctx.stack({ rps: { a: { host: 'rp-a.test' }, b: { host: 'rp-b.test' } }, profiles: PROFILES, notify: NOTIFY });
  const rpA = stack.rp.a;
  const rpB = stack.rp.b;
  await stack.seedHuman(rpA, 'alice');
  await stack.seedHuman(rpB, 'bob');

  const b = await stack.open('agent', `${rpA.origin}/sw`);
  assertInterceptionActive(b);
  assertVerifiedAssertion(rpA, await authenticate(b.page, { username: 'alice' }), { username: 'alice' });

  assert.deepEqual(stack.notify.notifications(), [], 'the exact allow rule needs no escalation: no notification for rp-a.test');

  // rp-b.test has no exact rule: it resolves through the wildcard `request`, which escalates and is denied by the human.
  await b.page.goto(`${rpB.origin}/sw`);
  const res = await authenticate(b.page, { username: 'bob' });
  assert.equal(res.ok, false, `a denied wildcard escalation must not authenticate: ${JSON.stringify(res)}`);
  assert.equal(res.name, 'NotAllowedError');
  assert.equal(rpB.authentications.length, 0, 'the wildcard-only RP must never receive an assertion');
  assert.equal(stack.notify.notifications().length, 1, 'the wildcard escalation showed exactly one notification');

  const audit = await stack.daemon.audit();
  const allowsA = policyEvents(audit, 'policy.allow').filter(e => e.profile_id === 'agent' && e.action === 'authenticate' && e.rp_id === 'rp-a.test');
  assert.equal(allowsA.length, 1, 'rp-a.test resolves through the exact allow rule: one policy.allow');
  assert.equal(policyEvents(audit, 'policy.allow').filter(e => e.rp_id === 'rp-b.test').length, 0, 'nothing may be allowed for rp-b.test');
  const deniesB = policyEvents(audit, 'policy.deny').filter(e => e.profile_id === 'agent' && e.action === 'authenticate' && e.rp_id === 'rp-b.test');
  assert.equal(deniesB.length, 1, `expected one audited deny for rp-b.test, audit: ${JSON.stringify(audit.map(e => e.event && e.event.kind))}`);
  assert.equal(deniesB[0].reason, 'escalation_denied');
  const requested = escalationEvents(audit, 'requested');
  assert.deepEqual(requested.map(e => [e.rp_id, e.rule]), [['rp-b.test', '*']], `the escalation went through the wildcard rule: ${JSON.stringify(requested)}`);
  assert.deepEqual(escalationEvents(audit, 'denied').map(e => e.cause), ['user']);
  assert.equal(policyEvents(audit, 'policy.deny').filter(e => e.rp_id === 'rp-a.test').length, 0, 'the exact rule must not also deny rp-a.test');
});

// V-M6: the audit carries no rule identity before P8 (`audit_events.rs`: `PolicyAllowMeta` has no `rule`), so the
// `rule = "*"` assertion for the wildcard path is tagged until then. It runs in the same stack shape as E2E-12.
scenario({
  id: 'E2E-12/audit-rule', title: 'wildcard match is audited rule="*"', ci: true,
  xfailUntil: 'P8', xfailMatch: /audit carries no rule identity/, xfailReason: 'policy.allow/deny events have no `rule` field until the P8 audit rework (V-M6)',
}, async ctx => {
  const stack = await ctx.stack({ rps: { a: { host: 'rp-a.test' }, b: { host: 'rp-b.test' } }, profiles: PROFILES, notify: NOTIFY });
  const rpB = stack.rp.b;
  await stack.seedHuman(rpB, 'bob');
  const b = await stack.open('agent', `${rpB.origin}/sw`);
  assertInterceptionActive(b);
  const res = await authenticate(b.page, { username: 'bob' });
  assert.equal(res.ok, false);
  const audit = await stack.daemon.audit();
  const denies = policyEvents(audit, 'policy.deny').filter(e => e.profile_id === 'agent' && e.rp_id === 'rp-b.test');
  assert.equal(denies.length, 1);
  assert.ok('rule' in denies[0], 'audit carries no rule identity yet');
  assert.equal(denies[0].rule, '*', 'a wildcard match is audited as rule="*"');
});
