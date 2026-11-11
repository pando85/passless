'use strict';
const { scenario, assert } = require('../lib/scenario');
const { policyEvents, escalationEvents, grantedRuleEvents, denyReasons, grantsStore, authenticate, assertVerifiedAssertion, assertInterceptionActive } = require('../lib/helpers');
const { requestProfile, start, settle, abort, waitForEscalation, sleep } = require('../lib/escalation');
const { parseAuthData } = require('../lib/rp-server');

// ADR 0014 section 8: a `request` rule escalates to the human through a notification; "Allow always" persists a grant.
// notify-double scripts (`ctx.stack({notify:{script}})`): approve invokes allow_always, deny invokes deny; the daemon
// accepts "Allow always" only 1000 ms after the notification was shown, so approvals are scripted at 1500 ms or later.
// An earlier approval is a deny (`early_approval`).

const ONE_RP = { rps: { a: { host: 'rp-a.test' } }, profiles: { agent: requestProfile(['rp-a.test']) } };

scenario({ id: 'E2E-23', title: 'approved escalation completes, persists a grant, and the next ceremony needs no prompt', ci: true }, async ctx => {
  const stack = await ctx.stack({ ...ONE_RP, notify: { script: ['approve:1500'] } });
  const rp = stack.rp.a;
  await stack.seedHuman(rp, 'alice');
  const b = await stack.open('agent', `${rp.origin}/sw`);
  assertInterceptionActive(b);

  assertVerifiedAssertion(rp, await authenticate(b.page, { username: 'alice' }), { username: 'alice' });
  const notifications = stack.notify.notifications();
  assert.equal(notifications.length, 1, 'the first ceremony showed one prompt');
  let audit = await stack.daemon.audit();
  const requested = escalationEvents(audit, 'requested');
  assert.deepEqual(requested.map(e => [e.rp_id, e.rule]), [['rp-a.test', 'exact']], `one escalation through the exact rule: ${JSON.stringify(requested)}`);
  assert.equal(escalationEvents(audit, 'approved').length, 1);
  const added = grantedRuleEvents(audit, 'add');
  assert.deepEqual(added.map(e => [e.rp_id, e.grant_kind]), [['rp-a.test', 'escalation']], JSON.stringify(added));
  const store = grantsStore(stack);
  assert.equal(store.exists, true, `the grant store was written: ${store.path}`);
  assert.deepEqual(store.grants.map(g => [g.rp_id, g.action, g.kind]), [['rp-a.test', 'authenticate', 'escalation']], JSON.stringify(store.grants));
  const allowsBefore = policyEvents(audit, 'policy.allow').length;

  // The grant upgrades the rule: the next ceremony needs no prompt and no new escalation.
  assertVerifiedAssertion(rp, await authenticate(b.page, { username: 'alice' }), { username: 'alice' });
  assert.equal(stack.notify.notifications().length, 1, 'the granted RP must not prompt again');
  audit = await stack.daemon.audit();
  assert.equal(escalationEvents(audit, 'requested').length, 1, 'no second escalation');
  assert.equal(policyEvents(audit, 'policy.allow').length, allowsBefore + 1, 'the second ceremony is an ordinary allow');
});

scenario({ id: 'E2E-24', title: 'denied escalation starts the cooldown: no prompt during it, a prompt after it', ci: true }, async ctx => {
  const stack = await ctx.stack({ ...ONE_RP, notify: { script: ['deny:500', 'deny:500'] }, agents: { escalation_cooldown: 2 } });
  const rp = stack.rp.a;
  await stack.seedHuman(rp, 'alice');
  const b = await stack.open('agent', `${rp.origin}/sw`);
  assertInterceptionActive(b);

  const first = await authenticate(b.page, { username: 'alice' });
  assert.equal(first.ok, false, JSON.stringify(first));
  assert.equal(first.name, 'NotAllowedError');
  assert.equal(stack.notify.notifications().length, 1);
  const deniedAt = Date.now();

  // Inside the cooldown (a fresh challenge each time: the options come from the RP for every call).
  const second = await authenticate(b.page, { username: 'alice' });
  assert.equal(second.ok, false, JSON.stringify(second));
  assert.equal(second.name, 'NotAllowedError');
  assert.equal(stack.notify.notifications().length, 1, 'no notification while the cooldown runs');
  assert.deepEqual(denyReasons(await stack.daemon.audit(), { rpId: 'rp-a.test' }), ['escalation_denied', 'escalation_cooldown']);

  // After it (2 s from the deny) the key prompts again.
  await sleep(Math.max(0, 2500 - (Date.now() - deniedAt)));
  const third = await authenticate(b.page, { username: 'alice' });
  assert.equal(third.ok, false, JSON.stringify(third));
  assert.equal(stack.notify.notifications().length, 2, 'the cooldown expired: the request prompts again');
  const audit = await stack.daemon.audit();
  assert.deepEqual(denyReasons(audit, { rpId: 'rp-a.test' }), ['escalation_denied', 'escalation_cooldown', 'escalation_denied']);
  assert.deepEqual(escalationEvents(audit, 'denied').map(e => e.cause), ['user', 'user']);
  assert.equal(rp.authentications.length, 0, 'no assertion was ever produced');
  assert.equal(grantsStore(stack).grants.length, 0, 'a deny stores nothing');
});

scenario({ id: 'E2E-25', title: 'two tabs asking for the same RP share one prompt and both succeed', ci: true }, async ctx => {
  const stack = await ctx.stack({ ...ONE_RP, notify: { script: ['approve:3000'] } });
  const rp = stack.rp.a;
  await stack.seedHuman(rp, 'alice');
  const url = `${rp.origin}/raw`;
  const b = await stack.open('agent', url);
  assertInterceptionActive(b);
  const second = await b.context.newPage();
  await second.goto(url);

  // `noVerify`: concurrent assertions of one credential can reach the RP out of counter order; they are verified in order below.
  const k1 = await start(b.page, 'authenticate', { username: 'alice', noVerify: true });
  const k2 = await start(second, 'authenticate', { username: 'alice', noVerify: true });
  const [r1, r2] = await Promise.all([settle(b.page, k1), settle(second, k2)]);
  assert.equal(r1.ok, true, JSON.stringify(r1));
  assert.equal(r2.ok, true, JSON.stringify(r2));
  assert.equal(stack.notify.notifications().length, 1, 'the two escalations of one key joined: one prompt');
  const counterOf = r => parseAuthData(Buffer.from(r.response.response.authenticatorData, 'base64url')).counter;
  for (const r of [r1, r2].sort((x, y) => counterOf(x) - counterOf(y))) {
    const ev = await rp.authVerify({ response: r.response });
    assertVerifiedAssertion(rp, { ok: true, ts: ev.ts, credentialId: r.response.id }, { username: 'alice' });
  }
  const audit = await stack.daemon.audit();
  assert.equal(escalationEvents(audit, 'approved').length, 1, 'one approval served both');
  assert.equal(grantedRuleEvents(audit, 'add').length, 1);
  assert.equal(policyEvents(audit, 'policy.allow').length, 2, 'both ceremonies were allowed');
});

// V-M2: a withdrawal (the last waiter leaves a pending escalation) is rate limited; the 3rd within 10 minutes starts the
// cooldown. Three aborts after the notification was shown, then the fourth request is refused without a prompt.
scenario({ id: 'E2E-50', title: 'three withdrawn escalations start the cooldown: the fourth request gets no prompt', ci: true }, async ctx => {
  const stack = await ctx.stack({ ...ONE_RP, notify: { script: ['ignore'] } });
  const rp = stack.rp.a;
  await stack.seedHuman(rp, 'alice');
  const b = await stack.open('agent', `${rp.origin}/raw`);
  assertInterceptionActive(b);

  for (let i = 1; i <= 3; i++) {
    const key = await start(b.page, 'authenticate', { username: 'alice' });
    assert.ok(await stack.notify.waitForNotify(i), `abort ${i}: the notification was shown`);
    await abort(b.page, key);
    const res = await settle(b.page, key);
    assert.equal(res.ok, false, JSON.stringify(res));
    assert.equal(res.name, 'AbortError', JSON.stringify(res));
    await waitForEscalation(stack, 'expired', i);
    assert.ok(stack.notify.closes().length >= i, `abort ${i}: the notification is withdrawn`);
  }
  const audit = await stack.daemon.audit();
  assert.deepEqual(escalationEvents(audit, 'expired').map(e => e.reason), ['aborted', 'aborted', 'aborted']);

  const fourth = await settle(b.page, await start(b.page, 'authenticate', { username: 'alice' }));
  assert.equal(fourth.ok, false, JSON.stringify(fourth));
  assert.equal(fourth.name, 'NotAllowedError', JSON.stringify(fourth));
  assert.equal(stack.notify.notifications().length, 3, 'the fourth request must not prompt');
  assert.deepEqual(denyReasons(await stack.daemon.audit(), { rpId: 'rp-a.test' }), ['aborted', 'aborted', 'aborted', 'escalation_cooldown']);
  assert.equal(rp.authentications.length, 0);
});
