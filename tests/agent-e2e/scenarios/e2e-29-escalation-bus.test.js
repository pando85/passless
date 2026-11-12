'use strict';
const { scenario, assert } = require('../lib/scenario');
const { escalationEvents, grantedRuleEvents, denyReasons, grantsStore, assertVerifiedAssertion, assertInterceptionActive, authenticate } = require('../lib/helpers');
const { requestProfile, start, settle, peek, abort, waitForEscalation, dbusSendSignal, sleep } = require('../lib/escalation');

const ONE_RP = { rps: { a: { host: 'rp-a.test' } }, profiles: { agent: requestProfile(['rp-a.test'], { register: 'request' }) } };

// The prompt child accepts `ActionInvoked` only from the notification server's unique name. Any other connection on the
// session bus that emits the signal (here dbus-send, a separate connection) is ignored: the request stays pending, even
// with the prompt's exact action key (read from the Notify call) and with the bare legacy key.
scenario({ id: 'E2E-29', exposeModes: ['port', 'pipe'], title: 'a spoofed ActionInvoked from another bus connection is ignored: the request stays pending, no grant', ci: true }, async ctx => {
  const stack = await ctx.stack({ ...ONE_RP, notify: { script: ['ignore'] } });
  const rp = stack.rp.a;
  await stack.seedHuman(rp, 'alice');
  const b = await stack.open('agent', `${rp.origin}/raw`);
  assertInterceptionActive(b);

  const key = await start(b.page, 'authenticate', { username: 'alice' });
  assert.ok(await stack.notify.waitForNotify(1), 'the notification was shown');
  const { id, actions } = stack.notify.notifications()[0];
  const allowKey = actions[0];
  assert.match(allowKey, /^allow_always:[0-9a-f]{32}$/);
  const spoof = key => dbusSendSignal(stack, ['/org/freedesktop/Notifications', 'org.freedesktop.Notifications.ActionInvoked', `uint32:${id}`, `string:${key}`]);
  assert.equal(await spoof(allowKey), 0, 'dbus-send emitted the spoofed signal');
  await sleep(1500); // past the 1000 ms review delay, so a real approval would be accepted now
  assert.equal(await spoof(allowKey), 0);
  assert.equal(await spoof('allow_always'), 0);
  await sleep(2500);

  const state = await peek(b.page, key);
  assert.equal(state.settled, false, `the spoofed approval must not complete the ceremony: ${JSON.stringify(state.result)}`);
  let audit = await stack.daemon.audit();
  assert.equal(escalationEvents(audit, 'approved').length, 0, 'no approval was recorded');
  assert.equal(grantedRuleEvents(audit, 'add').length, 0);
  assert.equal(grantsStore(stack).grants.length, 0, 'no grant was stored');
  assert.equal(rp.authentications.length, 0);

  await abort(b.page, key);
  const res = await settle(b.page, key);
  assert.equal(res.ok, false, JSON.stringify(res));
  assert.equal(res.name, 'AbortError');
  await waitForEscalation(stack, 'expired');
  audit = await stack.daemon.audit();
  assert.equal(escalationEvents(audit, 'approved').length, 0);
});

// Without a notification server the prompt child finds nobody to ask: the escalation is denied at once, audited, and no
// cooldown is set (a later request is again `escalation_unavailable`, not `escalation_cooldown`).
scenario({ id: 'E2E-30', exposeModes: ['port', 'pipe'], title: 'no notification server: immediate deny, escalation_unavailable, audited, no cooldown' }, async ctx => {
  const stack = await ctx.stack({ ...ONE_RP, notify: false });
  const rp = stack.rp.a;
  await stack.seedHuman(rp, 'alice');
  const b = await stack.open('agent', `${rp.origin}/raw`);
  assertInterceptionActive(b);
  await b.page.waitForFunction(() => window.e2e);

  const t0 = Date.now();
  const first = await b.page.evaluate(() => window.e2e.authenticate({ username: 'alice', timeout: 30000 }));
  const elapsed = Date.now() - t0;
  assert.equal(first.ok, false, JSON.stringify(first));
  assert.equal(first.name, 'NotAllowedError');
  assert.ok(elapsed < 8000, `an unavailable prompt is denied at once (${elapsed} ms)`);
  const reg = await b.page.evaluate(() => window.e2e.register({ username: 'frank', timeout: 30000 }));
  assert.equal(reg.ok, false, JSON.stringify(reg));
  const again = await b.page.evaluate(() => window.e2e.authenticate({ username: 'alice', timeout: 30000 }));
  assert.equal(again.ok, false, JSON.stringify(again));

  const audit = await stack.daemon.audit();
  assert.deepEqual(denyReasons(audit, { rpId: 'rp-a.test' }), ['escalation_unavailable', 'escalation_unavailable', 'escalation_unavailable'], 'unavailable sets no cooldown');
  assert.deepEqual(escalationEvents(audit, 'denied').map(e => e.cause), ['prompt_unavailable', 'prompt_unavailable', 'prompt_unavailable']);
  assert.equal(rp.authentications.length, 0);
});

// The notification server vanishes while a request waits: the escalation expires `server_lost` and sets no cooldown, so the
// next request prompts on a restarted server and completes.
scenario({ id: 'E2E-49', exposeModes: ['port', 'pipe'], title: 'notification server lost while waiting: expires server_lost, no cooldown, the next request prompts on the new server' }, async ctx => {
  const stack = await ctx.stack({ ...ONE_RP, notify: { script: ['ignore'] } });
  const rp = stack.rp.a;
  await stack.seedHuman(rp, 'alice');
  const b = await stack.open('agent', `${rp.origin}/raw`);
  assertInterceptionActive(b);

  const key = await start(b.page, 'authenticate', { username: 'alice' });
  assert.ok(await stack.notify.waitForNotify(1), 'the notification was shown');
  await stack.notify.stop();
  const lost = await settle(b.page, key);
  assert.equal(lost.ok, false, JSON.stringify(lost));
  assert.equal(lost.name, 'NotAllowedError');
  await waitForEscalation(stack, 'expired');
  let audit = await stack.daemon.audit();
  assert.deepEqual(escalationEvents(audit, 'expired').map(e => e.reason), ['server_lost']);
  assert.deepEqual(denyReasons(audit, { rpId: 'rp-a.test' }), ['escalation_expired']);

  const old = await stack.restartNotify({ script: ['approve:1500'] });
  assert.equal(old.notifications().length, 1);
  const ok = await authenticate(b.page, { username: 'alice' });
  assertVerifiedAssertion(rp, ok, { username: 'alice' });
  assert.equal(stack.notify.notifications().length, 1, 'the request prompted on the new server');
  audit = await stack.daemon.audit();
  assert.deepEqual(denyReasons(audit, { rpId: 'rp-a.test' }), ['escalation_expired'], 'server_lost set no cooldown');
  assert.equal(escalationEvents(audit, 'approved').length, 1);
  assert.deepEqual(grantsStore(stack).grants.map(g => g.rp_id), ['rp-a.test']);
});
