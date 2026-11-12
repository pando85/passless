'use strict';
const { scenario, assert } = require('../lib/scenario');
const { escalationEvents, grantedRuleEvents, grantsStore, assertInterceptionActive, storeFingerprint } = require('../lib/helpers');
const { DaemonStartError } = require('../lib/daemon');
const { requestProfile, start, settle, peek, abort, waitForEscalation } = require('../lib/escalation');

const ONE_RP = { rps: { a: { host: 'rp-a.test' } }, profiles: { agent: requestProfile(['rp-a.test']) } };

// A parked escalation holds no lock of the human path (plan section 5: the human operation lock can be acquired while a
// waiter is parked): while an agent request waits for approval, a human ceremony on the daemon's UHID authenticator completes.
scenario({ id: 'E2E-43', exposeModes: ['port', 'pipe'], title: 'a human ceremony completes while an escalation is pending' }, async ctx => {
  const stack = await ctx.stack({ ...ONE_RP, notify: { script: ['ignore'] } });
  const rp = stack.rp.a;
  await stack.seedHuman(rp, 'alice');
  const b = await stack.open('agent', `${rp.origin}/raw`);
  assertInterceptionActive(b);

  const key = await start(b.page, 'authenticate', { username: 'alice' });
  assert.ok(await stack.notify.waitForNotify(1), 'the escalation is waiting for its notification');
  const humanBefore = stack.daemon.humanStore().length;

  const seeded = await stack.seedHuman(rp, 'bob', { timeoutMs: 30000 }); // throws unless the human ceremony completed and stored a credential
  assert.equal(seeded.ok, true, JSON.stringify(seeded));
  assert.equal(stack.daemon.humanStore().length, humanBefore + 1, 'the human ceremony stored its credential');
  assert.equal((await peek(b.page, key)).settled, false, 'the escalation is still pending');
  assert.equal(escalationEvents(await stack.daemon.audit(), 'approved').length, 0);

  await abort(b.page, key);
  assert.equal((await settle(b.page, key)).name, 'AbortError');
  await waitForEscalation(stack, 'expired');
});

// PASSLESS_INTERACTION_MODE=automatic approves only the daemon's own human UHID path (cmd/passless/src/notification.rs).
// Escalation never reads it: the agent request still prompts, and with nobody approving it is never auto-approved.
// The operator acknowledges the combination (`agents.allow_automatic_human_path`, R19); without it agents refuse to
// start (E2E-44/startup-refusal).
// Port-only (axis-independent): the automatic-interaction check does not depend on the attach mode.
scenario({ id: 'E2E-44', title: 'automatic interaction mode never auto-approves an escalation' }, async ctx => {
  const stack = await ctx.stack({
    ...ONE_RP, notify: { script: ['deny:500'] }, agents: { allow_automatic_human_path: true },
    daemonEnv: { PASSLESS_INTERACTION_MODE: 'automatic' },
  });
  const rp = stack.rp.a;
  await stack.seedHuman(rp, 'alice');
  const b = await stack.open('agent', `${rp.origin}/raw`);
  assertInterceptionActive(b);
  await b.page.waitForFunction(() => window.e2e);
  const fingerprint = storeFingerprint(stack.daemon);

  const res = await b.page.evaluate(() => window.e2e.authenticate({ username: 'alice', timeout: 30000 }));
  assert.equal(res.ok, false, `the escalation must wait for the human, not be auto-approved: ${JSON.stringify(res)}`);
  assert.equal(res.name, 'NotAllowedError');
  assert.equal(stack.notify.notifications().length, 1, 'the request prompted');
  const audit = await stack.daemon.audit();
  assert.deepEqual(escalationEvents(audit, 'denied').map(e => e.cause), ['user']);
  assert.equal(escalationEvents(audit, 'approved').length, 0);
  assert.equal(grantedRuleEvents(audit, 'add').length, 0);
  assert.equal(grantsStore(stack).grants.length, 0);
  assert.equal(rp.authentications.length, 0);
  assert.equal(storeFingerprint(stack.daemon), fingerprint, 'nothing was signed');
});

// R19: a daemon whose human path is automatic refuses to run the agent subsystem while a same-user profile has an
// `allow` or `request` rule, unless `agents.allow_automatic_human_path` says so. The human path stays up.
// Port-only (axis-independent): the automatic-interaction check does not depend on the attach mode.
scenario({
  id: 'E2E-44/startup-refusal', title: 'agents refuse to start in automatic interaction mode without agents.allow_automatic_human_path',
}, async ctx => {
  let error = null;
  try {
    await ctx.stack({ ...ONE_RP, daemonEnv: { PASSLESS_INTERACTION_MODE: 'automatic' } });
  } catch (e) { error = e; }
  assert.ok(error instanceof DaemonStartError, `the daemon must refuse to start the agent subsystem in automatic mode, but it started${error ? `: ${error.message}` : ''}`);
  assert.match(error.message, /allow_automatic_human_path/);
  assert.match(error.message, /agent subsystem failed to start/i, 'the agent subsystem, not the daemon, refuses');
});
