'use strict';
const { scenario, assert } = require('../lib/scenario');
const { denyReasons, assertInterceptionActive, storeFingerprint } = require('../lib/helpers');
const { DaemonStartError } = require('../lib/daemon');

// ADR 0014 amendment sections 2.2 and 3: what the daemon refuses, and what it never does.
//
// E2E-61 (config refusals, one daemon start each; the agent subsystem refuses and the message names the fix):
//   `*` with register = "allow"            invalid: "a wildcard never registers without a human; use request"
//   `*` register = "request", no acknowledge_global_registration        names that acknowledgement
//   `*` register = "request", no acknowledge_same_user_registration     names that acknowledgement
//   `*` register = "request", no acknowledge_global_same_user           names that acknowledgement
//   `*` in an isolated profile             still invalid (the wildcard is same-user only)
// and, with a valid configuration, `localhost` is never matched through `*`: neither a registration nor a sign-in at
// http://localhost is allowed or prompted (an exact `localhost` rule is the only way).
const WILD_REQUEST = { rp: '*', authenticate: 'request', register: 'request' };

/** The refusal of a configuration: the DaemonStartError it produces. */
async function refused(ctx, profiles) {
  let error = null;
  try {
    await ctx.stack({ rps: {}, notify: false, profiles });
  } catch (e) { error = e; }
  assert.ok(error instanceof DaemonStartError, `the daemon must refuse this configuration, but it started${error ? `: ${error.message}` : ''}`);
  return error.message;
}

// Port-only (axis-independent): a configuration refused at startup has no browser to attach to.
scenario({ id: 'E2E-61', title: 'config refusals: `*` with register allow, a missing acknowledgement, an isolated `*`; `localhost` never registers or signs in through `*`', ci: true, timeoutMs: 300000 }, async ctx => {
  // register = "allow" on `*` is invalid, whatever the acknowledgements say.
  let message = await refused(ctx, { coding: { mode: 'same-user', rules: [{ rp: '*', authenticate: 'request', register: 'allow' }] } });
  assert.match(message, /wildcard RP scope '\*' must not have register = "allow"/, message);
  assert.match(message, /register = "request"/, 'the message points to request');

  // Each of the three acknowledgements is required, and the message names the missing one.
  message = await refused(ctx, { coding: { mode: 'same-user', rules: [WILD_REQUEST], omitAck: ['global_registration'] } });
  assert.match(message, /acknowledge_global_registration/, message);
  assert.match(message, /'coding'/, 'it names the profile');
  message = await refused(ctx, { coding: { mode: 'same-user', rules: [WILD_REQUEST], omitAck: ['same_user_registration'] } });
  assert.match(message, /acknowledge_same_user_registration/, message);
  message = await refused(ctx, { coding: { mode: 'same-user', rules: [WILD_REQUEST], omitAck: ['global_same_user'] } });
  assert.match(message, /acknowledge_global_same_user/, message);

  // The wildcard stays same-user only.
  message = await refused(ctx, { coding: { mode: 'isolated', rules: [WILD_REQUEST] } });
  assert.match(message, /wildcard RP scope '\*' is only supported in same-user mode/, message);
});

// `localhost` is never matched through `*` (ADR 0014 section 6.1), for registration as for sign-in. The profile is valid and
// fully acknowledged; a scripted approval is waiting and is never needed: there is no prompt.
scenario({ id: 'E2E-61/localhost', exposeModes: ['port', 'pipe'], title: '`localhost` is never registered or signed in through `*`: refused without a prompt, nothing stored', ci: true, timeoutMs: 240000 }, async ctx => {
  const stack = await ctx.stack({
    rps: { local: { host: 'localhost' } },
    profiles: { coding: { mode: 'same-user', rules: [WILD_REQUEST] } },
    notify: { script: ['approve:1500'] },
  });
  const rp = stack.rp.local;
  const fingerprint = storeFingerprint(stack.daemon);
  // The rules do not admit localhost as a start URL: launch blank and navigate.
  const b = await stack.open('coding', `${rp.origin}/raw`, { startUrl: false });
  assertInterceptionActive(b);
  await b.page.waitForFunction(() => window.e2e);

  const reg = await b.page.evaluate(() => window.e2e.register({ username: 'lena', userVerification: 'preferred', timeout: 30000 }));
  assert.equal(reg.ok, false, `a localhost registration through \`*\` must be refused: ${JSON.stringify(reg)}`);
  assert.equal(reg.name, 'NotAllowedError');
  const auth = await b.page.evaluate(() => window.e2e.authenticate({ username: 'lena', timeout: 30000 }));
  assert.equal(auth.ok, false, JSON.stringify(auth));
  assert.equal(auth.name, 'NotAllowedError');

  assert.deepEqual(stack.notify.notifications(), [], 'no prompt: `*` does not reach localhost');
  assert.equal(rp.registrations.filter(r => r.ok).length, 0, 'nothing was created');
  assert.equal(storeFingerprint(stack.daemon), fingerprint, 'the human store is untouched');
  const audit = await stack.daemon.audit();
  // Both refuse for lack of a rule that reaches `localhost`: the registration says the action is not allowed (the `*`
  // rule is not consulted for it), the sign-in that the RP does not match any rule. `*` is never what decides.
  const reasons = action => denyReasons(audit, { profile: 'coding', rpId: 'localhost', action });
  assert.deepEqual(reasons('register'), ['action_not_allowed']);
  assert.deepEqual(reasons('authenticate'), ['rp_id_not_match']);
});
