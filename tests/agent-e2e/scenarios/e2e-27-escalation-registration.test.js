'use strict';
const os = require('node:os');

const { scenario, assert } = require('../lib/scenario');
const { policyEvents, escalationEvents, grantedRuleEvents, denyReasons, grantsStore, assertInterceptionActive } = require('../lib/helpers');
const { requestProfile } = require('../lib/escalation');

const REGISTRATION = { rps: { a: { host: 'rp-a.test' } }, profiles: { iso: requestProfile(['rp-a.test'], { register: 'request', mode: 'isolated' }) } };

// ADR 0014 section 8.3: an approved registration persists `authenticate = allow` for the RP with `kind = registration` and
// the new credential's reference, but not `register = allow`: the next registration prompts again.
scenario({ id: 'E2E-27', exposeModes: ['port', 'pipe'], title: 'registration escalation: one credential, a registration grant with credential_ref, the next registration prompts', ci: true }, async ctx => {
  const stack = await ctx.stack({ ...REGISTRATION, notify: { script: ['approve:1500', 'deny:500'] } });
  const rp = stack.rp.a;
  const b = await stack.open('iso', `${rp.origin}/raw`);
  assertInterceptionActive(b);
  await b.page.waitForFunction(() => window.e2e);

  const first = await b.page.evaluate(() => window.e2e.register({ username: 'frank', userVerification: 'preferred', timeout: 30000 }));
  assert.equal(first.ok, true, `the approved registration completes: ${JSON.stringify(first)}`);
  assert.equal(rp.registrations.filter(r => r.ok).length, 1, 'the RP verified one credential');
  assert.equal(stack.daemon.profileStore('iso').length, 1, 'one credential in the isolated store');
  assert.equal(stack.notify.notifications().length, 1);
  let audit = await stack.daemon.audit();
  const added = grantedRuleEvents(audit, 'add');
  assert.equal(added.length, 1, JSON.stringify(added));
  assert.equal(added[0].grant_kind, 'registration');
  assert.equal(added[0].rp_id, 'rp-a.test');
  assert.ok(added[0].credential_ref, `the registration grant carries the credential reference: ${JSON.stringify(added[0])}`);
  const listed = await stack.daemon.adminJson('credential', 'list', '--domain', 'rp-a.test');
  assert.deepEqual(listed.credentials.map(c => c.credential_ref), [added[0].credential_ref], 'the grant names the stored credential');
  const store = grantsStore(stack, 'iso');
  assert.deepEqual(store.grants.map(g => [g.rp_id, g.action, g.kind]), [['rp-a.test', 'authenticate', 'registration']], JSON.stringify(store.grants));

  // register = request is not granted: a second registration prompts and the scripted human denies it.
  const second = await b.page.evaluate(() => window.e2e.register({ username: 'gina', userVerification: 'preferred', timeout: 30000 }));
  assert.equal(second.ok, false, JSON.stringify(second));
  assert.equal(second.name, 'NotAllowedError');
  assert.equal(stack.notify.notifications().length, 2, 'the second registration prompted again');
  assert.equal(stack.daemon.profileStore('iso').length, 1, 'no second credential');
  audit = await stack.daemon.audit();
  assert.deepEqual(denyReasons(audit, { profile: 'iso', action: 'register' }), ['escalation_denied']);
  assert.equal(policyEvents(audit, 'policy.allow').filter(e => e.action === 'register').length, 1);
  assert.deepEqual(escalationEvents(audit, 'requested').map(e => e.action), ['register', 'register']);
});

// ADR 0014 section 8.2: the prompt text is built from daemon-derived fields only. A page controls its title, URL, the user
// name and display name and the RP name, none of which may reach the notification. The actions are exactly allow_always
// and deny, and the notification never expires on its own (`expire_timeout = 0`).
const MARK = 'MARKER-9f3a7c';
scenario({ id: 'E2E-28', exposeModes: ['port', 'pipe'], title: 'the notification shows daemon-derived text only (no page markers), exactly two actions, no expiry', ci: true }, async ctx => {
  const stack = await ctx.stack({
    rps: { a: { host: 'rp-a.test' } },
    profiles: { agent: requestProfile(['rp-a.test'], { register: 'request' }) },
    notify: { script: ['deny:500', 'deny:500'] },
  });
  const rp = stack.rp.a;
  await stack.seedHuman(rp, 'alice');
  const b = await stack.open('agent', `${rp.origin}/raw?${MARK}-query`);
  assertInterceptionActive(b);
  await b.page.waitForFunction(() => window.e2e);
  await b.page.evaluate(t => { document.title = t; }, `${MARK}-title`);

  const reg = await b.page.evaluate(m => window.e2e.register({ username: `${m}-user`, displayName: `${m}-display`, userVerification: 'preferred', timeout: 30000 }), MARK);
  assert.equal(reg.ok, false, JSON.stringify(reg));
  const auth = await b.page.evaluate(() => window.e2e.authenticate({ username: 'alice', timeout: 30000 }));
  assert.equal(auth.ok, false, JSON.stringify(auth));

  const notes = stack.notify.notifications();
  assert.equal(notes.length, 2, 'one prompt for the registration, one for the sign-in');
  const user = os.userInfo().username;
  const expected = [
    ['Passless: agent registration request', 'register a new passkey'],
    ['Passless: agent sign-in request', 'sign in with a passkey'],
  ];
  notes.forEach((n, i) => {
    const text = `${n.summary}\n${n.body}`;
    assert.doesNotMatch(text, new RegExp(MARK), `page-controlled text reached the notification: ${text}`);
    assert.doesNotMatch(text, /E2E rp|rp-a\.test\/|\/raw/, `page-derived text reached the notification: ${text}`);
    assert.equal(n.summary, expected[i][0]);
    assert.equal(n.body,
      `Profile: agent (same-user)\nPrincipal user: ${user}\nAction: ${expected[i][1]}\nSite: rp-a.test (any page under this site)\nOrigin: https://rp-a.test\n"Allow always" is saved permanently.`);
    // actions are a flat [key, label, key, label] list.
    assert.deepEqual(n.actions.filter((_, j) => j % 2 === 0), ['allow_always', 'deny'], `actions: ${JSON.stringify(n.actions)}`);
    assert.equal(n.actions.length, 4);
    assert.equal(n.expire_timeout, 0, 'the notification does not expire by itself');
  });
});
