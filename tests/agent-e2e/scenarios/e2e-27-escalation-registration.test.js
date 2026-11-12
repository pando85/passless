'use strict';
const os = require('node:os');

const { scenario, assert } = require('../lib/scenario');
const { policyEvents, escalationEvents, grantedRuleEvents, denyReasons, grantsStore, assertInterceptionActive } = require('../lib/helpers');
const { requestProfile, REGISTER_SUMMARY, registrationBody, humanStoreLine, assertRegistrationActions } = require('../lib/escalation');

const REGISTRATION = { rps: { a: { host: 'rp-a.test' } }, profiles: { iso: requestProfile(['rp-a.test'], { register: 'request', mode: 'isolated' }) } };

// ADR 0014 section 8.3: an approved registration persists `authenticate = allow` for the RP with `kind = registration` and
// the new credential's reference, but not `register = allow`: the next registration prompts again. The prompt is the
// registration one (amendment section 5.1): "CREATE A NEW PASSKEY? (not a sign-in)", **Register once** and **Deny**
// (`register_once:<nonce>`), the isolated profile's own store and how many passkeys it holds for the site.
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
  const prompt1 = stack.notify.notifications()[0];
  assert.equal(prompt1.summary, REGISTER_SUMMARY);
  assert.equal(prompt1.body, registrationBody({
    site: 'rp-a.test',
    stored: 'the agent\'s own store (isolated profile "iso"), which holds no passkey for this site yet',
  }));
  const nonce1 = assertRegistrationActions(prompt1);
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
  const prompt2 = stack.notify.notifications()[1];
  assert.equal(prompt2.summary, REGISTER_SUMMARY);
  assert.equal(prompt2.body, registrationBody({
    site: 'rp-a.test',
    stored: 'the agent\'s own store (isolated profile "iso"), which already holds 1 passkey for this site',
  }), 'the store count follows the credential the first approval created');
  assert.notEqual(assertRegistrationActions(prompt2), nonce1, 'each prompt has its own nonce');
  assert.equal(stack.daemon.profileStore('iso').length, 1, 'no second credential');
  audit = await stack.daemon.audit();
  assert.deepEqual(denyReasons(audit, { profile: 'iso', action: 'register' }), ['escalation_denied']);
  assert.equal(policyEvents(audit, 'policy.allow').filter(e => e.action === 'register').length, 1);
  assert.deepEqual(escalationEvents(audit, 'requested').map(e => e.action), ['register', 'register']);
});

// ADR 0014 section 8.2: the prompt text is built from daemon-derived fields only. A page controls its title, URL, the user
// name and display name and the RP name, none of which may reach the notification. The actions are exactly allow_always
// and deny (a registration prompt: register_once and deny), and the notification never expires on its own
// (`expire_timeout = 0`). The registration prompt is the one of amendment section 5.1: it names the human's own store and
// how many passkeys it already holds for the site.
const MARK = 'MARKER-9f3a7c';
scenario({ id: 'E2E-28', exposeModes: ['port', 'pipe'], title: 'the notification shows daemon-derived text only (no page markers), exactly two actions per prompt kind, no expiry', ci: true }, async ctx => {
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
  // Registration first (a seeded human credential makes the store count 1), then the sign-in prompt.
  const expected = [
    {
      summary: REGISTER_SUMMARY,
      body: registrationBody({ site: 'rp-a.test', stored: humanStoreLine('agent', 1) }),
      key: 'register_once', label: 'Register once',
    },
    {
      summary: 'Passless: agent sign-in request',
      body: `Profile: agent (same-user)\nPrincipal user: ${user}\nAction: sign in with a passkey\nSite: rp-a.test (any page under this site)\nOrigin: https://rp-a.test\n"Allow always" is saved permanently.`,
      key: 'allow_always', label: 'Allow always',
    },
  ];
  notes.forEach((n, i) => {
    const text = `${n.summary}\n${n.body}`;
    assert.doesNotMatch(text, new RegExp(MARK), `page-controlled text reached the notification: ${text}`);
    assert.doesNotMatch(text, /E2E rp|rp-a\.test\/|\/raw/, `page-derived text reached the notification: ${text}`);
    assert.equal(n.summary, expected[i].summary);
    assert.equal(n.body, expected[i].body);
    assert.ok(n.body.split('\n').length <= 7, 'the body fits notify-osd\'s fallback dialog (seven lines at most)');
    // actions are a flat [key, label, key, label] list: exactly two. A sign-in prompt has "Allow always" and "Deny", a
    // registration prompt "Register once" and "Deny" (never "Allow always": the approval is one registration). The keys
    // carry one per-prompt nonce (`<key>:<nonce>`, `deny:<nonce>`) so a click is attributed to its own prompt even on a
    // server that reuses ids (notify-osd); the labels never show it.
    assert.equal(n.actions.length, 4, `actions: ${JSON.stringify(n.actions)}`);
    assert.deepEqual(n.actions.filter((_, j) => j % 2 === 1), [expected[i].label, 'Deny'], `actions: ${JSON.stringify(n.actions)}`);
    const nonce = (new RegExp(`^${expected[i].key}:([0-9a-f]{32})$`).exec(n.actions[0]) || [])[1];
    assert.ok(nonce, `approving key: ${n.actions[0]}`);
    assert.equal(n.actions[2], `deny:${nonce}`);
    if (i > 0) assert.notEqual(n.actions[0], notes[i - 1].actions[0], 'each prompt has its own keys');
    assert.equal(n.expire_timeout, 0, 'the notification does not expire by itself');
  });
});
