'use strict';
const { scenario, assert } = require('../lib/scenario');
const { authenticate, policyEvents, escalationEvents, grantedRuleEvents, denyReasons, grantsStore, assertVerifiedAssertion, assertInterceptionActive } = require('../lib/helpers');
const { REGISTER_SUMMARY, registrationBody, humanStoreLine, assertRegistrationActions } = require('../lib/escalation');

// ADR 0014 amendment section 2.2 (Phase 1, change 2): `register = "request"` on the `*` rule of a same-user profile that is
// listed in `acknowledge_global_registration` (lib/daemon.js writes the three acknowledgements for such a rule). A page at a
// site no exact rule lists asks to create a passkey; the human sees the registration prompt, approves it once, and the
// agent then signs in at that site, without asking, with the passkey it created.
const user = 'agent-user';
const WILDCARD = { rules: [{ rp: '*', authenticate: 'request', register: 'request' }] };

// E2E-59: the approved path, end to end.
//   - the prompt: the registration summary, "NOT on your list; matched by the * rule", the human's own store with its
//     count (alice is already there), and exactly Register once / Deny with a register_once:<nonce> key;
//   - the credential lands in the HUMAN store;
//   - the grant: kind registration, rule `*`, the new credential's reference, listed by `agent-admin grants list` (JSON
//     and the plain table with its header);
//   - the next sign-in needs no prompt and uses the new credential although alice (the human's) is at the same site:
//     `*` selects with `single`, and the registered site's candidates are the registration-granted credentials only.
scenario({ id: 'E2E-59', exposeModes: ['port', 'pipe'], title: 'wildcard registration approved: Register once prompt, human store, `*` grant, then a prompt-free sign-in with the new credential', ci: true, timeoutMs: 240000 }, async ctx => {
  const stack = await ctx.stack({
    rps: { a: { host: 'rp-a.test' } },
    profiles: { coding: { mode: 'same-user', ...WILDCARD } },
    notify: { script: ['approve:1500'] },
  });
  const rp = stack.rp.a;
  await stack.seedHuman(rp, 'alice');
  const humanBefore = stack.daemon.humanStore().length;
  assert.equal(humanBefore, 1, 'the human holds one passkey at the site');

  const b = await stack.open('coding', `${rp.origin}/raw`);
  assertInterceptionActive(b);
  await b.page.waitForFunction(() => window.e2e);
  const reg = await b.page.evaluate(u => window.e2e.register({ username: u, userVerification: 'preferred', timeout: 30000 }), user);
  assert.equal(reg.ok, true, `the approved registration completes: ${JSON.stringify(reg)}`);
  assert.equal(rp.registrations.filter(r => r.ok && r.username === user).length, 1, 'the RP verified the agent\'s credential');

  // The prompt.
  const notes = stack.notify.notifications();
  assert.equal(notes.length, 1, 'one prompt: the registration');
  assert.equal(notes[0].summary, REGISTER_SUMMARY);
  assert.equal(notes[0].body, registrationBody({ site: 'rp-a.test', siteRule: 'wildcard', stored: humanStoreLine('coding', 1) }));
  assert.ok(notes[0].body.split('\n').length <= 7, 'the body fits notify-osd\'s fallback dialog');
  assertRegistrationActions(notes[0]);

  // The credential is in the human store.
  assert.equal(stack.daemon.humanStore().length, humanBefore + 1, 'the new credential is in the human store');

  // The grant, in the audit, the store file and the admin CLI.
  let audit = await stack.daemon.audit();
  const requested = escalationEvents(audit, 'requested');
  assert.deepEqual(requested.map(e => [e.action, e.rp_id, e.rule]), [['register', 'rp-a.test', '*']], JSON.stringify(requested));
  const added = grantedRuleEvents(audit, 'add');
  assert.equal(added.length, 1, JSON.stringify(added));
  assert.equal(added[0].grant_kind, 'registration');
  assert.equal(added[0].rule, '*');
  assert.equal(added[0].rp_id, 'rp-a.test');
  assert.ok(added[0].credential_ref, 'the grant carries the new credential\'s reference');
  const store = grantsStore(stack, 'coding');
  assert.deepEqual(store.grants.map(g => [g.rp_id, g.action, g.kind, g.rule, g.credential_ref]),
    [['rp-a.test', 'authenticate', 'registration', '*', added[0].credential_ref]], JSON.stringify(store.grants));
  const listed = (await stack.daemon.adminJson('grants', 'list', '--profile', 'coding')).profiles[0];
  assert.deepEqual(listed.rules.map(r => [r.rp_id, r.kind, r.rule]), [['rp-a.test', 'registration', '*']], JSON.stringify(listed));
  const plain = await stack.daemon.adminPlain('grants', 'list', '--profile', 'coding');
  assert.equal(plain.code, 0, plain.stderr);
  const lines = plain.stdout.split('\n').filter(Boolean);
  assert.match(lines[0], /^coding: 1 rule\(s\), digest [0-9a-f]+$/, plain.stdout);
  assert.deepEqual(lines[1].trim().split(/\s+/).slice(0, 4), ['RP_ID', 'ACTION', 'KIND', 'RULE'], `a header row: ${plain.stdout}`);
  assert.deepEqual(lines[2].trim().split(/\s+/).slice(0, 4), ['rp-a.test', 'authenticate', 'registration', '*'], plain.stdout);
  assert.ok(lines[2].includes(added[0].credential_ref), 'the table shows the credential');

  // The next sign-in: no prompt, and the agent's own passkey although alice exists at the same site.
  const res = await authenticate(b.page, {});
  assertVerifiedAssertion(rp, res, { username: user });
  assert.equal(stack.notify.notifications().length, 1, 'the grant makes the sign-in prompt-free');
  audit = await stack.daemon.audit();
  const signIns = policyEvents(audit, 'policy.allow').filter(e => e.profile_id === 'coding' && e.action === 'authenticate');
  assert.equal(signIns.length, 1, JSON.stringify(signIns));
  assert.equal(signIns[0].rule, '*');
  assert.equal(signIns[0].grant_source, 'granted');
  assert.equal(signIns[0].credential_ref, added[0].credential_ref, 'signed with the credential the agent registered');
  assert.equal(signIns[0].credential_scope, 'registration_pinned');
  const registration = policyEvents(audit, 'policy.allow').filter(e => e.profile_id === 'coding' && e.action === 'register');
  assert.deepEqual(registration.map(e => [e.rule, e.rp_id]), [['*', 'rp-a.test']]);

  // Nothing was refused: one approval, one registration, one prompt-free sign-in.
  assert.equal(denyReasons(audit, { profile: 'coding' }).length, 0, 'nothing was refused so far');
});

// E2E-59/deny: a deny starts the per-key cooldown and the profile-wide wildcard registration cooldown. A second unlisted
// site is then refused without a prompt (`wildcard_registration_cooldown`), the denied site itself is in its per-key cooldown
// (`escalation_cooldown`), and an exact-rule registration of the same profile is unaffected: it still prompts.
scenario({ id: 'E2E-59/deny', exposeModes: ['port', 'pipe'], title: 'wildcard registration denied: per-key and profile-wide cooldown, a second unlisted site is refused without a prompt, exact rules unaffected', ci: true, timeoutMs: 240000 }, async ctx => {
  const stack = await ctx.stack({
    rps: { a: { host: 'rp-a.test' }, b: { host: 'rp-b.test' }, c: { host: 'rp-c.test' } },
    profiles: {
      coding: {
        mode: 'same-user',
        rules: [
          { rp: 'rp-c.test', authenticate: 'allow', register: 'request' },
          { rp: '*', authenticate: 'request', register: 'request' },
        ],
      },
    },
    notify: { script: ['deny:1500', 'approve:1500'] },
  });
  const [rpA, rpB, rpC] = [stack.rp.a, stack.rp.b, stack.rp.c];
  const b = await stack.open('coding', `${rpA.origin}/raw`);
  assertInterceptionActive(b);
  await b.page.waitForFunction(() => window.e2e);
  const register = name => b.page.evaluate(u => window.e2e.register({ username: u, userVerification: 'preferred', timeout: 30000 }), name);

  const denied = await register('dora');
  assert.equal(denied.ok, false, JSON.stringify(denied));
  assert.equal(denied.name, 'NotAllowedError');
  assert.equal(stack.notify.notifications().length, 1, 'the first unlisted site prompted');
  assert.equal(stack.notify.notifications()[0].summary, REGISTER_SUMMARY);

  // The same site again: the per-key cooldown.
  const again = await register('dora');
  assert.equal(again.ok, false, JSON.stringify(again));
  assert.equal(stack.notify.notifications().length, 1, 'no second prompt for the denied site');

  // Another unlisted site: the profile-wide wildcard registration cooldown.
  await b.page.goto(`${rpB.origin}/raw`);
  await b.page.waitForFunction(() => window.e2e);
  const other = await register('ed');
  assert.equal(other.ok, false, JSON.stringify(other));
  assert.equal(other.name, 'NotAllowedError');
  assert.equal(stack.notify.notifications().length, 1, 'the profile-wide cooldown refuses without a prompt');
  assert.equal(rpB.registrations.filter(r => r.ok).length, 0);

  // An exact-rule registration of the same profile is not a wildcard registration: it prompts, and the human approves.
  await b.page.goto(`${rpC.origin}/raw`);
  await b.page.waitForFunction(() => window.e2e);
  const exact = await register('fay');
  assert.equal(exact.ok, true, `an exact-rule registration is unaffected by the wildcard cooldown: ${JSON.stringify(exact)}`);
  assert.equal(stack.notify.notifications().length, 2, 'the exact rule prompted');
  assert.equal(stack.notify.notifications()[1].body.split('\n')[1], 'Site: rp-c.test (your rule for this site)');

  const audit = await stack.daemon.audit();
  assert.deepEqual(denyReasons(audit, { profile: 'coding', action: 'register' }).filter(r => r !== 'escalation_denied'),
    ['escalation_cooldown', 'wildcard_registration_cooldown'], 'the per-key cooldown, then the profile-wide one');
  assert.deepEqual(escalationEvents(audit, 'denied').map(e => [e.rp_id, e.cause]), [['rp-a.test', 'user']]);
  assert.deepEqual(escalationEvents(audit, 'requested').map(e => [e.rp_id, e.rule]), [['rp-a.test', '*'], ['rp-c.test', 'exact']]);
  assert.deepEqual(grantedRuleEvents(audit, 'add').map(e => [e.rp_id, e.rule, e.grant_kind]), [['rp-c.test', 'exact', 'registration']]);
});

// E2E-59/exact-later (review M1): a grant belongs to the rule it was approved through. The agent registers at rp-a.test
// through `*` and the human approves it once; the operator then lists rp-a.test with an exact `authenticate = "request"` rule
// (no pins) and the daemon restarts. The old grant (`rule = "*"`) must not upgrade that exact rule, and above all must not
// switch the candidates to discovery: a page that names the human's own passkey (alice) must prompt, and a deny must leave
// it unsigned. `profile check` reports the grant as inert.
scenario({ id: 'E2E-59/exact-later', exposeModes: ['port', 'pipe'], title: 'a wildcard registration grant does not upgrade a later exact request rule: the human\'s passkey needs a prompt, a deny signs nothing', ci: true, timeoutMs: 240000 }, async ctx => {
  const stack = await ctx.stack({
    rps: { a: { host: 'rp-a.test' } },
    profiles: { coding: { mode: 'same-user', ...WILDCARD } },
    notify: { script: ['approve:1500', 'deny:1500'] },
  });
  const rp = stack.rp.a;
  await stack.seedHuman(rp, 'alice');

  let b = await stack.open('coding', `${rp.origin}/raw`);
  assertInterceptionActive(b);
  await b.page.waitForFunction(() => window.e2e);
  const reg = await b.page.evaluate(u => window.e2e.register({ username: u, userVerification: 'preferred', timeout: 30000 }), user);
  assert.equal(reg.ok, true, `the approved registration completes: ${JSON.stringify(reg)}`);
  assert.equal(stack.notify.notifications().length, 1, 'one prompt: the registration');
  // The wildcard grant works as before while only `*` governs the site.
  assertVerifiedAssertion(rp, await authenticate(b.page, {}), { username: user });
  assert.equal(stack.notify.notifications().length, 1, 'the wildcard grant makes the sign-in prompt-free');
  assert.equal(grantsStore(stack, 'coding').grants.length, 1);

  // The operator lists the site with an exact rule that asks. No pins, so discovery would find alice.
  await stack.restartDaemon({
    coding: {
      mode: 'same-user',
      rules: [
        { rp: 'rp-a.test', authenticate: 'request', register: 'deny' },
        { rp: '*', authenticate: 'request', register: 'request' },
      ],
    },
  });
  b = await stack.open('coding', `${rp.origin}/raw`);
  assertInterceptionActive(b);
  const signedBefore = rp.authentications.filter(a => a.ok).length;
  const fingerprint = JSON.stringify(stack.daemon.humanStore().sort((x, y) => x.file.localeCompare(y.file)));

  // A sign-in that names the human's credential prompts (and the human denies): nothing is signed.
  const denied = await authenticate(b.page, { username: 'alice' });
  assert.equal(denied.ok, false, `the page named the human's passkey and must not get a silent assertion: ${JSON.stringify(denied)}`);
  assert.equal(denied.name, 'NotAllowedError');
  const notes = stack.notify.notifications();
  assert.equal(notes.length, 2, `the exact rule asked again: ${JSON.stringify(notes.map(n => n.summary))}`);
  assert.notEqual(notes[1].summary, REGISTER_SUMMARY, 'a sign-in prompt, not a registration one');
  assert.equal(rp.authentications.filter(a => a.ok).length, signedBefore, 'the RP saw no new assertion');
  assert.equal(rp.authentications.filter(a => a.ok && a.username === 'alice').length, 0, 'alice never signed in');
  assert.equal(JSON.stringify(stack.daemon.humanStore().sort((x, y) => x.file.localeCompare(y.file))), fingerprint, 'the store is unchanged');

  const audit = await stack.daemon.audit();
  const afterRestart = escalationEvents(audit, 'requested').filter(e => e.action === 'authenticate');
  assert.deepEqual(afterRestart.map(e => [e.rp_id, e.rule]), [['rp-a.test', 'exact']], JSON.stringify(afterRestart));
  assert.ok(!policyEvents(audit, 'policy.allow').some(e => e.action === 'authenticate' && e.rule === 'rp-a.test'),
    'no allow was recorded through the exact rule');

  // The doctor says why: the `*` grant is inert at a site an exact rule now governs.
  const report = await stack.daemon.adminJson('profile', 'check', 'coding');
  const inert = report.checks.find(c => c.name === 'granted_rules_inert');
  assert.ok(inert && inert.message.startsWith('warning:') && inert.message.includes('rp-a.test'), JSON.stringify(inert));
});
