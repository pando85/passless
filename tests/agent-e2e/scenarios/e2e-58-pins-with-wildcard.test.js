'use strict';
const fs = require('node:fs');
const path = require('node:path');

const { scenario, assert } = require('../lib/scenario');
const { authenticate, auditEvents, policyEvents, denyReasons, assertVerifiedAssertion, assertInterceptionActive } = require('../lib/helpers');

// ADR 0014 amendment section 2.1 (Phase 1, change 1): profile `credential_refs` coexist with a `*` rule. The pins
// constrain operations that resolve through an exact rule and never apply to one that resolves through `*`.
//
//   rp-a.test  exact `allow`, two human credentials (alice, bob), profile pin = alice  -> signs with alice only, never
//                                                                                          ambiguous, never bob
//   rp-b.test  no exact rule, `*` `allow`, one credential (carol)                      -> discovered through `*`
//   then alice's credential is deleted: rp-a.test has a pin and no pinned credential   -> fails closed (the profile has `*`,
//                                                                                          and bob is still there, but an
//                                                                                          exact RP never falls through)
// The operator surfaces say the same: `agent-admin profile check` and `passless doctor --agents` print what the pins cover
// and warn about the pin that is gone. The audit records where the candidates came from (`credential_scope`).
const PROFILE = pins => ({
  coding: {
    mode: 'same-user',
    rules: [
      { rp: 'rp-a.test', authenticate: 'allow', register: 'deny' },
      { rp: '*', authenticate: 'allow', register: 'deny' },
    ],
    extra: { credential_refs: pins },
  },
});

const checkOf = (checks, name) => checks.find(c => c.name === name);

scenario({ id: 'E2E-58', exposeModes: ['port', 'pipe'], title: 'pins with `*`: an exact RP signs only with its pin, an unlisted RP discovers through `*`, a missing pin fails closed with no fallthrough', ci: true, timeoutMs: 240000 }, async ctx => {
  const stack = await ctx.stack({
    rps: { a: { host: 'rp-a.test' }, b: { host: 'rp-b.test' } },
    // The pin is a credential reference, which exists only after seeding: the profile is configured by restart below.
    profiles: PROFILE([]),
  });
  const [rpA, rpB] = [stack.rp.a, stack.rp.b];
  await stack.seedHuman(rpA, 'alice');
  await stack.seedHuman(rpA, 'bob');
  await stack.seedHuman(rpB, 'carol');
  // `credential list` without --domain covers only the RPs of exact rules; --domain asks about one RP the profile reaches.
  const credentials = [
    ...(await stack.daemon.adminJson('credential', 'list', '--domain', 'rp-a.test')).credentials,
    ...(await stack.daemon.adminJson('credential', 'list', '--domain', 'rp-b.test')).credentials,
  ];
  const refOf = name => (credentials.find(c => c.user_name === name) || {}).credential_ref;
  const [aliceRef, bobRef, carolRef] = ['alice', 'bob', 'carol'].map(refOf);
  assert.ok(aliceRef && bobRef && carolRef, `credential refs: ${JSON.stringify(credentials)}`);

  // The daemon must start with pins together with `*` (it refused that configuration before the amendment).
  await stack.restartDaemon(PROFILE([aliceRef]));

  const b = await stack.open('coding', `${rpA.origin}/sw`);
  assertInterceptionActive(b);

  // An exact RP: the pin decides. Two credentials exist and `single` selection would fail on ambiguity without it.
  assertVerifiedAssertion(rpA, await authenticate(b.page, {}), { username: 'alice' });
  // Naming the other credential does not get around the pin: allowCredentials chooses within the pinned set only.
  const bobTry = await authenticate(b.page, { username: 'bob' });
  assert.equal(bobTry.ok, false, `bob is not pinned: ${JSON.stringify(bobTry)}`);
  assert.equal(bobTry.name, 'NotAllowedError');

  // An unlisted RP: matched by `*`, so the pin list does not apply and discovery finds the site's one credential.
  await b.page.goto(`${rpB.origin}/sw`);
  assertVerifiedAssertion(rpB, await authenticate(b.page, {}), { username: 'carol' });

  // The doctor surfaces: what the pins cover, and that every pin is in the store.
  let report = await stack.daemon.adminJson('profile', 'check', 'coding');
  let coverage = checkOf(report.checks, 'pin_coverage');
  assert.ok(coverage, `profile check has a pin_coverage check: ${JSON.stringify(report.checks.map(c => c.name))}`);
  assert.equal(coverage.message, 'credential_refs (1) constrain the 1 exact rule(s); RPs matched by `*` use discovery');
  let health = checkOf(report.checks, 'pin_health');
  assert.ok(health && health.passed && !health.message.startsWith('warning:'), JSON.stringify(health));

  // The pinned credential disappears from the store (the file is removed, as an operator or a store sync would do; the
  // daemon never deletes human credentials through the admin CLI) and the daemon restarts, which rebuilds its index from
  // the directory. rp-a.test now has a pin that points at nothing, and bob is still there.
  const aliceId = Buffer.from(rpA.registrations.find(r => r.username === 'alice').credentialId, 'base64url').toString('hex');
  const aliceFile = stack.daemon.humanStore().find(f => f.file.endsWith(`${aliceId}.bin`));
  assert.ok(aliceFile, `alice's credential file: ${JSON.stringify(stack.daemon.humanStore())}`);
  fs.rmSync(path.join(stack.env.dirs.store, aliceFile.file));
  await stack.restartDaemon(PROFILE([aliceRef]));
  const b2 = await stack.open('coding', `${rpA.origin}/sw`);
  assertInterceptionActive(b2);
  const gone = await authenticate(b2.page, {});
  assert.equal(gone.ok, false, `a missing pin must fail closed, bob and the wildcard notwithstanding: ${JSON.stringify(gone)}`);
  assert.equal(gone.name, 'NotAllowedError');
  assert.equal(rpA.authentications.filter(a => a.username === 'bob').length, 0, 'bob never signed in');
  // `*` is untouched by the missing pin.
  await b2.page.goto(`${rpB.origin}/sw`);
  assertVerifiedAssertion(rpB, await authenticate(b2.page, {}), { username: 'carol' });

  // The same two checks after the deletion: coverage is unchanged and the pin is reported missing, by ref prefix only.
  report = await stack.daemon.adminJson('profile', 'check', 'coding');
  health = checkOf(report.checks, 'pin_health');
  assert.ok(health.passed, 'a warning never makes the profile unhealthy');
  assert.match(health.message, /^warning: pin [0-9a-f]{12} is not in the store/);
  assert.ok(!health.message.includes(aliceRef), 'the full reference is never printed');
  assert.match(health.message, /fail closed/);
  coverage = checkOf(report.checks, 'pin_coverage');
  assert.equal(coverage.message, 'credential_refs (1) constrain the 1 exact rule(s); RPs matched by `*` use discovery');

  // `passless doctor --agents` runs the same checks offline, reading the store through its path index only.
  const doctor = await stack.daemon.doctorAgents();
  const offline = checkOf(doctor.checks, 'coding: pin_health');
  assert.ok(offline, `doctor --agents reports pin_health per profile: ${JSON.stringify(doctor.checks.map(c => c.name))}`);
  assert.match(offline.message, /^warning: pin [0-9a-f]{12} is not in the store/);
  assert.equal(checkOf(doctor.checks, 'coding: pin_coverage').message, coverage.message);

  // Audit (amendment section 8): the candidate source of every operation. A deny after the candidate set was chosen has one too.
  const audit = await stack.daemon.audit();
  const allows = policyEvents(audit, 'policy.allow').filter(e => e.profile_id === 'coding' && e.action === 'authenticate');
  assert.deepEqual(allows.map(e => [e.rp_id, e.rule, e.credential_scope]), [
    ['rp-a.test', 'exact', 'pinned'],
    ['rp-b.test', '*', 'discovered'],
    ['rp-b.test', '*', 'discovered'],
  ], JSON.stringify(allows));
  assert.deepEqual(allows.slice(0, 1).map(e => e.credential_ref), [aliceRef], 'the pinned credential signed');
  assert.deepEqual(allows.slice(1).map(e => e.credential_ref), [carolRef, carolRef]);
  const denies = policyEvents(audit, 'policy.deny').filter(e => e.profile_id === 'coding' && e.rp_id === 'rp-a.test');
  assert.deepEqual(denies.map(e => e.reason), ['allow_credentials_mismatch', 'credential_not_match'], JSON.stringify(denies));
  assert.deepEqual(denies.map(e => e.rule), ['exact', 'exact'], 'an exact RP is never audited as matched through `*`');
  assert.deepEqual(denyReasons(audit, { profile: 'coding', rpId: 'rp-b.test' }), []);
  assert.equal(auditEvents(audit).filter(e => e.kind === 'policy.allow' && e.profile_id === 'coding' && e.rp_id === 'rp-a.test').length, 1);
});
