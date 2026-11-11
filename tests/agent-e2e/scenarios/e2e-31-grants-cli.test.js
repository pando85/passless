'use strict';
const fs = require('node:fs');

const { scenario, assert } = require('../lib/scenario');
const { escalationEvents, grantedRuleEvents, denyReasons, grantsStore, authenticate, assertVerifiedAssertion, assertInterceptionActive, TRANSPORT_LOG, logMatches, waitFor } = require('../lib/helpers');
const { requestProfile } = require('../lib/escalation');

// ADR 0014 section 8.4 and the WP1 admin CLI: `agent-admin grants list|revoke|clear`. A revocation bumps the revocation epoch
// (active sessions die), so the browser is launched again before the next ceremony, which prompts again. A store file that
// does not parse, or that group/other can read, disables grants for the profile: escalation is then denied
// `grants_unavailable`, and `agent-admin profile check` (the doctor report) lists a failed `granted_rules` check. The store
// is read at daemon start, so those files are put in place before a daemon restart.
const PROFILES = { agent: requestProfile(['rp-a.test', 'rp-b.test']) };

const grantRules = async (stack, profile = 'agent') => {
  const list = await stack.daemon.adminJson('grants', 'list', '--profile', profile);
  assert.equal(list.profiles.length, 1, JSON.stringify(list));
  return list.profiles[0];
};
const rpsOf = p => p.rules.map(r => r.rp_id).sort();

// A revocation revokes the bearers but leaves the managed browser running: `browser launch` would hand back that browser
// with its dead bearer (and no start-URL tab). The operator restarts the browser; the harness kills it the way E2E-11 does
// and waits for the daemon to notice.
async function restartBrowser(stack, b, rp) {
  const crashes = () => stack.daemon.audit().then(a => a.filter(e => (e.event || e).kind === 'browser_lease.crash').length);
  const before = await crashes();
  stack.env.killTree(b.lease.pid);
  await waitFor('the daemon to record the browser exit', async () => (await crashes()) > before);
  return stack.open('agent', `${rp.origin}/sw`);
}

scenario({ id: 'E2E-31', title: 'grants CLI: list, revoke, clear; revocation kills sessions; a damaged store gives grants_unavailable and a doctor failure', ci: true, timeoutMs: 240000 }, async ctx => {
  const stack = await ctx.stack({
    rps: { a: { host: 'rp-a.test' }, b: { host: 'rp-b.test' } },
    profiles: PROFILES,
    notify: { script: Array(8).fill('approve:1500') },
  });
  const [rpA, rpB] = [stack.rp.a, stack.rp.b];
  await stack.seedHuman(rpA, 'alice');
  await stack.seedHuman(rpB, 'bob');
  const notified = () => stack.notify.notifications().length;

  let b = await stack.open('agent', `${rpA.origin}/sw`);
  assertInterceptionActive(b);
  assertVerifiedAssertion(rpA, await authenticate(b.page, { username: 'alice' }), { username: 'alice' });
  await b.page.goto(`${rpB.origin}/sw`);
  assertVerifiedAssertion(rpB, await authenticate(b.page, { username: 'bob' }), { username: 'bob' });
  assert.equal(notified(), 2);

  // list
  const listed = await grantRules(stack);
  assert.equal(listed.enabled, true);
  assert.deepEqual(rpsOf(listed), ['rp-a.test', 'rp-b.test']);
  assert.ok(listed.rules.every(r => r.action === 'authenticate' && r.kind === 'escalation' && r.rule === 'exact'), JSON.stringify(listed.rules));
  assert.deepEqual((await stack.daemon.adminJson('grants', 'list')).profiles.map(p => p.profile_id), ['agent'], 'list without --profile covers every profile');

  // revoke one RP: the session dies, the next ceremony at that RP prompts again, the other grant survives
  const revoked = await stack.daemon.adminJson('grants', 'revoke', '--profile', 'agent', '--rp', 'rp-a.test', '--confirm');
  assert.equal(revoked.revoked, 1, JSON.stringify(revoked));
  assert.deepEqual(rpsOf(await grantRules(stack)), ['rp-b.test']);
  assert.deepEqual(grantsStore(stack).grants.map(g => g.rp_id), ['rp-b.test'], 'the store file follows');
  assert.deepEqual(grantedRuleEvents(await stack.daemon.audit(), 'revoke').map(e => e.rp_id), ['rp-a.test']);
  const stale = await authenticate(b.page, { username: 'bob' });
  assert.equal(stale.ok, false, `the revoked session must not sign: ${JSON.stringify(stale)}`);
  assert.equal(stale.name, 'NotAllowedError');
  assert.equal(notified(), 2, 'a revoked session does not prompt');
  assert.deepEqual(logMatches(stack.daemon.log(), TRANSPORT_LOG.refused).map(m => m[2]), ['unauthorized'], 'the transport refused the revoked bearer');

  b = await restartBrowser(stack, b, rpA);
  assertInterceptionActive(b);
  assertVerifiedAssertion(rpA, await authenticate(b.page, { username: 'alice' }), { username: 'alice' });
  assert.equal(notified(), 3, 'the revoked RP prompts again');
  assert.deepEqual(rpsOf(await grantRules(stack)), ['rp-a.test', 'rp-b.test']);
  await b.page.goto(`${rpB.origin}/sw`);
  assertVerifiedAssertion(rpB, await authenticate(b.page, { username: 'bob' }), { username: 'bob' });
  assert.equal(notified(), 3, 'the surviving grant needs no prompt');

  // clear: every grant goes
  const cleared = await stack.daemon.adminJson('grants', 'clear', '--profile', 'agent', '--confirm');
  assert.equal(cleared.revoked, 2, JSON.stringify(cleared));
  assert.deepEqual((await grantRules(stack)).rules, []);
  assert.deepEqual(grantsStore(stack).grants, []);
  b = await restartBrowser(stack, b, rpB);
  assertVerifiedAssertion(rpB, await authenticate(b.page, { username: 'bob' }), { username: 'bob' });
  assert.equal(notified(), 4, 'after clear every RP prompts again');

  // a damaged store disables grants for the profile (it is read at start-up: restart with the file in place)
  const storeFile = grantsStore(stack).path;
  const damaged = [
    ['garbage', 'this is not = = toml\n', 0o600, /does not parse|parse/i],
    ['mode 0644', 'version = 1\n', 0o644, /mode|permission|readable/i],
  ];
  for (const [name, content, mode, reason] of damaged) {
    await stack.daemon.stop();
    fs.writeFileSync(storeFile, content, { mode });
    fs.chmodSync(storeFile, mode);
    await stack.restartDaemon(PROFILES);
    const before = notified();

    const report = await stack.daemon.adminJson('profile', 'check', 'agent');
    const check = (report.checks || []).find(c => c.name === 'granted_rules');
    assert.ok(check, `${name}: the doctor report has a granted_rules check: ${JSON.stringify(report.checks)}`);
    assert.equal(check.passed, false, `${name}: ${check.message}`);
    assert.match(check.message, reason, `${name}: ${check.message}`);
    const profile = await grantRules(stack);
    assert.equal(profile.enabled, false, `${name}: ${JSON.stringify(profile)}`);
    assert.deepEqual(profile.rules, []);

    const b2 = await stack.open('agent', `${rpA.origin}/sw`);
    const res = await authenticate(b2.page, { username: 'alice' });
    assert.equal(res.ok, false, `${name}: ${JSON.stringify(res)}`);
    assert.equal(res.name, 'NotAllowedError');
    assert.equal(notified(), before, `${name}: no prompt while grants are unavailable`);
    const audit = await stack.daemon.audit();
    assert.equal(denyReasons(audit, { rpId: 'rp-a.test' }).at(-1), 'grants_unavailable', `${name}: ${JSON.stringify(denyReasons(audit, { rpId: 'rp-a.test' }))}`);
    assert.equal(fs.readFileSync(storeFile, 'utf8'), content, `${name}: the damaged file is left for the operator`);
  }
  assert.ok(escalationEvents(await stack.daemon.audit(), 'approved').length >= 4);
});
