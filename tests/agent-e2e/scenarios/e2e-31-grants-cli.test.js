'use strict';
const fs = require('node:fs');

const { scenario, assert } = require('../lib/scenario');
const { escalationEvents, grantedRuleEvents, denyReasons, grantsStore, authenticate, assertVerifiedAssertion, assertInterceptionActive, extensionEndpoint, FramedClient, signRequest, policyEvents, auditEvents, TRANSPORT_LOG, logMatches, waitFor } = require('../lib/helpers');
const { stopExtensionWorker } = require('../lib/browser');
const { requestProfile } = require('../lib/escalation');

// ADR 0014 section 8.4 and the WP1 admin CLI: `agent-admin grants list|revoke|clear`. A revocation bumps the revocation epoch
// (active sessions die and the daemon terminates their browsers), so a fresh browser is launched before the next ceremony,
// which prompts again. A store file that
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

// A revocation (and a clear) bumps the revocation epoch: the daemon revokes every stale bearer and terminates its browser,
// the admin-launched one included. The scenario waits for the browser process to go, then launches a fresh one: it has a
// new bearer and the start-URL tab (a relaunch that handed back the dead browser would not).
const pidAlive = pid => { try { process.kill(pid, 0); return true; } catch (e) { return e.code === 'EPERM'; } };
async function assertBrowserTerminated(b, what) {
  await waitFor(`the daemon to terminate the browser after ${what}`, () => !pidAlive(b.lease.pid));
}
async function relaunchBrowser(stack, old, rp, what) {
  await assertBrowserTerminated(old, what);
  const audit = await stack.daemon.audit();
  assert.ok(auditEvents(audit).some(e => e.kind === 'browser_lease.revoke'), `${what}: the lease revocation is audited`);
  const fresh = await stack.open('agent', `${rp.origin}/sw`);
  assert.notEqual(fresh.lease.pid, old.lease.pid, `${what}: a fresh browser, not the revoked one`);
  assert.ok(fresh.page.url().startsWith(rp.origin), `${what}: the fresh browser has the start URL, at ${fresh.page.url()}`);
  return fresh;
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

  // The harness holds the browser's bearer over the daemon's wire protocol (as E2E-11 does), with the worker stopped so
  // this client is the bearer's only connection: after the revocation it proves the bearer is refused and audited.
  const endpoint = await extensionEndpoint(b);
  await stopExtensionWorker(b.browser);
  await waitFor('the daemon to see the worker connection close', () => logMatches(stack.daemon.log(), TRANSPORT_LOG.closed).length >= 1);
  const oldClient = await FramedClient.connect(endpoint.socketPath);
  assert.equal((await oldClient.hello(endpoint)).type, 'hello', 'the live bearer is accepted');

  // revoke one RP: every session dies and the browser is terminated, the next ceremony at that RP prompts again, the other
  // grant survives
  const revoked = await stack.daemon.adminJson('grants', 'revoke', '--profile', 'agent', '--rp', 'rp-a.test', '--confirm');
  assert.equal(revoked.revoked, 1, JSON.stringify(revoked));
  assert.deepEqual(rpsOf(await grantRules(stack)), ['rp-b.test']);
  assert.deepEqual(grantsStore(stack).grants.map(g => g.rp_id), ['rp-b.test'], 'the store file follows');
  assert.deepEqual(grantedRuleEvents(await stack.daemon.audit(), 'revoke').map(e => e.rp_id), ['rp-a.test']);
  assert.equal(notified(), 2, 'a revoked session does not prompt');
  // The old bearer is dead: a request on it is refused and audited `bearer_revoked`, never silently `unauthorized`.
  let auditSnapshot = await stack.daemon.audit();
  const refusals = () => policyEvents(auditSnapshot, 'policy.deny').filter(e => e.profile_id === 'agent' && e.reason === 'bearer_revoked');
  assert.equal(refusals().length, 0, 'nothing was refused before the harness used the old bearer');
  const late = await oldClient.request(2, 'get', signRequest({ origin: rpB.origin, rpId: 'rp-b.test' }));
  assert.equal(late.type, 'result', JSON.stringify(late));
  assert.equal(late.ok, false, `the revoked bearer must not sign: ${JSON.stringify(late)}`);
  assert.equal(late.error.code, 'unauthorized', JSON.stringify(late));
  assert.equal(late.error.dom, 'NotAllowedError', JSON.stringify(late));
  oldClient.close();
  auditSnapshot = await stack.daemon.audit();
  assert.deepEqual(refusals().map(e => [e.action, e.rp_id]), [['authenticate', 'rp-b.test']], JSON.stringify(auditSnapshot.map(e => (e.event || e).kind)));
  assert.equal(notified(), 2, 'a refused request does not prompt');

  b = await relaunchBrowser(stack, b, rpA, 'revoking one RP');
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
  b = await relaunchBrowser(stack, b, rpB, 'clearing every grant');
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
