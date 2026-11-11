'use strict';
const { scenario, assert } = require('../lib/scenario');
const { policyEvents, escalationEvents, grantedRuleEvents, grantsStore, assertVerifiedAssertion, assertInterceptionActive, waitFor, auditEvents, TRANSPORT_LOG, logMatches } = require('../lib/helpers');
const { connect, extensionWorkerTargets } = require('../lib/browser');
const { waitForPage } = require('../lib/stack');

// Catalogue E2E-20: a ceremony that waits longer than the MV3 five-minute limit still completes. The transport part is
// proven with a held result (E2E-20); the real cause of such a wait, an escalation, is E2E-20/escalation below. The daemon holds the
// finished result for HOLD_MS > 5 min (PASSLESS_E2E_HOLD_RESULT_MS, debug builds) while the page waits with a 10 min
// timeout. The worker keeps one native port open with keepalives in both directions (plan D2, D6 layer 1), which must
// keep it alive: the worker never restarts (a single hello, no connection close) and the ceremony completes.
//
// Playwright is disconnected for the wait: its CDP connection auto-attaches to service workers like an open DevTools,
// which keeps a worker alive by itself (spike Q2). Only the result is read afterwards, from the RP and the page.
//
// Over 5 minutes of real time, so local-full only (not in the CI subset).
const HOLD_MS = 330000;
const PAGE_TIMEOUT_MS = 600000;

scenario({ id: 'E2E-20', title: 'long wait (> 5 min) completes: native-port keepalive beats the MV3 limit', timeoutMs: HOLD_MS + 180000 }, async ctx => {
  const stack = await ctx.stack({
    rps: { a: { host: 'rp-a.test' } },
    profiles: { agent: { mode: 'same-user', max_session_ttl: 900, rules: [{ rp: 'rp-a.test', authenticate: 'allow', register: 'deny' }] } },
    daemonEnv: { PASSLESS_E2E_HOLD_RESULT_MS: String(HOLD_MS) },
  });
  const rp = stack.rp.a;
  await stack.seedHuman(rp, 'alice');
  const url = `${rp.origin}/raw`;
  const b = await stack.open('agent', url);
  assertInterceptionActive(b);
  await b.page.waitForFunction(() => window.e2e);
  assert.equal((await extensionWorkerTargets(b.browser)).length, 1, 'the extension worker runs');

  const key = await b.page.evaluate(t => window.e2e.start('authenticate', { username: 'alice', timeout: t }), PAGE_TIMEOUT_MS);
  await waitFor('the daemon to admit the request', () => logMatches(stack.daemon.log(), TRANSPORT_LOG.admitted).length === 1);
  const startedAt = Date.now();
  await b.browser.close(); // disconnects Playwright; the managed browser keeps running
  assert.doesNotThrow(() => process.kill(b.lease.pid, 0), 'the managed browser must keep running after Playwright disconnects');

  const ev = await waitFor('the RP to verify the held assertion', () => rp.authentications[0], { timeoutMs: HOLD_MS + 60000, intervalMs: 2000 });
  const waitedMs = Date.now() - startedAt;
  assert.ok(waitedMs >= 300000, `the ceremony must have waited past 5 minutes (${waitedMs} ms)`);
  assert.equal(ev.ok, true, `RP verification failed: ${ev.error}`);

  // The worker never restarted: one hello, the connection never closed, no degraded interception.
  const log = stack.daemon.log();
  assert.deepEqual(logMatches(log, TRANSPORT_LOG.hello).map(h => h[1]), ['true'], 'a single hello: the worker never restarted');
  assert.deepEqual(logMatches(log, TRANSPORT_LOG.closed), [], 'the worker connection never closed');
  const audit = await stack.daemon.audit();
  assert.deepEqual(auditEvents(audit).filter(e => e.kind === 'browser_lease.interception'), [], 'the lease never degraded');
  assert.equal(policyEvents(audit, 'policy.allow').length, 1);

  // The page got the credential.
  const again = await connect(b.cdpUrl);
  stack.browsers.push({ browser: again.browser });
  assert.equal((await extensionWorkerTargets(again.browser)).length, 1, 'the extension worker still runs');
  const page = await waitForPage(again.context, url);
  const peek = await page.evaluate(k => window.e2e.peek(k), key);
  assert.equal(peek.settled, true);
  assertVerifiedAssertion(rp, peek.result, { username: 'alice' });
  ctx.t.diagnostic(`E2E-20 [${ctx.variant.name}]: ceremony completed after ${peek.elapsedMs} ms with one worker instance`);
});

// P7: the real long wait. An escalation is approved by the human after 6 minutes (the double's `approve:360000`), longer than the
// MV3 service worker's five-minute limit: the ceremony parks in the daemon, the worker's native port keeps it alive (same
// mechanism as above), and on approval the assertion completes, the grant is stored and the audit shows requested and approved.
// The page timeout (10 min) is past the approval, the profile's session TTL (900 s) too.
//
// Playwright is disconnected during the wait (see above) and reattached afterwards to read the page.
const APPROVE_AFTER_MS = 360000;

scenario({ id: 'E2E-20/escalation', title: 'escalation approved after 6 min completes', timeoutMs: APPROVE_AFTER_MS + 240000 }, async ctx => {
  const stack = await ctx.stack({
    rps: { a: { host: 'rp-a.test' } },
    profiles: { agent: { mode: 'same-user', max_session_ttl: 900, rules: [{ rp: 'rp-a.test', authenticate: 'request', register: 'deny' }] } },
    notify: { script: [`approve:${APPROVE_AFTER_MS}`] },
  });
  const rp = stack.rp.a;
  await stack.seedHuman(rp, 'alice');
  const url = `${rp.origin}/raw`;
  const b = await stack.open('agent', url);
  assertInterceptionActive(b);
  await b.page.waitForFunction(() => window.e2e);
  assert.equal((await extensionWorkerTargets(b.browser)).length, 1, 'the extension worker runs');

  const key = await b.page.evaluate(t => window.e2e.start('authenticate', { username: 'alice', timeout: t }), PAGE_TIMEOUT_MS);
  assert.ok(await stack.notify.waitForNotify(1), 'an escalation notification is shown');
  const startedAt = Date.now();
  await new Promise(r => setTimeout(r, 3000));
  assert.equal((await b.page.evaluate(k => window.e2e.peek(k), key)).settled, false, 'the escalation is pending');
  await b.browser.close(); // disconnects Playwright; the managed browser keeps running
  assert.doesNotThrow(() => process.kill(b.lease.pid, 0), 'the managed browser must keep running after Playwright disconnects');

  const ev = await waitFor('the RP to verify the approved assertion', () => rp.authentications[0], { timeoutMs: APPROVE_AFTER_MS + 90000, intervalMs: 2000 });
  const waitedMs = Date.now() - startedAt;
  assert.ok(waitedMs >= 300000, `the ceremony must have waited past 5 minutes (${waitedMs} ms)`);
  assert.equal(ev.ok, true, `RP verification failed: ${ev.error}`);

  // The worker never restarted: one hello, the connection never closed, no degraded interception.
  const log = stack.daemon.log();
  assert.deepEqual(logMatches(log, TRANSPORT_LOG.hello).map(h => h[1]), ['true'], 'a single hello: the worker never restarted');
  assert.deepEqual(logMatches(log, TRANSPORT_LOG.closed), [], 'the worker connection never closed');
  const audit = await stack.daemon.audit();
  assert.deepEqual(auditEvents(audit).filter(e => e.kind === 'browser_lease.interception'), [], 'the lease never degraded');
  assert.deepEqual(escalationEvents(audit, 'requested').map(e => [e.rp_id, e.rule]), [['rp-a.test', 'exact']]);
  assert.equal(escalationEvents(audit, 'approved').length, 1);
  assert.deepEqual(grantedRuleEvents(audit, 'add').map(e => [e.rp_id, e.grant_kind]), [['rp-a.test', 'escalation']]);
  assert.deepEqual(grantsStore(stack).grants.map(g => g.rp_id), ['rp-a.test'], 'the grant is stored');
  assert.equal(stack.notify.notifications().length, 1);

  // The page got the credential.
  const again = await connect(b.cdpUrl);
  stack.browsers.push({ browser: again.browser });
  const page = await waitForPage(again.context, url);
  const peek = await page.evaluate(k => window.e2e.peek(k), key);
  assert.equal(peek.settled, true);
  assertVerifiedAssertion(rp, peek.result, { username: 'alice' });
  ctx.t.diagnostic(`E2E-20/escalation [${ctx.variant.name}]: approved ceremony completed after ${peek.elapsedMs} ms`);
});
