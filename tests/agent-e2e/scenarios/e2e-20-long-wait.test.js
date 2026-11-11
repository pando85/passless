'use strict';
const { scenario, assert } = require('../lib/scenario');
const { policyEvents, assertVerifiedAssertion, assertInterceptionActive, waitFor, auditEvents, TRANSPORT_LOG, logMatches } = require('../lib/helpers');
const { connect, extensionWorkerTargets } = require('../lib/browser');
const { waitForPage } = require('../lib/stack');

// Catalogue E2E-20: a ceremony that waits longer than the MV3 five-minute limit still completes. The escalation that
// causes such a wait arrives in P7 (E2E-20/escalation below). The transport part is proven now: the daemon holds the
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

// P7: the real long wait is an escalation approved after about 6 minutes. Until P7 a `request` rule is denied at once
// (`escalation_unavailable`), so the ceremony does not stay pending.
scenario({
  id: 'E2E-20/escalation', title: 'escalation approved after 6 min completes',
  xfailUntil: 'P7', xfailMatch: /escalation is not pending/, xfailReason: 'escalation (request rules) arrives in P7; until then a request rule is denied immediately',
  timeoutMs: 600000,
}, async ctx => {
  const stack = await ctx.stack({
    rps: { a: { host: 'rp-a.test' } },
    profiles: { agent: { mode: 'same-user', max_session_ttl: 900, rules: [{ rp: 'rp-a.test', authenticate: 'request', register: 'deny' }] } },
  });
  const rp = stack.rp.a;
  await stack.seedHuman(rp, 'alice');
  const b = await stack.open('agent', `${rp.origin}/raw`);
  assertInterceptionActive(b);
  await b.page.waitForFunction(() => window.e2e);
  const key = await b.page.evaluate(t => window.e2e.start('authenticate', { username: 'alice', timeout: t }), PAGE_TIMEOUT_MS);
  await new Promise(r => setTimeout(r, 5000));
  const peek = await b.page.evaluate(k => window.e2e.peek(k), key);
  if (peek.settled) throw new Error(`escalation is not pending: the ceremony settled after ${peek.elapsedMs} ms with ${JSON.stringify(peek.result)}`);
  assert.ok(await stack.notify.waitForNotify(1), 'an escalation notification is shown');
  // P7: approve after about 6 minutes through the notification double, then assert the verified assertion and the
  // escalation audit (requested, approved).
  assert.fail('P7: approval of the pending escalation is not scripted yet');
});
