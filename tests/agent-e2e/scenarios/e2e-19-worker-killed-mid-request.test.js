'use strict';
const { scenario, assert } = require('../lib/scenario');
const { authenticate, policyEvents, storeFingerprint, assertVerifiedAssertion, assertInterceptionActive, waitFor, TRANSPORT_LOG, logMatches, HUMAN_CTAP_LOG } = require('../lib/helpers');
const { stopExtensionWorker, extensionWorkerTargets } = require('../lib/browser');

// Catalogue: the worker dies while a request is pending. The daemon holds the request before key use
// (PASSLESS_E2E_HOLD_REQUEST_MS) and the worker target is closed meanwhile. Its native port closes, the relay exits, and
// the connection EOF cancels the request in the daemon: no signature, no result, the audit's terminal record is
// `policy.deny(reason=aborted)`, and nothing stays in flight (the next request works).
//
// Page side (not covered by the spike): either Chromium fails the pending proxy request itself when the worker dies,
// or the request stays pending until a new worker instance starts and fails the leftover ids it finds in
// chrome.storage.session (ADR 0014 §11). The scenario waits WAIT_MS for the first; if the page is still pending it wakes
// the worker from another tab with isUserVerifyingPlatformAuthenticatorAvailable() (answered by the proxy) and records
// which path settled the page. Either way the page must get NotAllowedError.
const HOLD_MS = 8000;
const WAIT_MS = 8000;

// Port-only: stops/kills the extension worker target over CDP; the extension worker is hidden from the agent in pipe mode by design (ADR 0014 §4.3, E2E-52).
scenario({ id: 'E2E-19', title: 'worker killed during a pending request: NotAllowedError, daemon cancels, nothing orphaned' }, async ctx => {
  const stack = await ctx.stack({
    rps: { a: { host: 'rp-a.test' } },
    profiles: { agent: { mode: 'same-user', rules: [{ rp: 'rp-a.test', authenticate: 'allow', register: 'deny' }] } },
    daemonEnv: { PASSLESS_E2E_HOLD_REQUEST_MS: String(HOLD_MS) },
  });
  const rp = stack.rp.a;
  await stack.seedHuman(rp, 'alice');
  const b = await stack.open('agent', `${rp.origin}/raw`);
  assertInterceptionActive(b);
  await b.page.waitForFunction(() => window.e2e);
  const storeBefore = storeFingerprint(stack.daemon);
  const logBefore = stack.daemon.log().length;

  const key = await b.page.evaluate(() => window.e2e.start('authenticate', { username: 'alice', timeout: 120000 }));
  const [[conn, id]] = await waitFor('the daemon to admit the request', () => {
    const m = logMatches(stack.daemon.log().slice(logBefore), TRANSPORT_LOG.admitted);
    return m.length ? m : null;
  });
  await stopExtensionWorker(b.browser);

  // Daemon side: EOF cancels the in-flight request; no result is written.
  await waitFor('the daemon to cancel the request', () =>
    logMatches(stack.daemon.log().slice(logBefore), TRANSPORT_LOG.answered).some(([c, i]) => c === conn && i === id), { timeoutMs: HOLD_MS + 5000 });
  const log = stack.daemon.log().slice(logBefore);
  assert.deepEqual(logMatches(log, TRANSPORT_LOG.closed).filter(([c]) => c === conn), [[conn, '1']], 'the connection EOF cancelled the one in-flight request');
  assert.deepEqual(logMatches(log, TRANSPORT_LOG.answered).filter(([c, i]) => c === conn && i === id), [[conn, id, 'not answered (connection closed)', 'aborted']],
    'the cancelled request writes no result');

  // Page side.
  let settledBy = 'chromium';
  let peek = await waitFor('the page to settle', async () => {
    const p = await b.page.evaluate(k => window.e2e.peek(k), key);
    return p.settled ? p : null;
  }, { timeoutMs: WAIT_MS }).catch(() => null);
  if (!peek) {
    settledBy = 'next worker start (storage.session leftovers)';
    assert.deepEqual(await extensionWorkerTargets(b.browser), [], 'no worker runs while the page is still pending');
    const waker = await b.context.newPage();
    await waker.goto(`${rp.origin}/raw`);
    const uvpaa = await waker.evaluate(() => PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable());
    assert.equal(uvpaa, false, 'the proxy answers UVPAA with false');
    await waker.close();
    await b.page.bringToFront();
    peek = await waitFor('the page to settle after the worker restarted', async () => {
      const p = await b.page.evaluate(k => window.e2e.peek(k), key);
      return p.settled ? p : null;
    }, { timeoutMs: 10000 });
  }
  ctx.t.diagnostic(`E2E-19 [${ctx.variant.name}]: page settled by ${settledBy} after ${peek.elapsedMs} ms: ${JSON.stringify(peek.result)}`);
  assert.equal(peek.result.ok, false, JSON.stringify(peek.result));
  assert.equal(peek.result.name, 'NotAllowedError', `the page must get NotAllowedError: ${JSON.stringify(peek.result)}`);

  // No signature, terminal record audited.
  assert.equal(rp.authentications.length, 0, 'the RP must never receive an assertion');
  assert.equal(storeFingerprint(stack.daemon), storeBefore, 'no key use: store (incl. counters) unchanged');
  const audit = await stack.daemon.audit();
  assert.deepEqual(policyEvents(audit, 'policy.deny').map(e => [e.rp_id, e.reason]), [['rp-a.test', 'aborted']], 'the terminal record is an aborted deny');
  assert.equal(policyEvents(audit, 'policy.allow').length, 0);

  // Nothing orphaned: the next request works (it waits out the request hold once more).
  const next = await authenticate(b.page, { username: 'alice', timeout: 60000 });
  assertVerifiedAssertion(rp, next, { username: 'alice' });
  assert.doesNotMatch(stack.daemon.log().slice(logBefore), HUMAN_CTAP_LOG, 'the human authenticator handled a request');
});
