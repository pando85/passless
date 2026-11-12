'use strict';
const { scenario, assert } = require('../lib/scenario');
const { policyEvents, storeFingerprint, assertInterceptionActive, assertNoNotification, waitFor, TRANSPORT_LOG, logMatches, HUMAN_CTAP_LOG } = require('../lib/helpers');

// Catalogue: an AbortSignal aborts a request mid-flight. Chromium rejects the page's promise with AbortError and fires
// onRequestCanceled; the worker sends `abort{id}`; the daemon cancels the request (ADR 0014 §11).
//
// Two moments matter:
// - E2E-17: the abort lands BEFORE key use. The debug hook PASSLESS_E2E_HOLD_REQUEST_MS holds each request before its
//   ceremony starts. Guarantee: no signature at all (human store and counters unchanged, nothing reaches the RP), and
//   the audit's terminal record is `policy.deny(reason=aborted)`.
// - E2E-17/after-key-use: the abort lands AFTER key use, while the daemon holds the finished result
//   (PASSLESS_E2E_HOLD_RESULT_MS). Guarantee: the result is discarded (the daemon answers `aborted`, the page and the RP
//   never see the assertion). The key was used, so the audit shows the allow and the counter moved.
const HOLD_MS = 6000;

async function setup(ctx, daemonEnv) {
  const stack = await ctx.stack({
    rps: { a: { host: 'rp-a.test' } },
    profiles: { agent: { mode: 'same-user', rules: [{ rp: 'rp-a.test', authenticate: 'allow', register: 'deny' }] } },
    daemonEnv,
  });
  const rp = stack.rp.a;
  await stack.seedHuman(rp, 'alice');
  const b = await stack.open('agent', `${rp.origin}/raw`);
  assertInterceptionActive(b);
  await b.page.waitForFunction(() => window.e2e);
  return { stack, rp, b };
}

/** Start a get, wait until the daemon admitted it, run `beforeAbort`, abort in the page; returns the page result. */
async function abortMidRequest(stack, b, beforeAbort = async () => {}) {
  const logBefore = stack.daemon.log().length;
  const key = await b.page.evaluate(() => window.e2e.start('authenticate', { username: 'alice', timeout: 60000 }));
  const [[conn, id]] = await waitFor('the daemon to admit the request', () => {
    const m = logMatches(stack.daemon.log().slice(logBefore), TRANSPORT_LOG.admitted);
    return m.length ? m : null;
  });
  await beforeAbort();
  const t0 = Date.now();
  await b.page.evaluate(k => window.e2e.abort(k), key);
  const res = await b.page.evaluate(k => window.e2e.result(k), key);
  return { res, conn, id, abortToSettleMs: Date.now() - t0, logBefore };
}

scenario({ id: 'E2E-17', exposeModes: ['port', 'pipe'], title: 'AbortSignal before key use: AbortError, daemon cancels, no signature, audited aborted', ci: true }, async ctx => {
  const { stack, rp, b } = await setup(ctx, { PASSLESS_E2E_HOLD_REQUEST_MS: String(HOLD_MS) });
  const storeBefore = storeFingerprint(stack.daemon);

  const { res, conn, id, abortToSettleMs, logBefore } = await abortMidRequest(stack, b);
  assert.equal(res.ok, false, JSON.stringify(res));
  assert.equal(res.name, 'AbortError', `the page must get AbortError: ${JSON.stringify(res)}`);
  assert.ok(abortToSettleMs < 2000, `the page settles at once on abort (${abortToSettleMs} ms)`);

  // The daemon received the abort for that request while it was in flight, and answered it `aborted`.
  await waitFor('the daemon to answer the aborted request', () =>
    logMatches(stack.daemon.log().slice(logBefore), TRANSPORT_LOG.answered).some(([c, i]) => c === conn && i === id));
  const log = stack.daemon.log().slice(logBefore);
  assert.deepEqual(logMatches(log, TRANSPORT_LOG.abort), [[conn, id, 'in flight']], 'the daemon received abort{id} for the in-flight request');
  assert.deepEqual(logMatches(log, TRANSPORT_LOG.answered).filter(([c, i]) => c === conn && i === id).map(m => m[3]), ['aborted']);
  assert.doesNotMatch(log, HUMAN_CTAP_LOG, 'the human authenticator handled a request');

  // No signature.
  assert.equal(rp.authentications.length, 0, 'the RP must never receive an assertion');
  assert.equal(storeFingerprint(stack.daemon), storeBefore, 'no key use: store (incl. counters) unchanged');
  const audit = await stack.daemon.audit();
  const denies = policyEvents(audit, 'policy.deny').filter(e => e.profile_id === 'agent' && e.action === 'authenticate');
  assert.deepEqual(denies.map(e => [e.rp_id, e.reason]), [['rp-a.test', 'aborted']], `the terminal record is an aborted deny: ${JSON.stringify(denies)}`);
  assert.equal(policyEvents(audit, 'policy.allow').length, 0, 'nothing allowed');
  assertNoNotification(stack);
});

scenario({ id: 'E2E-17/after-key-use', exposeModes: ['port', 'pipe'], title: 'AbortSignal after key use: the held result is discarded' }, async ctx => {
  const { stack, rp, b } = await setup(ctx, { PASSLESS_E2E_HOLD_RESULT_MS: String(HOLD_MS) });
  const storeBefore = storeFingerprint(stack.daemon);

  const { res, conn, id, logBefore } = await abortMidRequest(stack, b, () =>
    // Abort only once the key was used (the result is then being held).
    waitFor('the key use', async () => policyEvents(await stack.daemon.audit(), 'policy.allow').length === 1));
  assert.equal(res.ok, false, JSON.stringify(res));
  assert.equal(res.name, 'AbortError', `the page must get AbortError: ${JSON.stringify(res)}`);

  await waitFor('the daemon to answer the aborted request', () =>
    logMatches(stack.daemon.log().slice(logBefore), TRANSPORT_LOG.answered).some(([c, i]) => c === conn && i === id), { timeoutMs: HOLD_MS + 5000 });
  const log = stack.daemon.log().slice(logBefore);
  assert.deepEqual(logMatches(log, TRANSPORT_LOG.abort), [[conn, id, 'in flight']], 'the daemon received abort{id}');
  assert.deepEqual(logMatches(log, TRANSPORT_LOG.answered).filter(([c, i]) => c === conn && i === id).map(m => m[3]), ['aborted'],
    'the held assertion is discarded: the result is `aborted`, never the assertion');
  assert.equal(rp.authentications.length, 0, 'the RP must never receive the discarded assertion');
  assert.notEqual(storeFingerprint(stack.daemon), storeBefore, 'the key was used before the abort (counter moved)');
  const audit = await stack.daemon.audit();
  assert.equal(policyEvents(audit, 'policy.allow').length, 1, 'the key use is audited');
  assert.equal(policyEvents(audit, 'policy.deny').length, 0);
});
