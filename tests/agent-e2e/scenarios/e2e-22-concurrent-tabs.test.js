'use strict';
const { scenario, assert } = require('../lib/scenario');
const { parseAuthData } = require('../lib/rp-server');
const { policyEvents, storeFingerprint, assertVerifiedAssertion, assertInterceptionActive, waitFor, TRANSPORT_LOG, logMatches, HUMAN_CTAP_LOG } = require('../lib/helpers');

// Catalogue: 20 concurrent ceremonies across tabs: no silent drops; caps return explicit `busy` (plan R11).
//
// One managed browser, one worker, so one daemon connection and one bearer session carry all 20 requests. The daemon
// holds every admitted request for HOLD_MS before its ceremony (PASSLESS_E2E_HOLD_REQUEST_MS), so all 20 overlap; the
// per-connection and per-session caps (CAP) admit CAP of them and answer the rest `busy` at once. `get()` is used: it is
// not subject to Chromium's focus rule for background tabs (ADR 0014 §11).
//
// Accounting that must add up: every page settles (success or an explicit error, never a hang); successes == admitted
// requests == `ok` results == policy.allow == RP-verified assertions; NotAllowedErrors == `busy` refusals.
const TABS = 20;
const CAP = 8;
const HOLD_MS = 4000;

// Port-only (not ported): 20 concurrent tabs; E2E-14, 25 and 48 cover concurrent tabs in pipe mode.
scenario({ id: 'E2E-22', title: '20 concurrent ceremonies across tabs: no silent drops, caps answer busy', timeoutMs: 240000 }, async ctx => {
  const stack = await ctx.stack({
    rps: { a: { host: 'rp-a.test' } },
    profiles: { agent: { mode: 'same-user', max_operations: 64, rules: [{ rp: 'rp-a.test', authenticate: 'allow', register: 'deny' }] } },
    limits: { max_concurrent_requests: 32, max_requests_per_profile: 32, max_requests_per_connection: CAP, max_requests_per_session: CAP },
    daemonEnv: { PASSLESS_E2E_HOLD_REQUEST_MS: String(HOLD_MS) },
  });
  const rp = stack.rp.a;
  await stack.seedHuman(rp, 'alice');
  const url = `${rp.origin}/raw`;
  const b = await stack.open('agent', url);
  assertInterceptionActive(b);
  const pages = [b.page];
  for (let i = 1; i < TABS; i++) {
    const p = await b.context.newPage();
    await p.goto(url);
    pages.push(p);
  }
  await Promise.all(pages.map(p => p.waitForFunction(() => window.e2e)));
  const storeBefore = storeFingerprint(stack.daemon);
  const logBefore = stack.daemon.log().length;

  // Fire all 20 at once; every page must settle within the hold plus a margin.
  // The pages do not post their assertions to the RP: concurrent assertions of one credential can arrive out of counter
  // order, which a real RP rejects ("counter lower than expected"). The harness verifies them in counter order below.
  const keys = await Promise.all(pages.map(p => p.evaluate(() => window.e2e.start('authenticate', { username: 'alice', timeout: 60000, noVerify: true }))));
  const results = await waitFor('every page to settle', async () => {
    const peeks = await Promise.all(pages.map((p, i) => p.evaluate(k => window.e2e.peek(k), keys[i])));
    return peeks.every(x => x.settled) ? peeks.map(x => x.result) : null;
  }, { timeoutMs: HOLD_MS * 3 + 30000, intervalMs: 500 });

  const ok = results.filter(r => r.ok);
  const failed = results.filter(r => !r.ok);
  ctx.t.diagnostic(`E2E-22 [${ctx.variant.name}]: ${ok.length} succeeded, ${failed.length} failed (${JSON.stringify([...new Set(failed.map(r => r.name))])})`);
  assert.equal(ok.length + failed.length, TABS, 'every page settled');
  for (const r of failed) assert.equal(r.name, 'NotAllowedError', `an over-cap request is an explicit NotAllowedError: ${JSON.stringify(r)}`);
  assert.equal(ok.length, CAP, `exactly the capped number succeeds (${ok.length})`);
  const counterOf = r => parseAuthData(Buffer.from(r.response.response.authenticatorData, 'base64url')).counter;
  const counters = ok.map(counterOf).sort((x, y) => x - y);
  assert.equal(new Set(counters).size, CAP, `every success is its own signature: counters ${counters}`);
  for (const r of [...ok].sort((x, y) => counterOf(x) - counterOf(y))) {
    const ev = await rp.authVerify({ response: r.response });
    assertVerifiedAssertion(rp, { ok: true, ts: ev.ts, credentialId: r.response.id }, { username: 'alice' });
  }

  // Daemon accounting.
  await waitFor('every admitted request to be answered', () =>
    logMatches(stack.daemon.log().slice(logBefore), TRANSPORT_LOG.answered).length >= CAP);
  const log = stack.daemon.log().slice(logBefore);
  const admitted = logMatches(log, TRANSPORT_LOG.admitted);
  const answered = logMatches(log, TRANSPORT_LOG.answered);
  const refused = logMatches(log, TRANSPORT_LOG.refused);
  assert.equal(new Set(admitted.map(m => m[0])).size, 1, 'one connection carried every request');
  assert.equal(admitted.length + refused.length, TABS, `every request frame got exactly one outcome: ${admitted.length} admitted, ${refused.length} refused`);
  assert.equal(admitted.length, CAP);
  assert.deepEqual([...new Set(answered.map(m => `${m[2]}:${m[3]}`))], ['answered:ok'], 'every admitted request was answered ok');
  assert.equal(answered.length, CAP);
  assert.deepEqual(refused.map(m => m[2]), Array(TABS - CAP).fill('busy'), 'every refusal is an explicit busy');
  assert.match(log, /agent ceremony request answered busy \((connection|session) cap reached/, 'the busy replies are logged');
  assert.doesNotMatch(log, HUMAN_CTAP_LOG, 'the human authenticator handled a request');

  const audit = await stack.daemon.audit();
  assert.equal(policyEvents(audit, 'policy.allow').length, CAP, 'one policy.allow per admitted ceremony');
  assert.equal(policyEvents(audit, 'policy.deny').length, 0, 'busy is answered before policy, so nothing is denied');
  assert.equal(rp.authentications.length, CAP, 'the RP saw exactly the successful ceremonies');
  assert.notEqual(storeFingerprint(stack.daemon), storeBefore);
});
