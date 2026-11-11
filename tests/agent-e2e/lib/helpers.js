'use strict';
// Shared assertions and page helpers for scenarios.

const assert = require('node:assert/strict');
const http = require('node:http');

/** Audit event bodies (the `event` objects), in order. */
const auditEvents = audit => audit.map(e => e.event || e);

const policyEvents = (audit, kind) => auditEvents(audit).filter(e => e.kind === kind);

/** Run window.e2e.authenticate in `page` (or a frame) after the helper script is ready. */
async function authenticate(pageOrFrame, opts = {}) {
  await pageOrFrame.waitForFunction(() => window.e2e, null, { timeout: 15000 });
  return pageOrFrame.evaluate(o => window.e2e.authenticate(o), { timeout: 20000, userVerification: 'preferred', ...opts });
}

/** Sorted list of human-store credential files and hashes; used to prove nothing was signed or changed. */
const storeFingerprint = daemon => JSON.stringify(daemon.humanStore().sort((a, b) => a.file.localeCompare(b.file)));

/**
 * The RP accepted an assertion with UP and UV, the right RP ID hash and origin, and a higher counter.
 * Judged from the RP server's own verified record (`rp.authentications`), matched to the page's result by
 * timestamp, never from fields the page relayed.
 */
function assertVerifiedAssertion(rp, result, { username } = {}) {
  assert.equal(result.ok, true, `authentication failed: ${JSON.stringify(result)}`);
  const ev = rp.authentications.find(e => e.ts === result.ts);
  assert.ok(ev, 'the RP has no record of this assertion');
  assert.equal(ev.ok, true, `RP verification failed: ${ev.error}`);
  assert.equal(ev.flags.up, true, 'UP flag');
  assert.equal(ev.flags.uv, true, 'UV flag');
  assert.equal(ev.rpIdHashOk, true, 'RP ID hash');
  assert.equal(ev.origin, rp.origin, 'origin seen by the RP');
  assert.equal(ev.counterIncreased, true, `counter ${ev.previousCounter} -> ${ev.counter}`);
  assert.equal(result.credentialId, ev.credentialId);
  if (username) assert.equal(ev.username, username);
  return ev;
}

/** The browser had the extension injected (before trusting any result from the managed browser). */
function assertInterceptionActive(b) {
  assert.equal(b.extensionWorker, true, 'extension service worker did not start');
  assert.equal(b.injected, true, 'extension content script was not injected into the page');
}

function assertNoNotification(stack) {
  assert.deepEqual(stack.notify.notifications(), [], 'a notification was shown');
}

/** The daemon's audit log shows `n` agent-path allows for authentication at `rpId` (proves the ceremony used the agent path, not a native fallback). */
async function assertAgentAllowed(stack, { rpId, profile = 'agent', n = 1, action = 'authenticate' }) {
  const audit = await stack.daemon.audit();
  const allows = policyEvents(audit, 'policy.allow').filter(e => e.profile_id === profile && e.action === action && e.rp_id === rpId);
  assert.equal(allows.length, n, `expected ${n} policy.allow(${action}) for ${profile}@${rpId}, audit: ${JSON.stringify(auditEvents(audit).map(e => e.kind))}`);
  return allows;
}


/**
 * The daemon endpoint the managed browser's extension was given: the sign socket and the lease-bound bearer.
 * Read the way the extension itself holds them (its generated worker script), through the extension's own service
 * worker, so no on-disk layout is assumed. Test-only: a page can never do this.
 */
async function extensionEndpoint(b) {
  const worker = b.context.serviceWorkers().find(w => /^chrome-extension:\/\/[a-p]{32}\/worker\.js$/.test(w.url()));
  assert.ok(worker, 'extension service worker not found');
  const source = await worker.evaluate(async url => (await fetch(url)).text(), worker.url());
  const m = source.match(/\}\)\(("(?:[^"\\]|\\.)*"),\s*("(?:[^"\\]|\\.)*")\);\s*$/);
  assert.ok(m, 'could not read the endpoint arguments from the extension worker');
  return { socketPath: JSON.parse(m[1]), bearer: JSON.parse(m[2]) };
}

/** POST JSON to the daemon's sign socket (`path` is `/register` or `/sign`) with a bearer; resolves {status, body}. */
function postToDaemon({ socketPath, bearer }, path, payload) {
  const data = Buffer.from(JSON.stringify(payload));
  return new Promise((resolve, reject) => {
    const req = http.request({
      socketPath, path, method: 'POST',
      headers: { authorization: `Bearer ${bearer}`, 'content-type': 'application/json', 'content-length': data.length },
    }, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('error', reject);
    req.setTimeout(10000, () => req.destroy(new Error('daemon request timed out')));
    req.end(data);
  });
}

/** A minimal valid daemon `/register` request for `rp` (a test RP). Distinct `challenge` per attempt (replay key). */
function registerRequest(rp, { username = 'dora', challenge } = {}) {
  const b64u = b => Buffer.from(b).toString('base64url');
  return {
    origin: rp.origin, rp_id: rp.host, challenge_b64u: b64u(challenge || `challenge-${Date.now()}-${Math.random()}`),
    user_id_b64u: b64u(username), user_name: username, user_display_name: username, rp_name: rp.host,
    exclude_credentials: [], pub_key_cred_params: [-7], user_verification: false, cross_origin: false,
  };
}

/** Poll until `predicate()` is truthy, or fail with `what`. */
async function waitFor(what, predicate, { timeoutMs = 15000, intervalMs = 200 } = {}) {
  const end = Date.now() + timeoutMs;
  for (;;) {
    const v = await predicate();
    if (v) return v;
    if (Date.now() > end) assert.fail(`timed out waiting for ${what}`);
    await new Promise(r => setTimeout(r, intervalMs));
  }
}

module.exports = { extensionEndpoint, postToDaemon, registerRequest, waitFor, assertAgentAllowed, auditEvents, policyEvents, authenticate, storeFingerprint, assertVerifiedAssertion, assertInterceptionActive, assertNoNotification };
