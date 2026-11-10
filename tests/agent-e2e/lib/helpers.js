'use strict';
// Shared assertions and page helpers for scenarios.

const assert = require('node:assert/strict');

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

module.exports = { assertAgentAllowed, auditEvents, policyEvents, authenticate, storeFingerprint, assertVerifiedAssertion, assertInterceptionActive, assertNoNotification };
