'use strict';
const { scenario, assert } = require('../lib/scenario');
const { authenticate, policyEvents, storeFingerprint, assertInterceptionActive, assertNoNotification, TRANSPORT_LOG, logMatches, HUMAN_CTAP_LOG } = require('../lib/helpers');

// Catalogue: a cross-origin iframe to rp-b inside rp-a is denied (ADR 0014 §11: cross-origin frames fail closed).
// Both RPs are allowed, so the only reason for the denial is the frame's origin. The iframe is delegated WebAuthn
// (`allow="publickey-credentials-get *"` in pages/embed.html), so Chromium hands it to the extension's WebAuthn proxy with
// `sameOriginWithAncestors = false`; the daemon must deny and audit it (`cross_origin_denied`) and sign nothing.
scenario({ id: 'E2E-10', title: 'cross-origin iframe is denied and audited', ci: true }, async ctx => {
  const stack = await ctx.stack({
    rps: { a: { host: 'rp-a.test' }, b: { host: 'rp-b.test' } },
    profiles: { agent: { mode: 'same-user', rules: [
      { rp: 'rp-a.test', authenticate: 'allow', register: 'deny' },
      { rp: 'rp-b.test', authenticate: 'allow', register: 'deny' },
    ] } },
  });
  const [rpA, rpB] = [stack.rp.a, stack.rp.b];
  await stack.seedHuman(rpB, 'alice'); // a credential exists, so a leak would succeed
  const storeBefore = storeFingerprint(stack.daemon);

  const b = await stack.open('agent', `${rpA.origin}/embed?target=${encodeURIComponent(`${rpB.origin}/sw`)}`);
  assertInterceptionActive(b);
  await b.page.waitForLoadState('load');
  const frame = b.page.frames().find(f => f.name() === 'f');
  assert.ok(frame, 'iframe not found');
  await frame.waitForLoadState('load');
  assert.equal(new URL(frame.url()).origin, rpB.origin, `iframe is not on rp-b: ${frame.url()}`);
  const logBefore = stack.daemon.log().length;

  const res = await authenticate(frame, { username: 'alice' });
  assert.equal(res.ok, false, `cross-origin ceremony must not succeed: ${JSON.stringify(res)}`);
  assert.equal(res.name, 'NotAllowedError');
  assert.equal(rpB.authentications.length, 0, 'the RP must never receive an assertion');
  assert.equal(storeFingerprint(stack.daemon), storeBefore, 'no key use: store (incl. counters) unchanged');
  assertNoNotification(stack);

  const audit = await stack.daemon.audit();
  const denies = policyEvents(audit, 'policy.deny').filter(e => e.profile_id === 'agent' && e.action === 'authenticate' && e.rp_id === 'rp-b.test');
  assert.equal(denies.length, 1, `expected one audited deny for rp-b.test, audit: ${JSON.stringify(audit.map(e => e.event && e.event.kind))}`);
  assert.equal(denies[0].reason, 'cross_origin_denied');
  assert.equal(denies[0].cross_origin, true, `the audit records the cross-origin flag: ${JSON.stringify(denies[0])}`);
  assert.equal(policyEvents(audit, 'policy.allow').length, 0, 'nothing may be allowed');
  // It reached the daemon through the proxy (the browser-supplied sameOriginWithAncestors=false), not the human device.
  const newLog = stack.daemon.log().slice(logBefore);
  assert.equal(logMatches(newLog, TRANSPORT_LOG.admitted).length, 1, 'the request reached the daemon over the transport');
  assert.doesNotMatch(newLog, HUMAN_CTAP_LOG, 'the human authenticator handled a request');
});
