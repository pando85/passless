'use strict';
const { scenario, assert } = require('../lib/scenario');
const { authenticate, policyEvents, storeFingerprint, assertInterceptionActive, assertNoNotification } = require('../lib/helpers');

// Catalogue: a `request` rule before P7 (a legacy `confirm`/`supervised` rule maps to it, see E2E-13): denied with audit
// `escalation_unavailable`; the native `get` is never invoked.
//
// Evidence that nothing reached the human authenticator (a credential for alice exists in its store, so a leak would
// succeed): the RP never sees an assertion, the human store (including its signature counters) is unchanged, and
// the daemon log has no new CTAP request after the ceremony. No notification is shown (notify-double).
scenario({ id: 'E2E-09', title: 'request rule acts as deny until P7: no prompt, no human authenticator', ci: true }, async ctx => {
  const stack = await ctx.stack({
    rps: { a: { host: 'rp-a.test' } },
    profiles: { agent: { mode: 'same-user', rules: [{ rp: 'rp-a.test', authenticate: 'request', register: 'deny' }] } },
  });
  const rp = stack.rp.a;
  await stack.seedHuman(rp, 'alice');
  const storeBefore = storeFingerprint(stack.daemon);
  const assertionsBefore = rp.authentications.length;
  // Positive control: the daemon logs every CTAP request that reaches the human UHID device (seeding just made some).
  assert.match(stack.daemon.log(), HUMAN_CTAP_LOG, 'log pattern control: seeding must have produced human CTAP log lines');

  const b = await stack.open('agent', `${rp.origin}/sw`);
  assertInterceptionActive(b);
  const logBefore = stack.daemon.log().length;
  const res = await authenticate(b.page, { username: 'alice' });

  assert.equal(res.ok, false, `a request rule must not authenticate: ${JSON.stringify(res)}`);
  assert.equal(res.name, 'NotAllowedError');
  assert.equal(rp.authentications.length, assertionsBefore, 'the RP must never receive an assertion');
  assert.equal(storeFingerprint(stack.daemon), storeBefore, 'human store (incl. counters) unchanged: the human authenticator signed nothing');
  assertNoNotification(stack);

  const audit = await stack.daemon.audit();
  const denies = policyEvents(audit, 'policy.deny').filter(e => e.profile_id === 'agent' && e.action === 'authenticate' && e.rp_id === 'rp-a.test');
  assert.equal(denies.length, 1, `expected one audited deny, audit: ${JSON.stringify(audit.map(e => e.event && e.event.kind))}`);
  assert.equal(denies[0].reason, 'escalation_unavailable');
  assert.equal(policyEvents(audit, 'policy.allow').length, 0);

  // The ceremony was handled on the agent path: the human CTAP path logged nothing while it ran.
  const newLog = stack.daemon.log().slice(logBefore);
  assert.doesNotMatch(newLog, HUMAN_CTAP_LOG, `the human authenticator handled a request during the ceremony:\n${newLog.slice(0, 2000)}`);
});

const HUMAN_CTAP_LOG = /Worker received packet from host|CTAP response: \d+ bytes/;
