'use strict';
const { scenario, assert } = require('../lib/scenario');
const {
  authenticate, auditEvents, policyEvents, escalationEvents, grantedRuleEvents, assertVerifiedAssertion, assertInterceptionActive,
  waitFor, TRANSPORT_LOG, logMatches,
} = require('../lib/helpers');
const { section12, missingFields } = require('../lib/audit-fields');

// Catalogue: audit content for allow, deny, escalation and abort (ADR 0014 section 12). Every operation record carries
// every field of the canonical section 12 list (`SECTION_12_OPERATION_FIELDS` in `audit_events.rs`, read by
// lib/audit-fields.js; unit tests check the record types against the same list), and every reservation (`policy.allow`)
// is closed by exactly one `operation.terminal` record.
//
// E2E-32 runs four ceremonies of one session through one browser:
//   rp-a.test  exact `allow`                                  -> reservation + terminal(success), rule "exact", source "config"
//   rp-b.test  exact `deny`                                   -> policy.deny(action_not_allowed), no reservation
//   rp-c.test  exact `request`, approved ("Allow always")     -> escalation requested/approved, granted_rule.add, then
//                                                                reservation + terminal(success), source "granted"
//   rp-d.test  exact `request`, denied by the human           -> escalation requested/denied, policy.deny(escalation_denied)
// E2E-32/abort aborts a ceremony before key use (the PASSLESS_E2E_HOLD_REQUEST_MS hook of E2E-17): a refused operation record
// with result and failure class `aborted`, and no reservation.
//
// The daemon accepts "Allow always" only 1000 ms after the notification was shown, so the approval is scripted at 1500 ms.
const HEX64 = /^[0-9a-f]{64}$/;
const PROFILES = {
  agent: {
    mode: 'same-user',
    rules: [
      { rp: 'rp-a.test', authenticate: 'allow', register: 'deny' },
      { rp: 'rp-b.test', authenticate: 'deny', register: 'deny' },
      { rp: 'rp-c.test', authenticate: 'request', register: 'deny' },
      { rp: 'rp-d.test', authenticate: 'request', register: 'deny' },
    ],
  },
};

/** Every operation record of `profile` (reservation, refusal, served duplicate, terminal) in audit order. */
const operationRecords = (audit, kinds, profile = 'agent') => auditEvents(audit).filter(e => kinds.includes(e.kind) && e.profile_id === profile);

/** Assert that `record` carries every field of the canonical section 12 operation list (null counts as carried). */
function assertCanonicalFields(record, fields) {
  const missing = missingFields(record, fields);
  assert.deepEqual(missing, [], `${record.kind} for ${record.rp_id} lacks section 12 field(s) ${missing.join(', ')}: ${JSON.stringify(record)}`);
}

scenario({ id: 'E2E-32', title: 'audit content for allow, deny, escalation: every section 12 field, one terminal record per reservation', ci: true, timeoutMs: 240000 }, async ctx => {
  const stack = await ctx.stack({
    rps: Object.fromEntries('abcd'.split('').map(c => [c, { host: `rp-${c}.test` }])),
    profiles: PROFILES,
    notify: { script: ['approve:1500', 'deny:500'] },
  });
  for (const c of 'abcd') await stack.seedHuman(stack.rp[c], 'alice');
  const [rpA, rpB, rpC, rpD] = 'abcd'.split('').map(c => stack.rp[c]);
  const fields = section12();

  const b = await stack.open('agent', `${rpA.origin}/sw`);
  assertInterceptionActive(b);
  assertVerifiedAssertion(rpA, await authenticate(b.page, { username: 'alice' }), { username: 'alice' });

  await b.page.goto(`${rpB.origin}/sw`);
  const denied = await authenticate(b.page, { username: 'alice' });
  assert.equal(denied.ok, false, JSON.stringify(denied));
  assert.equal(denied.name, 'NotAllowedError');

  await b.page.goto(`${rpC.origin}/sw`);
  assertVerifiedAssertion(rpC, await authenticate(b.page, { username: 'alice' }), { username: 'alice' });

  await b.page.goto(`${rpD.origin}/sw`);
  const refused = await authenticate(b.page, { username: 'alice' });
  assert.equal(refused.ok, false, JSON.stringify(refused));
  assert.equal(refused.name, 'NotAllowedError');
  assert.equal(rpB.authentications.length + rpD.authentications.length, 0, 'the denied RPs never receive an assertion');

  const audit = await stack.daemon.audit();
  const all = auditEvents(audit);
  const kinds = JSON.stringify(all.map(e => e.kind));

  // --- Every operation record carries the whole canonical list.
  const operations = operationRecords(audit, fields.operationKinds);
  assert.ok(operations.length >= 6, `expected 2 reservations, 2 terminals and 2 refusals, got ${kinds}`);
  for (const record of operations) assertCanonicalFields(record, fields.operation);

  // --- Reservations and their terminal records.
  const allows = operationRecords(audit, ['policy.allow']);
  const terminals = operationRecords(audit, ['operation.terminal']);
  assert.deepEqual(allows.map(e => e.rp_id), ['rp-a.test', 'rp-c.test'], `one reservation per allowed ceremony: ${kinds}`);
  assert.equal(terminals.length, allows.length, 'one terminal record per reservation');
  for (const allow of allows) {
    const closing = terminals.filter(t => t.request_id === allow.request_id);
    assert.equal(closing.length, 1, `exactly one terminal record for ${allow.request_id}`);
    assert.ok(all.indexOf(closing[0]) > all.indexOf(allow), 'the terminal record follows its reservation');
  }

  const sessionHash = allows[0].session_id_hash;
  const [[allowA, termA], [allowC, termC]] = allows.map(a => [a, terminals.find(t => t.request_id === a.request_id)]);
  for (const [allow, term] of [[allowA, termA], [allowC, termC]]) {
    for (const record of [allow, term]) {
      assert.equal(record.action, 'authenticate');
      assert.match(record.session_id_hash, HEX64, 'a hash of the session identifier, never the bearer');
      assert.equal(record.session_id_hash, sessionHash, 'one session');
      assert.match(record.request_id, /^req-[0-9a-f]{32}$/);
      assert.equal(record.profile_id, 'agent');
      assert.equal(record.mode, 'same-user');
      assert.ok(['shared-uid', 'distinct-uid'].includes(record.principal_relationship), record.principal_relationship);
      assert.equal(record.backend, 'local', 'a same-user profile reports the human backend\'s storage kind (the harness daemon runs --backend-type local)');
      assert.equal(record.key_provider, 'software');
      assert.ok(Number.isInteger(record.revocation_epoch) && Number.isInteger(record.grant_epoch), 'the real epochs');
      assert.equal(record.top_origin, null, 'top_origin is null on the proxy path');
      assert.equal(record.cross_origin, false);
      assert.equal(record.decision, 'allow');
      assert.equal(record.evidence_source, 'agent');
      assert.equal(record.rule, 'exact');
      assert.equal(record.selection_rule, 'single');
      assert.match(record.credential_ref, /^[0-9a-f]+$/);
      assert.ok(Number.isInteger(record.counter_before), 'the counter before key use');
    }
    assert.equal(allow.origin, allow.rp_id === 'rp-a.test' ? rpA.origin : rpC.origin);
    assert.equal(allow.result, null, 'a reservation has no result yet');
    assert.equal(allow.failure_class, null);
    assert.equal(allow.counter_after, null);
    assert.equal(term.result, 'success');
    assert.equal(term.failure_class, null);
    assert.ok(term.counter_after >= term.counter_before, `the counter moves forward: ${term.counter_before} -> ${term.counter_after}`);
    assert.equal(term.credential_ref, allow.credential_ref);
    assert.equal(term.rule, allow.rule);
  }
  assert.equal(allowA.grant_source, 'config');
  assert.equal(allowA.escalation_id, null, 'no escalation for the exact allow');
  assert.equal(allowC.grant_source, 'granted', 'the approved escalation upgraded the rule through a granted rule');
  assert.equal(termC.grant_source, 'granted');
  assert.ok(termC.grant_epoch > termA.grant_epoch, `adding the grant bumped the grant epoch: ${termA.grant_epoch} -> ${termC.grant_epoch}`);
  assert.equal(termC.revocation_epoch, termA.revocation_epoch, 'a grant never revokes');

  // --- Refusals: deny rule (no reservation) and a denied escalation.
  const denies = operationRecords(audit, ['policy.deny']);
  assert.deepEqual(denies.map(e => [e.rp_id, e.reason]), [['rp-b.test', 'action_not_allowed'], ['rp-d.test', 'escalation_denied']], kinds);
  const [denyB, denyD] = denies;
  for (const deny of denies) {
    assert.equal(deny.decision, 'deny');
    assert.equal(deny.result, 'denied');
    assert.equal(deny.failure_class, deny.reason);
    assert.equal(deny.evidence_source, null);
    assert.equal(deny.rule, 'exact');
    assert.equal(deny.grant_source, 'config');
    assert.equal(deny.credential_ref, null, 'a refusal selected no credential');
    assert.equal(deny.counter_before, null);
    assert.equal(deny.session_id_hash, sessionHash);
    assert.match(deny.request_id, /^req-[0-9a-f]{32}$/);
  }
  assert.equal(denyB.escalation_id, null);
  assert.equal(allows.filter(e => e.rp_id === 'rp-b.test' || e.rp_id === 'rp-d.test').length, 0, 'a refusal owns no reservation');

  // --- Escalation records carry the listed fields and tie to the operation records by escalation ID.
  const requested = escalationEvents(audit, 'requested');
  assert.deepEqual(requested.map(e => [e.rp_id, e.rule, e.origin]), [['rp-c.test', 'exact', rpC.origin], ['rp-d.test', 'exact', rpD.origin]], kinds);
  const approved = escalationEvents(audit, 'approved');
  const escalationDenied = escalationEvents(audit, 'denied');
  assert.deepEqual([approved.length, escalationDenied.length], [1, 1], kinds);
  assert.deepEqual(escalationDenied.map(e => e.cause), ['user']);
  for (const record of escalationEvents(audit)) {
    const expected = fields.other[record.kind];
    assert.ok(expected, `section 12 lists ${record.kind}`);
    const missing = missingFields(record, expected);
    assert.deepEqual(missing, [], `${record.kind} lacks section 12 field(s) ${missing.join(', ')}: ${JSON.stringify(record)}`);
  }
  assert.equal(allowC.escalation_id, approved[0].escalation_id, 'the reservation names the escalation that approved it');
  assert.equal(termC.escalation_id, approved[0].escalation_id);
  assert.equal(denyD.escalation_id, escalationDenied[0].escalation_id, 'the refusal names the escalation the human denied');
  assert.equal(approved[0].escalation_id, requested[0].escalation_id);

  // --- The grant that the approval persisted, and the session grant of the browser launch.
  const added = grantedRuleEvents(audit, 'add');
  assert.deepEqual(added.map(e => [e.rp_id, e.grant_kind, e.rule, e.escalation_id]), [['rp-c.test', 'escalation', 'exact', approved[0].escalation_id]], JSON.stringify(added));
  for (const record of [...added, ...all.filter(e => e.kind === 'grant.request' || e.kind === 'grant.approve')]) {
    const missing = missingFields(record, fields.other[record.kind]);
    assert.deepEqual(missing, [], `${record.kind} lacks section 12 field(s) ${missing.join(', ')}: ${JSON.stringify(record)}`);
  }
  const grantRequest = all.find(e => e.kind === 'grant.request' && e.profile_id === 'agent');
  assert.ok(grantRequest, `the session grant request is audited: ${kinds}`);
  assert.match(grantRequest.principal, HEX64);
  assert.ok(Array.isArray(grantRequest.rp_ids) && grantRequest.ttl_secs > 0, 'the session grant carries its RP scope and TTL');
  // Browser-lease records (creation, expiry, revocation, exit, cleanup) carry their listed fields; `cdp_expose` is optional.
  for (const record of all.filter(e => /^browser_lease\.(launch|revoke|expire|crash|cleanup)$/.test(e.kind))) {
    const missing = missingFields(record, fields.other[record.kind].filter(f => f !== 'cdp_expose'));
    assert.deepEqual(missing, [], `${record.kind} lacks section 12 field(s) ${missing.join(', ')}`);
  }

  assert.equal(policyEvents(audit, 'policy.replay_served').length, 0, 'no duplicates in this scenario');
});

// Abort before key use: Chromium rejects the page's promise with AbortError, the worker sends `abort{id}` and the daemon cancels
// the request (as in E2E-17). The refusal carries the whole operation record with result and failure class `aborted`; nothing
// was reserved, so no terminal record is owed.
const HOLD_MS = 6000;

scenario({ id: 'E2E-32/abort', title: 'an aborted ceremony is audited with every section 12 field and no reservation', ci: true }, async ctx => {
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
  const fields = section12();

  const logBefore = stack.daemon.log().length;
  const key = await b.page.evaluate(() => window.e2e.start('authenticate', { username: 'alice', timeout: 60000 }));
  await waitFor('the daemon to admit the request', () => {
    const m = logMatches(stack.daemon.log().slice(logBefore), TRANSPORT_LOG.admitted);
    return m.length ? m : null;
  });
  await b.page.evaluate(k => window.e2e.abort(k), key);
  const res = await b.page.evaluate(k => window.e2e.result(k), key);
  assert.equal(res.ok, false, JSON.stringify(res));
  assert.equal(res.name, 'AbortError', JSON.stringify(res));

  const audit = await waitFor('the aborted refusal in the audit', async () => {
    const events = await stack.daemon.audit();
    return policyEvents(events, 'policy.deny').some(e => e.reason === 'aborted') ? events : null;
  }, { timeoutMs: HOLD_MS + 10000 });
  const denies = operationRecords(audit, ['policy.deny']);
  assert.equal(denies.length, 1, JSON.stringify(denies));
  const [deny] = denies;
  assertCanonicalFields(deny, fields.operation);
  assert.equal(deny.rp_id, 'rp-a.test');
  assert.equal(deny.reason, 'aborted');
  assert.equal(deny.failure_class, 'aborted');
  assert.equal(deny.result, 'aborted');
  assert.equal(deny.decision, 'deny');
  assert.equal(deny.origin, rp.origin);
  assert.equal(deny.top_origin, null);
  assert.equal(deny.rule, 'exact');
  assert.match(deny.session_id_hash, HEX64);
  assert.match(deny.request_id, /^req-[0-9a-f]{32}$/);
  assert.equal(policyEvents(audit, 'policy.allow').length, 0, 'the abort came before the reservation');
  assert.equal(policyEvents(audit, 'operation.terminal').length, 0, 'no reservation, so no terminal record');
  assert.equal(rp.authentications.length, 0);
});
