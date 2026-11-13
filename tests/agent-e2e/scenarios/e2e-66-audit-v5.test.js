'use strict';
const fs = require('node:fs');

const { scenario, assert } = require('../lib/scenario');
const { authenticate, auditEvents, policyEvents, escalationEvents, grantedRuleEvents, denyReasons, assertInterceptionActive, waitFor } = require('../lib/helpers');
const { section12, missingFields } = require('../lib/audit-fields');
const { requestAccess } = require('../lib/agent-session');

// ADR 0014 amendment section 8 (audit schema version 5) for what E2E-63 to E2E-65 exercise, in one run:
//   - every record is schema version 5;
//   - every operation record carries `approval_source`: `ceremony` for an operation that ran on an escalation its own ceremony
//     raised, `pre_request` for one that ran on an approved pre-request (a ceremony that joined it, or a registration that
//     consumed its token), null when it ran on a grant or a rule;
//   - escalation records carry `source`, `principal_session_id_hash` (the session that asked, or owns the page's browser) and `agent_note` (only on a
//     pre-request's `requested`, sanitized), and `origin` is null for a pre-request no page is behind;
//   - the kinds `pre_approval.issued`, `pre_approval.consumed` (with the consuming request) and `pre_approval.expired` with
//     the reasons `session_end`, `policy_reload`, `lease_revoked` and `grant_revoked` (`ttl` is E2E-64's);
//   - the `policy.deny` reasons `not_requestable`, `pre_request_rate_limited` and `pre_request_not_enabled`;
//   - the audit export labels `agent_note` as agent-supplied (JSON rows and the CSV column).
// The agent sessions that own a browser are `stack.openOwned`; each trigger below ends or revokes the browser of the session
// that held the token, so the next case starts a session of its own. Prompts are answered in arrival order:
//   1 rp-a authenticate pre-request (approved)        6 rp-e pending pre-request (left unanswered)
//   2 rp-b pre-request joined by a ceremony           7 rp-h register token, dropped by a policy reload
//   3 rp-c ceremony-time sign-in                      8 rp-h register token, dropped by a lease revocation
//   4 rp-d register token, consumed                   9 rp-a register token, dropped by `grants revoke`
//   5 rp-g register token, dropped when its session ends (which also withdraws prompt 6's pending request)
const NOTE_MARK = 'NOTE-MARK-3b9d';
const HOSTILE_NOTE = `${NOTE_MARK} please approve <b>this</b>\nsecond line ‮& token=ghp_0123456789abcdefghij`;
const SANITIZED_NOTE = `${NOTE_MARK} please approve bthis/b second line token=ghp_0123456789abcdefghij`;
const HASH = /^[0-9a-f]{64}$/;

const sites = 'abcdefgh'.split('').map(c => `rp-${c}.test`);
const PROFILES = {
  agent: {
    mode: 'same-user',
    extra: { pre_request_actions: ['authenticate', 'register'] },
    rules: sites.map(rp => ({ rp, authenticate: 'request', register: 'request' })),
  },
  plain: { mode: 'same-user', rules: [{ rp: 'rp-a.test', authenticate: 'request', register: 'deny' }] },
};

scenario({ id: 'E2E-66', exposeModes: ['port', 'pipe'], title: 'audit schema 5: approval_source, pre-request escalation fields, the agent note, pre_approval records with every drop reason, the new deny reasons', ci: true, timeoutMs: 600000 }, async ctx => {
  const stack = await ctx.stack({
    rps: Object.fromEntries('abcd'.split('').map(c => [c, { host: `rp-${c}.test` }])),
    profiles: PROFILES,
    notify: { script: ['approve:1500', 'approve:5000', 'approve:1500', 'approve:1500', 'approve:1500', 'ignore', 'approve:1500', 'approve:1500', 'approve:1500'] },
  });
  const rp = Object.fromEntries('abcd'.split('').map(c => [c, stack.rp[c]]));
  await stack.seedHuman(rp.a, 'alice');
  await stack.seedHuman(rp.b, 'bella');
  await stack.seedHuman(rp.c, 'cora');
  const prompts = () => stack.notify.notifications();
  const register = (page, username) => page.evaluate(u => window.e2e.register({ username: u, userVerification: 'preferred', timeout: 30000 }), username);
  const signIn = async (b, key, username) => { await b.page.goto(`${rp[key].origin}/sw`); return authenticate(b.page, { username }); };
  const endSession = b => (b.agent || b.pipe.agent).close();
  const expiredTokens = async () => policyEvents(await stack.daemon.audit(), 'pre_approval.expired');
  const waitForExpiry = (rpId, n = 1) => waitFor(`a pre_approval.expired for ${rpId}`, async () => (await expiredTokens()).filter(e => e.rp_id === rpId)[n - 1]);

  // ---- 1: an authenticate pre-request from outside any session (a fresh principal session), with a hostile note.
  let s0 = await stack.openOwned('agent', `${rp.a.origin}/sw`);
  assertInterceptionActive(s0);
  const one = await requestAccess(stack, 'agent', 'rp-a.test', { note: HOSTILE_NOTE });
  assert.equal(one.status.state, 'approved', JSON.stringify(one));
  assert.equal((await authenticate(s0.page, { username: 'alice' })).ok, true, 'the grant signs in without a prompt');
  assert.equal(prompts().length, 1);

  // ---- 2: a pre-request that a sign-in ceremony of the same site joins while it waits for the human.
  const pending = await s0.session.requestAccess('rp-b.test', { wait: 0 });
  assert.equal(pending.status.state, 'pending', JSON.stringify(pending));
  await waitFor('the second prompt', () => prompts().length === 2, { timeoutMs: 10000 });
  assert.equal((await signIn(s0, 'b', 'bella')).ok, true, 'the ceremony joined the pre-request and signed in once it was approved');
  assert.equal(prompts().length, 2, 'one prompt for both');

  // ---- 3: a ceremony-time escalation, the control.
  assert.equal((await signIn(s0, 'c', 'cora')).ok, true);
  assert.equal(prompts().length, 3);

  // ---- 4: a register token, consumed by the browser's own registration.
  const four = await s0.session.requestAccess('rp-d.test', { register: true });
  assert.equal(four.status.state, 'approved', JSON.stringify(four));
  await s0.page.goto(`${rp.d.origin}/raw`);
  await s0.page.waitForFunction(() => window.e2e);
  assert.equal((await register(s0.page, 'dina')).ok, true);
  assert.equal(prompts().length, 4);

  // ---- 5 and 6: a register token that a session end will drop, then the refusals: an unlisted site, one pending pre-request per
  // session (the request for rp-e stays pending, so the session asks for its token first), a profile that did not opt in.
  const five = await s0.session.requestAccess('rp-g.test', { register: true });
  assert.equal(five.status.state, 'approved', JSON.stringify(five));
  assert.equal(prompts().length, 5);
  assert.equal((await s0.session.requestAccess('rp-z.test')).status.state, 'not_requestable');
  const left = await s0.session.requestAccess('rp-e.test', { wait: 0 });
  assert.equal(left.status.state, 'pending', JSON.stringify(left));
  await waitFor('the sixth prompt', () => prompts().length === 6, { timeoutMs: 10000 });
  assert.equal((await s0.session.requestAccess('rp-f.test', { wait: 0 })).status.state, 'rate_limited');
  assert.equal((await requestAccess(stack, 'plain', 'rp-a.test')).status.state, 'not_enabled');
  assert.equal(prompts().length, 6);

  // The session ends: its live token is dropped (and the pending rp-e request withdrawn).
  await endSession(s0);
  assert.equal((await waitForExpiry('rp-g.test')).reason, 'session_end');

  // ---- 7: a policy reload that changes the profile drops its tokens.
  const s1 = await stack.openOwned('agent', `${rp.a.origin}/raw`);
  assertInterceptionActive(s1);
  const seven = await s1.session.requestAccess('rp-h.test', { register: true });
  assert.equal(seven.status.state, 'approved', JSON.stringify(seven));
  fs.appendFileSync(stack.daemon.configPath, '\n[[agents.profiles.agent.rules]]\nrp_id = "rp-i.test"\nauthenticate = "deny"\nregister = "deny"\n');
  await stack.daemon.adminJson('policy', 'reload', 'agent');
  assert.equal((await waitForExpiry('rp-h.test')).reason, 'policy_reload');
  await endSession(s1);

  // ---- 8: a revoked browser lease drops the token of the session that owned it (the session itself lives on).
  const s2 = await stack.openOwned('agent', `${rp.a.origin}/raw`);
  assertInterceptionActive(s2);
  const eight = await s2.session.requestAccess('rp-h.test', { register: true });
  assert.equal(eight.status.state, 'approved', JSON.stringify(eight));
  const grant = (await stack.daemon.adminJson('sessions', 'list', '--profile', 'agent')).grants[0];
  assert.ok(grant, 'the browser has a session grant');
  await stack.daemon.adminJson('sessions', 'revoke', grant.grant_id, '--confirm');
  assert.equal((await waitForExpiry('rp-h.test', 2)).reason, 'lease_revoked');
  await endSession(s2);

  // ---- 9: revoking the site's grant drops the token for it.
  const s3 = await stack.openOwned('agent', `${rp.a.origin}/raw`);
  assertInterceptionActive(s3);
  const nine = await s3.session.requestAccess('rp-a.test', { register: true });
  assert.equal(nine.status.state, 'approved', JSON.stringify(nine));
  assert.equal((await stack.daemon.adminJson('grants', 'revoke', '--profile', 'agent', '--rp', 'rp-a.test', '--confirm')).revoked, 1);
  assert.equal((await waitForExpiry('rp-a.test')).reason, 'grant_revoked');
  await endSession(s3);
  assert.equal(prompts().length, 9);

  // ================================ the audit ================================
  const rows = await stack.daemon.audit();
  const audit = rows;
  const all = auditEvents(audit);
  const fields = section12();

  const versions = [...new Set(all.map(e => e.v))];
  assert.deepEqual(versions, [5], `one schema version: ${versions}`);

  // Operation records: every canonical field, `approval_source` among them.
  const operations = all.filter(e => fields.operationKinds.includes(e.kind));
  for (const record of operations) {
    assert.deepEqual(missingFields(record, fields.operation), [], `${record.kind} lacks a canonical field: ${JSON.stringify(record)}`);
    assert.ok([null, 'ceremony', 'pre_request'].includes(record.approval_source), `${record.kind}: ${record.approval_source}`);
  }
  const reservation = (action, rpId) => policyEvents(audit, 'policy.allow').find(e => e.profile_id === 'agent' && e.action === action && e.rp_id === rpId);
  assert.equal(reservation('authenticate', 'rp-a.test').approval_source, null, 'a sign-in on a grant ran on no escalation');
  assert.equal(reservation('authenticate', 'rp-b.test').approval_source, 'pre_request', 'the ceremony that joined a pre-request ran on it');
  assert.equal(reservation('authenticate', 'rp-c.test').approval_source, 'ceremony', 'a ceremony-time escalation');
  assert.equal(reservation('register', 'rp-d.test').approval_source, 'pre_request', 'a registration that consumed a token');
  for (const reservationRecord of [reservation('authenticate', 'rp-b.test'), reservation('register', 'rp-d.test')]) {
    const terminal = policyEvents(audit, 'operation.terminal').find(e => e.request_id === reservationRecord.request_id);
    assert.equal(terminal.approval_source, 'pre_request', 'the terminal record repeats it');
  }

  // Escalation records: `source`, the session hash, the note, the nullable origin.
  const requested = escalationEvents(audit, 'requested');
  assert.deepEqual(requested.map(e => [e.rp_id, e.action, e.source]), [
    ['rp-a.test', 'authenticate', 'pre_request'], ['rp-b.test', 'authenticate', 'pre_request'], ['rp-c.test', 'authenticate', 'ceremony'],
    ['rp-d.test', 'register', 'pre_request'], ['rp-g.test', 'register', 'pre_request'], ['rp-e.test', 'authenticate', 'pre_request'],
    ['rp-h.test', 'register', 'pre_request'], ['rp-h.test', 'register', 'pre_request'], ['rp-a.test', 'register', 'pre_request'],
  ], JSON.stringify(requested.map(e => [e.rp_id, e.action, e.source])));
  for (const e of escalationEvents(audit)) {
    const own = fields.other[e.kind];
    assert.deepEqual(missingFields(e, own), [], `${e.kind} lacks a canonical field: ${JSON.stringify(e)}`);
    if (e.source === 'pre_request') {
      assert.match(e.principal_session_id_hash, HASH, `${e.kind}: the requesting session's hash`);
      assert.equal(e.origin, null, `${e.kind}: no page is behind a pre-request`);
    } else {
      assert.equal(e.source, 'ceremony');
      // A ceremony's escalation names the principal session whose browser the page runs in.
      assert.match(e.principal_session_id_hash, HASH, `${e.kind}: the owning session's hash`);
      assert.equal(e.origin, 'https://rp-c.test');
    }
  }
  assert.equal(requested[0].agent_note, SANITIZED_NOTE, 'the note is sanitized (markup, line break and bidi control gone) and kept');
  assert.deepEqual(escalationEvents(audit).filter(e => e.agent_note !== null).map(e => e.kind), ['escalation.requested'], 'the note is on one `requested` record only');
  assert.ok(requested.slice(1).every(e => e.agent_note === null));
  assert.ok(requested[0].agent_note.length <= 200);
  // Sessions: the fresh session of rp-a's request differs from the owner's.
  const hashOf = rpId => requested.find(e => e.rp_id === rpId).principal_session_id_hash;
  assert.notEqual(hashOf('rp-a.test'), hashOf('rp-b.test'), 'a fresh session for the CLI call outside a session, the owner\'s for the rest');
  assert.equal(hashOf('rp-b.test'), hashOf('rp-d.test'), 'the owner asked for both');
  assert.equal(hashOf('rp-c.test'), hashOf('rp-b.test'), 'the ceremony-time escalation names the owner of the page\'s browser');
  assert.ok(escalationEvents(audit, 'approved').some(e => e.source === 'pre_request'));
  assert.deepEqual(grantedRuleEvents(audit, 'add').filter(e => e.rp_id === 'rp-a.test').map(e => e.grant_kind), ['escalation']);
  for (const e of grantedRuleEvents(audit, 'add')) assert.deepEqual(missingFields(e, fields.other['granted_rule.add']), []);

  // pre_approval.*: the tokens of 4 and 6 to 9, each record with its canonical fields.
  const issued = policyEvents(audit, 'pre_approval.issued');
  const consumed = policyEvents(audit, 'pre_approval.consumed');
  const expired = policyEvents(audit, 'pre_approval.expired');
  assert.deepEqual(issued.map(e => e.rp_id), ['rp-d.test', 'rp-g.test', 'rp-h.test', 'rp-h.test', 'rp-a.test']);
  assert.deepEqual(consumed.map(e => e.rp_id), ['rp-d.test']);
  assert.equal(consumed[0].request_id, reservation('register', 'rp-d.test').request_id, 'the consuming request');
  assert.deepEqual(expired.map(e => [e.rp_id, e.reason]), [
    ['rp-g.test', 'session_end'], ['rp-h.test', 'policy_reload'], ['rp-h.test', 'lease_revoked'], ['rp-a.test', 'grant_revoked'],
  ], JSON.stringify(expired.map(e => [e.rp_id, e.reason])));
  for (const e of [...issued, ...consumed, ...expired]) {
    assert.deepEqual(missingFields(e, fields.other[e.kind]), [], `${e.kind}: ${JSON.stringify(e)}`);
    assert.match(e.principal_session_id_hash, HASH);
    assert.equal(e.rule, 'exact');
  }
  assert.ok(issued.every(e => e.ttl_secs > 0 && e.ttl_secs <= 600));
  // A token is issued once per approved register pre-request, and each ends exactly once.
  assert.equal(issued.length, consumed.length + expired.length);

  // The new refusals, each without a prompt.
  assert.deepEqual(denyReasons(audit, { profile: 'agent', rpId: 'rp-z.test' }), ['not_requestable']);
  assert.deepEqual(denyReasons(audit, { profile: 'agent', rpId: 'rp-f.test' }), ['pre_request_rate_limited']);
  assert.deepEqual(denyReasons(audit, { profile: 'plain' }), ['pre_request_not_enabled']);
  for (const e of policyEvents(audit, 'policy.deny').filter(e => /^(not_requestable|pre_request_)/.test(e.reason))) {
    assert.equal(e.credential_scope, null);
    assert.ok(!JSON.stringify(e).includes(NOTE_MARK));
  }

  // No notification shows the agent's note, or anything it wrote.
  for (const n of prompts()) assert.doesNotMatch(`${n.summary}\n${n.body}\n${n.actions.join('\n')}`, new RegExp(`${NOTE_MARK}|ghp_|please approve|second line`), 'the note reached a prompt');

  // The export labels the agent's words: the JSON rows name the field, the CSV has a column for it.
  const labelled = rows.filter(r => r.agent_supplied);
  assert.deepEqual(labelled.map(r => [r.event.kind, r.agent_supplied]), [['escalation.requested', ['agent_note']]], 'only the record with a note is labelled');
  const csv = await stack.daemon.adminJson('audit', 'export', '--format', 'csv');
  const csvLines = fs.readFileSync(csv.path, 'utf8').split('\n').filter(Boolean);
  assert.equal(csvLines[0], 'sequence,wall_time_ms,monotonic_ms,kind,event,agent_supplied');
  const withNote = csvLines.slice(1).filter(l => l.includes(NOTE_MARK));
  assert.equal(withNote.length, 1);
  assert.ok(withNote[0].endsWith(',agent_note'), withNote[0].slice(-60));
  assert.ok(csvLines.slice(1).filter(l => !l.includes(NOTE_MARK)).every(l => l.endsWith(',')), 'every other row has an empty label');
});
