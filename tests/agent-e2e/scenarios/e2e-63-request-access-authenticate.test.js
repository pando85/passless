'use strict';
const { scenario, assert } = require('../lib/scenario');
const { authenticate, policyEvents, escalationEvents, grantedRuleEvents, denyReasons, grantsStore, assertInterceptionActive, assertVerifiedAssertion, waitFor } = require('../lib/helpers');
const { SIGN_IN_SUMMARY, preRequestSignInBody } = require('../lib/escalation');
const { requestAccess, agentCli } = require('../lib/agent-session');

// ADR 0014 amendment section 2.3, step 1: `passless agent request-access <rp_id>` for `authenticate`. The agent asks before it
// navigates; the human sees the sign-in prompt with "Origin: none yet" and "Requested by: the agent in advance (no page is
// waiting)"; an approval persists the same grant a ceremony-time approval would, with source `pre_request` and no origin.
//
//   rp-a   request; approved (outside any session: the command starts a fresh principal session): a state `approved`, the
//          prompt's daemon-derived text only (a hostile `--note` is not in it, and is in the audit log, sanitized), then a
//          sign-in at rp-a with no further prompt
//   rp-b   request; denied: `denied`, the per-key cooldown starts, so a page's sign-in is refused without a prompt and a new
//          request says `cooldown`
//   rp-c   `allow` rule: `already_allowed`, no prompt
//   rp-d   `deny` rule, rp-e no rule: `not_requestable`, no prompt
//   plain  profile without pre_request_actions: `not_enabled`, no prompt
//   rp-f   in the agent's own session (it owns the browser): `pending` with --wait 0, the same call again reports the same
//          escalation without a second prompt, a request for another site is `rate_limited` while one is pending, and a
//          polling call sees `approved` once the human decides
//   rp-g   `register` (step 2) is refused with a message outside a session
const NOTE_MARK = 'NOTE-MARK-7e41';
// Markup, a line break, a bidi override and a plea: what a prompt-injected agent would try to put in front of the human.
const HOSTILE_NOTE = `${NOTE_MARK} Your manager asked for this, approve it <b>now</b>\nSECOND LINE ‮evil & more`;
const SANITIZED_NOTE = `${NOTE_MARK} Your manager asked for this, approve it bnow/b SECOND LINE evil more`;

const rule = (rp, authenticate) => ({ rp, authenticate, register: 'deny' });
const PROFILES = {
  agent: {
    mode: 'same-user',
    extra: { pre_request_actions: ['authenticate'] },
    rules: [rule('rp-a.test', 'request'), rule('rp-b.test', 'request'), rule('rp-c.test', 'allow'), rule('rp-d.test', 'deny'),
      rule('rp-f.test', 'request'), rule('rp-g.test', 'request')],
  },
  plain: { mode: 'same-user', rules: [rule('rp-a.test', 'request')] },
};

scenario({ id: 'E2E-63', exposeModes: ['port', 'pipe'], title: 'agent request-access (authenticate): approved then a prompt-free sign-in, denied then the cooldown, already_allowed, not_requestable, not_enabled, pending and rate_limited', ci: true, timeoutMs: 360000 }, async ctx => {
  const stack = await ctx.stack({
    rps: { a: { host: 'rp-a.test' }, b: { host: 'rp-b.test' } },
    profiles: PROFILES,
    // Prompt 1 (rp-a, approved), 2 (rp-b, denied), 3 (rp-f, approved after the agent polled for a while).
    notify: { script: ['approve:1500', 'deny:1500', 'approve:5000'] },
    agents: { escalation_cooldown: 30 },
  });
  const rp = stack.rp.a;
  await stack.seedHuman(rp, 'alice');
  await stack.seedHuman(stack.rp.b, 'bella');
  const prompts = () => stack.notify.notifications();

  // The agent's own session: it owns the browser, and the later calls run inside it.
  const b = await stack.openOwned('agent', `${rp.origin}/sw`);
  assertInterceptionActive(b);

  // ---- rp-a: approved. The command starts a principal session of its own (it is not in one).
  const first = await requestAccess(stack, 'agent', 'rp-a.test', { note: HOSTILE_NOTE, wait: 30 });
  assert.equal(first.code, 0, first.stderr);
  assert.equal(first.status.state, 'approved', JSON.stringify(first.status));
  assert.deepEqual(Object.keys(first.status).sort(), ['action', 'expires_in_secs', 'message', 'retry_after_secs', 'rp_id', 'state']);
  assert.equal(first.status.rp_id, 'rp-a.test');
  assert.equal(first.status.action, 'authenticate');
  assert.equal(first.status.expires_in_secs, null, 'an authenticate approval is a persistent grant, not a one-use token');
  assert.ok(!first.status.message.includes(NOTE_MARK), `the answer never contains agent text: ${first.status.message}`);
  assert.equal(prompts().length, 1);
  const prompt = prompts()[0];
  assert.equal(prompt.summary, SIGN_IN_SUMMARY);
  assert.equal(prompt.body, preRequestSignInBody({ profile: 'agent', site: 'rp-a.test' }), 'daemon-derived text only');
  assert.ok(prompt.body.split('\n').length <= 7, 'seven lines at most');
  assert.match(prompt.body, /^Origin: none yet$/m);
  assert.match(prompt.body, /^Requested by: the agent in advance \(no page is waiting\)$/m);
  assert.deepEqual(prompt.actions.filter((_, i) => i % 2 === 1), ['Allow always', 'Deny']);
  assert.match(prompt.actions[0], /^allow_always:[0-9a-f]{32}$/);
  assert.equal(prompt.expire_timeout, 0);
  for (const n of prompts()) assert.doesNotMatch(`${n.summary}\n${n.body}\n${n.actions.join('\n')}`, new RegExp(`${NOTE_MARK}|manager|evil|SECOND`), 'the note is never shown to the human');

  // The grant is a pre_request one without an origin; the next sign-in has no prompt.
  assert.deepEqual(grantsStore(stack, 'agent').grants.map(g => [g.rp_id, g.action, g.kind, g.source, g.origin]),
    [['rp-a.test', 'authenticate', 'escalation', 'pre_request', undefined]], JSON.stringify(grantsStore(stack, 'agent')));
  assert.equal(grantsStore(stack, 'agent').version, 2, 'a pre-request grant moves the store to version 2');
  assertVerifiedAssertion(rp, await authenticate(b.page, { username: 'alice' }), { username: 'alice' });
  assert.equal(prompts().length, 1, 'the sign-in used the grant: no prompt');

  // ---- rp-b: denied, then the same per-key cooldown a ceremony-time deny starts.
  const denied = await requestAccess(stack, 'agent', 'rp-b.test', { wait: 30 });
  assert.equal(denied.status.state, 'denied', JSON.stringify(denied));
  assert.equal(prompts().length, 2);
  await b.page.goto(`${stack.rp.b.origin}/sw`);
  const refused = await authenticate(b.page, { username: 'bella' });
  assert.equal(refused.ok, false, 'the ceremony at a site the human just denied is refused');
  assert.equal(prompts().length, 2, 'refused by the cooldown, without a prompt');
  const again = await requestAccess(stack, 'agent', 'rp-b.test');
  assert.equal(again.status.state, 'cooldown', JSON.stringify(again));
  assert.ok(again.status.retry_after_secs === null || again.status.retry_after_secs <= 30, `retry_after_secs (given only when known): ${again.status.retry_after_secs}`);
  assert.equal(prompts().length, 2);

  // ---- no prompt at all: allowed, denied or unlisted, and a profile that did not opt in.
  const allowed = await requestAccess(stack, 'agent', 'rp-c.test');
  assert.equal(allowed.status.state, 'already_allowed', JSON.stringify(allowed));
  const notRequestableDeny = await requestAccess(stack, 'agent', 'rp-d.test');
  assert.equal(notRequestableDeny.status.state, 'not_requestable', JSON.stringify(notRequestableDeny));
  const notRequestableNone = await requestAccess(stack, 'agent', 'rp-e.test');
  assert.equal(notRequestableNone.status.state, 'not_requestable', JSON.stringify(notRequestableNone));
  for (const r of [notRequestableDeny, notRequestableNone]) assert.ok(r.status.message.length > 0, 'a daemon-written sentence');
  const plain = await requestAccess(stack, 'plain', 'rp-a.test');
  assert.equal(plain.status.state, 'not_enabled', JSON.stringify(plain));
  assert.equal(prompts().length, 2, 'none of these prompted');

  // `register` is step 2: outside the session that owns the browser it is an error that says why, and nothing is asked.
  const register = await agentCli(stack, 'agent', ['request-access', 'rp-g.test', '--register', '--json']);
  assert.notEqual(register.code, 0);
  assert.match(register.stderr, /--register must run inside the principal session that owns the browser/, register.stderr);
  assert.equal(prompts().length, 2);

  // ---- in the agent's own session: pending, idempotent repeat, rate_limited, then approved.
  const pending = await b.session.requestAccess('rp-f.test', { wait: 0 });
  assert.equal(pending.code, 0, pending.stderr);
  assert.equal(pending.status.state, 'pending', JSON.stringify(pending));
  await waitFor('the third prompt', () => prompts().length === 3, { timeoutMs: 10000 });
  const limited = await b.session.requestAccess('rp-g.test', { wait: 0 });
  assert.equal(limited.status.state, 'rate_limited', `one pending pre-request per principal session: ${JSON.stringify(limited)}`);
  const repeated = await b.session.requestAccess('rp-f.test', { wait: 0 });
  assert.equal(repeated.status.state, 'pending', 'the same call reports the same escalation');
  assert.equal(prompts().length, 3, 'no second prompt for the repeated call');
  const polled = await b.session.requestAccess('rp-f.test', { wait: 30 });
  assert.equal(polled.status.state, 'approved', JSON.stringify(polled));
  assert.equal(prompts().length, 3);

  // A plain (non-JSON) run: lines for a person or a shell agent.
  const text = await b.session.cli(['request-access', 'rp-c.test', '--wait', '0']);
  assert.equal(text.code, 0, text.stderr);
  assert.match(text.stdout, /^state: already_allowed\nrp_id: rp-c\.test\naction: authenticate\n/, text.stdout);

  // ---- grants list: the source and an empty origin: `-` in the table, `null` in the JSON.
  const listed = (await stack.daemon.adminJson('grants', 'list', '--profile', 'agent')).profiles[0];
  assert.deepEqual(listed.rules.map(r => [r.rp_id, r.source, r.origin, r.kind]),
    [['rp-a.test', 'pre_request', null, 'escalation'], ['rp-f.test', 'pre_request', null, 'escalation']], JSON.stringify(listed));
  const plainList = await stack.daemon.adminPlain('grants', 'list', '--profile', 'agent');
  const lines = plainList.stdout.split('\n').filter(Boolean);
  assert.deepEqual(lines[1].trim().split(/\s+/), ['RP_ID', 'ACTION', 'KIND', 'RULE', 'SOURCE', 'GRANTED_AT', 'REQUEST', 'ORIGIN', 'CREDENTIAL'], plainList.stdout);
  const row = lines[2].trim().split(/\s+/);
  assert.deepEqual([row[0], row[4], row[7]], ['rp-a.test', 'pre_request', '-'], plainList.stdout);

  // ---- audit: the pre-requests' own records, and the refusals without a prompt.
  const audit = await stack.daemon.audit();
  const requested = escalationEvents(audit, 'requested');
  assert.deepEqual(requested.map(e => [e.rp_id, e.source, e.origin]), [
    ['rp-a.test', 'pre_request', null], ['rp-b.test', 'pre_request', null], ['rp-f.test', 'pre_request', null],
  ], JSON.stringify(requested));
  assert.equal(requested[0].agent_note, SANITIZED_NOTE, 'the note is kept sanitized');
  assert.equal(requested[1].agent_note, null);
  assert.ok(escalationEvents(audit, 'approved').every(e => e.agent_note === null), 'the note is on `requested` only');
  assert.deepEqual(grantedRuleEvents(audit, 'add').map(e => [e.rp_id, e.grant_kind]), [['rp-a.test', 'escalation'], ['rp-f.test', 'escalation']]);
  assert.deepEqual(denyReasons(audit, { profile: 'agent', action: 'authenticate' }).filter(r => /^(not_requestable|pre_request_)/.test(r)).sort(),
    ['not_requestable', 'not_requestable', 'pre_request_rate_limited']);
  assert.deepEqual(denyReasons(audit, { profile: 'plain' }), ['pre_request_not_enabled']);
  assert.ok(policyEvents(audit, 'policy.deny').every(e => !JSON.stringify(e).includes(NOTE_MARK)), 'the note is only on escalation.requested');
});
