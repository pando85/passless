'use strict';
const { scenario, assert } = require('../lib/scenario');
const { policyEvents, escalationEvents, grantedRuleEvents, denyReasons, auditEvents, grantsStore, assertInterceptionActive, waitFor } = require('../lib/helpers');
const { REGISTER_SUMMARY, humanStoreLine, assertRegistrationActions, preRequestRegistrationBody } = require('../lib/escalation');
const { startPrincipalShell } = require('../lib/adapters');

// ADR 0014 amendment section 2.3, step 2: `passless agent request-access --register`. The approval is a one-use token (10
// minutes at most, never longer than the principal session) bound to the principal session that owns the browser, which is
// the session that asked: it is consumed by the next registration ceremony of that browser at that site.
//
//   rp-a   token consumed: the prompt is the registration one with "Origin: none yet" and "Requested by: the agent in
//          advance"; the next registration at rp-a (no page was waiting when it was approved) completes with no second
//          prompt; a third prompts again (the token was one-use) and the scripted human denies it
//   rp-b   another principal session of the profile cannot ask: `not_requestable`, no prompt; and the owner's pending
//          request is ADOPTED by the page's registration ceremony: one prompt, one registration, no token left over
//   short  a profile whose principal session lives 45 s: the token ends with the session (`ttl`), audited as expired
//   rp-c   a live token is dropped when its principal session ends (`session_end`)
const PROFILES = {
  agent: {
    mode: 'same-user',
    extra: { pre_request_actions: ['authenticate', 'register'] },
    rules: ['rp-a.test', 'rp-b.test', 'rp-c.test'].map(rp => ({ rp, authenticate: 'request', register: 'request' })),
  },
  short: {
    mode: 'same-user',
    max_session_ttl: 45,
    extra: { pre_request_actions: ['register'] },
    rules: [{ rp: 'rp-a.test', authenticate: 'request', register: 'request' }],
  },
};

/** The token records of `kind` (`issued`, `consumed`, `expired`). */
const tokens = (audit, kind) => policyEvents(audit, `pre_approval.${kind}`);

scenario({ id: 'E2E-64', exposeModes: ['port', 'pipe'], title: 'agent request-access --register: a one-use token consumed by the owning session, refused for another session, adopted while pending, dropped with the session', ci: true, timeoutMs: 420000 }, async ctx => {
  const stack = await ctx.stack({
    rps: { a: { host: 'rp-a.test' }, b: { host: 'rp-b.test' }, c: { host: 'rp-c.test' } },
    profiles: PROFILES,
    // 1 rp-a token (approved), 2 rp-a third registration (denied), 3 rp-b adopted (approved after the page asked), 4 short
    // profile token (approved), 5 rp-c token (approved).
    notify: { script: ['approve:1500', 'deny:1500', 'approve:5000', 'approve:1500', 'approve:1500'] },
  });
  const [rpA, rpB, rpC] = [stack.rp.a, stack.rp.b, stack.rp.c];
  await stack.seedHuman(rpA, 'alice');
  const prompts = () => stack.notify.notifications();
  const register = (page, username) => page.evaluate(u => window.e2e.register({ username: u, userVerification: 'preferred', timeout: 30000 }), username);
  const registered = rp => rp.registrations.filter(r => r.ok).length;
  const humanFiles = () => stack.daemon.humanStore().length;

  // ---- rp-a: the owner asks, the token is consumed by the next registration, and only one.
  let b = await stack.openOwned('agent', `${rpA.origin}/raw`);
  assertInterceptionActive(b);
  await b.page.waitForFunction(() => window.e2e);
  const asked = await b.session.requestAccess('rp-a.test', { register: true, note: 'sign up at rp-a' });
  assert.equal(asked.code, 0, asked.stderr);
  assert.equal(asked.status.state, 'approved', JSON.stringify(asked));
  assert.equal(asked.status.action, 'register');
  assert.ok(asked.status.expires_in_secs > 0 && asked.status.expires_in_secs <= 300, `capped by the session's remaining TTL (300 s here): ${asked.status.expires_in_secs}`);
  assert.equal(prompts().length, 1);
  assert.equal(prompts()[0].summary, REGISTER_SUMMARY);
  assert.equal(prompts()[0].body, preRequestRegistrationBody({ site: 'rp-a.test', stored: humanStoreLine('agent', 1) }), 'daemon-derived text only');
  assertRegistrationActions(prompts()[0]);
  assert.ok(!prompts()[0].body.includes('sign up at rp-a'), 'the note is not in the prompt');
  assert.equal(grantsStore(stack, 'agent').grants.length, 0, 'a token persists nothing');
  const humanBefore = humanFiles();

  const registeredBefore = registered(rpA);
  const first = await register(b.page, 'rita');
  assert.equal(first.ok, true, `the token is consumed by the next registration: ${JSON.stringify(first)}`);
  assert.equal(registered(rpA), registeredBefore + 1, 'the RP verified the registration');
  assert.equal(humanFiles(), humanBefore + 1, 'the credential is in the human store');
  assert.equal(prompts().length, 1, 'the ceremony used the token: no second prompt');

  const second = await register(b.page, 'rolf');
  assert.equal(second.ok, false, `the token was one-use: ${JSON.stringify(second)}`);
  assert.equal(second.name, 'NotAllowedError');
  assert.equal(prompts().length, 2, 'the third registration prompted, and the scripted human denied it');
  assert.equal(humanFiles(), humanBefore + 1);

  let audit = await stack.daemon.audit();
  assert.equal(tokens(audit, 'issued').length, 1);
  assert.equal(tokens(audit, 'consumed').length, 1);
  assert.equal(tokens(audit, 'expired').length, 0);
  assert.equal(tokens(audit, 'issued')[0].rp_id, 'rp-a.test');
  // Ten minutes, but never longer than the principal session's own 300 s (the harness's max_session_ttl) that remain.
  assert.ok(tokens(audit, 'issued')[0].ttl_secs > 0 && tokens(audit, 'issued')[0].ttl_secs <= 300, `ttl_secs: ${tokens(audit, 'issued')[0].ttl_secs}`);
  const consumedBy = policyEvents(audit, 'policy.allow').find(e => e.action === 'register' && e.rp_id === 'rp-a.test');
  assert.equal(tokens(audit, 'consumed')[0].request_id, consumedBy.request_id, 'the record names the ceremony that consumed it');

  // ---- rp-b, another principal session of the profile: it cannot run the owner's ceremonies, so it is not issued a token.
  const other = startPrincipalShell(stack, 'agent', [
    '"$PASSLESS" agent --profile agent request-access rp-b.test --register --json --wait 0; echo "EXIT $?"',
    'exec sleep 900',
  ].join('\n'));
  try {
    await other.waitForLine(/^EXIT \d+$/, 60000);
    const status = JSON.parse(other.lines().find(l => l.startsWith('{')));
    assert.equal(status.state, 'not_requestable', JSON.stringify(status));
    assert.match(status.message, /Another session owns this profile's browser/, `the message says why: ${status.message}`);
    assert.equal(prompts().length, 2, 'refused without a prompt');
  } finally { await other.close(); }

  // ---- rp-b, the owner: the pending request is adopted by the registration ceremony that arrives while it waits.
  await b.page.goto(`${rpB.origin}/raw`);
  await b.page.waitForFunction(() => window.e2e);
  const pending = await b.session.requestAccess('rp-b.test', { register: true, wait: 0 });
  assert.equal(pending.status.state, 'pending', JSON.stringify(pending));
  await waitFor('the third prompt', () => prompts().length === 3, { timeoutMs: 10000 });
  const adopted = await register(b.page, 'bruno');
  assert.equal(adopted.ok, true, `the ceremony adopted the pending request and completed: ${JSON.stringify(adopted)}`);
  assert.equal(registered(rpB), 1);
  assert.equal(prompts().length, 3, 'one prompt for the request and the ceremony together');
  assert.equal(prompts()[2].body, preRequestRegistrationBody({ site: 'rp-b.test', stored: humanStoreLine('agent', 0) }));
  audit = await stack.daemon.audit();
  assert.equal(tokens(audit, 'issued').length, 1, 'adoption issues no token');
  assert.deepEqual(escalationEvents(audit, 'requested').map(e => [e.rp_id, e.action, e.source]), [
    ['rp-a.test', 'register', 'pre_request'], ['rp-a.test', 'register', 'ceremony'], ['rp-b.test', 'register', 'pre_request'],
  ], 'the third registration at rp-a asked on its own; the pending one was not asked twice');
  assert.deepEqual(denyReasons(audit, { profile: 'agent', rpId: 'rp-b.test' }), ['not_requestable']);

  // ---- session end: a live token is dropped with its principal session, and so is the browser's.
  // The shared browser belongs to the session that launched it, so a new owner needs that session gone first. Its end
  // is also what ends the browser; the token of the new owner at rp-c then waits for no ceremony and is dropped with it.
  await (b.agent || b.pipe.agent).close();
  b = await stack.openOwned('agent', `${rpC.origin}/raw`);
  assertInterceptionActive(b);
  // Prompt 4 is the short profile's token, 5 is rp-c's.
  const shortB = await stack.openOwned('short', `${rpA.origin}/raw`);
  assertInterceptionActive(shortB);
  const shortAsked = await shortB.session.requestAccess('rp-a.test', { register: true });
  assert.equal(shortAsked.status.state, 'approved', JSON.stringify(shortAsked));
  assert.ok(shortAsked.status.expires_in_secs <= 45, `the token never outlives its session: ${shortAsked.status.expires_in_secs}`);
  const ownedAsked = await b.session.requestAccess('rp-c.test', { register: true });
  assert.equal(ownedAsked.status.state, 'approved', JSON.stringify(ownedAsked));
  assert.equal(tokens(await stack.daemon.audit(), 'issued').length, 3);
  assert.equal(prompts().length, 5);
  await (b.agent || b.pipe.agent).close();
  const ended = await waitFor('the session-end drop', async () => tokens(await stack.daemon.audit(), 'expired').find(e => e.rp_id === 'rp-c.test'), { timeoutMs: 20000 });
  assert.equal(ended.reason, 'session_end');

  // ---- short profile: the token ends with its principal session at the 45 s limit (audited as a ttl expiry).
  const expired = await waitFor('the short profile\'s token to expire', async () => tokens(await stack.daemon.audit(), 'expired').find(e => e.rp_id === 'rp-a.test'), { timeoutMs: 90000, intervalMs: 500 });
  assert.ok(['ttl', 'session_end'].includes(expired.reason), `the token ended with its short-lived session: ${expired.reason}`);
  assert.equal(expired.profile_id, 'short');
  ctx.t.diagnostic(`short-profile token expiry reason: ${expired.reason}`);

  audit = await stack.daemon.audit();
  assert.equal(tokens(audit, 'issued').length, 3);
  assert.equal(tokens(audit, 'consumed').length, 1);
  assert.equal(tokens(audit, 'expired').length, 2);
  assert.ok(grantedRuleEvents(audit, 'add').every(e => e.grant_kind === 'registration'), 'only registrations persisted a grant');
  assert.ok(auditEvents(audit).every(e => e.kind !== 'pre_approval.consumed' || e.profile_id === 'agent'));
});
