'use strict';
const { scenario, assert } = require('../lib/scenario');
const { authenticate, policyEvents, assertVerifiedAssertion, assertInterceptionActive, assertAgentAllowed, extensionEndpoint, postToDaemon } = require('../lib/helpers');

// Catalogue: `http://localhost` RP works. P4 made the daemon accept `rp_id = "localhost"` and `http://localhost[:port]`
// origins for exact rules (R15): step 1 proves that by posting a sign request straight to the daemon with the extension's
// own endpoint. The extension's worker still parses https origins only (R12), so the page-level ceremony (step 2) is
// rejected before it reaches the daemon until the P6 rewrite; that remaining failure is what the xfail matches.
scenario({
  id: 'E2E-06', title: 'http://localhost RP works', ci: true,
  xfailUntil: 'P6', xfailMatch: /extension rejected the http:\/\/localhost origin/, xfailReason: 'the daemon accepts localhost since P4, but the extension worker (worker.js) parses https origins only until the P6 rewrite (R12, R15)',
}, async ctx => {
  const stack = await ctx.stack({
    rps: { local: { host: 'localhost' } },
    profiles: { agent: { mode: 'same-user', rules: [{ rp: 'localhost', authenticate: 'allow', register: 'deny' }] } },
  });
  const rp = stack.rp.local;
  await stack.seedHuman(rp, 'alice');
  const b = await stack.open('agent', `${rp.origin}/sw`);
  assertInterceptionActive(b);

  // Step 1 (daemon): an exact `localhost` rule signs for the `http://localhost:<port>` origin, with UP and UV set.
  const request = {
    origin: rp.origin, rp_id: 'localhost', challenge_b64u: Buffer.from(`localhost-${Date.now()}`).toString('base64url'),
    allow_credentials: [], user_verification: false, cross_origin: false,
  };
  const direct = await postToDaemon(await extensionEndpoint(b), '/sign', request);
  assert.equal(direct.status, 200, `the daemon must sign for rp_id localhost / origin ${rp.origin}: ${direct.status} ${direct.body}`);
  const authData = Buffer.from(JSON.parse(direct.body).sign_assertion_result.authenticator_data_b64u, 'base64url');
  assert.equal(authData[32] & 0x05, 0x05, 'agent evidence: UP and UV are set');
  await assertAgentAllowed(stack, { rpId: 'localhost', n: 1 });

  // Step 2 (page, through the extension).
  const res = await authenticate(b.page, { username: 'alice' });
  if (!res.ok) {
    const audit = await stack.daemon.audit();
    const reached = policyEvents(audit, 'policy.allow').filter(e => e.rp_id === 'localhost').length > 1
      || policyEvents(audit, 'policy.deny').some(e => e.rp_id === 'localhost');
    if (!reached) throw new Error(`extension rejected the http://localhost origin: the page ceremony never reached the daemon (${JSON.stringify(res)})`);
  }
  assertVerifiedAssertion(rp, res, { username: 'alice' });
  await assertAgentAllowed(stack, { rpId: 'localhost', n: 2 });
});
