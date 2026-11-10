'use strict';
const { scenario } = require('../lib/scenario');
const { authenticate, assertVerifiedAssertion, assertInterceptionActive, assertAgentAllowed } = require('../lib/helpers');

// Catalogue: `http://localhost` RP works. Today it cannot: validate_rp_id rejects "localhost" (needs two
// labels, so the whole agent subsystem fails to start), and the extension manifest matches https://*/*
// only (R12, R15).
scenario({
  id: 'E2E-06', title: 'http://localhost RP works', ci: true,
  xfailUntil: 'P6', xfailMatch: /Configuration error: RP ID must have at least two labels: 'localhost'/, xfailReason: 'config rejects rp_id "localhost" (R15, P4) and the manifest matches https only (R12, P6)',
}, async ctx => {
  const stack = await ctx.stack({
    rps: { local: { host: 'localhost' } },
    profiles: { agent: { mode: 'same-user', rules: [{ rp: 'localhost', authenticate: 'allow', register: 'deny' }] } },
  });
  const rp = stack.rp.local;
  await stack.seedHuman(rp, 'alice');
  const b = await stack.open('agent', `${rp.origin}/sw`);
  assertInterceptionActive(b);
  assertVerifiedAssertion(rp, await authenticate(b.page, { username: 'alice' }), { username: 'alice' });
  await assertAgentAllowed(stack, { rpId: 'localhost', n: 1 });
});
