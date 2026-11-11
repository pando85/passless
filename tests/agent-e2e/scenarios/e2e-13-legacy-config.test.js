'use strict';
const { scenario, assert } = require('../lib/scenario');
const { authenticate, policyEvents, assertVerifiedAssertion, assertInterceptionActive } = require('../lib/helpers');
const { DaemonStartError } = require('../lib/daemon');

// Catalogue: a legacy config warns and maps; `allow` with human (or none) evidence fails startup (ADR 0014 6.4,
// plan R8). The legacy vocabulary is accepted for one minor release:
//   `autonomous` -> allow, `supervised` and `confirm` evidence tables -> request, allow+agent+agent -> allow.
// The daemon logs one deprecation warning per mapped rule field at load, and `passless agent-admin profile check`
// (the doctor report) shows them as `config_deprecation` checks.
const EVIDENCE_CONFIRM = '{ authorization = "confirm", user_presence = "human", user_verification = "human" }';
const EVIDENCE_ALLOW_AGENT = '{ authorization = "allow", user_presence = "agent", user_verification = "agent" }';

scenario({ id: 'E2E-13', title: 'legacy config warns and maps; allow+human fails startup', ci: true }, async ctx => {
  const stack = await ctx.stack({
    rps: { a: { host: 'rp-a.test' }, b: { host: 'rp-b.test' } },
    profiles: {
      agent: {
        mode: 'same-user',
        legacyRules: [
          // alias -> allow
          { rp: 'rp-a.test', authenticate: '"autonomous"', register: '"deny"' },
          // evidence table confirm+human -> request (denied with escalation_unavailable: no notification server)
          { rp: 'rp-b.test', authenticate: EVIDENCE_CONFIRM, register: '"deny"' },
          // evidence table allow+agent+agent -> allow
          { rp: 'rp-c.test', authenticate: EVIDENCE_ALLOW_AGENT, register: '"supervised"' },
        ],
      },
    },
    notify: false,
  });
  const rpA = stack.rp.a;
  const rpB = stack.rp.b;

  // Warnings: once per mapped legacy field, at load, from the daemon log.
  const log = stack.daemon.log();
  for (const [rule, field, to] of [['rp-a.test', 'authenticate', 'allow'], ['rp-b.test', 'authenticate', 'request'], ['rp-c.test', 'authenticate', 'allow'], ['rp-c.test', 'register', 'request']]) {
    const re = new RegExp(`agent profile 'agent': rule '${rule.replace(/\./g, '\\.')}': .*${field}.* is deprecated and was mapped to \`${field} = "${to}"\``);
    const hits = log.split('\n').filter(l => re.test(l));
    assert.equal(hits.length, 1, `expected exactly one deprecation warning for ${rule} ${field} -> ${to}, log:\n${log.split('\n').filter(l => /deprecat/.test(l)).join('\n')}`);
  }
  assert.equal(log.split('\n').filter(l => /rule 'rp-[ab]\.test': .*register/.test(l) && /deprecated/.test(l)).length, 0, '`register = "deny"` is not legacy vocabulary and must not warn');

  // The doctor report surfaces the same warnings without failing the profile.
  const report = await stack.daemon.adminJson('profile', 'check', 'agent');
  const deprecations = (report.checks || []).filter(c => c.name === 'config_deprecation');
  assert.equal(deprecations.length, 4, `doctor must list the 4 deprecations: ${JSON.stringify(report.checks)}`);
  assert.ok(deprecations.every(c => c.passed === true), 'a deprecation never makes the profile unhealthy');

  // Mapping behaviour: `autonomous` is `allow`; a confirm table is `request`.
  await stack.seedHuman(rpA, 'alice');
  await stack.seedHuman(rpB, 'bob');
  const b = await stack.open('agent', `${rpA.origin}/sw`);
  assertInterceptionActive(b);
  assertVerifiedAssertion(rpA, await authenticate(b.page, { username: 'alice' }), { username: 'alice' });
  await b.page.goto(`${rpB.origin}/sw`);
  const res = await authenticate(b.page, { username: 'bob' });
  assert.equal(res.ok, false, `a legacy confirm table maps to request, which is denied without a notification server: ${JSON.stringify(res)}`);
  assert.equal(res.name, 'NotAllowedError');
  const audit = await stack.daemon.audit();
  assert.equal(policyEvents(audit, 'policy.allow').filter(e => e.rp_id === 'rp-a.test').length, 1);
  const denies = policyEvents(audit, 'policy.deny').filter(e => e.rp_id === 'rp-b.test');
  assert.equal(denies.length, 1);
  assert.equal(denies[0].reason, 'escalation_unavailable');
});

// Configs that cannot be mapped safely must stop the daemon with an actionable message.
const failing = [
  ['allow-human', 'allow + human evidence', {
    legacyRules: [{ rp: 'rp-a.test', authenticate: '{ authorization = "allow", user_presence = "human", user_verification = "agent" }', register: '"deny"' }],
  }, /cannot be mapped safely[\s\S]*request/],
  ['allow-none', 'allow + none evidence', {
    legacyRules: [{ rp: 'rp-a.test', authenticate: '{ authorization = "allow", user_presence = "none", user_verification = "none" }', register: '"deny"' }],
  }, /cannot be mapped safely/],
  ['removed-key', 'removed profile key require_uv', {
    rules: [{ rp: 'rp-a.test', authenticate: 'allow', register: 'deny' }], extra: { require_uv: true },
  }, /require_uv[\s\S]*removed[\s\S]*agents\.profiles\.agent\.rules/],
];
for (const [slug, name, profile, pattern] of failing) {
  scenario({ id: `E2E-13/${slug}`, title: `legacy config fails startup: ${name}`, ci: true }, async ctx => {
    const stack = await ctx.stack({ rps: { a: { host: 'rp-a.test' } }, profiles: { agent: { mode: 'same-user', rules: [{ rp: 'rp-a.test', authenticate: 'allow', register: 'deny' }] } } });
    let error = null;
    try { await stack.restartDaemon({ agent: { mode: 'same-user', ...profile } }); } catch (e) { error = e; }
    assert.ok(error instanceof DaemonStartError, `the daemon must refuse to start, got: ${error && error.stack || 'it started'}`);
    assert.match(error.message, pattern);
  });
}
