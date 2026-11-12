'use strict';
const { scenario, assert } = require('../lib/scenario');
const { authenticate, auditEvents, assertVerifiedAssertion, assertInterceptionActive } = require('../lib/helpers');

// Catalogue: deployment axes (ADR 0014 section 13). `mode` (configured) and the principal relationship (the principal UID
// against the daemon UID, `shared-uid` or `distinct-uid`) are reported by `passless doctor` (`agent-admin profile check`)
// and by every audit operation record. A principal that shares the daemon's UID is a supported deployment, not an error:
// only `isolated` + shared-UID warns (separation is administrative only), at daemon start and in the doctor report.
//
// The catalogue asks for a distinct-UID principal "if a second local user is available, else unit-level". The harness runs
// the daemon and its principals as the invoking user and creating a second user needs root, so this scenario covers the
// shared-UID column (same-user and isolated). The distinct-UID column and the no-warning cells are unit-level
// (`deployment.rs`, `doctor.rs`, `runtime.rs` tests: every mode x relationship combination).
const PROFILES = {
  same: { mode: 'same-user', rules: [{ rp: 'rp-a.test', authenticate: 'allow', register: 'deny' }] },
  iso: { mode: 'isolated', rules: [{ rp: 'rp-a.test', authenticate: 'allow', register: 'allow' }] },
};

/** The axes check of a doctor report, and the warning check if present. */
const axesOf = report => ({
  axes: (report.checks || []).find(c => c.name === 'deployment_axes'),
  warning: (report.checks || []).find(c => c.name === 'isolated_shared_uid'),
});

scenario({ id: 'E2E-33', exposeModes: ['port', 'pipe'], title: 'deployment axes: doctor and audit report both; shared-UID isolated warns', ci: true }, async ctx => {
  const stack = await ctx.stack({ rps: { a: { host: 'rp-a.test' } }, profiles: PROFILES, notify: false });
  const rpA = stack.rp.a;
  await stack.seedHuman(rpA, 'alice');

  // --- Doctor: both axes per profile; the shared-UID isolated warning only for the isolated profile.
  const same = await stack.daemon.adminJson('profile', 'check', 'same');
  const iso = await stack.daemon.adminJson('profile', 'check', 'iso');
  const sameChecks = axesOf(same);
  const isoChecks = axesOf(iso);
  assert.ok(sameChecks.axes, `doctor must report the axes: ${JSON.stringify(same.checks)}`);
  assert.ok(isoChecks.axes, `doctor must report the axes: ${JSON.stringify(iso.checks)}`);
  assert.match(sameChecks.axes.message, /mode: same-user, principal_relationship: shared-uid/);
  assert.match(isoChecks.axes.message, /mode: isolated, principal_relationship: shared-uid/);
  assert.ok(sameChecks.axes.passed && isoChecks.axes.passed, 'an axis is never a failure');
  assert.equal(sameChecks.warning, undefined, `same-user + shared-UID does not warn: ${JSON.stringify(same.checks)}`);
  assert.ok(isoChecks.warning, `isolated + shared-UID must warn: ${JSON.stringify(iso.checks)}`);
  assert.match(isoChecks.warning.message, /^warning: .*administrative only/);
  assert.equal(isoChecks.warning.passed, true, 'a warning never makes the profile unhealthy');

  // --- Daemon log: one warning at start for the isolated profile only.
  const log = stack.daemon.log().split('\n');
  const warned = log.filter(l => /WARN/.test(l) && /isolated with a shared-UID principal/.test(l));
  assert.equal(warned.length, 1, `exactly one start-up warning, log:\n${warned.join('\n')}`);
  assert.match(warned[0], /profile 'iso'/);
  assert.ok(!log.some(l => /profile 'same'/.test(l) && /shared-UID principal/.test(l)), 'no warning for the same-user profile');

  // --- Audit: the operation records carry the same two axes.
  const b = await stack.open('same', `${rpA.origin}/sw`);
  assertInterceptionActive(b);
  assertVerifiedAssertion(rpA, await authenticate(b.page, { username: 'alice' }), { username: 'alice' });
  const records = auditEvents(await stack.daemon.audit()).filter(e => ['policy.allow', 'operation.terminal'].includes(e.kind) && e.profile_id === 'same');
  assert.ok(records.length >= 2, `expected a reservation and a terminal record: ${JSON.stringify(records.map(r => r.kind))}`);
  for (const record of records) {
    assert.equal(record.mode, 'same-user');
    assert.equal(record.principal_relationship, 'shared-uid', 'the harness principal runs as the daemon user');
  }
});
