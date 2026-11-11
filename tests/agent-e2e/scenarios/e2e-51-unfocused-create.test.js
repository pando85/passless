'use strict';
const { scenario, assert } = require('../lib/scenario');
const { policyEvents, auditEvents, assertInterceptionActive } = require('../lib/helpers');

// Catalogue: create() from an unfocused tab (an older tab in front of the new one). Known limitation (ADR 0014 §11,
// spike "focus rule"): Chromium hands the request to the proxy and the daemon registers the credential, but Chromium
// then rejects the page's create() with NotAllowedError because the tab does not have focus. The audit records the
// registration and an orphan credential stays in the isolated profile store until the operator deletes it with
// `passless agent-admin credential delete <ref> --confirm` (found with `agent-admin credential list`).
scenario({ id: 'E2E-51', title: 'create() from an unfocused tab: NotAllowedError, audited registration, orphan removable' }, async ctx => {
  const stack = await ctx.stack({
    rps: { a: { host: 'rp-a.test' } },
    profiles: { iso: { mode: 'isolated', rules: [{ rp: 'rp-a.test', register: 'allow', authenticate: 'allow' }] } },
  });
  const rp = stack.rp.a;
  const url = `${rp.origin}/raw`;
  const b = await stack.open('iso', url);
  assertInterceptionActive(b);
  const older = b.page;

  const newer = await b.context.newPage();
  await newer.goto(url);
  await newer.waitForFunction(() => window.e2e);
  await older.bringToFront();

  const reg = await newer.evaluate(() => window.e2e.register({ username: 'frank', userVerification: 'preferred', timeout: 20000 }));
  assert.equal(reg.ok, false, `create() from an unfocused tab must fail: ${JSON.stringify(reg)}`);
  assert.equal(reg.name, 'NotAllowedError', JSON.stringify(reg));
  assert.match(reg.message, /focus/i, `Chromium rejects it for lack of focus: ${reg.message}`);
  assert.equal(rp.registrations.length, 0, 'the RP never receives the credential');

  // The daemon registered it: audited, and the orphan is in the isolated profile store.
  const audit = await stack.daemon.audit();
  const allows = policyEvents(audit, 'policy.allow').filter(e => e.profile_id === 'iso' && e.action === 'register' && e.rp_id === 'rp-a.test');
  assert.equal(allows.length, 1, 'the registration is audited');
  assert.equal(stack.daemon.profileStore('iso').length, 1, 'the orphan credential is in the isolated profile store');
  assert.deepEqual(stack.daemon.humanStore(), [], 'nothing in the human store');

  // Documented cleanup: the operator finds the credential and deletes it.
  const list = await stack.daemon.adminJson('credential', 'list', '--domain', 'rp-a.test');
  const orphans = list.credentials.filter(c => c.rp_id === 'rp-a.test' && c.user_name === 'frank');
  assert.equal(orphans.length, 1, `agent-admin credential list shows the orphan: ${JSON.stringify(list)}`);
  const deleted = await stack.daemon.adminJson('credential', 'delete', orphans[0].credential_ref, '--confirm');
  assert.equal(deleted.deleted, true, JSON.stringify(deleted));
  assert.equal(stack.daemon.profileStore('iso').length, 0, 'the orphan is gone from the isolated profile store');
  const after = await stack.daemon.audit();
  assert.ok(auditEvents(after).some(e => e.kind === 'admin.credential_delete' || e.kind === 'credential.delete'),
    `the deletion is audited: ${JSON.stringify(auditEvents(after).map(e => e.kind))}`);

  // A focused create() works (control): the same tab, brought to the front.
  await newer.bringToFront();
  const ok = await newer.evaluate(() => window.e2e.register({ username: 'frank', userVerification: 'preferred', timeout: 20000 }));
  assert.equal(ok.ok, true, `create() from the focused tab works: ${JSON.stringify(ok)}`);
  assert.equal(stack.daemon.profileStore('iso').length, 1);
});
