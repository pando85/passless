'use strict';
const { scenario, assert } = require('../lib/scenario');
const {
  authenticate, auditEvents, grantedRuleEvents, escalationEvents, assertVerifiedAssertion, assertInterceptionActive, waitFor,
} = require('../lib/helpers');
const { requestProfile } = require('../lib/escalation');
const { browserProcesses } = require('../lib/adapters');
const { processesMentioning } = require('../lib/env');
const { startPipeBrowser } = require('../lib/pipe-driver');

const PIPE_RULES = [{ rp: 'rp-a.test', authenticate: 'allow', register: 'deny' }];

// ADR 0014 section 4.3: "MCP adapters / direct_cdp clients refuse a pipe-mode profile by design". The callers that can only use a
// CDP endpoint (the Playwright MCP bootstrap and the chrome-devtools adapter send `direct_cdp = true`) are refused before any
// browser starts, with the documented error: "Playwright browser discovery requires browser_cdp_expose = 'port' (trusted agents
// only); in pipe mode run `passless agent browser` and drive the browser with `passless agent browser-control`".
// - `agent mcp chrome-devtools` ensures the browser up front, so the adapter itself exits with the error on stderr;
// - `agent mcp playwright` is lazy: the MCP server starts, and its first browser tool call fails because the bootstrap's
//   discovery points Playwright at its error endpoint, which answers `503` with the class (`refused`) and a fixed hint (the
//   bootstrap never repeats the daemon's text to the page-side client; the wrapper prints it on its stderr, which the MCP
//   client keeps as the server's log).
// Then a positive control: the same profile is served by `agent browser` and browser-control, so the refusal is about the
// endpoint, not the profile.
// `pinsExpose: 'pipe'`: this scenario writes its own pipe-mode profile, whatever attach mode the run's axis selects.
scenario({
  id: 'E2E-53', title: 'pipe mode: the MCP adapters (direct_cdp clients) are refused with the documented error and start no browser',
  pinsExpose: 'pipe', timeoutMs: 240000,
}, async ctx => {
  const stack = await ctx.stack({
    rps: { a: { host: 'rp-a.test' } },
    profiles: {
      agent: { mode: 'same-user', cdpExpose: 'pipe', rules: PIPE_RULES },
      portagent: { mode: 'same-user', cdpExpose: 'port', rules: PIPE_RULES },
    },
  });
  const rp = stack.rp.a;
  await stack.seedHuman(rp, 'alice');
  const documented = /requires browser_cdp_expose = 'port'/;
  const redirect = /passless agent browser/;

  // chrome-devtools: the adapter exits non-zero with the documented error and starts no browser.
  const devtools = stack.adapter('chrome-devtools', { profile: 'agent' });
  const exit = await waitFor('the chrome-devtools adapter to exit', () => (devtools.client.child.exitCode !== null || devtools.client.child.signalCode !== null
    ? { code: devtools.client.child.exitCode, signal: devtools.client.child.signalCode } : null), { timeoutMs: 60000, intervalMs: 100 });
  assert.notEqual(exit.code, 0, `the adapter must fail for a pipe-mode profile: ${JSON.stringify(exit)}`);
  assert.match(devtools.client.stderr, documented, `the documented refusal: ${devtools.client.stderr}`);
  assert.match(devtools.client.stderr, redirect, `it points at \`passless agent browser\`: ${devtools.client.stderr}`);
  assert.deepEqual(browserProcesses(stack, processesMentioning), [], 'a browser was started for a refused chrome-devtools adapter');
  assert.deepEqual(devtools.npxCalls(), [], 'the adapter never reached npx');

  // Playwright MCP: the server starts, the first browser tool call is refused.
  const playwright = stack.adapter('playwright', { profile: 'agent' });
  const init = await playwright.client.initialize();
  assert.ok(init.serverInfo, 'the adapter speaks MCP on stdio (it is lazy)');
  let refusal = '';
  try {
    const nav = await playwright.client.callTool('browser_navigate', { url: `${rp.origin}/sw` }, 120000);
    assert.equal(nav.isError, true, `browser_navigate must fail: ${JSON.stringify(nav).slice(0, 400)}`);
    refusal = (nav.content || []).map(c => c.text || '').join('\n');
  } catch (e) { refusal = String(e.message || e); }
  // The tool error carries the bootstrap's `503` with the class and a fixed hint, never the daemon's text. The full documented
  // text goes to the wrapper's stderr, so the tool error says that it was refused and the MCP server's stderr says why; the
  // control below (a port-mode profile of the same daemon and adapter navigates fine) shows the refusal is specific to the
  // pipe-mode profile.
  assert.match(refusal, /503/, `the discovery request was answered 503: ${refusal.slice(0, 400)}`);
  assert.match(refusal, /managed browser unavailable \(refused\)/, `the tool error names the class: ${refusal.slice(0, 600)}`);
  const stderrOf = () => playwright.client.stderr;
  await waitFor('the wrapper to print the refusal on stderr', () => (documented.test(stderrOf()) ? true : null), { timeoutMs: 15000, intervalMs: 100 })
    .catch(() => {});
  assert.match(stderrOf(), documented, `the documented refusal on the Playwright wrapper's stderr: ${stderrOf()}`);
  assert.match(stderrOf(), redirect, `it points at \`passless agent browser\`: ${stderrOf()}`);
  assert.match(stderrOf(), /\(refused\)/, `the refusal is classified: ${stderrOf()}`);
  assert.deepEqual(browserProcesses(stack, processesMentioning), [], 'a browser was started for a refused Playwright MCP adapter');

  // Control: the same adapter against a port-mode profile of this daemon works, so the 503 above is the pipe-mode refusal.
  const portControl = stack.adapter('playwright', { profile: 'portagent' });
  await portControl.client.initialize();
  const ok = await portControl.client.callTool('browser_navigate', { url: `${rp.origin}/sw` }, 120000);
  assert.ok(!ok.isError, `a port-mode profile is served by the same adapter: ${JSON.stringify(ok).slice(0, 400)}`);

  // No lease was launched for the refused callers (the control's port-mode lease is the only one), and nothing was signed.
  let audit = await stack.daemon.audit();
  assert.deepEqual(auditEvents(audit).filter(e => e.kind === 'browser_lease.launch').map(e => e.profile_id), ['portagent'], 'the refused callers started no lease');
  assert.equal(rp.authentications.length, 0, 'nothing authenticated');

  // Positive control: the same profile is served on the pipe path.
  const pb = await startPipeBrowser(stack, 'agent', { url: `${rp.origin}/sw` });
  assert.equal(pb.status.cdp_exposure, 'pipe', JSON.stringify(pb.status));
  const page = await pb.attach((await pb.pageTargets()).find(t => t.url.startsWith(rp.origin)).targetId);
  await page.bringToFront();
  assertVerifiedAssertion(rp, await authenticate(page, { username: 'alice' }), { username: 'alice' });
  audit = await stack.daemon.audit();
  assert.equal(auditEvents(audit).filter(e => e.kind === 'browser_lease.launch' && e.cdp_expose === 'pipe').length, 1, 'the pipe lease launched once');
});

// Session revocation in pipe mode (the pipe-mode counterpart of E2E-31's revocation, which reads the extension's bearer and so
// needs port mode): "Allow always" persists a grant; `agent-admin grants revoke` bumps the revocation epoch, the daemon
// revokes the principal session and terminates its browser; browser-control on that session is refused afterwards; a new
// session gets a fresh browser, and the revoked RP prompts again while the surviving grant needs no prompt.
scenario({
  id: 'E2E-54', title: 'pipe mode: grants revoke ends the principal session and its browser; browser-control is refused; a new session prompts again',
  pinsExpose: 'pipe', timeoutMs: 240000,
}, async ctx => {
  const profiles = { agent: { ...requestProfile(['rp-a.test', 'rp-b.test']), cdpExpose: 'pipe' } };
  const stack = await ctx.stack({
    rps: { a: { host: 'rp-a.test' }, b: { host: 'rp-b.test' } },
    profiles,
    notify: { script: Array(6).fill('approve:1500') },
  });
  const [rpA, rpB] = [stack.rp.a, stack.rp.b];
  await stack.seedHuman(rpA, 'alice');
  await stack.seedHuman(rpB, 'bob');
  const notified = () => stack.notify.notifications().length;

  const b = await stack.open('agent', `${rpA.origin}/sw`);
  assertInterceptionActive(b);
  assertVerifiedAssertion(rpA, await authenticate(b.page, { username: 'alice' }), { username: 'alice' });
  await b.page.goto(`${rpB.origin}/sw`);
  assertVerifiedAssertion(rpB, await authenticate(b.page, { username: 'bob' }), { username: 'bob' });
  assert.equal(notified(), 2, 'both first ceremonies prompted');
  assert.deepEqual(grantedRuleEvents(await stack.daemon.audit(), 'add').map(e => e.rp_id).sort(), ['rp-a.test', 'rp-b.test']);
  const leaseId = auditEvents(await stack.daemon.audit()).find(e => e.kind === 'browser_lease.launch' && e.profile_id === 'agent').lease_id;
  assert.ok(leaseId, 'the pipe lease is audited');

  // Revoke one RP: the session dies and the browser is terminated.
  const revoked = await stack.daemon.adminJson('grants', 'revoke', '--profile', 'agent', '--rp', 'rp-a.test', '--confirm');
  assert.equal(revoked.revoked, 1, JSON.stringify(revoked));
  await waitFor("the daemon to terminate the session's browser", () => browserProcesses(stack, processesMentioning).length === 0, { timeoutMs: 60000, intervalMs: 200 });
  const audit = await waitFor('the lease revocation to be audited', async () => {
    const events = await stack.daemon.audit();
    return auditEvents(events).some(e => e.kind === 'browser_lease.revoke' && e.lease_id === leaseId) ? events : null;
  }, { timeoutMs: 60000 });
  assert.deepEqual(grantedRuleEvents(audit, 'revoke').map(e => e.rp_id), ['rp-a.test']);

  // browser-control on the dead session is refused (the lease is gone), never served by some other browser.
  const late = await b.pipe.control('Runtime.evaluate', { expression: '1 + 1', returnByValue: true }, b.page.sessionId);
  assert.notEqual(late.rc, 0, `browser-control after the revocation must fail: ${JSON.stringify(late.messages)}`);
  assert.match(late.stderr, /lease|browser|session|denied|forbidden|unauthorized/i, late.stderr);
  assert.equal(notified(), 2, 'a revoked session does not prompt');

  // A new principal session: a fresh browser. The revoked RP prompts again, the surviving grant does not.
  const fresh = await stack.open('agent', `${rpA.origin}/sw`);
  assertInterceptionActive(fresh);
  assertVerifiedAssertion(rpA, await authenticate(fresh.page, { username: 'alice' }), { username: 'alice' });
  assert.equal(notified(), 3, 'the revoked RP prompts again');
  await fresh.page.goto(`${rpB.origin}/sw`);
  assertVerifiedAssertion(rpB, await authenticate(fresh.page, { username: 'bob' }), { username: 'bob' });
  assert.equal(notified(), 3, 'the surviving grant needs no prompt');
  const launches = auditEvents(await stack.daemon.audit()).filter(e => e.kind === 'browser_lease.launch' && e.profile_id === 'agent');
  assert.equal(launches.length, 2, 'a second lease for the new session');
  assert.notEqual(launches[1].lease_id, leaseId, 'a fresh lease, not the revoked one');
  assert.equal(escalationEvents(await stack.daemon.audit(), 'approved').length, 3);
});
