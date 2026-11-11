'use strict';
const fs = require('node:fs');
const path = require('node:path');

const { scenario, assert } = require('../lib/scenario');
const { assertVerifiedAssertion, assertAgentAllowed, auditEvents, waitFor, HUMAN_CTAP_LOG } = require('../lib/helpers');
const { startPrincipalShell, browserProcesses } = require('../lib/adapters');
const { processesMentioning } = require('../lib/env');

// The fixed extension ID (the manifest `key`, `AGENT_EXTENSION_ID` in browser.rs).
const EXTENSION_ID = 'lfbahamapdlbimlffmhiomfdemnjhjkc';

// Review M3 (ADR 0014 section 4.3): in pipe mode the agent's CDP goes through `passless agent browser-control`, and the
// daemon keeps it away from the Passless extension. The agent here is a principal session (`agent run`) that serves
// browser-control calls from a FIFO, so the test can drive it step by step. `passless agent browser` ensures the
// session's pipe-mode browser (no endpoint) and prints how to drive it; then:
// - the extension worker is hidden from Target.getTargets (also with a service_worker filter);
// - Target.setAutoAttach {flatten: true}, the attach Playwright and Puppeteer perform, never hands out a session on the
//   worker (the daemon detaches it), and no message the agent receives names the extension;
// - opening the worker's URL, chrome://extensions or chrome://inspect (from which it could be inspected or disabled),
//   the Extensions domain, exposeDevToolsProtocol and stopping service workers are refused and audited as denied
//   browser-control records;
// - even with the worker's target ID in hand (the harness reads it from the daemon's debug log, which the agent does not
//   need: the filter refuses it either way), attaching to it, asking for its info, activating or closing it is refused;
// - ordinary page CDP works: the agent navigates the page and evaluates in it;
// - the extension still intercepts afterwards: a WebAuthn get() driven through browser-control on the RP page is signed
//   on the agent path (a pipe-mode passkey login), without touching the human authenticator;
// - the session's end tears the browser down, and the lease is audited (launch, with its CDP mode, then revoke/cleanup).
scenario({
  id: 'E2E-52', title: 'pipe mode: browser-control cannot reach the extension worker', ci: true,
}, async ctx => {
  const stack = await ctx.stack({
    rps: { a: { host: 'rp-a.test' } },
    profiles: { agent: { mode: 'same-user', cdpExpose: 'pipe', rules: [{ rp: 'rp-a.test', authenticate: 'allow', register: 'deny' }] } },
  });
  const rp = stack.rp.a;
  await stack.seedHuman(rp, 'alice');
  const logBefore = stack.daemon.log().length;

  const dir = fs.mkdtempSync(path.join(stack.env.dirs.work, 'pipe-agent-'));
  const fifo = path.join(dir, 'requests');
  // `agent browser` ensures the session's browser and waits for interception; in pipe mode it prints how to drive it
  // (no endpoint), and `browser-status` reports the same lease.
  const agent = startPrincipalShell(stack, 'agent', [
    `D=${JSON.stringify(dir)}`,
    'mkfifo "$D/requests"',
    `"$PASSLESS" agent browser --profile agent --wait --url ${JSON.stringify(`${rp.origin}/raw`)} >"$D/browser.out" 2>&1; echo $? >"$D/browser.rc"`,
    '"$PASSLESS" agent browser-status --profile agent >"$D/status.json" 2>&1',
    '"$PASSLESS" agent browser --profile agent --json >"$D/again.out" 2>&1; echo $? >"$D/again.rc"',
    '"$PASSLESS" agent browser --profile agent --env >"$D/env.out" 2>&1; echo $? >"$D/env.rc"',
    'echo AGENT-READY',
    'exec 9<>"$D/requests"',
    'while read -r req <&9; do',
    '  "$PASSLESS" agent browser-control --profile agent --request-file "$req" --timeout-ms 30000 >"$req.out" 2>"$req.err"',
    '  echo $? >"$req.rc.tmp" && mv "$req.rc.tmp" "$req.rc"',
    'done',
  ].join('\n'));

  let seq = 0;
  /** One browser-control call from inside the principal session: {rc, messages, stderr}. */
  const control = async (method, params, sessionId) => {
    seq += 1;
    const request = { id: seq, method, ...(params ? { params } : {}), ...(sessionId ? { sessionId } : {}) };
    const file = path.join(dir, `req-${seq}.json`);
    fs.writeFileSync(file, JSON.stringify(request), { mode: 0o600 });
    fs.appendFileSync(fifo, `${file}\n`);
    await waitFor(`browser-control ${method} to finish`, () => fs.existsSync(`${file}.rc`), { timeoutMs: 60000, intervalMs: 50 });
    const rc = Number(fs.readFileSync(`${file}.rc`, 'utf8').trim());
    const stdout = fs.readFileSync(`${file}.out`, 'utf8');
    const stderr = fs.readFileSync(`${file}.err`, 'utf8');
    const messages = rc === 0 ? JSON.parse(stdout).data.messages.map(m => JSON.parse(m)) : [];
    return { rc, messages, stderr, response: messages.find(m => m.id === seq) };
  };
  const assertDenied = async (label, method, params, sessionId) => {
    const r = await control(method, params, sessionId);
    assert.notEqual(r.rc, 0, `${label} was not refused: ${JSON.stringify(r.messages)}`);
    assert.match(r.stderr, /denied/i, `${label}: ${r.stderr}`);
  };
  const namesExtension = m => JSON.stringify(m).toLowerCase().includes(EXTENSION_ID);

  try {
    await agent.waitForLine(/^AGENT-READY$/);
    const status = JSON.parse(fs.readFileSync(path.join(dir, 'status.json'), 'utf8')).data;
    const launched = fs.readFileSync(path.join(dir, 'browser.out'), 'utf8');
    assert.equal(fs.readFileSync(path.join(dir, 'browser.rc'), 'utf8').trim(), '0', `agent browser succeeded in pipe mode: ${launched}`);
    assert.match(launched, /pipe mode/, launched);
    assert.match(launched, /passless agent browser-control --profile agent/, `it says how to drive the browser: ${launched}`);
    assert.doesNotMatch(launched, /https?:\/\/127\.0\.0\.1/, `no endpoint is printed: ${launched}`);
    assert.equal(status.running, true, JSON.stringify(status));
    assert.equal(status.interception, 'attached', `the worker attached the proxy: ${JSON.stringify(status)}`);
    assert.equal(status.incognito_allowed, true, JSON.stringify(status));
    assert.equal(status.cdp_exposure, 'pipe', JSON.stringify(status));
    assert.equal(status.cdp_endpoint ?? null, null, 'pipe mode hands out no CDP endpoint');
    // `agent browser` is idempotent: a second call reuses the lease, and `--json` carries no endpoint either.
    const read = name => fs.readFileSync(path.join(dir, name), 'utf8');
    assert.equal(read('again.rc').trim(), '0', read('again.out'));
    const againData = JSON.parse(read('again.out')).data;
    assert.equal(againData.endpoint, null, read('again.out'));
    assert.equal(againData.cdp_exposure, 'pipe', read('again.out'));
    assert.match(againData.control_command, /browser-control --profile agent/, read('again.out'));
    assert.notEqual(read('env.rc').trim(), '0', '--env has no endpoint to export in pipe mode');
    assert.match(read('env.out'), /no CDP endpoint to export/, read('env.out'));

    // The worker is hidden from the target list, also when the agent asks for service workers only.
    const targets = await control('Target.getTargets');
    assert.equal(targets.rc, 0, targets.stderr);
    const infos = targets.response.result.targetInfos;
    assert.ok(!infos.some(namesExtension), `the extension target was listed: ${JSON.stringify(infos)}`);
    const page = infos.find(i => i.type === 'page' && i.url.startsWith(rp.origin));
    assert.ok(page, `the RP page is listed: ${JSON.stringify(infos)}`);
    const workers = await control('Target.getTargets', { filter: [{ type: 'service_worker' }] });
    assert.equal(workers.rc, 0, workers.stderr);
    assert.ok(!workers.response.result.targetInfos.some(namesExtension), JSON.stringify(workers.response));

    // Auto-attach to everything, as Playwright does over CDP: no session on the worker reaches the agent.
    const autoAttach = await control('Target.setAutoAttach', { autoAttach: true, waitForDebuggerOnStart: false, flatten: true });
    assert.equal(autoAttach.rc, 0, autoAttach.stderr);
    assert.ok(!autoAttach.messages.some(namesExtension), `a message named the extension: ${JSON.stringify(autoAttach.messages)}`);
    const discover = await control('Target.setDiscoverTargets', { discover: true });
    assert.equal(discover.rc, 0, discover.stderr);
    assert.ok(!discover.messages.some(namesExtension), JSON.stringify(discover.messages));

    // Reaching the worker any other way is refused.
    const session = (await control('Target.attachToTarget', { targetId: page.targetId, flatten: true })).response.result.sessionId;
    assert.ok(session, 'an ordinary page attaches');
    await assertDenied('opening the worker script', 'Target.createTarget', { url: `chrome-extension://${EXTENSION_ID}/worker.js` });
    await assertDenied('navigating to chrome://extensions', 'Page.navigate', { url: 'chrome://extensions' }, session);
    await assertDenied('navigating to chrome://inspect', 'Page.navigate', { url: 'chrome://inspect/#service-workers' }, session);
    await assertDenied('the Extensions domain', 'Extensions.getStorageItems', { id: EXTENSION_ID, storageArea: 'session' });
    await assertDenied('exposing CDP to the page', 'Target.exposeDevToolsProtocol', { targetId: page.targetId });
    await assertDenied('stopping service workers', 'ServiceWorker.stopAllWorkers', undefined, session);

    // With the worker's target ID in hand the filter still refuses it. The agent never sees the ID; the harness reads it
    // from the daemon's debug log (written when the filter hid the target in the listing above).
    const hidden = [...stack.daemon.log().matchAll(/cdp filter: hid extension target (\S+)/g)].map(m => m[1]);
    assert.ok(hidden.length > 0, 'the daemon logged the extension target it hid');
    const workerId = hidden[0];
    await assertDenied('attaching to the worker by its target ID', 'Target.attachToTarget', { targetId: workerId, flatten: true });
    await assertDenied("asking for the worker's target info", 'Target.getTargetInfo', { targetId: workerId });
    await assertDenied('activating the worker', 'Target.activateTarget', { targetId: workerId });
    await assertDenied('closing the worker', 'Target.closeTarget', { targetId: workerId });
    await assertDenied('messaging the worker', 'Target.sendMessageToTarget', { targetId: workerId, message: '{"id":1,"method":"Runtime.evaluate","params":{"expression":"1"}}' });
    // ...and the worker is still hidden afterwards.
    const after = (await control('Target.getTargets')).response.result.targetInfos;
    assert.ok(!after.some(namesExtension), 'the worker is still hidden');

    // Ordinary page CDP works through browser-control: navigate the page, then evaluate in it.
    const target = `${rp.origin}/raw?pipe-nav=1`;
    const navigated = await control('Page.navigate', { url: target }, session);
    assert.equal(navigated.rc, 0, navigated.stderr);
    assert.ok(navigated.response.result.frameId, JSON.stringify(navigated.response));
    await waitFor('the page to load the new URL', async () => {
      const r = await control('Runtime.evaluate', { expression: 'document.readyState + " " + location.href', returnByValue: true }, session);
      return r.rc === 0 && r.response.result.result.value === `complete ${target}`;
    }, { timeoutMs: 30000, intervalMs: 200 });
    const sum = await control('Runtime.evaluate', { expression: '6 * 7', returnByValue: true }, session);
    assert.equal(sum.rc, 0, sum.stderr);
    assert.equal(sum.response.result.result.value, 42);

    // The extension still intercepts: a get() on the RP page through browser-control is signed on the agent path (a
    // pipe-mode passkey login).
    const evaluated = await control('Runtime.evaluate', {
      expression: `new Promise(r => { const t = setInterval(() => { if (window.e2e) { clearInterval(t); r(); } }, 50); })
        .then(() => window.e2e.authenticate({ username: 'alice', userVerification: 'preferred', timeout: 20000 }))`,
      awaitPromise: true, returnByValue: true,
    }, session);
    assert.equal(evaluated.rc, 0, evaluated.stderr);
    assertVerifiedAssertion(rp, evaluated.response.result.result.value, { username: 'alice' });
    await assertAgentAllowed(stack, { rpId: 'rp-a.test', n: 1 });
    assert.doesNotMatch(stack.daemon.log().slice(logBefore), HUMAN_CTAP_LOG, 'the human authenticator handled a request');

    const denied = auditEvents(await stack.daemon.audit())
      .filter(e => e.kind === 'browser_control.request' && e.outcome === 'denied')
      .map(e => e.cdp_method);
    for (const method of ['Target.createTarget', 'Page.navigate', 'Extensions.getStorageItems', 'Target.exposeDevToolsProtocol', 'ServiceWorker.stopAllWorkers',
      'Target.attachToTarget', 'Target.getTargetInfo', 'Target.activateTarget', 'Target.closeTarget', 'Target.sendMessageToTarget']) {
      assert.ok(denied.includes(method), `${method} audited as denied: ${JSON.stringify(denied)}`);
    }
    const allowed = auditEvents(await stack.daemon.audit())
      .filter(e => e.kind === 'browser_control.request' && e.outcome === 'success').map(e => e.cdp_method);
    assert.ok(allowed.includes('Runtime.evaluate') && allowed.includes('Page.navigate'), `ordinary page CDP is audited per command: ${JSON.stringify(allowed)}`);

    // The lease is the principal session's: launched once with its CDP mode, and torn down with the session.
    const launches = auditEvents(await stack.daemon.audit()).filter(e => e.kind === 'browser_lease.launch');
    assert.equal(launches.length, 1, `one lease launch: ${JSON.stringify(launches)}`);
    assert.equal(launches[0].cdp_expose, 'pipe', JSON.stringify(launches[0]));
    assert.ok(browserProcesses(stack, processesMentioning).length > 0, 'the browser runs while the session lives');
    await agent.close();
    await waitFor("the session's browser to be torn down", () => browserProcesses(stack, processesMentioning).length === 0, { timeoutMs: 60000, intervalMs: 200 });
    const ended = await waitFor('the lease teardown to be audited', async () => {
      const events = auditEvents(await stack.daemon.audit());
      return events.some(e => e.kind === 'browser_lease.cleanup' && e.lease_id === launches[0].lease_id) ? events : null;
    }, { timeoutMs: 60000, intervalMs: 200 });
    assert.ok(ended.some(e => e.kind === 'browser_lease.revoke' && e.lease_id === launches[0].lease_id), `the lease revocation is audited: ${ended.filter(e => /^browser_lease/.test(e.kind)).map(e => e.kind)}`);
  } finally {
    await agent.close();
  }
});

// The tightened filter rules (a review of cdp_filter.rs): every session is flat (`flatten: true`, as Playwright and
// Puppeteer attach), so a non-flat attach, a non-flat auto-attach and the legacy `Target.sendMessageToTarget` relay are
// refused even for an ordinary page, and so are `about:` pages other than about:blank and about:srcdoc.
// (Review H1 and M-a, cdp_filter.rs.)
scenario({
  id: 'E2E-52/strict', title: 'pipe mode: non-flat sessions, sendMessageToTarget and about: pages are refused', ci: true,
}, async ctx => {
  const stack = await ctx.stack({
    rps: { a: { host: 'rp-a.test' } },
    profiles: { agent: { mode: 'same-user', cdpExpose: 'pipe', rules: [{ rp: 'rp-a.test', authenticate: 'allow', register: 'deny' }] } },
  });
  const rp = stack.rp.a;
  const dir = fs.mkdtempSync(path.join(stack.env.dirs.work, 'pipe-strict-'));
  const fifo = path.join(dir, 'requests');
  const agent = startPrincipalShell(stack, 'agent', [
    `D=${JSON.stringify(dir)}`,
    'mkfifo "$D/requests"',
    `"$PASSLESS" agent browser --profile agent --wait --url ${JSON.stringify(`${rp.origin}/raw`)} >"$D/browser.out" 2>&1`,
    'echo AGENT-READY',
    'exec 9<>"$D/requests"',
    'while read -r req <&9; do',
    '  "$PASSLESS" agent browser-control --profile agent --request-file "$req" --timeout-ms 30000 >"$req.out" 2>"$req.err"',
    '  echo $? >"$req.rc.tmp" && mv "$req.rc.tmp" "$req.rc"',
    'done',
  ].join('\n'));
  let seq = 0;
  const control = async (method, params, sessionId) => {
    seq += 1;
    const request = { id: seq, method, ...(params ? { params } : {}), ...(sessionId ? { sessionId } : {}) };
    const file = path.join(dir, `req-${seq}.json`);
    fs.writeFileSync(file, JSON.stringify(request), { mode: 0o600 });
    fs.appendFileSync(fifo, `${file}\n`);
    await waitFor(`browser-control ${method} to finish`, () => fs.existsSync(`${file}.rc`), { timeoutMs: 60000, intervalMs: 50 });
    const rc = Number(fs.readFileSync(`${file}.rc`, 'utf8').trim());
    const messages = rc === 0 ? JSON.parse(fs.readFileSync(`${file}.out`, 'utf8')).data.messages.map(m => JSON.parse(m)) : [];
    return { rc, messages, stderr: fs.readFileSync(`${file}.err`, 'utf8'), response: messages.find(m => m.id === seq) };
  };
  const assertDenied = async (label, method, params, sessionId) => {
    const r = await control(method, params, sessionId);
    assert.notEqual(r.rc, 0, `${label} was not refused: ${JSON.stringify(r.messages)}`);
    assert.match(r.stderr, /denied/i, `${label}: ${r.stderr}`);
  };

  try {
    await agent.waitForLine(/^AGENT-READY$/);
    const infos = (await control('Target.getTargets')).response.result.targetInfos;
    const page = infos.find(i => i.type === 'page' && i.url.startsWith(rp.origin));
    assert.ok(page, `the RP page is listed: ${JSON.stringify(infos)}`);
    // A flat session works.
    const session = (await control('Target.attachToTarget', { targetId: page.targetId, flatten: true })).response.result.sessionId;
    assert.ok(session, 'a flat attach to an ordinary page works');
    // These are refused.
    await assertDenied('a non-flat attach to an ordinary page', 'Target.attachToTarget', { targetId: page.targetId, flatten: false });
    await assertDenied('an attach without `flatten`', 'Target.attachToTarget', { targetId: page.targetId });
    await assertDenied('a non-flat auto-attach', 'Target.setAutoAttach', { autoAttach: true, waitForDebuggerOnStart: false, flatten: false });
    await assertDenied('relaying a message to an ordinary page', 'Target.sendMessageToTarget', { targetId: page.targetId, message: '{"id":1,"method":"Runtime.evaluate","params":{"expression":"1"}}' });
    await assertDenied('navigating to about:policy', 'Page.navigate', { url: 'about:policy' }, session);
    await assertDenied('navigating to chrome-untrusted:', 'Page.navigate', { url: 'chrome-untrusted://terminal/' }, session);
    // about:blank still works.
    const blank = await control('Page.navigate', { url: 'about:blank' }, session);
    assert.equal(blank.rc, 0, blank.stderr);
  } finally {
    await agent.close();
  }
});
