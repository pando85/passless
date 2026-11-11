'use strict';
const fs = require('node:fs');
const path = require('node:path');

const { scenario, assert } = require('../lib/scenario');
const { assertVerifiedAssertion, assertAgentAllowed, auditEvents, waitFor, HUMAN_CTAP_LOG } = require('../lib/helpers');
const { startPrincipalShell } = require('../lib/adapters');

// The fixed extension ID (the manifest `key`, `AGENT_EXTENSION_ID` in browser.rs).
const EXTENSION_ID = 'lfbahamapdlbimlffmhiomfdemnjhjkc';

// Review M3 (ADR 0014 section 4.3): in pipe mode the agent's CDP goes through `passless agent browser-control`, and the
// daemon keeps it away from the Passless extension. The agent here is a principal session (`agent run`) that serves
// browser-control calls from a FIFO, so the test can drive it step by step:
// - the extension worker is hidden from Target.getTargets (also with a service_worker filter);
// - Target.setAutoAttach {flatten: true}, the attach Playwright and Puppeteer perform, never hands out a session on the
//   worker (the daemon detaches it), and no message the agent receives names the extension;
// - opening the worker's URL, chrome://extensions or chrome://inspect (from which it could be inspected or disabled),
//   the Extensions domain, exposeDevToolsProtocol and stopping service workers are refused and audited as denied
//   browser-control records. (Attaching by the worker's target ID needs that ID, which the agent never sees here; the
//   daemon's own lookup that refuses it is covered by browser.rs `test_cdp_round_trip_denies_attaching_to_the_extension_worker`.);
// - the extension still intercepts afterwards: a WebAuthn get() driven through browser-control on the RP page is signed
//   on the agent path.
//
// XFAIL: no principal path launches a pipe-mode browser yet. `EnsureBrowser` (`agent browser`) refuses pipe mode ("requires
// browser_cdp_expose = 'port'", runtime/browser_ensure.rs), and an admin `browser launch` binds no principal session, so
// `browser-control` has no lease to act on. The filter itself is tested against a scripted browser pipe in browser.rs
// (`test_cdp_round_trip_*extension*`) and cdp_filter.rs. Remove the tag when a principal can launch a pipe-mode browser.
scenario({
  id: 'E2E-52', title: 'pipe mode: browser-control cannot reach the extension worker', ci: true,
  xfailUntil: 'pipe-mode EnsureBrowser',
  xfailReason: 'no principal path launches a pipe-mode browser, so browser-control has no lease',
  xfailMatch: /no principal launch path for a pipe-mode browser/,
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
  // `agent browser` launches and waits for interception; in pipe mode it has no endpoint to print, so its exit status is
  // not the signal: `browser-status` is.
  const agent = startPrincipalShell(stack, 'agent', [
    `D=${JSON.stringify(dir)}`,
    'mkfifo "$D/requests"',
    `"$PASSLESS" agent browser --profile agent --wait --url ${JSON.stringify(`${rp.origin}/raw`)} >"$D/browser.out" 2>&1 || true`,
    '"$PASSLESS" agent browser-status --profile agent >"$D/status.json" 2>&1',
    'echo AGENT-READY',
    'exec 3<>"$D/requests"',
    'while read -r req <&3; do',
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
    if (!status.running && /requires browser_cdp_expose = 'port'/.test(launched)) {
      assert.fail(`no principal launch path for a pipe-mode browser: ${launched.trim()}`);
    }
    assert.equal(status.interception, 'attached', `the worker attached the proxy: ${JSON.stringify(status)}`);
    assert.equal(status.cdp_endpoint ?? null, null, 'pipe mode hands out no CDP endpoint');

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

    // The agent can still drive the page, and the extension still intercepts: a get() on the RP page through
    // browser-control is signed on the agent path.
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
    for (const method of ['Target.createTarget', 'Page.navigate', 'Extensions.getStorageItems', 'Target.exposeDevToolsProtocol', 'ServiceWorker.stopAllWorkers']) {
      assert.ok(denied.includes(method), `${method} audited as denied: ${JSON.stringify(denied)}`);
    }
  } finally {
    await agent.close();
  }
});
