'use strict';
const { scenario, assert } = require('../lib/scenario');
const { authenticate, assertVerifiedAssertion, assertInterceptionActive, assertAgentAllowed, waitFor, auditEvents, TRANSPORT_LOG, logMatches, HUMAN_CTAP_LOG } = require('../lib/helpers');
const { stopExtensionWorker, extensionWorkerTargets } = require('../lib/browser');

// Catalogue E2E-45: a request from the managed browser never reaches the human device (ADR 0014 invariant 25, plan D6).
// Evidence for "the human authenticator records no CTAP request": the daemon logs every CTAP packet that reaches its
// human UHID device (HUMAN_CTAP_LOG; seeding a human credential is the positive control), and a credential for alice
// exists in the human store, so a request that leaked to the device would find something to sign with.
//
// Covered now:
// - before attach: the product cannot open a page before the worker attached the proxy. The launch opens the start
//   URL only after the worker's attached hello (defect B2); the start page (/probe) asks
//   isConditionalMediationAvailable() as early as it can, which is false only when the proxy is attached;
// - conditional mediation: isConditionalMediationAvailable() is false and a conditional get() is rejected at once with
//   NotAllowedError, without reaching the daemon;
// - worker stopped: the request wakes the worker and the proxy handles it (agent path, audited allow).
// E2E-45/cdp-context: a page in a CDP-created browser context (Target.createBrowserContext), intercepted because the
// launcher seeds incognito access for the extension (plan D4) and the launch requires the worker to report it.
// Not covered here: an unloaded extension (chrome.runtime.reload()); no product path unloads it (plan D1), and D6
// layer 3 (no device access, E2E-46) is what contains it.
// Port-only: lists worker targets and creates browser contexts over a CDP port; the extension worker is hidden from the agent in pipe mode by design (ADR 0014 §4.3, E2E-52).
scenario({ id: 'E2E-45', title: 'never native: before attach, conditional mediation, worker stopped', ci: true }, async ctx => {
  const stack = await ctx.stack({
    rps: { a: { host: 'rp-a.test' } },
    profiles: { agent: { mode: 'same-user', rules: [{ rp: 'rp-a.test', authenticate: 'allow', register: 'deny' }] } },
  });
  const rp = stack.rp.a;
  await stack.seedHuman(rp, 'alice');
  assert.match(stack.daemon.log(), HUMAN_CTAP_LOG, 'log pattern control: seeding must have produced human CTAP log lines');
  const logBefore = stack.daemon.log().length;

  // Before attach (B2 regression): the start URL is opened only after the attached hello.
  const b = await stack.open('agent', `${rp.origin}/probe`);
  assertInterceptionActive(b);
  const launchLog = stack.daemon.log().slice(logBefore).split('\n');
  const helloLine = launchLog.findIndex(l => /sign transport: connection \d+ hello accepted \(attached=true/.test(l));
  const openedLine = launchLog.findIndex(l => /opened start URL/.test(l));
  assert.ok(helloLine !== -1 && openedLine !== -1, 'the daemon logged the attached hello and the start URL');
  assert.ok(helloLine < openedLine, 'the start URL is opened only after the worker said hello attached');
  const probe = await b.page.evaluate(() => window.__probe);
  assert.equal(probe.conditionalMediation, false, 'the start page loaded with the WebAuthn proxy already attached');
  assert.deepEqual(b.blankPages.map(p => p.url()), ['about:blank'], 'the browser itself started on about:blank');

  // Conditional mediation.
  await b.page.waitForFunction(() => window.e2e);
  const conditional = await b.page.evaluate(async () => {
    const t0 = Date.now();
    const timeout = new Promise(r => setTimeout(() => r({ ok: false, name: 'still pending after 5 s' }), 5000));
    const r = await Promise.race([window.e2e.authenticate({ mediation: 'conditional', timeout: 60000 }), timeout]);
    return { ...r, ms: Date.now() - t0, available: await PublicKeyCredential.isConditionalMediationAvailable() };
  });
  assert.equal(conditional.available, false, 'isConditionalMediationAvailable() is false while attached');
  assert.equal(conditional.name, 'NotAllowedError', `a conditional get() is rejected: ${JSON.stringify(conditional)}`);
  assert.ok(conditional.ms < 3000, `and at once (${conditional.ms} ms)`);
  const afterConditional = stack.daemon.log().slice(logBefore);
  assert.equal(logMatches(afterConditional, TRANSPORT_LOG.admitted).length + logMatches(afterConditional, TRANSPORT_LOG.refused).length, 0,
    'the conditional request never reached the daemon');
  assert.equal(auditEvents(await stack.daemon.audit()).filter(e => /^policy\./.test(e.kind)).length, 0, 'nothing audited for it');

  // Worker stopped: the request wakes it and goes through the proxy.
  await stopExtensionWorker(b.browser);
  await waitFor('the daemon to see the worker connection close', () => logMatches(stack.daemon.log(), TRANSPORT_LOG.closed).length >= 1);
  await b.page.goto(`${rp.origin}/raw`);
  assertVerifiedAssertion(rp, await authenticate(b.page, { username: 'alice' }), { username: 'alice' });
  assert.equal((await extensionWorkerTargets(b.browser)).length, 1, 'the request woke the worker');
  assert.equal(logMatches(stack.daemon.log(), TRANSPORT_LOG.hello).length, 2, 'the woken worker said hello again');
  await assertAgentAllowed(stack, { rpId: 'rp-a.test', n: 1 });

  const newLog = stack.daemon.log().slice(logBefore);
  assert.doesNotMatch(newLog, HUMAN_CTAP_LOG, `the human authenticator handled a request:\n${newLog.slice(0, 2000)}`);
});

/** Evaluate `expression` in target `targetId` through a browser-level CDP session (no Playwright page needed). */
async function evaluateInTarget(cdp, targetId, expression, timeoutMs = 20000) {
  const { sessionId } = await cdp.send('Target.attachToTarget', { targetId, flatten: false });
  let seq = 0;
  const call = (method, params) => new Promise((resolve, reject) => {
    const id = ++seq;
    const timer = setTimeout(() => { cdp.off('Target.receivedMessageFromTarget', onMessage); reject(new Error(`${method} timed out in the CDP-created context`)); }, timeoutMs);
    const onMessage = ev => {
      if (ev.sessionId !== sessionId) return;
      const msg = JSON.parse(ev.message);
      if (msg.id !== id) return;
      clearTimeout(timer);
      cdp.off('Target.receivedMessageFromTarget', onMessage);
      if (msg.error) reject(new Error(msg.error.message)); else resolve(msg.result);
    };
    cdp.on('Target.receivedMessageFromTarget', onMessage);
    cdp.send('Target.sendMessageToTarget', { sessionId, message: JSON.stringify({ id, method, params }) }).catch(reject);
  });
  try {
    await call('Runtime.runIfWaitingForDebugger', {}).catch(() => {});
    const end = Date.now() + timeoutMs;
    for (;;) {
      const r = await call('Runtime.evaluate', { expression: 'document.readyState === "complete" && !!window.e2e', returnByValue: true });
      if (r.result.value === true) break;
      if (Date.now() > end) throw new Error('the page in the CDP-created context did not load');
      await new Promise(res => setTimeout(res, 200));
    }
    const r = await call('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true });
    if (r.exceptionDetails) throw new Error(`evaluation failed: ${JSON.stringify(r.exceptionDetails)}`);
    return r.result.value;
  } finally {
    await cdp.send('Target.detachFromTarget', { sessionId }).catch(() => {});
  }
}

// A page in a CDP-created browser context (Target.createBrowserContext, as an agent's CDP client may create) is an
// off-the-record profile: the proxy covers it only because the daemon seeds incognito access for the extension (plan
// D4) and refuses the launch unless the worker reports isAllowedIncognitoAccess() = true. Without that such a request
// would go native (contained by the private /dev, E2E-46). The scenario still never issues a ceremony there unless the
// proxy is proven attached: it first asks isConditionalMediationAvailable() (false only under the proxy, true
// natively; spike Q6) and fails before any get() when it is true.
// Port-only: lists worker targets and creates browser contexts over a CDP port; the extension worker is hidden from the agent in pipe mode by design (ADR 0014 §4.3, E2E-52).
scenario({ id: 'E2E-45/cdp-context', title: 'never native: request from a CDP-created browser context', ci: true }, async ctx => {
  const stack = await ctx.stack({
    rps: { a: { host: 'rp-a.test' } },
    profiles: { agent: { mode: 'same-user', rules: [{ rp: 'rp-a.test', authenticate: 'allow', register: 'deny' }] } },
  });
  const rp = stack.rp.a;
  await stack.seedHuman(rp, 'alice');
  const logBefore = stack.daemon.log().length;
  const b = await stack.open('agent', `${rp.origin}/raw`);
  assertInterceptionActive(b);
  assert.equal(b.lease.incognito_allowed, true, `the launch reports incognito access: ${JSON.stringify(b.lease)}`);

  const cdp = await b.browser.newBrowserCDPSession();
  const { browserContextId } = await cdp.send('Target.createBrowserContext', {});
  try {
    const { targetId } = await cdp.send('Target.createTarget', { url: `${rp.origin}/raw`, browserContextId });
    const available = await evaluateInTarget(cdp, targetId, 'PublicKeyCredential.isConditionalMediationAvailable()');
    if (available !== false) {
      // Nothing was sent to any authenticator: the probe is answered locally.
      assert.doesNotMatch(stack.daemon.log().slice(logBefore), HUMAN_CTAP_LOG, 'the human authenticator handled a request');
      throw new Error(`CDP-created context is not intercepted: isConditionalMediationAvailable() = ${available}; no ceremony was attempted there`);
    }
    const res = await evaluateInTarget(cdp, targetId, `window.e2e.authenticate({ username: 'alice', timeout: 20000 })`);
    assertVerifiedAssertion(rp, res, { username: 'alice' });
    await assertAgentAllowed(stack, { rpId: 'rp-a.test', n: 1 });
    assert.doesNotMatch(stack.daemon.log().slice(logBefore), HUMAN_CTAP_LOG, 'the human authenticator handled a request');
  } finally {
    await cdp.send('Target.disposeBrowserContext', { browserContextId }).catch(() => {});
    await cdp.detach().catch(() => {});
  }
});
