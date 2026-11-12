'use strict';
const { scenario, assert } = require('../lib/scenario');
const { authenticate, assertVerifiedAssertion, assertInterceptionActive, assertAgentAllowed, HUMAN_CTAP_LOG } = require('../lib/helpers');

// Catalogue: popup and same-origin iframe both work. Interception is the browser-level WebAuthn proxy (plan D1), so
// every frame and window of the profile is covered without content scripts; the ceremonies below are verified by the
// RP and audited as agent allows, and the human UHID authenticator logs no CTAP traffic meanwhile.
// Port-only (not ported): needs Playwright frame and popup APIs; lib/pipe-driver.js is page-level (ADR 0014 §4.3 allows it through browser-control).
scenario({ id: 'E2E-08', title: 'popup and same-origin iframe' }, async ctx => {
  const stack = await ctx.stack({
    rps: { a: { host: 'rp-a.test' } },
    profiles: { agent: { mode: 'same-user', max_operations: 32, rules: [{ rp: 'rp-a.test', authenticate: 'allow', register: 'deny' }] } },
  });
  const rp = stack.rp.a;
  await stack.seedHuman(rp, 'alice');

  // Same-origin iframe.
  const b = await stack.open('agent', `${rp.origin}/iframe-host`);
  assertInterceptionActive(b);
  const logBefore = stack.daemon.log().length;
  const frame = b.page.frames().find(f => f.name() === 'f');
  assert.ok(frame, 'iframe not found');
  await frame.waitForLoadState('load');
  assertVerifiedAssertion(rp, await authenticate(frame, { username: 'alice' }), { username: 'alice' });

  // Popup opened by the page.
  await b.page.goto(`${rp.origin}/popup-opener`);
  const [popup] = await Promise.all([
    b.context.waitForEvent('page', { timeout: 15000 }),
    b.page.evaluate(() => window.openPopup('/sw')),
  ]);
  await popup.waitForLoadState('load');
  await popup.bringToFront();
  assertVerifiedAssertion(rp, await authenticate(popup, { username: 'alice' }), { username: 'alice' });
  await popup.close();

  await assertAgentAllowed(stack, { rpId: 'rp-a.test', n: 2 });

  // Same-origin about:blank, srcdoc and blob: frames are covered too (the proxy is browser-level; no content script has
  // to reach them). Their request carries the parent's origin and is handled by the daemon like any other.
  await b.page.goto(`${rp.origin}/sw`);
  await b.page.bringToFront();
  await b.page.waitForFunction(() => window.e2e);
  const results = await b.page.evaluate(async () => {
    const out = {};
    for (const kind of ['blank', 'srcdoc', 'blob']) {
      const f = document.createElement('iframe');
      f.allow = 'publickey-credentials-get *';
      if (kind === 'srcdoc') f.srcdoc = '<!doctype html><title>x</title>';
      if (kind === 'blob') f.src = URL.createObjectURL(new Blob(['<!doctype html><title>x</title>'], { type: 'text/html' }));
      const loaded = new Promise(r => f.addEventListener('load', r, { once: true }));
      document.body.appendChild(f);
      if (kind !== 'blank') await loaded;
      const w = f.contentWindow;
      const native = /\[native code\]/.test(Function.prototype.toString.call(w.navigator.credentials.get));
      const o = await (await fetch('/api/auth/options', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: 'alice' }) })).json();
      const publicKey = { ...o, challenge: window.e2e.b64uToBuf(o.challenge), allowCredentials: o.allowCredentials.map(c => ({ ...c, id: window.e2e.b64uToBuf(c.id) })) };
      let r;
      try {
        const cred = await w.navigator.credentials.get({ publicKey });
        r = { ok: true, ts: (await window.e2e.verifyAuth(cred.toJSON())).ts, credentialId: cred.id };
      } catch (e) { r = { ok: false, name: e.name, message: e.message }; }
      out[kind] = { origin: w.location.origin, native, ...r };
    }
    return out;
  });
  for (const kind of ['blank', 'srcdoc', 'blob']) {
    const r = results[kind];
    assert.equal(r.native, true, `${kind} frame: navigator.credentials.get must be the browser's own (no shim)`);
    assertVerifiedAssertion(rp, r, { username: 'alice' });
  }
  await assertAgentAllowed(stack, { rpId: 'rp-a.test', n: 5 });
  const newLog = stack.daemon.log().slice(logBefore);
  assert.doesNotMatch(newLog, HUMAN_CTAP_LOG, 'the human authenticator handled a request during the agent ceremonies');
});
