'use strict';
const { scenario, assert } = require('../lib/scenario');
const { authenticate, assertVerifiedAssertion, assertInterceptionActive, assertAgentAllowed, storeFingerprint } = require('../lib/helpers');

// Catalogue: popup and same-origin iframe both work.
scenario({ id: 'E2E-08', title: 'popup and same-origin iframe' }, async ctx => {
  const stack = await ctx.stack({
    rps: { a: { host: 'rp-a.test' } },
    profiles: { agent: { mode: 'same-user', rules: [{ rp: 'rp-a.test', authenticate: 'allow', register: 'deny' }] } },
  });
  const rp = stack.rp.a;
  await stack.seedHuman(rp, 'alice');

  // Same-origin iframe.
  const b = await stack.open('agent', `${rp.origin}/iframe-host`);
  assertInterceptionActive(b);
  await b.page.waitForLoadState('load');
  const frame = b.page.frames().find(f => f.name() === 'f');
  assert.ok(frame, 'iframe not found');
  assertVerifiedAssertion(rp, await authenticate(frame, { username: 'alice' }), { username: 'alice' });

  // Popup opened by the page.
  await b.page.goto(`${rp.origin}/popup-opener`);
  const [popup] = await Promise.all([
    b.context.waitForEvent('page', { timeout: 15000 }),
    b.page.evaluate(() => window.openPopup('/sw')),
  ]);
  await popup.waitForLoadState('load');
  const injected = await popup.evaluate(() => document.documentElement.hasAttribute('data-passless-agent-broker'));
  assert.equal(injected, true, 'extension content script not injected into the popup');
  assertVerifiedAssertion(rp, await authenticate(popup, { username: 'alice' }), { username: 'alice' });

  await assertAgentAllowed(stack, { rpId: 'rp-a.test', n: 2 });

  // Same-origin about:blank, srcdoc and blob: frames must be intercepted too (manifest match_about_blank and
  // match_origin_as_fallback), never left to the native path. Their sender.url is not https, so the worker refuses the
  // request (fail closed): NotAllowedError, no assertion, no key use. A credential exists in the human store, so a
  // native fallback would succeed.
  await b.page.goto(`${rp.origin}/sw`);
  await b.page.waitForFunction(() => window.e2e);
  const storeBefore = storeFingerprint(stack.daemon);
  const assertionsBefore = rp.authentications.length;
  const results = await b.page.evaluate(async () => {
    const out = {};
    for (const kind of ['blank', 'srcdoc', 'blob']) {
      const f = document.createElement('iframe');
      f.allow = 'publickey-credentials-get *';
      if (kind === 'srcdoc') f.srcdoc = '<!doctype html><title>x</title>';
      if (kind === 'blob') f.src = URL.createObjectURL(new Blob(['<!doctype html><title>x</title>'], { type: 'text/html' }));
      document.body.appendChild(f);
      const w = f.contentWindow;
      const end = Date.now() + 5000;
      while (Date.now() < end && !(w.document.documentElement && w.document.documentElement.hasAttribute('data-passless-agent-broker'))) {
        await new Promise(r => setTimeout(r, 50));
      }
      const injected = w.document.documentElement.hasAttribute('data-passless-agent-broker');
      const native = /\[native code\]/.test(Function.prototype.toString.call(w.navigator.credentials.get));
      const o = await (await fetch('/api/auth/options', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: 'alice' }) })).json();
      const publicKey = { ...o, challenge: window.e2e.b64uToBuf(o.challenge), allowCredentials: o.allowCredentials.map(c => ({ ...c, id: window.e2e.b64uToBuf(c.id) })) };
      let name = 'resolved';
      try { await w.navigator.credentials.get({ publicKey }); } catch (e) { name = e.name; }
      out[kind] = { origin: w.location.origin, injected, native, name };
    }
    return out;
  });
  for (const kind of ['blank', 'srcdoc', 'blob']) {
    const r = results[kind];
    assert.equal(r.injected, true, `extension not injected into the ${kind} frame: ${JSON.stringify(results)}`);
    assert.equal(r.native, false, `${kind} frame has the native navigator.credentials.get`);
    assert.equal(r.name, 'NotAllowedError', `${kind} frame: ${JSON.stringify(r)}`);
  }
  assert.equal(rp.authentications.length, assertionsBefore, 'no assertion may come from a blank frame');
  assert.equal(storeFingerprint(stack.daemon), storeBefore, 'no key use from a blank frame');
});
