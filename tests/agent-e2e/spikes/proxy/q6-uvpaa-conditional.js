'use strict';
// Q6: capability queries and conditional mediation while the proxy is attached (and, for contrast, while it is not).
const L = require('./lib');
const { say, eventsOf, sleep } = L;
const PORT = new URL(L.CTRL_BASE).port;
const A = 'http://rp-a.localhost:' + PORT;
const race = (name, expr, ms = 4000) => `Promise.race([(${expr}).then(v => ({ ok: v }), e => ({ err: e.name + ': ' + e.message })), new Promise(r => setTimeout(() => r({ hang: ${ms} }), ${ms}))])`;

const UNATTACHED = !!process.env.UNATTACHED; // contrast run: the worker never calls attach(), so everything is native
const TAG = UNATTACHED ? 'UNATTACHED ' : 'ATTACHED ';
const B = UNATTACHED ? { noAttach: true } : {};
L.forEachConfig('Q6' + (UNATTACHED ? '-UNATTACHED(native)' : ''), async (h, st) => {
  const ctx = h.browser.contexts()[0];
  st.pages['*'] = { html: '<!doctype html><title>q6</title><input id=u autocomplete="username webauthn">' };
  const attach = UNATTACHED ? (await L.waitEvent(st, 'attachSkipped') ? 'skipped (native path)' : '?') : await L.waitAttached(st);
  const p = await L.pageWithHelpers(ctx, A + '/');
  const run = async (title, cfg) => {
    st.cfg = { ...B, ...cfg }; const t = Date.now();
    const cm = await p.evaluate(race('cm', 'PublicKeyCredential.isConditionalMediationAvailable()'));
    const uv = await p.evaluate(race('uvpaa', 'PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()', 5000));
    const caps = await p.evaluate(race('caps', 'PublicKeyCredential.getClientCapabilities ? PublicKeyCredential.getClientCapabilities() : Promise.resolve("n/a")'));
    await sleep(300);
    say(title, '\n    isConditionalMediationAvailable ->', JSON.stringify(cm), '\n    isUserVerifyingPlatformAuthenticatorAvailable ->', JSON.stringify(uv),
      '\n    getClientCapabilities ->', JSON.stringify(caps), '\n    onIsUvpaaRequest events:', eventsOf(st, 'onIsUvpaaRequest', t).map((e) => JSON.stringify(e.data.evt)),
      '| completeIsUvpaa:', eventsOf(st, 'completeIsUvpaa', t).map((e) => e.data.res));
  };
  say('attach:', attach);
  await run(TAG + '[answers isUvpaa=true]', { mode: 'ok', uvpaa: true });
  await run(TAG + '[extension answers isUvpaa=false]', { mode: 'ok', uvpaa: false });
  await run(TAG + '[extension never answers isUvpaa]', { mode: 'ok', uvpaa: 'ignore' });

  // conditional mediation get()
  for (const [title, expr] of [
    ['conditional get, attached', `window.__get({}, 6000, { mediation: 'conditional', signal: AbortSignal.timeout(5000) })`],
    ['conditional get, userVerification=required', `navigator.credentials.get({ mediation: 'conditional', signal: AbortSignal.timeout(5000), publicKey: { challenge: new Uint8Array(32), rpId: location.hostname, userVerification: 'required' } }).then(c => ({ ok: !!c }), e => ({ err: e.name + ': ' + e.message }))`],
  ]) {
    st.cfg = { ...B, mode: 'ok', uvpaa: true }; const t = Date.now();
    const r = await p.evaluate(expr).catch((e) => ({ err: 'EVAL ' + e.message.split('\n')[0] }));
    await sleep(300);
    say(TAG + title, '->', JSON.stringify(r).slice(0, 300), '| onGetRequest:', eventsOf(st, 'onGetRequest', t).length, '| onRequestCanceled:', eventsOf(st, 'onRequestCanceled', t).length, '| elapsed ms:', Date.now() - t);
  }
  // timing of rejection (fast reject vs hang until abort)
  st.cfg = { ...B, mode: 'ok' };
  const t0 = Date.now();
  const r = await p.evaluate(() => { const s = performance.now(); return navigator.credentials.get({ mediation: 'conditional', signal: AbortSignal.timeout(5000), publicKey: { challenge: new Uint8Array(32), rpId: location.hostname } }).then(() => ({ ok: 1, ms: performance.now() - s }), (e) => ({ err: e.name, ms: Math.round(performance.now() - s) })); });
  say(TAG + 'conditional get rejection timing ->', JSON.stringify(r));
  // an ordinary (modal) get still works afterwards
  const t = Date.now();
  say(TAG + 'modal get after conditional ->', (await p.evaluate(() => window.__get({}, 6000))).ok ? 'credential' : 'FAIL', '| onGetRequest:', eventsOf(st, 'onGetRequest', t).length);
}, () => ({ cfg: B }));
