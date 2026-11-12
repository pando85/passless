'use strict';
// Q1 supplement: a headed Q2 run once produced "NotAllowedError: the page does not have focus" although the proxy event fired.
// Stress create/get repeatedly and count outcomes; also with/without a second (background) tab to see if focus matters.
const L = require('./lib');
const { say, sleep } = L;
const PORT = new URL(L.CTRL_BASE).port;
const A = 'http://rp-a.localhost:' + PORT;
const N = +(process.env.N || 40);

L.forEachConfig('Q1d', async (h, st) => {
  const ctx = h.browser.contexts()[0];
  st.pages['*'] = { html: '<!doctype html><title>q1d</title>' };
  await L.waitAttached(st);
  st.cfg = { mode: 'ok' };
  const tally = {};
  const bump = (k, r) => { const key = k + ':' + (r.ok ? 'credential' : r.err ? r.err.split(':').slice(0, 2).join(':').slice(0, 90) : JSON.stringify(r)); tally[key] = (tally[key] || 0) + 1; };
  for (const variant of ['single tab', 'two tabs (older tab in front of the new one)', 'new tab, bringToFront']) {
    for (const k of Object.keys(tally)) delete tally[k];
    const p1 = await L.pageWithHelpers(ctx, A + '/');
    let p = p1;
    if (variant.startsWith('two')) { p = await L.pageWithHelpers(ctx, A + '/'); await p1.bringToFront(); }
    if (variant.endsWith('bringToFront')) { p = await L.pageWithHelpers(ctx, A + '/'); await p.bringToFront(); }
    for (let i = 0; i < N; i++) {
      const kind = i % 2 ? 'get' : 'create';
      bump(kind, await p.evaluate(([k]) => (k === 'get' ? window.__get({}, 6000) : window.__create({}, 6000)), [kind]));
      await sleep(100);
    }
    say(variant + ' x' + N + ':', JSON.stringify(tally));
    for (const pg of ctx.pages()) if (pg.url().startsWith(A)) await pg.close();
    await ctx.newPage();
  }
});
