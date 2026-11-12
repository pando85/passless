'use strict';
// Q1 / Q1b-origin-payload: attach(), onCreateRequest/onGetRequest/onRequestCanceled, complete*Request,
// native PublicKeyCredential on the page. Dumps the complete event payloads.
const L = require('./lib');
const { say, waitEvent, eventsOf, sleep } = L;

L.forEachConfig('Q1', async (h, st) => {
  const ctx = h.browser.contexts()[0];
  say('attach result:', await L.waitAttached(st));
  st.pages['*'] = { html: '<!doctype html><title>q1</title>' };
  const origin = 'http://rp-a.localhost:' + new URL(L.CTRL_BASE).port;
  const p = await L.pageWithHelpers(ctx, origin + '/');

  let t = Date.now();
  st.cfg = { mode: 'ok' };
  const c = await p.evaluate(() => window.__create());
  say('CREATE page result:', c);
  const ce = await waitEvent(st, 'onCreateRequest', { since: t });
  say('CREATE event payload (full):', ce && ce.data.evt);
  say('CREATE requestDetailsJson keys:', ce && Object.keys(ce.data.details));
  say('CREATE complete:', eventsOf(st, 'complete', t).map((e) => e.data));

  t = Date.now();
  const g = await p.evaluate(() => window.__get());
  say('GET page result:', g);
  const ge = await waitEvent(st, 'onGetRequest', { since: t });
  say('GET event payload (full):', ge && ge.data.evt);
  say('GET complete:', eventsOf(st, 'complete', t).map((e) => e.data));

  // cancel: extension never answers, page aborts
  t = Date.now();
  st.cfg = { mode: 'ignore' };
  const cancelCreate = await p.evaluate(async () => {
    const ac = new AbortController();
    setTimeout(() => ac.abort(), 1500);
    return await window.__create({}, 6000, { signal: ac.signal });
  });
  say('CANCEL create page result:', cancelCreate);
  await sleep(500);
  say('onRequestCanceled after create abort:', eventsOf(st, 'onRequestCanceled', t).map((e) => e.data));
  const createReq = eventsOf(st, 'onCreateRequest', t).map((e) => e.data.evt.requestId);
  say('  (create requestIds:', createReq, ')');

  t = Date.now();
  const cancelGet = await p.evaluate(async () => {
    const ac = new AbortController();
    setTimeout(() => ac.abort(), 1500);
    return await window.__get({}, 6000, { signal: ac.signal });
  });
  say('CANCEL get page result:', cancelGet);
  await sleep(500);
  say('onRequestCanceled after get abort:', eventsOf(st, 'onRequestCanceled', t).map((e) => e.data));
  say('  (get requestIds:', eventsOf(st, 'onGetRequest', t).map((e) => e.data.evt.requestId), ')');
});
