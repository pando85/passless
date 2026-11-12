'use strict';
// Q2b: natural idle stop of the service worker while attached, and extension reload.
// Runs WITHOUT Playwright (raw CDP only): Playwright's connectOverCDP auto-attaches to service workers, which behaves
// like an open DevTools window and prevents the idle stop.
const L = require('./lib');
const { say, eventsOf, sleep, waitEvent } = L;
const PORT = new URL(L.CTRL_BASE).port;
const A = 'http://rp-a.localhost:' + PORT;
const MAXWAIT = +(process.env.IDLE_WAIT || 90);
const summarise = (st, t) => eventsOf(st, 'workerStart', t).length + ' workerStart, ' + eventsOf(st, 'attach', t).map((e) => 'attach=' + e.data.res).join(',') +
  ', ' + eventsOf(st, 'onGetRequest', t).length + ' onGetRequest';
const GET = (abortMs) => `window.__get({}, ${abortMs + 1000}, { signal: AbortSignal.timeout(${abortMs}) })`;

L.forEachConfig('Q2b', async (h, st) => {
  st.pages['*'] = { html: '<!doctype html><title>q2b</title>' };
  say('initial attach:', await L.waitAttached(st));
  const pg = await h.rawPage(A + '/');
  st.cfg = { mode: 'ok' };
  let t = Date.now();
  const base = await pg.ev(GET(8000));
  say('baseline get ->', base && base.ok ? 'credential' : JSON.stringify(base));

  // (e) natural idle stop
  t = Date.now();
  let gone = false;
  for (let i = 0; i < MAXWAIT / 2 && !gone; i++) { await sleep(2000); gone = !(await h.cdp.workerTarget()); }
  say('(e) idle attached worker:', gone ? 'stopped after ~' + Math.round((Date.now() - t) / 1000) + 's of idleness' : 'still running after ' + MAXWAIT + 's');
  if (gone) {
    st.cfg = { mode: 'ok', noAttach: true };   // the restarted worker will NOT call attach()
    t = Date.now();
    const r = await pg.ev(GET(9000));
    say('(e) get after natural idle stop (restart skips attach()) ->', r && r.ok ? 'credential (attachment persisted, event woke worker)' : JSON.stringify(r), '|', summarise(st, t));
  }

  // (f) extension reload: is the attachment released? (worker skips attach() on its next start)
  st.cfg = { mode: 'ok' };
  await pg.ev(GET(8000));                       // make sure the worker is up
  for (let i = 0; i < 20 && !(await h.cdp.workerTarget()); i++) await sleep(200);
  const manifestProbe = async () => { const mp = await h.rawPage('chrome-extension://' + L.EXT_ID + '/manifest.json'); await sleep(500);
    const r = (await mp.ev('location.protocol + " " + (document.body ? document.body.innerText.slice(0, 40).replace(/\\s+/g, " ") : "(no body)")')); await mp.close(); return r; };
  say('(f) manifest probe BEFORE reload:', await manifestProbe());
  st.cfg = { mode: 'ok', noAttach: true };
  try { await h.cdp.evalInWorker('chrome.runtime.reload()'); } catch {}
  await sleep(3000);
  say('(f) worker target after chrome.runtime.reload():', !!(await h.cdp.workerTarget()));
  say('(f) manifest probe AFTER reload:', await manifestProbe());
  // start the worker explicitly (ServiceWorker domain) to prove the extension is still enabled
  const regs = [];
  h.cdp.handlers.push((d) => { if (d.method === 'ServiceWorker.workerRegistrationUpdated') regs.push(...d.params.registrations); });
  await h.cdp.send('ServiceWorker.enable', {}, pg.sessionId);
  await sleep(1000);
  const mine = regs.filter((r) => r.scopeURL.includes(L.EXT_ID));
  say('(f) ServiceWorker registrations for the extension:', mine.map((r) => r.scopeURL));
  t = Date.now();
  if (mine[0]) { try { await h.cdp.send('ServiceWorker.startWorker', { scopeURL: mine[0].scopeURL }, pg.sessionId); } catch (e) { say('(f) startWorker error:', String(e).slice(0, 200)); } }
  const ws = await waitEvent(st, 'workerStart', { since: t, timeout: 5000 });
  say('(f) explicit start of extension worker ->', ws ? 'workerStart logged (extension enabled)' : 'no workerStart');
  say('(f) attach events since reload:', eventsOf(st, 'attach', t).map((e) => e.data.res), '(none expected: noAttach)');
  t = Date.now();
  const rf = await pg.ev(GET(9000));
  say('(f) get after reload, attach() NOT re-run ->', rf && rf.ok ? 'credential (attachment persisted)' : JSON.stringify(rf), '|', summarise(st, t));
}, () => ({ noPlaywright: true }));
