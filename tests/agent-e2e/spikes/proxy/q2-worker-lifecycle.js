'use strict';
// Q2 (this file: forced stop via CDP; see q2b-idle-and-reload.js for natural idle stop and extension reload): does the proxy attachment survive a service-worker stop? Does an event wake the worker?
// Does a second attach() throw? Where does a request go while the worker is stopped?
const L = require('./lib');
const { say, eventsOf, sleep, waitEvent } = L;
const PORT = new URL(L.CTRL_BASE).port;
const A = 'http://rp-a.localhost:' + PORT;

const stopWorker = async (h) => {
  const w = await h.cdp.workerTarget();
  if (!w) return 'no worker target';
  await h.cdp.send('Target.closeTarget', { targetId: w.targetId });
  for (let i = 0; i < 30; i++) { if (!(await h.cdp.workerTarget())) return 'stopped'; await sleep(200); }
  return 'STILL RUNNING';
};
const summarise = (st, t) => eventsOf(st, 'workerStart', t).length + ' workerStart, ' + eventsOf(st, 'attach', t).map((e) => 'attach=' + e.data.res).join(',') +
  ', ' + eventsOf(st, 'onGetRequest', t).length + ' onGetRequest, ' + eventsOf(st, 'onCreateRequest', t).length + ' onCreateRequest';

L.forEachConfig('Q2', async (h, st) => {
  const ctx = h.browser.contexts()[0];
  st.pages['*'] = { html: '<!doctype html><title>q2</title>' };
  say('initial attach:', await L.waitAttached(st));
  const p = await L.pageWithHelpers(ctx, A + '/');
  st.cfg = { mode: 'ok' };
  let t = Date.now();
  say('baseline get ->', (await p.evaluate(() => window.__get(), 0)).ok ? 'credential' : 'FAIL');

  // (a) second attach() while already attached
  say('(a) attach() again while attached:', await h.cdp.evalInWorker('new Promise(r=>chrome.webAuthenticationProxy.attach(()=>r(chrome.runtime.lastError?chrome.runtime.lastError.message:"ok")))'));
  say('(a) detach()+attach():', await h.cdp.evalInWorker('new Promise(r=>chrome.webAuthenticationProxy.detach(()=>{const d=chrome.runtime.lastError?chrome.runtime.lastError.message:"ok"; chrome.webAuthenticationProxy.attach(()=>r("detach="+d+" attach="+(chrome.runtime.lastError?chrome.runtime.lastError.message:"ok")))}))'));

  // (b) stop worker; worker WOULD re-attach on start (normal behaviour)
  st.cfg = { mode: 'ok' };
  say('(b) stop worker via CDP Target.closeTarget:', await stopWorker(h));
  t = Date.now();
  const rb = await p.evaluate(() => window.__get({}, 10000));
  say('(b) get while worker stopped -> page:', rb.ok ? 'credential (proxy handled it)' : JSON.stringify(rb), '|', summarise(st, t));
  say('(b) worker target after request:', !!(await h.cdp.workerTarget()));

  // (c) stop worker; on wake the worker does NOT call attach() => is the browser-side attachment still there?
  st.cfg = { mode: 'ok', noAttach: true };
  say('(c) stop worker (restart will skip attach()):', await stopWorker(h));
  t = Date.now();
  const rc = await p.evaluate(() => window.__get({}, 10000));
  say('(c) get, worker restarts WITHOUT attach() -> page:', rc.ok ? 'credential (attachment persisted)' : JSON.stringify(rc), '|', summarise(st, t));
  t = Date.now();
  const rc2 = await p.evaluate(() => window.__create({}, 10000));
  say('(c) create after wake, no attach() -> page:', rc2.ok ? 'credential' : JSON.stringify(rc2), '|', summarise(st, t));
});
