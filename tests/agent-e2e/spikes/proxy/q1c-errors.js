'use strict';
// Q1 supplement: error completion. D1 says the reply goes through complete*Request with responseJson OR a DOMException name.
// Which names does Chrome accept and how does the page see them? What if responseJson is garbage?
const L = require('./lib');
const { say, sleep } = L;
const PORT = new URL(L.CTRL_BASE).port;
const A = 'http://rp-a.localhost:' + PORT;
const NAMES = ['NotAllowedError', 'AbortError', 'InvalidStateError', 'SecurityError', 'NotSupportedError', 'ConstraintError', 'UnknownError', 'TypeError', 'NetworkError', 'TimeoutError', 'WhateverError'];

L.forEachConfig('Q1c', async (h, st) => {
  const ctx = h.browser.contexts()[0];
  st.pages['*'] = { html: '<!doctype html><title>q1c</title>' };
  await L.waitAttached(st);
  const p = await L.pageWithHelpers(ctx, A + '/');
  const out = {};
  for (const kind of ['get', 'create']) {
    for (const n of NAMES) {
      st.cfg = { mode: 'error', errorName: n };
      const r = await p.evaluate(([k]) => (k === 'get' ? window.__get({}, 6000) : window.__create({}, 6000)), [kind]);
      (out[kind] = out[kind] || []).push(n + ' -> ' + (r.err ? r.err.split(':')[0] : JSON.stringify(r)));
    }
  }
  say('error names as seen by the page: get:', out.get.join(' | '));
  say('error names as seen by the page: create:', out.create.join(' | '));
  for (const kind of ['get', 'create']) {
    st.cfg = { mode: 'ok', garbage: true };
    const r = await p.evaluate(([k]) => (k === 'get' ? window.__get({}, 6000) : window.__create({}, 6000)), [kind]);
    say('garbage responseJson (' + kind + ') -> page:', r.err ? r.err.slice(0, 160) : JSON.stringify(r).slice(0, 200));
  }
  // complete with a requestId that does not exist / twice
  st.cfg = { mode: 'ignore' };
  say('complete with unknown requestId ->', await h.cdp.evalInWorker('new Promise(r=>chrome.webAuthenticationProxy.completeGetRequest({requestId: 12345, error:{name:"NotAllowedError", message:"x"}}, ()=>r(chrome.runtime.lastError?chrome.runtime.lastError.message:"ok")))'));
});
