'use strict';
// Q1b: origin provenance, clientDataJSON ownership, forged remoteDesktopClientOverride,
// cross-origin iframe (sameOriginWithAncestors / top origin), RP ID validation before the proxy event.
// Hostnames: *.localhost (secure context over http; resolved by --host-resolver-rules -> 127.0.0.1).
const L = require('./lib');
const { say, eventsOf, sleep } = L;
const PORT = new URL(L.CTRL_BASE).port;
const O = (h) => 'http://' + h + ':' + PORT;
const lastEv = (st, t, kind) => eventsOf(st, kind, t).pop();
const lastReq = (st, t, kind) => { const e = lastEv(st, t, kind); if (!e) return null; const d = e.data.details; return { requestId: e.data.evt.requestId, rpId: (d.rp && d.rp.id) || d.rpId, ext: d.extensions, challenge: d.challenge }; };
const short = (r) => r.ok ? { ok: { ctor: r.ok.ctor, isPKC: r.ok.isPKC, cd: r.ok.clientDataJSON ? JSON.parse(r.ok.clientDataJSON) : '(empty clientDataJSON)' } } : r;
const rdo = (ev) => ev && ev.ext && ev.ext.remoteDesktopClientOverride;

L.forEachConfig('Q1b', async (h, st) => {
  const ctx = h.browser.contexts()[0];
  say('attach:', await L.waitAttached(st));
  const FRAMEHOST = (inner, allow) => `<!doctype html><title>host</title><iframe id=f src="${inner}" ${allow ? 'allow="publickey-credentials-get *; publickey-credentials-create *"' : ''}></iframe>`;
  st.pages['/'] = { html: '<!doctype html><title>top</title>' };
  st.pages['/framed'] = { html: '<!doctype html><title>framed</title>' };
  st.pages['/fh-allow'] = { html: FRAMEHOST(O('evil.localhost') + '/framed', true) };
  st.pages['/fh-noallow'] = { html: FRAMEHOST(O('evil.localhost') + '/framed', false) };
  st.pages['/fh-same'] = { html: FRAMEHOST(O('rp-a.localhost') + '/framed', false) };
  const A = O('rp-a.localhost'), pA = await L.pageWithHelpers(ctx, A + '/');

  // (1) baseline: what the extension sees
  let t = Date.now(); st.cfg = { mode: 'ok' };
  say('1a baseline get -> page:', short(await pA.evaluate(() => window.__get())));
  say('1a baseline get -> ext saw:', lastReq(st, t, 'onGetRequest'));

  // (2) who builds clientDataJSON? The extension returns a WRONG origin / WRONG challenge / no clientDataJSON.
  st.cfg = { mode: 'ok', clientDataOrigin: 'https://evil.test' };
  say('2a wrong clientData.origin (create) ->', short(await pA.evaluate(() => window.__create())));
  say('2a wrong clientData.origin (get) ->', short(await pA.evaluate(() => window.__get())));
  st.cfg = { mode: 'ok', clientDataChallenge: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' };
  say('2b wrong clientData.challenge (create) ->', short(await pA.evaluate(() => window.__create())));
  say('2b wrong clientData.challenge (get) ->', short(await pA.evaluate(() => window.__get())));
  st.cfg = { mode: 'ok', omitClientData: true };
  say('2c clientDataJSON omitted by extension (create) ->', short(await pA.evaluate(() => window.__create())));
  say('2c clientDataJSON omitted by extension (get) ->', short(await pA.evaluate(() => window.__get())));

  // (3) page-forged remoteDesktopClientOverride
  st.cfg = { mode: 'ok' };
  const forged = { remoteDesktopClientOverride: { origin: 'https://evil.test', sameOriginWithAncestors: true } };
  t = Date.now();
  say('3a forged override (get) -> page:', short(await pA.evaluate((x) => window.__get({ extensions: x }), forged)));
  say('3a forged override (get) -> ext saw:', lastReq(st, t, 'onGetRequest'));
  t = Date.now();
  say('3b forged override (create) -> page:', short(await pA.evaluate((x) => window.__create({ extensions: x }), forged)));
  say('3b forged override (create) -> ext saw:', lastReq(st, t, 'onCreateRequest'));
  t = Date.now();
  const forged2 = { remoteDesktopClientOverride: { origin: 'https://evil.test', sameOriginWithAncestors: false } };
  say('3c forged override sameOriginWithAncestors=false (get) -> page:', short(await pA.evaluate((x) => window.__get({ extensions: x }), forged2)));
  say('3c -> ext saw:', lastReq(st, t, 'onGetRequest'));

  // (4) RP ID validation before the proxy event
  const rpCases = [['own host rp-a.localhost', A, 'rp-a.localhost'], ['page A -> rpId evil.localhost', A, 'evil.localhost'],
    ['page A -> rpId localhost (parent)', A, 'localhost'], ['page sub.rp-a -> rpId rp-a.localhost', O('sub.rp-a.localhost'), 'rp-a.localhost'],
    ['page A -> rpId sub.rp-a.localhost', A, 'sub.rp-a.localhost'], ['page A -> rpId with port', A, 'rp-a.localhost:' + PORT],
    ['page A -> rpId https URL', A, 'https://rp-a.localhost'], ['page evil -> rpId rp-a.localhost', O('evil.localhost'), 'rp-a.localhost']];
  for (const [label, base, rpId] of rpCases) {
    const pg = base === A ? pA : await L.pageWithHelpers(ctx, base + '/');
    for (const kind of ['get', 'create']) {
      t = Date.now();
      const r = await pg.evaluate(([k, id]) => (k === 'get' ? window.__get({ rpId: id }) : window.__create({ rpId: id })), [kind, rpId]);
      await sleep(200);
      const ev = lastReq(st, t, kind === 'get' ? 'onGetRequest' : 'onCreateRequest');
      say('4', label, kind, '-> page:', r.err || (r.ok ? 'OK(credential)' : JSON.stringify(r)), '| proxy event fired:', !!ev, ev ? '| ext origin: ' + (rdo(ev) || {}).origin : '');
    }
    if (pg !== pA) await pg.close();
  }

  // (5) frames
  for (const [label, url] of [['same-origin iframe, no allow attr', '/fh-same'], ['cross-origin iframe WITH allow attr', '/fh-allow'], ['cross-origin iframe WITHOUT allow attr', '/fh-noallow']]) {
    const pg = await L.pageWithHelpers(ctx, A + url); await sleep(600);
    const fr = pg.frames().find((f) => f.parentFrame());
    const fhost = new URL(fr.url()).hostname;
    for (const kind of ['get', 'create']) {
      t = Date.now();
      const r = await fr.evaluate(([k, id]) => (k === 'get' ? window.__get({ rpId: id }) : window.__create({ rpId: id })), [kind, fhost]);
      await sleep(200);
      const evn = lastEv(st, t, kind === 'get' ? 'onGetRequest' : 'onCreateRequest');
      say('5', label, '(frame ' + fr.url() + ')', kind, '-> page:', r.err || (r.ok ? 'OK' : JSON.stringify(r)),
        '| ext saw override:', evn && JSON.stringify(evn.data.details.extensions), '| event top-level keys:', evn && Object.keys(evn.data.evt));
    }
    t = Date.now();
    const r = await fr.evaluate(() => window.__get({ rpId: 'rp-a.localhost' }));
    await sleep(200);
    say('5x', label, '- frame requests TOP rpId rp-a.localhost ->', r.err || (r.ok ? 'OK' : JSON.stringify(r)), '| event fired:', !!lastReq(st, t, 'onGetRequest'),
      '| ext origin:', (rdo(lastReq(st, t, 'onGetRequest')) || {}).origin);
    // frame forging the override: claim the TOP origin and sameOriginWithAncestors=true
    t = Date.now();
    const fx = { remoteDesktopClientOverride: { origin: A, sameOriginWithAncestors: true } };
    const rf = await fr.evaluate(([id, x]) => window.__get({ rpId: id, extensions: x }), [fhost, fx]);
    await sleep(200);
    say('5y', label, '- frame FORGES override {origin: top, sameOriginWithAncestors:true} ->', rf.err || (rf.ok ? 'OK' : JSON.stringify(rf)), '| ext saw:', JSON.stringify((lastReq(st, t, 'onGetRequest') || {}).ext));
    await pg.close();
  }
});
