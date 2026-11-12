'use strict';
// Shared harness for the chrome.webAuthenticationProxy spikes (P0a Q1/Q1b/Q2/Q3/Q6).
//
// Hermetic: every launch gets a fresh HOME / XDG_* / --user-data-dir under SPIKE_TMP
// (default: $TMPDIR or a mkdtemp'd dir). Nothing under the real $HOME is touched.
// Run the scripts under a private session bus and X server:
//   dbus-run-session -- xvfb-run -a node q1-proxy-basic.js
const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');
const { chromium } = require('playwright-core');

const REAL_HOME = os.homedir();
// Playwright's Chromium: PW_BROWSERS_PATH (default ~/.cache/ms-playwright); install with
//   PLAYWRIGHT_BROWSERS_PATH=<dir> node ../node_modules/playwright-core/cli.js install chromium
const PW = process.env.PW_BROWSERS_PATH || path.join(REAL_HOME, '.cache/ms-playwright');
const pwChromium = () => { try { const d = fs.readdirSync(PW).filter((x) => /^chromium-\d+$/.test(x)).sort().pop(); return path.join(PW, d, 'chrome-linux64/chrome'); } catch { return path.join(PW, 'chromium-MISSING/chrome-linux64/chrome'); } };
const EXT_SRC = path.join(__dirname, 'ext');
const EXT_ID = fs.readFileSync(path.join(EXT_SRC, 'EXTENSION_ID.txt'), 'utf8').trim();
const CTRL_PORT = +(process.env.SPIKE_PORT || 18731);
const CTRL_BASE = 'http://127.0.0.1:' + CTRL_PORT;
const TMP_ROOT = process.env.SPIKE_TMP || fs.mkdtempSync(path.join(os.tmpdir(), 'passless-proxy-spike-'));

const BROWSERS = {
  chromium: '/usr/bin/chromium',
  'pw-chromium': pwChromium(),
};
// The matrix required by the P0a questions.
const CONFIGS = [
  { browser: 'chromium', mode: 'headed' },
  { browser: 'chromium', mode: 'headless-new' },
  { browser: 'pw-chromium', mode: 'headed' },
  { browser: 'pw-chromium', mode: 'headless-new' },
];
function selectedConfigs() {
  const only = process.env.ONLY; // e.g. ONLY=chromium:headed,pw-chromium:headless-new
  return CONFIGS.filter((c) => !only || only.split(',').includes(c.browser + ':' + c.mode));
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const b64uToStr = (s) => Buffer.from(s, 'base64url').toString('utf8');

// ---------------------------------------------------------------- control server
// Serves test pages for ANY Host header (so rp-a.localhost / evil.localhost resolve to it),
// collects extension logs on POST /log and hands the worker its behaviour on GET /cfg.
function startServer() {
  const state = { events: [], cfg: {}, pages: {}, requests: [] };
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x');
    const cors = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': '*' };
    if (req.method === 'OPTIONS') { res.writeHead(204, cors); return res.end(); }
    if (u.pathname === '/log' && req.method === 'POST') {
      let b = ''; req.on('data', (d) => (b += d)); req.on('end', () => { try { state.events.push(JSON.parse(b)); } catch {} res.writeHead(200, cors); res.end('ok'); });
      return;
    }
    if (u.pathname === '/cfg') { res.writeHead(200, { ...cors, 'Content-Type': 'application/json' }); return res.end(JSON.stringify(state.cfg)); }
    state.requests.push({ host: req.headers.host, url: req.url });
    const page = state.pages[u.pathname] || state.pages['*'] || { html: '<!doctype html><title>spike</title><p>spike</p>' };
    res.writeHead(200, { 'Content-Type': 'text/html', ...(page.headers || {}) });
    res.end(typeof page.html === 'function' ? page.html(req) : page.html);
  });
  return new Promise((resolve) => srv.listen(CTRL_PORT, '127.0.0.1', () => resolve({ srv, state, close: () => srv.close() })));
}
const waitEvent = async (state, type, { since = 0, timeout = 8000 } = {}) => {
  const end = Date.now() + timeout;
  while (Date.now() < end) { const e = state.events.find((x) => x.type === type && x.t >= since); if (e) return e; await sleep(50); }
  return null;
};
const eventsOf = (state, type, since = 0) => state.events.filter((x) => x.type === type && x.t >= since);

// ---------------------------------------------------------------- raw CDP (browser level)
class Cdp {
  constructor(url) { this.ws = new WebSocket(url); this.id = 0; this.pend = new Map(); this.handlers = []; this.ready = new Promise((r, j) => { this.ws.onopen = r; this.ws.onerror = j; }); this.ready.catch(() => {});
    this.ws.onmessage = (m) => { const d = JSON.parse(m.data); if (d.id && this.pend.has(d.id)) { const [res, rej] = this.pend.get(d.id); this.pend.delete(d.id); d.error ? rej(new Error(JSON.stringify(d.error))) : res(d.result); } else if (d.method) this.handlers.forEach((h) => h(d)); }; }
  async send(method, params = {}, sessionId) { await this.ready; const id = ++this.id; this.ws.send(JSON.stringify({ id, method, params, sessionId })); return new Promise((res, rej) => this.pend.set(id, [res, rej])); }
  close() { try { this.ws.close(); } catch {} }
  async targets() { return (await this.send('Target.getTargets')).targetInfos; }
  async workerTarget() { return (await this.targets()).find((t) => t.type === 'service_worker' && t.url.startsWith('chrome-extension://' + EXT_ID + '/')); }
  async evalInWorker(expression, targetId) {
    const t = targetId ? { targetId } : await this.workerTarget();
    if (!t) throw new Error('no worker target');
    const { sessionId } = await this.send('Target.attachToTarget', { targetId: t.targetId, flatten: true });
    try {
      const r = await this.send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true }, sessionId);
      return r.exceptionDetails ? { exception: r.exceptionDetails.exception && r.exceptionDetails.exception.description || r.exceptionDetails.text } : r.result.value;
    } finally { await this.send('Target.detachFromTarget', { sessionId }).catch(() => {}); }
  }
}

// ---------------------------------------------------------------- launch
function prepExt(tmp, manifestPatch) {
  const dir = path.join(tmp, 'ext');
  fs.cpSync(EXT_SRC, dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'ctl.js'), 'var CTRL_BASE = ' + JSON.stringify(CTRL_BASE) + ';\n');
  if (manifestPatch) {
    const mp = path.join(dir, 'manifest.json');
    fs.writeFileSync(mp, JSON.stringify({ ...JSON.parse(fs.readFileSync(mp, 'utf8')), ...manifestPatch }, null, 2));
  }
  return dir;
}

async function launch(conf, o = {}) {
  const tmp = o.tmpDir || fs.mkdtempSync(path.join(TMP_ROOT, 'run-'));
  const home = path.join(tmp, 'home'), prof = path.join(tmp, 'profile'), run = path.join(tmp, 'xdg-run');
  for (const d of [home, prof]) fs.mkdirSync(d, { recursive: true });
  fs.mkdirSync(run, { recursive: true, mode: 0o700 });
  if (o.preProfile) o.preProfile(prof);
  const extDir = o.noExt ? null : prepExt(tmp, o.manifestPatch);
  const args = ['--user-data-dir=' + prof, '--no-first-run', '--no-default-browser-check', '--disable-sync',
    '--password-store=basic', '--use-mock-keychain', '--disable-background-networking', '--disable-component-update',
    '--remote-debugging-port=0', '--remote-debugging-address=127.0.0.1', '--remote-allow-origins=*',
    '--host-resolver-rules=MAP *.localhost 127.0.0.1, MAP *.test 127.0.0.1',
    ...(extDir ? ['--load-extension=' + extDir] : []),
    ...(conf.mode === 'headless-new' ? ['--headless=new'] : []), ...(o.args || []), o.startUrl || 'about:blank'];
  const env = { PATH: process.env.PATH, HOME: home, XDG_CONFIG_HOME: home + '/.config', XDG_CACHE_HOME: home + '/.cache',
    XDG_DATA_HOME: home + '/.local/share', XDG_RUNTIME_DIR: run, DISPLAY: process.env.DISPLAY || '',
    DBUS_SESSION_BUS_ADDRESS: process.env.DBUS_SESSION_BUS_ADDRESS || '', LANG: 'C.UTF-8' };
  if (!env.DBUS_SESSION_BUS_ADDRESS || !env.DISPLAY) throw new Error('run under: dbus-run-session -- xvfb-run -a node <script>');
  try { fs.rmSync(path.join(prof, 'DevToolsActivePort')); } catch {} // stale file from a previous launch of a reused profile
  let stderr = '';
  const proc = spawn(BROWSERS[conf.browser], args, { detached: true, env, stdio: ['ignore', 'ignore', 'pipe'] });
  proc.stderr.on('data', (d) => { if (stderr.length < 20000) stderr += d; });
  let exited = false; proc.on('exit', () => (exited = true));
  const pf = path.join(prof, 'DevToolsActivePort');
  for (let i = 0; i < 150 && !fs.existsSync(pf) && !exited; i++) await sleep(200);
  if (!fs.existsSync(pf)) throw new Error('browser did not start: ' + stderr.slice(0, 400));
  const [port, wsPath] = fs.readFileSync(pf, 'utf8').split('\n');
  const endpoint = 'http://127.0.0.1:' + port;
  const cdp = new Cdp('ws://127.0.0.1:' + port + wsPath);
  // Playwright auto-attaches to service workers (like an open DevTools), which keeps them alive: skip it when testing idle stop.
  const browser = o.noPlaywright ? null : await chromium.connectOverCDP(endpoint);
  const h = { conf, tmp, prof, home, extDir, endpoint, cdp, browser, proc, stderr: () => stderr,
    async stop(opt = {}) {
      if (opt.graceful) { try { await cdp.send('Browser.close'); } catch {} for (let i = 0; i < 50 && !exited; i++) await sleep(200); }
      try { if (browser) await browser.close(); } catch {} cdp.close(); try { process.kill(-proc.pid, 'SIGKILL'); } catch {} await sleep(500);
      if (!process.env.KEEP && !opt.keep) fs.rmSync(tmp, { recursive: true, force: true }); },
    rawPage: (url) => rawPage(cdp, url) };
  // wait for the extension worker to show up
  if (extDir) for (let i = 0; i < 50 && !(await cdp.workerTarget()); i++) await sleep(200);
  return h;
}

// A page driven by raw CDP only (no Playwright => no DevTools-style auto-attach keeping workers alive).
async function rawPage(cdp, url, opts = {}) {
  const { targetId } = await cdp.send('Target.createTarget', { url: 'about:blank', ...(opts.browserContextId ? { browserContextId: opts.browserContextId } : {}) });
  const { sessionId } = await cdp.send('Target.attachToTarget', { targetId, flatten: true });
  await cdp.send('Page.enable', {}, sessionId);
  await cdp.send('Page.addScriptToEvaluateOnNewDocument', { source: PAGE_HELPERS }, sessionId);
  await cdp.send('Page.navigate', { url }, sessionId);
  const ev = async (expression) => {
    const r = await cdp.send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true, userGesture: true }, sessionId);
    return r.exceptionDetails ? { exception: (r.exceptionDetails.exception && r.exceptionDetails.exception.description) || r.exceptionDetails.text } : r.result.value;
  };
  for (let i = 0; i < 50; i++) { try { if ((await ev('document.readyState + "|" + location.href')).startsWith('complete|' + url.slice(0, 7))) break; } catch {} await sleep(100); }
  return { targetId, sessionId, ev, close: () => cdp.send('Target.closeTarget', { targetId }).catch(() => {}) };
}

// Wait until the worker has reported its attach() result.
async function waitAttached(state, since = 0) {
  const e = await waitEvent(state, 'attach', { since, timeout: 8000 });
  return e ? e.data.res : 'no-attach-event';
}

// ---------------------------------------------------------------- page-side helpers
// Serialise a credential the page received (runs in the page).
function PAGE_SERIALISE(c) {
  const o = { ctor: c && c.constructor && c.constructor.name, isPKC: c instanceof PublicKeyCredential, proto: Object.prototype.toString.call(c),
    id: c.id, type: c.type, attachment: c.authenticatorAttachment, respCtor: c.response && c.response.constructor.name };
  const dec = (b) => new TextDecoder().decode(b);
  try { o.clientDataJSON = dec(c.response.clientDataJSON); } catch (e) { o.cdErr = String(e); }
  try { o.ext = c.getClientExtensionResults(); } catch (e) { o.extErr = String(e); }
  try { o.hasToJSON = typeof c.toJSON === 'function'; } catch {}
  try { o.transports = c.response.getTransports && c.response.getTransports(); } catch {}
  return o;
}
const PAGE_HELPERS = `
  const b64u = (s) => Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')), c => c.charCodeAt(0));
  const ser = ${PAGE_SERIALISE.toString()};
  const CH = () => crypto.getRandomValues(new Uint8Array(32));
  const withTimeout = (p, ms) => Promise.race([p.then(v => ({ok: v}), e => ({err: e.name + ': ' + e.message})), new Promise(r => setTimeout(() => r({hang: ms}), ms))]);
  window.__create = async (over = {}, ms = 8000, extra = {}) => {
    const rpId = over.rpId === undefined ? location.hostname : over.rpId;
    const publicKey = { rp: { name: 'rp', ...(rpId ? { id: rpId } : {}) }, user: { id: new Uint8Array([1,2,3]), name: 'u', displayName: 'u' },
      challenge: over.challenge || CH(), pubKeyCredParams: [{ type: 'public-key', alg: -7 }], authenticatorSelection: { residentKey: 'preferred' },
      timeout: 120000, attestation: 'none', ...(over.extensions ? { extensions: over.extensions } : {}) };
    const r = await withTimeout(navigator.credentials.create({ publicKey, ...extra }), ms);
    return r.ok ? { ok: ser(r.ok) } : r;
  };
  window.__get = async (over = {}, ms = 8000, extra = {}) => {
    const rpId = over.rpId === undefined ? location.hostname : over.rpId;
    const publicKey = { challenge: over.challenge || CH(), ...(rpId ? { rpId } : {}), timeout: 120000, userVerification: 'preferred',
      ...(over.allowCredentials ? { allowCredentials: over.allowCredentials } : {}), ...(over.extensions ? { extensions: over.extensions } : {}) };
    const r = await withTimeout(navigator.credentials.get({ publicKey, ...extra }), ms);
    return r.ok ? { ok: ser(r.ok) } : r;
  };
`;
async function pageWithHelpers(ctx, url) {
  const p = await ctx.newPage();
  await p.addInitScript(PAGE_HELPERS);
  await p.goto(url, { waitUntil: 'load' });
  return p;
}

// ---------------------------------------------------------------- reporting
const out = [];
function say(...a) { const s = a.map((x) => (typeof x === 'string' ? x : JSON.stringify(x))).join(' '); out.push(s); console.log(s); }

// Run fn(h, server) for every selected config, isolating failures.
async function forEachConfig(name, fn, launchOpts = () => ({})) {
  const server = await startServer();
  try {
    for (const conf of selectedConfigs()) {
      const label = conf.browser + '/' + conf.mode;
      say('\n=== ' + name + ' :: ' + label + ' ===');
      server.state.events.length = 0; server.state.pages = {};
      const lo = launchOpts(conf);
      server.state.cfg = lo.cfg || {}; // initial worker behaviour, read by the worker at start
      let h;
      try {
        h = await launch(conf, lo);
        await fn(h, server.state, label);
      } catch (e) { say('FATAL ' + label + ': ' + (e && e.stack || e).toString().split('\n').slice(0, 4).join(' | ')); }
      finally { if (h) await h.stop(); }
    }
  } finally { server.close(); }
}

module.exports = { CONFIGS, selectedConfigs, BROWSERS, EXT_ID, CTRL_BASE, sleep, b64uToStr, startServer, waitEvent, eventsOf, Cdp, launch, waitAttached,
  PAGE_HELPERS, pageWithHelpers, rawPage, say, forEachConfig, TMP_ROOT };
