'use strict';
// Browser discovery, matrix variants, CDP attach, and a plain (extension-less) launcher.
//
// Browser ids:
//   chromium     distro /usr/bin/chromium
//   pw-chromium  Playwright Chromium from the harness cache <repo>/target/agent-e2e-cache/ms-playwright (auto-installed once)
//   cft          Chrome for Testing, downloaded once via @puppeteer/browsers into
//                <repo>/target/agent-e2e-cache/cft (skipped, with a reason, when offline)
// Negative controls (never in the default matrix): `chrome` (branded Google Chrome) and
// `headless-shell` (they cannot load the extension); select them explicitly with AGENT_E2E_BROWSERS.
//
// The managed browser is launched by the product (daemon.launchBrowser); this module only decides the
// executable and the variant flags that go into the profile's `browser_command`.

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn, spawnSync, execFileSync } = require('node:child_process');

const { chromium } = require('playwright-core');

const { CACHE_DIR, HARNESS_ROOT } = require('./paths');

const sleep = ms => new Promise(r => setTimeout(r, ms));

function version(exe) {
  const r = spawnSync(exe, ['--version'], { encoding: 'utf8', timeout: 15000 });
  return r.status === 0 ? r.stdout.trim() : null;
}

// Playwright browsers come ONLY from the harness cache (<repo>/target/agent-e2e-cache/ms-playwright), which
// is also what PLAYWRIGHT_BROWSERS_PATH points at for every child. The shared ~/.cache/ms-playwright is
// never read, installed into or pruned (Playwright's installer garbage-collects that cache). An explicit
// AGENT_E2E_PW_BROWSERS_PATH may add a read-only extra root.
function pwRoots() {
  return [process.env.AGENT_E2E_PW_BROWSERS_PATH, path.join(CACHE_DIR, 'ms-playwright')]
    .filter(Boolean).filter(d => fs.existsSync(d));
}

function findPlaywrightChromium() {
  for (const base of pwRoots()) {
    const dirs = fs.readdirSync(base).filter(d => /^chromium-\d+$/.test(d))
      .sort((a, b) => Number(b.split('-')[1]) - Number(a.split('-')[1]));
    for (const d of dirs) {
      for (const sub of ['chrome-linux64/chrome', 'chrome-linux/chrome']) {
        const p = path.join(base, d, sub);
        if (fs.existsSync(p)) return p;
      }
    }
  }
  return null;
}

/** Install Playwright's Chromium into the harness cache (never into ~/.cache/ms-playwright). */
function downloadPlaywrightChromium() {
  const root = path.join(CACHE_DIR, 'ms-playwright');
  fs.mkdirSync(root, { recursive: true });
  const cli = path.join(HARNESS_ROOT, 'node_modules', 'playwright-core', 'cli.js');
  const r = spawnSync(process.execPath, [cli, 'install', 'chromium'], {
    encoding: 'utf8', timeout: 300000, env: { ...process.env, PLAYWRIGHT_BROWSERS_PATH: root },
  });
  if (r.status !== 0) return { ok: false, reason: `playwright install failed (likely offline): ${(r.stderr || r.stdout || '').trim().split('\n').pop()}` };
  return { ok: true };
}

function findCft() {
  const root = path.join(CACHE_DIR, 'cft');
  if (!fs.existsSync(root)) return null;
  const hits = [];
  const walk = (d, depth) => {
    if (depth > 4) return;
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) walk(p, depth + 1);
      else if (e.name === 'chrome' && /chrome-linux64$/.test(d)) hits.push(p);
    }
  };
  walk(root, 0);
  return hits.sort().pop() || null;
}

function downloadCft() {
  const root = path.join(CACHE_DIR, 'cft');
  fs.mkdirSync(root, { recursive: true });
  const bin = path.join(HARNESS_ROOT, 'node_modules', '.bin', 'browsers');
  const r = spawnSync(bin, ['install', 'chrome@stable', '--path', root], { encoding: 'utf8', timeout: 300000 });
  if (r.status !== 0) return { ok: false, reason: `download failed (likely offline): ${(r.stderr || r.stdout || '').trim().split('\n').pop()}` };
  return { ok: true };
}

/** Detect the kind of a Chrome-family binary from `--version` (the UA does not say "for Testing"). */
function classify(versionString) {
  if (!versionString) return 'unknown';
  if (/for Testing/i.test(versionString)) return 'cft';
  if (/^Chromium/i.test(versionString)) return 'chromium';
  if (/^Google Chrome/i.test(versionString)) return 'chrome';
  return 'unknown';
}

const _cache = new Map();
/** @returns {{id, exe?, version?, skip?: string}} */
function discover(id) {
  if (_cache.has(id)) return _cache.get(id);
  let r;
  if (id === 'chromium') {
    const exe = process.env.AGENT_E2E_CHROMIUM || '/usr/bin/chromium';
    r = fs.existsSync(exe) ? { id, exe, version: version(exe) } : { id, skip: `${exe} not found` };
  } else if (id === 'pw-chromium') {
    let exe = findPlaywrightChromium();
    let why = null;
    if (!exe && process.env.AGENT_E2E_OFFLINE !== '1') {
      const d = downloadPlaywrightChromium();
      if (d.ok) exe = findPlaywrightChromium(); else why = d.reason;
    } else if (!exe) why = 'AGENT_E2E_OFFLINE=1 and no Playwright Chromium found';
    r = exe ? { id, exe, version: version(exe) } : { id, skip: why || 'Playwright Chromium unavailable' };
  } else if (id === 'cft') {
    let exe = findCft();
    let why = null;
    if (!exe && process.env.AGENT_E2E_OFFLINE !== '1') {
      const d = downloadCft();
      if (d.ok) exe = findCft(); else why = d.reason;
    } else if (!exe) why = 'AGENT_E2E_OFFLINE=1 and no cached Chrome for Testing';
    if (exe) {
      const v = version(exe);
      r = classify(v) === 'cft' ? { id, exe, version: v } : { id, skip: `${exe} is not Chrome for Testing (${v})` };
    } else r = { id, skip: why || 'Chrome for Testing unavailable' };
  } else if (id === 'chrome') {
    const exe = ['/usr/bin/google-chrome-stable', '/usr/bin/google-chrome'].find(p => fs.existsSync(p));
    r = exe ? { id, exe, version: version(exe), negativeControl: true } : { id, skip: 'branded Google Chrome not installed' };
  } else if (id === 'headless-shell') {
    let exe = null;
    for (const base of pwRoots()) {
      const d = fs.readdirSync(base).filter(x => /^chromium_headless_shell-\d+$/.test(x)).sort().pop();
      exe = d && ['chrome-headless-shell-linux64/chrome-headless-shell', 'chrome-linux/headless_shell'].map(x => path.join(base, d, x)).find(fs.existsSync);
      if (exe) break;
    }
    r = exe ? { id, exe, version: version(exe), negativeControl: true } : { id, skip: 'chrome-headless-shell not found' };
  } else r = { id, skip: `unknown browser id ${id}` };
  _cache.set(id, r);
  return r;
}

/**
 * Matrix variants from env.
 *   AGENT_E2E_BROWSERS  comma list of ids (default: pw-chromium for `ci`, chromium,pw-chromium,cft for `full`)
 *   AGENT_E2E_HEADLESS  `new`, `headed` or `both` (default: new for `ci`, both for `full`)
 *   AGENT_E2E_MATRIX    `ci` (default) or `full`
 *   AGENT_E2E_EXPOSE    the CDP exposure ("attach mode") axis: `port`, `pipe` or `all` (default: port for `ci`, all for `full`)
 * `expose` is the list of attach modes the run covers; lib/scenario.js crosses it with each scenario's `exposeModes`.
 */
function matrix() {
  const m = process.env.AGENT_E2E_MATRIX || 'ci';
  const ids = (process.env.AGENT_E2E_BROWSERS || (m === 'full' ? 'chromium,pw-chromium,cft' : 'pw-chromium')).split(',').map(s => s.trim()).filter(Boolean);
  const hl = process.env.AGENT_E2E_HEADLESS || (m === 'full' ? 'both' : 'new');
  const modes = hl === 'both' ? ['new', 'headed'] : hl.split(',').map(s => s.trim());
  const ex = process.env.AGENT_E2E_EXPOSE || (m === 'full' ? 'all' : 'port');
  if (!['port', 'pipe', 'all'].includes(ex)) throw new Error(`AGENT_E2E_EXPOSE must be port, pipe or all (got ${ex})`);
  const expose = ex === 'all' ? ['port', 'pipe'] : [ex];
  const out = [];
  for (const id of ids) for (const mode of modes) {
    const b = discover(id);
    let skip = b.skip;
    if (!skip && mode === 'headed' && !process.env.DISPLAY) skip = 'headed variant needs DISPLAY (run via run.sh, which uses xvfb-run)';
    out.push({ browser: b, mode, name: `${id}/${mode === 'new' ? 'headless' : 'headed'}`, skip });
  }
  return { name: m, variants: out, expose };
}

/** Flags that belong to the variant (put after the executable in browser_command). */
function variantArgs(variant) {
  return variant.mode === 'new' ? ['--headless=new'] : [];
}

/** Attach Playwright to a CDP endpoint (http://127.0.0.1:PORT). Uses the default context, as Playwright MCP does. */
async function connect(cdpUrl) {
  let browser = null;
  let lastErr = null;
  // The debugging port can accept connections slightly before the HTTP/WebSocket endpoint is usable.
  for (let i = 0; i < 20 && !browser; i++) {
    try { browser = await chromium.connectOverCDP(cdpUrl); } catch (e) { lastErr = e; await sleep(500); }
  }
  if (!browser) throw lastErr;
  const context = browser.contexts()[0];
  if (!context) throw new Error('browser has no default context');
  return { browser, context };
}

/** The Passless agent extension has a fixed ID (manifest `key`); its only script is the service worker. */
const EXTENSION_ID = 'lfbahamapdlbimlffmhiomfdemnjhjkc';
const EXTENSION_WORKER_URL = `chrome-extension://${EXTENSION_ID}/worker.js`;

/** CDP target infos of the Passless extension's service worker (zero or one), via a browser-level session. */
async function extensionWorkerTargets(browser) {
  const cdp = await browser.newBrowserCDPSession();
  try {
    const { targetInfos } = await cdp.send('Target.getTargets');
    return targetInfos.filter(t => t.type === 'service_worker' && t.url === EXTENSION_WORKER_URL);
  } finally { await cdp.detach().catch(() => {}); }
}

/** Wait until the Passless extension's service worker (`worker.js` of the fixed extension ID) is running. */
async function waitForExtensionWorker(browser, timeoutMs = 15000) {
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) {
    if ((await extensionWorkerTargets(browser)).length) return true;
    await sleep(200);
  }
  return false;
}

/**
 * Stop the extension's service worker the way Chromium stops an idle worker, with CDP `Target.closeTarget` on the
 * worker target (plan V-L6; spike Q2). Its native port closes with it, so the relay exits and the daemon sees EOF.
 * Resolves once the target is gone.
 */
async function stopExtensionWorker(browser, timeoutMs = 10000) {
  const [worker] = await extensionWorkerTargets(browser);
  if (!worker) throw new Error('no extension service worker to stop');
  const cdp = await browser.newBrowserCDPSession();
  try {
    const { success } = await cdp.send('Target.closeTarget', { targetId: worker.targetId });
    if (!success) throw new Error('Target.closeTarget on the extension worker failed');
  } finally { await cdp.detach().catch(() => {}); }
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) {
    if (!(await extensionWorkerTargets(browser)).some(t => t.targetId === worker.targetId)) return worker.targetId;
    await sleep(100);
  }
  throw new Error('the extension service worker did not stop');
}

/**
 * Plain browser: same executable, no extension, fresh profile, always under bubblewrap with a private
 * /dev, so it cannot open ANY hidraw device (real security keys, other Passless instances). Pass
 * `{hidraw: '/dev/hidrawN'}` to expose exactly that one node (this run's own human UHID device); that is how
 * a human credential is seeded. bwrap argv as proven in spikes/RESULTS-env.md (Q8); Chromium's own sandbox
 * keeps working nested inside bwrap's user namespace.
 */
async function launchPlain(env, variant, extraArgs = [], { hidraw = null } = {}) {
  const prof = fs.mkdtempSync(path.join(env.dirs.work, 'plain-'));
  const started = await startPlain(variant, prof, extraArgs, { hidraw, spawnFn: (...a) => env.spawnTracked(spawn, ...a), env: env.env, timeoutMs: 30000 });
  if (!started.ok) { env.killTree(started.child.pid); throw new Error(`plain browser (bwrap) did not start: ${started.detail}`); }
  return { cdpUrl: started.cdpUrl, kill: () => env.killTree(started.child.pid) };
}

/**
 * Start the plain browser under bwrap in `prof` and wait for its DevToolsActivePort file. Resolves
 * `{ok, child, cdpUrl}`, or `{ok: false, child, detail}` when the browser exits first or the wait runs out; `detail`
 * carries the exit status and the tail of the browser's (and bwrap's) stderr, which is captured in `prof/browser.stderr`.
 */
async function startPlain(variant, prof, extraArgs, { hidraw, spawnFn, env, timeoutMs }) {
  const bwrap = bwrapPath();
  if (!bwrap) throw new Error('bubblewrap (bwrap) is required to run an extension-less browser hermetically; install it (unprivileged user namespaces must be enabled)');
  const args = [`--user-data-dir=${prof}`, '--no-first-run', '--no-default-browser-check', '--disable-sync', '--password-store=basic',
    '--disable-background-networking', '--disable-component-update', '--remote-debugging-port=0', '--remote-debugging-address=127.0.0.1',
    '--remote-allow-origins=*', ...variantArgs(variant), ...extraArgs, 'about:blank'];
  const prefix = ['--dev-bind', '/', '/', '--dev', '/dev', '--die-with-parent'];
  if (hidraw) prefix.push('--dev-bind', hidraw, hidraw);
  const errFile = path.join(prof, 'browser.stderr');
  const errFd = fs.openSync(errFile, 'w');
  const child = spawnFn(bwrap, [...prefix, variant.browser.exe, ...args], { stdio: ['ignore', 'ignore', errFd], env });
  fs.closeSync(errFd);
  let exited = null;
  child.once('exit', (code, signal) => { exited = signal ? `signal ${signal}` : `exit status ${code}`; });
  const portFile = path.join(prof, 'DevToolsActivePort');
  for (let waited = 0; waited < timeoutMs && !fs.existsSync(portFile) && !exited; waited += 200) await sleep(200);
  if (!fs.existsSync(portFile)) {
    let tail = '';
    try { tail = fs.readFileSync(errFile, 'utf8').trim().split('\n').slice(-12).join('\n'); } catch { /* no stderr captured */ }
    return { ok: false, child, detail: `${exited ? `the browser exited (${exited})` : `no DevToolsActivePort after ${timeoutMs / 1000}s`}${tail ? `; stderr tail:\n${tail}` : ''}` };
  }
  return { ok: true, child, cdpUrl: `http://127.0.0.1:${fs.readFileSync(portFile, 'utf8').split('\n')[0]}` };
}

/**
 * Preflight for the selected variants: a plain browser under bwrap (the launch every scenario's seeding and the
 * product's contained launch rely on) must come up. Returns the list of failures (empty when all is well), so a
 * runner whose sandbox prerequisites are missing fails in seconds with the browser's own stderr instead of timing
 * out scenario by scenario.
 */
async function preflightPlainBrowsers() {
  const failures = [];
  for (const variant of matrix().variants.filter(v => !v.skip)) {
    const prof = fs.mkdtempSync(path.join(process.env.AGENT_E2E_TMPDIR || os.tmpdir(), 'pl-pre-'));
    let child = null;
    try {
      const r = await startPlain(variant, prof, [], { hidraw: null, spawnFn: (bin, a, o) => spawn(bin, a, { ...o, detached: true }), env: process.env, timeoutMs: 30000 });
      child = r.child;
      if (!r.ok) failures.push({ variant: variant.name, detail: r.detail });
    } catch (e) { failures.push({ variant: variant.name, detail: e.message }); }
    finally {
      if (child && child.pid) { try { process.kill(-child.pid, 'SIGKILL'); } catch { /* already gone */ } }
      fs.rmSync(prof, { recursive: true, force: true });
    }
  }
  return failures;
}

function bwrapPath() {
  for (const d of (process.env.PATH || '').split(':')) { const p = path.join(d, 'bwrap'); if (fs.existsSync(p)) return p; }
  return null;
}

module.exports = { bwrapPath, discover, matrix, variantArgs, connect, launchPlain, preflightPlainBrowsers, classify, waitForExtensionWorker, extensionWorkerTargets, stopExtensionWorker, EXTENSION_ID, EXTENSION_WORKER_URL };
