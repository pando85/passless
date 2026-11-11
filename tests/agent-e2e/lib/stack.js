'use strict';
// One scenario's full stack: hermetic env, test RPs, notification double, daemon, and (on demand)
// managed browsers. Created by ctx.stack() in lib/scenario.js; closed automatically.

const fs = require('node:fs');
const path = require('node:path');

const { createEnv } = require('./env');
const { ARTIFACTS_DIR } = require('./paths');
const { startDaemon } = require('./daemon');
const { startNotifyDouble } = require('./notify-double');
const { RpServer } = require('./rp-server');
const { ensureTestTls, rpBrowserArgs } = require('./tls');
const { variantArgs, connect, waitForExtensionWorker, launchPlain } = require('./browser');

const sleep = ms => new Promise(r => setTimeout(r, ms));

/** The (single) tab of `context` whose URL starts with `url`; waits for the daemon to open it. */
async function waitForPage(context, url, timeoutMs = 15000) {
  const end = Date.now() + timeoutMs;
  for (;;) {
    const hits = context.pages().filter(p => p.url().startsWith(url));
    if (hits.length > 1) throw new Error(`more than one tab shows ${url}: ${context.pages().map(p => p.url()).join(', ')}`);
    if (hits.length === 1) return hits[0];
    if (Date.now() > end) throw new Error(`no tab shows the start URL ${url}; tabs: ${context.pages().map(p => p.url()).join(', ')}`);
    await sleep(100);
  }
}

/**
 * @param {object} variant  from browser.matrix()
 * @param {object} o
 * @param {Object<string,{host?:string,requireUV?:boolean}>} o.rps    e.g. {a:{host:'rp-a.test'}} or {local:{host:'localhost'}}
 * @param {Object<string,object>} o.profiles   see daemon.renderConfig
 * @param {object|false} [o.notify]            {script:[...]} or false to skip the double
 * @param {object} [o.daemonEnv]
 */
async function createStack(label, variant, o) {
  const env = createEnv(label);
  const stack = { env, variant, rp: {}, browsers: [], failed: false };
  try {
    const tls = Object.values(o.rps || {}).some(r => r.host && r.host !== 'localhost') ? ensureTestTls() : null;
    for (const [key, spec] of Object.entries(o.rps || {})) {
      const host = spec.host || 'localhost';
      stack.rp[key] = await new RpServer({ name: key, host, tls: host === 'localhost' ? null : tls, requireUV: spec.requireUV }).start();
    }
    const rpList = Object.values(stack.rp);
    if (o.notify !== false) stack.notify = await startNotifyDouble(env, o.notify || {});

    stack.startDaemon = profiles => startDaemon(env, {
      profiles,
      limits: o.limits,
      browserExe: variant.browser.exe,
      browserArgs: [...variantArgs(variant), ...rpBrowserArgs(rpList)],
      env: o.daemonEnv,
    });
    stack.daemon = await stack.startDaemon(o.profiles);
  } catch (e) {
    // The stack never reaches the caller, so keep the evidence and clean up here.
    try { await saveFailureArtifacts(stack, path.join(ARTIFACTS_DIR, label), { error: String(e && e.stack || e) }); } catch { /* best effort */ }
    await closeStack(stack, true);
    env.cleanup();
    throw e;
  }

  /**
   * Restart the daemon with a different profile set. The human store and the RPs persist; used when a
   * profile needs state that only exists after seeding (e.g. a credential reference).
   */
  stack.restartDaemon = async profiles => {
    for (const b of stack.browsers) { try { await b.browser.close(); } catch { /* gone */ } }
    stack.browsers = [];
    await stack.daemon.stop();
    fs.rmSync(path.join(env.dirs.run, 'agent'), { recursive: true, force: true });
    stack.daemon = await stack.startDaemon(profiles);
    return stack.daemon;
  };

  /** Launch the managed browser for `profile` via the product path and attach Playwright. */
  stack.launch = async (profile, startUrl) => {
    const lease = await stack.daemon.launchBrowser(profile, startUrl);
    const { browser, context } = await connect(lease.cdpUrl);
    const b = { lease, browser, context, cdpUrl: lease.cdpUrl, profile };
    stack.browsers.push(b);
    return b;
  };

  /**
   * Launch the managed browser with `url` as its start URL (the product path) and return it with `b.page` set to the
   * start-URL tab. The launch returns only once the extension worker reported the WebAuthn proxy attached, and the
   * daemon opens the start URL only after that (defect B2), in a new tab: the browser itself starts on about:blank,
   * so Playwright sees that blank tab too (`b.blankPages`). The start-URL tab is brought to the front, so a `create()`
   * from it is not rejected for lack of focus (ADR 0014 section 11).
   * `b.extensionWorker` reports whether the extension's service worker is running.
   *
   * `{startUrl: false}`: launch without a start URL and navigate the blank tab instead. Needed for a URL the
   * profile's rules do not admit as a start URL (an unlisted or denied RP); interception is attached either way.
   */
  stack.open = async (profile, url, { startUrl = true } = {}) => {
    const b = await stack.launch(profile, startUrl ? url : undefined);
    b.extensionWorker = await waitForExtensionWorker(b.browser);
    if (startUrl) {
      b.page = await waitForPage(b.context, url);
    } else {
      const pages = b.context.pages();
      if (pages.length !== 1) throw new Error(`expected exactly the blank tab, got: ${pages.map(p => p.url()).join(', ')}`);
      b.page = pages[0];
      await b.page.goto(url);
    }
    b.blankPages = b.context.pages().filter(p => p !== b.page);
    await b.page.waitForLoadState('load');
    await b.page.bringToFront();
    return b;
  };

  /**
   * Put a credential for `username` at `rp` into the HUMAN store, the way a human would have created it:
   * a plain (extension-less) browser ceremony against this daemon's human UHID authenticator.
   *
   * Hermetic: the browser runs under bwrap with a private /dev that contains only this daemon's own hidraw
   * node (identified through sysfs), so no real security key or other Passless instance can answer. If the
   * node cannot be identified unambiguously, or the ceremony fails, this fails fast with its own message.
   *
   * Why not the agent path: a same-user profile's agent registration would also land in the human store, but the
   * scenarios need credentials that exist independently of the agent path under test.
   */
  stack.seedHuman = async (rp, username, { timeoutMs = 40000 } = {}) => {
    if (!stack.daemon.hidraw) throw new Error(`seeding ${username}@${rp.host}: cannot identify this daemon's hidraw node: ${stack.daemon.hidrawError}`);
    const before = new Set(stack.daemon.humanStore().map(f => f.file));
    const plain = await launchPlain(stack.env, variant, rpBrowserArgs(Object.values(stack.rp)), { hidraw: stack.daemon.hidraw });
    try {
      const { browser, context } = await connect(plain.cdpUrl);
      const page = context.pages()[0] || await context.newPage();
      await page.goto(`${rp.origin}/raw`);
      await page.waitForFunction(() => window.e2e);
      let timer;
      const res = await Promise.race([
        page.evaluate(u => window.e2e.register({ username: u, userVerification: 'discouraged', timeout: 30000 }), username),
        new Promise((_, rej) => { timer = setTimeout(() => rej(new Error('timed out')), timeoutMs); }),
      ]).catch(e => ({ ok: false, error: String(e.message || e) }));
      clearTimeout(timer);
      await browser.close().catch(() => {});
      if (!res.ok) throw new Error(`seeding ${username}@${rp.host} failed: ${JSON.stringify(res)} (hidraw ${stack.daemon.hidraw})`);
      const grown = stack.daemon.humanStore().filter(f => !before.has(f.file));
      if (grown.length !== 1) throw new Error(`seeding ${username}@${rp.host}: RP accepted the credential but this daemon's store grew by ${grown.length} (expected 1)`);
      return { ...res, username };
    } finally { plain.kill(); }
  };
  return stack;
}

async function closeStack(stack, failed) {
  stack.failed = stack.failed || failed;
  for (const b of stack.browsers || []) { try { await b.browser.close(); } catch { /* gone */ } }
  stack.browsers = [];
  if (stack.daemon) { try { await stack.daemon.stop(); } catch { /* gone */ } }
  if (stack.notify) stack.notify.stop();
  for (const rp of Object.values(stack.rp || {})) { try { await rp.stop(); } catch { /* gone */ } }
}

/** Write everything useful for diagnosing a failure. */
async function saveFailureArtifacts(stack, destDir, extra = {}) {
  fs.mkdirSync(destDir, { recursive: true });
  stack.env.saveArtifacts(destDir);
  for (const [k, rp] of Object.entries(stack.rp)) fs.writeFileSync(path.join(destDir, `rp-${k}.json`), JSON.stringify(rp.state(), null, 2));
  if (stack.daemon) {
    try { fs.writeFileSync(path.join(destDir, 'audit.json'), JSON.stringify(await stack.daemon.audit(), null, 2)); } catch { /* daemon may be gone */ }
    try { fs.copyFileSync(stack.daemon.configPath, path.join(destDir, 'config.toml')); } catch { /* optional */ }
  }
  fs.writeFileSync(path.join(destDir, 'extra.json'), JSON.stringify(extra, null, 2));
}

module.exports = { createStack, closeStack, saveFailureArtifacts, waitForPage };
