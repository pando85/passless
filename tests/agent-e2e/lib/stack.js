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
const { startAdapter, startPrincipalShell } = require('./adapters');
const { openPipe, serveLines } = require('./pipe-driver');
const { sessionRunner, ownedSessionScript } = require('./agent-session');

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
 * @param {object|false} [o.notify]            {script:[...]} or false to skip the double (the private bus then has no
 *                                             notification server: escalation is denied `escalation_unavailable`)
 * @param {object} [o.agents]                  raw `[agents]` keys, e.g. {escalation_cooldown: 2}
 * @param {string} [o.browserScope]            `browser_scope` of every profile (default "profile")
 * @param {boolean} [o.noBrowserCommand]       profiles get no `browser_command`: the daemon picks the browser (`agents.browser_path`)
 * @param {object} [o.daemonEnv]
 */
async function createStack(label, variant, o) {
  const env = createEnv(label);
  const stack = { env, variant, rp: {}, browsers: [], adapters: [], pipeAgents: [], failed: false };
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
      expose: variant.expose || 'port',
      limits: o.limits,
      agents: o.agents,
      browserScope: o.browserScope,
      noBrowserCommand: o.noBrowserCommand,
      browserExe: variant.browser.exe,
      browserArgs: [...variantArgs(variant), ...rpBrowserArgs(rpList)],
      // The principal sessions the daemon starts inherit its environment: the npx shim logs here.
      env: { AGENT_E2E_NPX_LOG: path.join(env.dirs.logs, 'npx.jsonl'), ...(o.daemonEnv || {}) },
    });
    stack.profiles = o.profiles;
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
    for (const a of stack.pipeAgents) { try { await a.close(); } catch { /* gone */ } }
    stack.pipeAgents = [];
    stack.profiles = profiles;
    await stack.daemon.stop();
    fs.rmSync(path.join(env.dirs.run, 'agent'), { recursive: true, force: true });
    stack.daemon = await stack.startDaemon(profiles);
    return stack.daemon;
  };

  /**
   * Replace the notification double: stop the current one (waits for it to release the bus name), start a new one with
   * `opts` (`{script:[...]}`) and its own log. `stack.notify` is the new double; the old one is returned for its log.
   */
  stack.restartNotify = async (opts = {}) => {
    const previous = stack.notify;
    if (previous) await previous.stop();
    stack.notify = await startNotifyDouble(env, opts);
    return previous;
  };

  /**
   * Start an MCP adapter (`passless agent mcp playwright|chrome-devtools`) for `profile` as an agent would, with the
   * harness's npx stand-in; returns {client, npxCalls()} (see lib/adapters.js). Closed with the stack.
   */
  stack.adapter = (kind, opts) => {
    const a = startAdapter(stack, kind, opts);
    stack.adapters.push(a);
    return a;
  };

  /** The attach mode (CDP exposure) of `profile`: its own `cdpExpose`, else the run's. */
  stack.exposeOf = profile => ((stack.profiles || {})[profile] || {}).cdpExpose || variant.expose || 'port';

  /** Launch the managed browser for `profile` via the product path and attach Playwright (port mode only). */
  stack.launch = async (profile, startUrl) => {
    if (stack.exposeOf(profile) === 'pipe') throw new Error(`stack.launch(${profile}): a pipe-mode profile has no CDP endpoint to attach Playwright to; use stack.open (browser-control)`);
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
    // Pipe mode: a principal session ensures the browser and the page is driven through `browser-control` (lib/pipe-driver.js).
    if (stack.exposeOf(profile) === 'pipe') {
      const b = await openPipe(stack, profile, url, { startUrl });
      stack.browsers.push(b);
      return b;
    }
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
   * `stack.open` through a principal session of an agent's own, which owns the browser: the shape a `register` pre-request
   * needs (its one-use approval binds to the session that owns the browser, ADR 0014 amendment section 2.3). The same `b` as
   * `stack.open`, plus `b.session`: `session.cli(args)` and `session.requestAccess(rp, opts)` run `passless agent ...` inside
   * that session (lib/agent-session.js). Pipe mode is `stack.open` (it already is such a session); port mode starts
   * `passless agent run` that runs `agent browser --env --wait` and attaches Playwright to the endpoint it printed.
   */
  stack.openOwned = async (profile, url, { startUrl = true } = {}) => {
    if (stack.exposeOf(profile) === 'pipe') {
      const b = await stack.open(profile, url, { startUrl });
      b.session = sessionRunner(stack, profile, b.pipe.dir);
      return b;
    }
    const dir = fs.mkdtempSync(path.join(env.dirs.work, 'owned-agent-'));
    const agent = startPrincipalShell(stack, profile, [ownedSessionScript(dir, profile, startUrl ? url : null, 'port'), ...serveLines].join('\n'));
    stack.pipeAgents.push(agent);
    try { await agent.waitForLine(/^AGENT-READY$/); } catch (e) { await agent.close(); throw e; }
    const read = name => fs.readFileSync(path.join(dir, name), 'utf8');
    if (read('browser.rc').trim() !== '0') throw new Error(`agent browser failed for ${profile}: ${read('browser.out').trim()}`);
    const endpoint = (/^PASSLESS_CDP_URL=(\S+)$/m.exec(read('browser.out')) || [])[1];
    if (!endpoint) throw new Error(`agent browser --env printed no endpoint: ${read('browser.out')}`);
    const { browser, context } = await connect(endpoint);
    const b = { lease: JSON.parse(read('status.json')).data, browser, context, cdpUrl: endpoint, profile, agent };
    stack.browsers.push(b);
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
    b.session = sessionRunner(stack, profile, dir);
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
  for (const a of stack.adapters || []) { try { a.close(); } catch { /* gone */ } }
  stack.adapters = [];
  for (const b of stack.browsers || []) { try { await b.browser.close(); } catch { /* gone */ } }
  stack.browsers = [];
  for (const a of stack.pipeAgents || []) { try { await a.close(); } catch { /* gone */ } }
  stack.pipeAgents = [];
  if (stack.daemon) { try { await stack.daemon.stop(); } catch { /* gone */ } }
  if (stack.notify) { try { await stack.notify.stop(); } catch { /* gone */ } }
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
