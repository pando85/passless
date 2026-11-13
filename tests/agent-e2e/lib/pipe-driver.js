'use strict';
// Drives a pipe-mode managed browser the way an agent must (ADR 0014 section 4.3): through `passless agent browser-control`
// from inside a principal session (`passless agent run`), so every CDP command goes through the daemon's `cdp_filter.rs` and
// is audited per command. There is no CDP endpoint and no Playwright connection; this is NOT a bypass:
//
//   - the agent is a principal session whose script ensures the browser (`agent browser --wait`) and then serves
//     `browser-control --request-file` calls from a FIFO, one at a time (the daemon also allows one call per lease);
//   - `PipeBrowser.control()` is the one entry point (E2E-52 uses the same);
//   - `PipePage` offers the small Playwright-shaped subset the scenarios use (`evaluate`, `waitForFunction`, `goto`,
//     `bringToFront`, `waitForLoadState`, ...), built from flat sessions on ordinary page targets and `Runtime.evaluate`.
//
// A call has a 30 s limit (the daemon's cap), so `evaluate` never holds a call for a long ceremony: it starts the function in
// the page, keeps its promise in a page-side slot and polls the slot with short awaited calls. Other pages' calls interleave
// between the polls, so two tabs can have ceremonies in flight at once.

const fs = require('node:fs');
const path = require('node:path');

const { startPrincipalShell } = require('./adapters');
const { waitFor } = require('./helpers');

const sleep = ms => new Promise(r => setTimeout(r, ms));
const q = s => JSON.stringify(String(s));

/** The `control` function of a principal shell that serves browser-control requests from `<dir>/requests`. */
function makeControl(dir) {
  const fifo = path.join(dir, 'requests');
  let seq = 0;
  /** One browser-control call: `{rc, messages, stderr, response}` (`response` is the message answering this request). */
  return async function control(method, params, sessionId) {
    seq += 1;
    const id = seq;
    const request = { id, method, ...(params ? { params } : {}), ...(sessionId ? { sessionId } : {}) };
    const file = path.join(dir, `req-${id}.json`);
    fs.writeFileSync(file, JSON.stringify(request), { mode: 0o600 });
    fs.appendFileSync(fifo, `${file}\n`);
    await waitFor(`browser-control ${method} to finish`, () => fs.existsSync(`${file}.rc`), { timeoutMs: 60000, intervalMs: 25 });
    const rc = Number(fs.readFileSync(`${file}.rc`, 'utf8').trim());
    const stdout = fs.readFileSync(`${file}.out`, 'utf8');
    const stderr = fs.readFileSync(`${file}.err`, 'utf8');
    const messages = rc === 0 ? JSON.parse(stdout).data.messages.map(m => JSON.parse(m)) : [];
    return { rc, messages, stderr, response: messages.find(m => m.id === id) };
  };
}

/**
 * The shell lines that serve the FIFO (after `AGENT-READY`): a line is a browser-control request file, or `run:<script>`, a
 * script of the harness's (lib/agent-session.js) that runs as a child of this principal session, so that `passless agent
 * request-access` can be called from the session that owns the browser. Both leave `<file>.out`, `.err` and `.rc`.
 */
const serveLines = [
  'exec 9<>"$D/requests"',
  'while read -r req <&9; do',
  '  case "$req" in',
  '    run:*) req="${req#run:}"; /bin/bash "$req" >"$req.out" 2>"$req.err" ;;',
  '    *) "$PASSLESS" agent browser-control --profile "$P" --request-file "$req" --timeout-ms 30000 >"$req.out" 2>"$req.err" ;;',
  '  esac',
  '  echo $? >"$req.rc.tmp" && mv "$req.rc.tmp" "$req.rc"',
  'done',
];

/** `fn` (a function or an expression string) applied to `arg`, as source text for `Runtime.evaluate`. */
function callSource(fn, arg) {
  const source = typeof fn === 'function' ? `(${fn.toString()})` : `(() => (${fn}))()`;
  const argSource = arg === undefined ? 'undefined' : JSON.stringify(arg);
  return typeof fn === 'function' ? `${source}(${argSource})` : source;
}

class PipePage {
  constructor(browser, targetId, sessionId) {
    this.browser = browser;
    this.targetId = targetId;
    this.sessionId = sessionId;
  }

  /** A CDP command on this page's flat session; resolves with its `result`, throws on a refusal or a CDP error. */
  cdp(method, params) { return this.browser.call(method, params, this.sessionId); }

  /**
   * `fn(arg)` in the page (a function, or a string expression), awaited like Playwright's `page.evaluate`: the result
   * by value, an exception in the page thrown here. Runs as long as the page function does (up to `timeoutMs`).
   */
  async evaluate(fn, arg, { timeoutMs = 150000 } = {}) {
    const inner = callSource(fn, arg);
    const start = `(() => {
      const w = window; w.__pwPipe = w.__pwPipe || { seq: 0, slots: {} };
      const key = 'k' + (++w.__pwPipe.seq);
      const slot = w.__pwPipe.slots[key] = { done: false };
      slot.p = (async () => { try { return { ok: true, v: await ${inner} }; } catch (e) { return { ok: false, name: e && e.name, message: String(e && e.message || e) }; } })()
        .then(r => { slot.done = true; slot.r = r; });
      return Promise.race([slot.p, new Promise(r => setTimeout(r, 50))])
        .then(() => slot.done ? (delete w.__pwPipe.slots[key], { done: true, r: slot.r }) : { done: false, key });
    })()`;
    let step = await this._run(start);
    const end = Date.now() + timeoutMs;
    while (!step.done) {
      if (Date.now() > end) throw new Error(`page function did not finish within ${timeoutMs} ms`);
      const key = JSON.stringify(step.key);
      step = await this._run(`(() => {
        const w = window; const slot = w.__pwPipe && w.__pwPipe.slots[${key}];
        if (!slot) return { done: true, r: { ok: false, name: 'Error', message: 'the page function was lost (the page navigated or closed)' } };
        return Promise.race([slot.p, new Promise(r => setTimeout(r, 250))])
          .then(() => slot.done ? (delete w.__pwPipe.slots[${key}], { done: true, r: slot.r }) : { done: false, key: ${key} });
      })()`);
    }
    if (!step.r.ok) {
      const e = new Error(step.r.message);
      e.name = step.r.name || 'Error';
      throw e;
    }
    return step.r.v;
  }

  /** One awaited `Runtime.evaluate` that returns a JSON value (the harness's own bookkeeping expressions). */
  async _run(expression) {
    const result = await this.cdp('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true, userGesture: true });
    if (result.exceptionDetails) {
      const d = result.exceptionDetails;
      throw new Error(`evaluate failed: ${(d.exception && d.exception.description) || d.text}`);
    }
    return result.result.value;
  }

  /** Playwright's `waitForFunction`: polls `fn(arg)` in the page until it is truthy. */
  async waitForFunction(fn, arg, { timeout = 30000 } = {}) {
    const inner = callSource(fn, arg);
    const ok = await this.evaluate(`new Promise(resolve => {
      const end = Date.now() + ${Number(timeout)};
      const tick = async () => {
        let v = false;
        try { v = await ${inner}; } catch { /* retry */ }
        if (v) return resolve(true);
        if (Date.now() > end) return resolve(false);
        setTimeout(tick, 50);
      };
      tick();
    })`, undefined, { timeoutMs: timeout + 30000 });
    if (!ok) throw new Error(`waitForFunction timed out after ${timeout} ms`);
  }

  /** The page's current URL. */
  currentUrl() { return this.evaluate('location.href'); }

  /** `Page.navigate`, then wait for the new document to be complete (Playwright's `goto` waits for `load`). */
  async goto(url) {
    const nav = await this.cdp('Page.navigate', { url });
    if (nav.errorText) throw new Error(`navigation to ${url} failed: ${nav.errorText}`);
    const target = new URL(url).href;
    await waitFor(`the page to load ${url}`, async () => {
      try { return (await this.evaluate('location.href + " " + document.readyState')) === `${target} complete`; } catch { return false; }
    }, { timeoutMs: 30000, intervalMs: 100 });
  }

  async waitForLoadState() {
    await waitFor('the page to finish loading', async () => {
      try { return (await this.evaluate('document.readyState')) === 'complete'; } catch { return false; }
    }, { timeoutMs: 30000, intervalMs: 100 });
  }

  /** Bring the tab to the front (Chromium rejects a WebAuthn `create()` from an unfocused tab, ADR section 11). */
  async bringToFront() { await this.cdp('Page.bringToFront'); }

  async close() { await this.browser.call('Target.closeTarget', { targetId: this.targetId }); }
}

class PipeBrowser {
  constructor({ stack, profile, dir, agent, status }) {
    this.stack = stack;
    this.profile = profile;
    this.dir = dir;
    this.agent = agent;
    this.status = status;
    this.control = makeControl(dir);
    this.closed = false;
    /** Playwright-shaped `context`: only what the scenarios need (`newPage`). */
    this.context = { newPage: () => this.newPage() };
  }

  /** `control` that returns the CDP `result` and throws on a refusal (`denied`, ...) or a CDP error. */
  async call(method, params, sessionId) {
    const r = await this.control(method, params, sessionId);
    if (r.rc !== 0) throw new Error(`browser-control ${method} failed (${r.rc}): ${r.stderr.trim()}`);
    if (!r.response) throw new Error(`browser-control ${method}: no response among ${JSON.stringify(r.messages).slice(0, 300)}`);
    if (r.response.error) throw new Error(`CDP ${method} failed: ${JSON.stringify(r.response.error)}`);
    return r.response.result;
  }

  /** Page targets (type `page`) the daemon's filter shows the agent. */
  async pageTargets() {
    return (await this.call('Target.getTargets')).targetInfos.filter(i => i.type === 'page');
  }

  /** A flat session on the page target, as Playwright and Puppeteer attach. */
  async attach(targetId) {
    const { sessionId } = await this.call('Target.attachToTarget', { targetId, flatten: true });
    return new PipePage(this, targetId, sessionId);
  }

  async newPage() {
    const { targetId } = await this.call('Target.createTarget', { url: 'about:blank' });
    return this.attach(targetId);
  }

  /** Ends the principal session: the daemon revokes it and tears the browser down. */
  async close() {
    this.closed = true;
    await this.agent.close();
  }
}

/**
 * Start a principal session for `profile` that ensures its pipe-mode browser and serves browser-control, and return a
 * `PipeBrowser`. With `url` the daemon opens it as the start URL (after the worker attached the proxy).
 */
async function startPipeBrowser(stack, profile, { url } = {}) {
  const dir = fs.mkdtempSync(path.join(stack.env.dirs.work, 'pipe-agent-'));
  const agent = startPrincipalShell(stack, profile, [
    `D=${q(dir)}`,
    `P=${q(profile)}`,
    'mkfifo "$D/requests"',
    `"$PASSLESS" agent browser --profile "$P" --wait ${url ? `--url ${q(url)}` : ''} >"$D/browser.out" 2>&1; echo $? >"$D/browser.rc"`,
    '"$PASSLESS" agent browser-status --profile "$P" >"$D/status.json" 2>&1',
    'echo AGENT-READY',
    ...serveLines,
  ].join('\n'));
  stack.pipeAgents.push(agent);
  try {
    await agent.waitForLine(/^AGENT-READY$/);
    const read = name => fs.readFileSync(path.join(dir, name), 'utf8');
    if (read('browser.rc').trim() !== '0') throw new Error(`agent browser failed for ${profile}: ${read('browser.out').trim()}`);
    const status = JSON.parse(read('status.json')).data;
    return new PipeBrowser({ stack, profile, dir, agent, status });
  } catch (e) {
    await agent.close();
    throw e;
  }
}

/**
 * `stack.open` for a pipe-mode profile: the same contract as the port path (`b.page` is the start-URL tab, in front and
 * loaded; `b.blankPages` the browser's own blank tab), driven through browser-control. `b.lease` is the daemon's
 * `browser-status` of the session's lease. The extension worker is hidden from the agent by the filter (that is the
 * point of pipe mode), so `b.extensionWorker` is null: lib/helpers.js `assertInterceptionActive` judges the lease's
 * `interception` and `incognito_allowed` instead.
 */
async function openPipe(stack, profile, url, { startUrl = true } = {}) {
  const pb = await startPipeBrowser(stack, profile, { url: startUrl ? url : undefined });
  const b = { pipe: pb, lease: pb.status, browser: { close: () => pb.close() }, context: pb.context, cdpUrl: null, profile, extensionWorker: null };
  let targets;
  if (startUrl) {
    targets = await waitFor(`a tab showing ${url}`, async () => {
      const t = await pb.pageTargets();
      return t.some(i => i.url.startsWith(url)) ? t : null;
    }, { timeoutMs: 15000, intervalMs: 100 });
    const hits = targets.filter(i => i.url.startsWith(url));
    if (hits.length > 1) throw new Error(`more than one tab shows ${url}: ${targets.map(i => i.url).join(', ')}`);
    b.page = await pb.attach(hits[0].targetId);
  } else {
    targets = await pb.pageTargets();
    if (targets.length !== 1) throw new Error(`expected exactly the blank tab, got: ${targets.map(i => i.url).join(', ')}`);
    b.page = await pb.attach(targets[0].targetId);
    await b.page.goto(url);
  }
  b.blankPages = targets.filter(i => i.targetId !== b.page.targetId);
  await b.page.waitForLoadState('load');
  await b.page.bringToFront();
  return b;
}

module.exports = { openPipe, startPipeBrowser, makeControl, serveLines, PipeBrowser, PipePage };
