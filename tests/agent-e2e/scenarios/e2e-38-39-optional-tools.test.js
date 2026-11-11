'use strict';
// Catalogue E2E-38 (browser-use `cdp_url`) and E2E-39 (agent-browser `--cdp`): "local, optional". Each skips cleanly
// (SKIP-OPT, never a failure) when its tool is absent; when it is present it must log in with a passkey through the
// managed browser's endpoint, from `passless agent browser`.
//
// - agent-browser: the `agent-browser` binary from AGENT_E2E_AGENT_BROWSER, then PATH, then tests/agent-e2e/node_modules/.bin and target/agent-e2e-cache/agent-browser/node_modules/.bin.
//   Verified against agent-browser 0.42.0 (`agent-browser --cdp <url> open|eval|close`).
// - browser-use: a Python that imports `browser_use` (AGENT_E2E_BROWSER_USE_PYTHON, else `python3`). Its API changes between
//   releases; the driver below targets browser-use 1.x (verified with 1.0.2; 1.0 removed `new_page()` and `evaluate()`).
//   Install it into the harness cache with `python3 -m venv target/agent-e2e-cache/browser-use-venv` and its `pip install browser-use`.

const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { execFile, spawnSync } = require('node:child_process');

const { scenario, assert, skipOptional } = require('../lib/scenario');
const { assertVerifiedAssertion, assertAgentAllowed } = require('../lib/helpers');
const { startAgentBrowser, authenticateFn } = require('../lib/adapters');
const { HARNESS_ROOT, REPO_ROOT } = require('../lib/paths');

// Optional tools may live in the harness's own cache (never in the user's home): a venv with browser-use and an npm prefix
// with agent-browser under target/agent-e2e-cache.
const CACHE = path.join(REPO_ROOT, 'target', 'agent-e2e-cache');
const CACHED_PYTHON = path.join(CACHE, 'browser-use-venv', 'bin', 'python');
const CACHED_BIN_DIR = path.join(CACHE, 'agent-browser', 'node_modules', '.bin');

const profiles = { agent: { mode: 'same-user', rules: [{ rp: 'rp-a.test', authenticate: 'allow', register: 'deny' }] } };

const run = (bin, args, { env, timeout = 120000 } = {}) => new Promise(resolve => {
  execFile(bin, args, { env, timeout, maxBuffer: 8 * 1024 * 1024 }, (error, stdout, stderr) => resolve({ code: error ? (error.code ?? 1) : 0, stdout, stderr }));
});

function findOnPath(name, extraDirs = []) {
  for (const d of [...extraDirs, ...(process.env.PATH || '').split(':')]) {
    const p = path.join(d, name);
    try { fs.accessSync(p, fs.constants.X_OK); return p; } catch { /* next */ }
  }
  return null;
}

scenario({ id: 'E2E-38', title: 'browser-use with cdp_url from `agent browser` (local, optional)', ci: false }, async ctx => {
  const python = process.env.AGENT_E2E_BROWSER_USE_PYTHON || (fs.existsSync(CACHED_PYTHON) ? CACHED_PYTHON : findOnPath('python3'));
  if (!python) skipOptional('no python3');
  // Detection with the user's own site-packages (plain `python3 -c`, not `-I`, which ignores the user site) in a clean
  // environment; the run keeps the scenario's temp HOME and only points PYTHONUSERBASE at the real user base.
  const userBase = process.env.PYTHONUSERBASE || path.join(os.homedir(), '.local');
  const cleanEnv = { PATH: process.env.PATH, HOME: os.homedir(), PYTHONUSERBASE: userBase };
  if (spawnSync(python, ['-c', 'import browser_use'], { encoding: 'utf8', env: cleanEnv }).status !== 0) {
    skipOptional('browser-use is not installed (pip install browser-use, or set AGENT_E2E_BROWSER_USE_PYTHON)');
  }
  const stack = await ctx.stack({ rps: { a: { host: 'rp-a.test' } }, profiles });
  const rp = stack.rp.a;
  await stack.seedHuman(rp, 'alice');
  const { url, agent } = await startAgentBrowser(stack, 'agent');
  try {
    const script = path.join(stack.env.dirs.work, 'browser_use_login.py');
    // browser-use 1.0: `Browser(cdp_url=...).start()` attaches a browser-harness daemon to the endpoint and returns the
    // environment (BU_NAME) the REPL worker gets; the agent then drives pages with the browser-harness helpers
    // (new_tab / js / wait_for_load), exactly as browser-use's own REPL cells do.
    fs.writeFileSync(script, [
      'import asyncio, json, os, sys',
      'from browser_use import Browser',
      'async def main(cdp_url, page_url, fn):',
      '    browser = Browser(cdp_url=cdp_url)',
      '    os.environ.update(await browser.start())',
      '    try:',
      '        from browser_harness import helpers as h',
      '        h.new_tab(page_url)',
      '        h.wait_for_load()',
      '        result = h.js("(" + fn + ")()")',
      '        print("RESULT:" + (result if isinstance(result, str) else json.dumps(result)))',
      '    finally:',
      '        await browser.stop()',
      'asyncio.run(main(sys.argv[1], sys.argv[2], sys.argv[3]))',
    ].join('\n'));
    const r = await run(python, [script, url, `${rp.origin}/sw`, authenticateFn('alice')], { env: { ...stack.daemon.cliEnv, PYTHONUSERBASE: userBase, ANONYMIZED_TELEMETRY: 'false' } });
    assert.equal(r.code, 0, `browser-use failed: ${r.stderr.slice(-800)}`);
    const line = r.stdout.split('\n').find(l => l.startsWith('RESULT:'));
    assert.ok(line, `no result line: ${r.stdout.slice(-400)}`);
    assertVerifiedAssertion(rp, JSON.parse(line.slice('RESULT:'.length)), { username: 'alice' });
    await assertAgentAllowed(stack, { rpId: 'rp-a.test', n: 1 });
  } finally { await agent.close(); }
});

scenario({ id: 'E2E-39', title: 'agent-browser --cdp with the endpoint from `agent browser` (local, optional)', ci: false }, async ctx => {
  const bin = process.env.AGENT_E2E_AGENT_BROWSER || findOnPath('agent-browser', [path.join(HARNESS_ROOT, 'node_modules', '.bin'), CACHED_BIN_DIR]);
  if (!bin) skipOptional('agent-browser is not installed (npm i -g agent-browser, or set AGENT_E2E_AGENT_BROWSER)');
  const stack = await ctx.stack({ rps: { a: { host: 'rp-a.test' } }, profiles });
  const rp = stack.rp.a;
  await stack.seedHuman(rp, 'alice');
  const { url, agent } = await startAgentBrowser(stack, 'agent');
  const env = { ...stack.daemon.cliEnv, HOME: stack.env.dirs.home };
  try {
    const open = await run(bin, ['--cdp', url, 'open', `${rp.origin}/sw`], { env });
    assert.equal(open.code, 0, `agent-browser open failed: ${open.stderr.slice(-600)}${open.stdout.slice(-300)}`);
    const evalRes = await run(bin, ['--cdp', url, 'eval', `(${authenticateFn('alice')})()`], { env });
    assert.equal(evalRes.code, 0, `agent-browser eval failed: ${evalRes.stderr.slice(-600)}${evalRes.stdout.slice(-300)}`);
    let value = evalRes.stdout.trim();
    for (let i = 0; i < 2 && typeof value === 'string'; i++) { try { value = JSON.parse(value); } catch { break; } }
    assertVerifiedAssertion(rp, value, { username: 'alice' });
    await assertAgentAllowed(stack, { rpId: 'rp-a.test', n: 1 });
  } finally {
    await run(bin, ['close', '--all'], { env, timeout: 20000 }).catch(() => {});
    await agent.close();
  }
});
