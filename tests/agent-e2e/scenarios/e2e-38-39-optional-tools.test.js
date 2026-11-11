'use strict';
// Catalogue E2E-38 (browser-use `cdp_url`) and E2E-39 (agent-browser `--cdp`): "local, optional". Each skips cleanly
// (SKIP-OPT, never a failure) when its tool is absent; when it is present it must log in with a passkey through the
// managed browser's endpoint, from `passless agent browser`.
//
// - agent-browser: the `agent-browser` binary from AGENT_E2E_AGENT_BROWSER, then PATH, then tests/agent-e2e/node_modules/.bin.
//   Verified against agent-browser 0.42.0 (`agent-browser --cdp <url> open|eval|close`).
// - browser-use: a Python that imports `browser_use` (AGENT_E2E_BROWSER_USE_PYTHON, else `python3`). Its API changes between
//   releases; the driver below uses `Browser(cdp_url=...)` with `start()`, `new_page()` / `get_current_page()` and
//   `evaluate()` (browser-use 0.7+). Not run on the machine this was written on (browser-use is not installed there).

const fs = require('node:fs');
const path = require('node:path');
const { execFile, spawnSync } = require('node:child_process');

const { scenario, assert, skipOptional } = require('../lib/scenario');
const { assertVerifiedAssertion, assertAgentAllowed } = require('../lib/helpers');
const { startAgentBrowser, authenticateFn } = require('../lib/adapters');
const { HARNESS_ROOT } = require('../lib/paths');

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
  const python = process.env.AGENT_E2E_BROWSER_USE_PYTHON || findOnPath('python3');
  if (!python) skipOptional('no python3');
  if (spawnSync(python, ['-I', '-c', 'import browser_use'], { encoding: 'utf8' }).status !== 0) {
    skipOptional('browser-use is not installed (pip install browser-use, or set AGENT_E2E_BROWSER_USE_PYTHON)');
  }
  const stack = await ctx.stack({ rps: { a: { host: 'rp-a.test' } }, profiles });
  const rp = stack.rp.a;
  await stack.seedHuman(rp, 'alice');
  const { url, agent } = await startAgentBrowser(stack, 'agent');
  try {
    const script = path.join(stack.env.dirs.work, 'browser_use_login.py');
    fs.writeFileSync(script, [
      'import asyncio, json, sys',
      'from browser_use import Browser',
      'async def main(cdp_url, page_url, fn):',
      '    browser = Browser(cdp_url=cdp_url)',
      '    await browser.start()',
      '    try:',
      '        page = await browser.new_page(page_url)',
      '        result = await page.evaluate(fn)',
      '        print("RESULT:" + (result if isinstance(result, str) else json.dumps(result)))',
      '    finally:',
      '        await browser.stop()',
      'asyncio.run(main(sys.argv[1], sys.argv[2], sys.argv[3]))',
    ].join('\n'));
    const r = await run(python, ['-I', script, url, `${rp.origin}/sw`, authenticateFn('alice')], { env: { ...stack.daemon.cliEnv, ANONYMIZED_TELEMETRY: 'false' } });
    assert.equal(r.code, 0, `browser-use failed: ${r.stderr.slice(-800)}`);
    const line = r.stdout.split('\n').find(l => l.startsWith('RESULT:'));
    assert.ok(line, `no result line: ${r.stdout.slice(-400)}`);
    assertVerifiedAssertion(rp, JSON.parse(line.slice('RESULT:'.length)), { username: 'alice' });
    await assertAgentAllowed(stack, { rpId: 'rp-a.test', n: 1 });
  } finally { await agent.close(); }
});

scenario({ id: 'E2E-39', title: 'agent-browser --cdp with the endpoint from `agent browser` (local, optional)', ci: false }, async ctx => {
  const bin = process.env.AGENT_E2E_AGENT_BROWSER || findOnPath('agent-browser', [path.join(HARNESS_ROOT, 'node_modules', '.bin')]);
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
