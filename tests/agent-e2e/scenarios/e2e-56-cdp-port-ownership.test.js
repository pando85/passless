'use strict';
const fs = require('node:fs');
const http = require('node:http');
const net = require('node:net');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');

const { scenario, assert } = require('../lib/scenario');
const { waitFor } = require('../lib/helpers');
const { processesMentioning, descendants } = require('../lib/env');
const { bwrapPath, discover } = require('../lib/browser');
const { browserProcesses, startPrincipalShell, toolText } = require('../lib/adapters');

const sleep = ms => new Promise(r => setTimeout(r, ms));
const rules = [{ rp: 'rp-a.test', authenticate: 'allow', register: 'deny' }];
/** A refusal must come fast: the pre-launch probe and the ownership check never wait out the 30 s discovery timeout. */
const FAST_MS = 10000;

/** A port that is free on 127.0.0.1 now (never 9222, which developer browsers default to). */
async function freePort() {
  for (;;) {
    const port = await new Promise((resolve, reject) => {
      const s = net.createServer();
      s.once('error', reject);
      s.listen(0, '127.0.0.1', () => { const { port: p } = s.address(); s.close(() => resolve(p)); });
    });
    if (port !== 9222) return port;
  }
}

/**
 * A fake DevTools listener on 127.0.0.1:<port>: answers `/json/version` (and `/json/list`) with a well-formed
 * `ws://127.0.0.1:<port>/devtools/browser/<guid>` and records every request.
 */
async function fakeDevtools(port) {
  const guid = crypto.randomUUID();
  const requests = [];
  const server = http.createServer((req, res) => {
    requests.push(req.url);
    const ws = `ws://127.0.0.1:${port}/devtools/browser/${guid}`;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify(req.url.startsWith('/json/list') ? [] : { Browser: 'Chrome/156.0.0.0', 'Protocol-Version': '1.3', webSocketDebuggerUrl: ws }));
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, '127.0.0.1', resolve); });
  return { guid, requests, close: () => new Promise(r => server.close(r)) };
}

/**
 * A real, plain Chromium (Playwright Chromium from the harness cache, never ~/.cache/ms-playwright) started first with
 * `--remote-debugging-port=<port>`, contained like every harness browser (bwrap, private /dev). Resolves once its
 * DevTools endpoint answers, with its browser GUID and its pids.
 */
async function squatterChromium(env, port) {
  const pw = discover('pw-chromium');
  if (!pw.exe) throw new Error(`the harness Playwright Chromium is unavailable: ${pw.skip}`);
  const bwrap = bwrapPath();
  if (!bwrap) throw new Error('bwrap is required');
  const prof = fs.mkdtempSync(path.join(env.dirs.work, 'squatter-'));
  const errFd = fs.openSync(path.join(prof, 'browser.stderr'), 'w');
  const child = env.spawnTracked(spawn, bwrap, ['--dev-bind', '/', '/', '--dev', '/dev', '--die-with-parent', pw.exe,
    `--user-data-dir=${prof}`, '--headless=new', '--no-first-run', '--no-default-browser-check', '--disable-sync',
    '--password-store=basic', '--disable-background-networking', '--disable-component-update',
    `--remote-debugging-port=${port}`, 'about:blank'], { stdio: ['ignore', 'ignore', errFd], env: env.env });
  fs.closeSync(errFd);
  const version = await waitFor(`the squatter Chromium on 127.0.0.1:${port}`, () => getJson(port, '/json/version'), { timeoutMs: 30000, intervalMs: 200 });
  const guid = version.webSocketDebuggerUrl.split('/').pop();
  return { guid, prof, child, pids: () => [child.pid, ...descendants(child.pid)], kill: () => env.killTree(child.pid) };
}

function getJson(port, urlPath) {
  return new Promise(resolve => {
    const req = http.get({ host: '127.0.0.1', port, path: urlPath, timeout: 2000 }, res => {
      let body = '';
      res.on('data', d => { body += d; });
      res.on('end', () => { try { resolve(JSON.parse(body)); } catch { resolve(null); } });
    });
    req.on('error', () => resolve(null));
    req.on('timeout', () => { req.destroy(); resolve(null); });
  });
}

/** Managed browser processes of this run started for `port`, other than the squatter (whose profile is `except`). */
function managedBrowsers(stack, port, except) {
  const cmdline = pid => { try { return fs.readFileSync(`/proc/${pid}/cmdline`, 'utf8'); } catch { return ''; } };
  return browserProcesses(stack, processesMentioning)
    .filter(pid => cmdline(pid).split('\0').includes(`--remote-debugging-port=${port}`) && !cmdline(pid).includes(except));
}

/**
 * Every launch path refuses `profile` fast, hands out no endpoint, and leaves no managed browser running:
 * the admin launch, `agent browser` in a principal session, and `agent mcp playwright` (lazily, on the first tool call).
 * `expect` is the error text; `foreignGuid` must appear nowhere.
 */
async function assertRefusedEverywhere(stack, profile, { port, expect, foreignGuid, except }) {
  const fail = out => `${profile}: ${out}`;

  let t0 = Date.now();
  const admin = await stack.daemon.admin('browser', 'launch', '--profile', profile);
  const adminOut = `${admin.stderr}\n${admin.stdout}`;
  assert.notEqual(admin.code, 0, fail(`the admin launch must be refused: ${adminOut}`));
  assert.ok(Date.now() - t0 < FAST_MS, fail(`the admin launch was refused only after ${Date.now() - t0} ms`));
  assert.match(adminOut, expect, fail(adminOut));
  assert.match(adminOut, /remove browser_cdp_port/, fail(`the error says how to fix it: ${adminOut}`));
  assert.doesNotMatch(adminOut, /extension/i, fail(`not blamed on the extension: ${adminOut}`));
  assert.ok(!adminOut.includes(foreignGuid), fail('the foreign endpoint was handed out by the admin launch'));

  t0 = Date.now();
  const agent = startPrincipalShell(stack, profile, `"$PASSLESS" agent browser --profile ${profile} --env --wait; echo "AGENT-EXIT=$?"; exec sleep 900`);
  try {
    const exit = await agent.waitForLine(/^AGENT-EXIT=/, 60000);
    assert.notEqual(exit, 'AGENT-EXIT=0', fail(`agent browser must fail: ${agent.out.stderr}`));
    assert.ok(Date.now() - t0 < FAST_MS + 5000, fail(`agent browser was refused only after ${Date.now() - t0} ms`));
    assert.match(agent.out.stderr, expect, fail(`agent browser stderr: ${agent.out.stderr}`));
    assert.ok(!agent.lines().some(l => l.startsWith('PASSLESS_CDP_URL=')), fail(`an endpoint was printed: ${agent.out.stdout}`));
    assert.ok(!`${agent.out.stdout}${agent.out.stderr}`.includes(foreignGuid), fail('the foreign endpoint reached the agent'));
  } finally {
    await agent.close();
  }

  const mcp = stack.adapter('playwright', { profile });
  try {
    await mcp.client.initialize();
    t0 = Date.now();
    const nav = await mcp.client.callTool('browser_navigate', { url: `${stack.rp.a.origin}/sw` }, 120000);
    assert.equal(nav.isError, true, fail(`browser_navigate must fail: ${JSON.stringify(nav).slice(0, 400)}`));
    assert.ok(Date.now() - t0 < FAST_MS * 3, fail(`the MCP tool call failed only after ${Date.now() - t0} ms`));
    assert.ok(!toolText(nav).includes(foreignGuid), fail('the foreign endpoint reached the MCP server'));
    await waitFor('the wrapper to print the refusal', () => (expect.test(mcp.client.stderr) ? true : null), { timeoutMs: 15000, intervalMs: 100 })
      .catch(() => assert.fail(fail(`the Playwright wrapper's stderr: ${mcp.client.stderr}`)));
    assert.ok(!mcp.client.stderr.includes(foreignGuid), fail('the foreign endpoint reached the wrapper'));
  } finally {
    await mcp.close();
  }

  await waitFor(`no managed browser of ${profile} left running`, () => managedBrowsers(stack, port, except).length === 0, { timeoutMs: 10000, intervalMs: 200 })
    .catch(() => assert.fail(fail(`browser processes left: ${managedBrowsers(stack, port, except).join(', ')}`)));
  assert.ok(!stack.daemon.log().includes(foreignGuid), fail('the foreign GUID appears in the daemon log'));
}

// Catalogue E2E-56 (FURTHER_ANALYSIS: CDP endpoint ownership): with a fixed `browser_cdp_port`, the daemon hands out a CDP
// endpoint only when the listener on 127.0.0.1:<port> is the launched browser's. Before the fix, another process holding the
// port (a developer's Chromium or Firefox with --remote-debugging-port, or an attacker of any UID) answered the daemon's
// /json/version, while the managed Chromium silently fell back to [::1]:<port>, and the agent was handed that foreign browser,
// with no WebAuthn interception and no policy.
// (control) A free fixed port launches, and the endpoint is on that port.
// (a) A fake HTTP listener pre-bound on the port that answers /json/version with a well-formed ws URL.
// (b) A real plain Chromium pre-started with --remote-debugging-port=<port>.
// Each is refused by every launch path (admin launch, `agent browser`, `agent mcp playwright`) within seconds by the pre-launch
// probe, with an error that names the holder and the fix; again with the probe disabled (debug hook
// PASSLESS_E2E_SKIP_CDP_PORT_PROBE, the probe-to-launch race), by the ownership check after the launch. No endpoint is handed
// out, the foreign browser's GUID reaches nobody, and no managed browser is left running.
// Port-only: the finding is about the port mode's endpoint (pipe mode has none, ADR 0014 §4.3).
scenario({ id: 'E2E-56', title: 'a fixed browser_cdp_port held by another process is refused; the agent never gets its endpoint', ci: true, timeoutMs: 300000 }, async ctx => {
  const [free, fake, real] = [await freePort(), await freePort(), await freePort()];
  const fakeA = await fakeDevtools(fake);
  let squatter = null;
  try {
    const profiles = {
      free: { mode: 'same-user', rules, cdpPort: free },
      fake: { mode: 'same-user', rules, cdpPort: fake },
      real: { mode: 'same-user', rules, cdpPort: real },
    };
    const stack = await ctx.stack({ rps: { a: { host: 'rp-a.test' } }, profiles, notify: false });
    squatter = await squatterChromium(stack.env, real);
    // Its tabs (page targets; Chromium's own component-extension workers come and go by themselves).
    const pagesOf = async () => (await getJson(real, '/json/list')).filter(t => t.type === 'page').map(t => `${t.id} ${t.url}`).sort();
    const squatterTargets = await pagesOf();

    // Control: a free fixed port works, and its endpoint is the managed browser's on that very port.
    const lease = await stack.daemon.launchBrowser('free');
    assert.equal(new URL(lease.cdp_endpoint).port, String(free), JSON.stringify(lease));
    assert.match(lease.cdp_endpoint, /^ws:\/\/127\.0\.0\.1:\d+\/devtools\/browser\/[0-9a-f-]+$/);
    assert.equal(lease.interception, 'attached', JSON.stringify(lease));
    const version = await getJson(free, '/json/version');
    assert.equal(version.webSocketDebuggerUrl, lease.cdp_endpoint, 'the endpoint is what the browser on that port serves');

    // (a) the fake listener: the probe refuses; the holder is this test process.
    await assertRefusedEverywhere(stack, 'fake', {
      port: fake,
      expect: new RegExp(`browser_cdp_port ${fake} on 127\\.0\\.0\\.1 is already in use \\([^)]*, pid ${process.pid}\\)`),
      foreignGuid: fakeA.guid, except: squatter.prof,
    });
    // (b) the real Chromium: the probe refuses; the holder is the squatter's browser process.
    const realExpect = new RegExp(`browser_cdp_port ${real} on 127\\.0\\.0\\.1 is already in use \\([^)]*, pid (\\d+)\\)`);
    await assertRefusedEverywhere(stack, 'real', { port: real, expect: realExpect, foreignGuid: squatter.guid, except: squatter.prof });
    const again = await stack.daemon.admin('browser', 'launch', '--profile', 'real');
    const named = Number(`${again.stderr}\n${again.stdout}`.match(realExpect)?.[1]);
    assert.ok(squatter.pids().includes(named), `the named holder (pid ${named}) is the squatter Chromium (${squatter.pids().join(', ')})`);
    await stack.daemon.stop();

    // The same with the pre-launch probe disabled: the managed browser starts, cannot bind 127.0.0.1:<port>, and the
    // ownership check refuses the foreign listener (the probe-to-launch race the check closes).
    const raced = await ctx.stack({ rps: { a: { host: 'rp-a.test' } }, profiles, notify: false, daemonEnv: { PASSLESS_E2E_SKIP_CDP_PORT_PROBE: '1' } });
    await assertRefusedEverywhere(raced, 'fake', {
      port: fake,
      expect: new RegExp(`CDP endpoint on 127\\.0\\.0\\.1:${fake} does not belong to the launched browser \\(it is held by [^)]*, pid ${process.pid}\\)`),
      foreignGuid: fakeA.guid, except: squatter.prof,
    });
    await assertRefusedEverywhere(raced, 'real', {
      port: real,
      expect: new RegExp(`CDP endpoint on 127\\.0\\.0\\.1:${real} does not belong to the launched browser`),
      foreignGuid: squatter.guid, except: squatter.prof,
    });

    // Nobody asked the fake for its endpoint (the daemon checks the socket owner before any request), and the squatter
    // was never driven: its targets are what it started with.
    assert.deepEqual(fakeA.requests.filter(u => u.startsWith('/json')), [], `requests to the fake listener: ${fakeA.requests.join(', ')}`);
    assert.deepEqual(await pagesOf(), squatterTargets, 'the squatter Chromium was driven (its tabs changed)');

    // The doctor warns about both held ports (a warning, not a failure) and is fine with the free one.
    const doctor = await new Promise(resolve => {
      require('node:child_process').execFile(raced.daemon.bin, ['doctor', '--agents', '-o', 'json'], { env: raced.daemon.cliEnv, timeout: 60000 },
        (error, stdout) => resolve(stdout));
    });
    const checks = JSON.parse(doctor).data.checks;
    const byName = n => checks.find(c => c.name === `${n}: browser_cdp_port`);
    for (const [n, port] of [['fake', fake], ['real', real]]) {
      const c = byName(n);
      assert.ok(c && c.passed && c.message.startsWith('warning:'), `${n}: ${JSON.stringify(c)}`);
      assert.match(c.message, new RegExp(`browser_cdp_port ${port} on 127\\.0\\.0\\.1 is in use by [^;]*pid \\d+`));
    }
    assert.match(byName('free').message, /is free/, JSON.stringify(byName('free')));
  } finally {
    await fakeA.close();
    squatter?.kill();
    await sleep(100);
  }
});
