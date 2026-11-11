'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { execFile } = require('node:child_process');

const { scenario, assert } = require('../lib/scenario');
const { processesMentioning } = require('../lib/env');
const { discover } = require('../lib/browser');
const { browserProcesses } = require('../lib/adapters');

const profiles = { agent: { mode: 'same-user', rules: [{ rp: 'rp-a.test', authenticate: 'allow', register: 'deny' }] } };

const run = (bin, args, env) => new Promise(resolve => {
  execFile(bin, args, { env, timeout: 60000, maxBuffer: 4 * 1024 * 1024 }, (error, stdout, stderr) => resolve({ code: error ? (error.code ?? 1) : 0, stdout, stderr }));
});

/** A stand-in browser: executable script that prints `versionLine` for --version and refuses to do anything else. */
function fakeBrowser(dir, rel, versionLine) {
  const file = path.join(dir, rel);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `#!/bin/sh\nif [ "$1" = "--version" ]; then echo ${JSON.stringify(versionLine)}; exit 0; fi\necho "refused browser was started" >&2\nexit 99\n`, { mode: 0o755 });
  return file;
}

// Catalogue E2E-41 (R14): `agents.browser_path` naming branded Google Chrome or chrome-headless-shell is refused with an
// actionable error, and no browser starts. Neither can load the interception extension: branded Chrome ignores
// --load-extension, the headless shell loads no extensions. Stand-ins prove it hermetically (the version lines are the
// real ones: branded Chrome prints "Google Chrome 157...", while chrome-headless-shell prints "Google Chrome for Testing
// ..." like the full Chrome for Testing, so it is recognised by its name); the real binaries are used too when present.
// `passless doctor --agents` reports the same refusal. A supported browser named the same way launches (positive control).
scenario({ id: 'E2E-41', title: '`agents.browser_path` set to Google Chrome or chrome-headless-shell is refused', ci: true }, async ctx => {
  const probe = await ctx.stack({ rps: { a: { host: 'rp-a.test' } }, profiles, notify: false });
  const fakes = path.join(probe.env.dirs.work, 'fake-browsers');
  const cases = [
    { name: 'branded Google Chrome (stand-in)', exe: fakeBrowser(fakes, 'opt/google/chrome/google-chrome-stable', 'Google Chrome 157.0.8103.38 '), expect: /branded Google Chrome/ },
    { name: 'chrome-headless-shell (stand-in)', exe: fakeBrowser(fakes, 'cache/chrome-headless-shell-linux64/chrome-headless-shell', 'Google Chrome for Testing 155.0.8059.12 '), expect: /chrome-headless-shell/ },
  ];
  for (const id of ['chrome', 'headless-shell']) {
    const real = discover(id);
    if (real.exe) cases.push({ name: `${id} (real, ${real.version})`, exe: real.exe, expect: id === 'chrome' ? /branded Google Chrome/ : /chrome-headless-shell/ });
  }
  await probe.daemon.stop(); // the first stack only provided a work directory; each case below gets its own daemon

  for (const c of cases) {
    const stack = await ctx.stack({
      rps: { a: { host: 'rp-a.test' } }, profiles, notify: false, noBrowserCommand: true, agents: { browser_path: c.exe },
    });
    for (let attempt = 1; attempt <= 2; attempt++) { // a retry must not slip through either
      const r = await stack.daemon.admin('browser', 'launch', '--profile', 'agent');
      const out = `${r.stderr}\n${r.stdout}`;
      assert.notEqual(r.code, 0, `${c.name}: launch must be refused (attempt ${attempt}): ${out}`);
      assert.match(out, c.expect, `${c.name}: the error names what was refused: ${out}`);
      assert.match(out, /--load-extension|loads no extensions/, `${c.name}: and why: ${out}`);
      assert.match(out, /playwright install chromium/, `${c.name}: and what to use instead: ${out}`);
      assert.doesNotMatch(out, /cdp_endpoint/, `${c.name}: no endpoint may be handed out`);
    }
    assert.deepEqual(browserProcesses(stack, processesMentioning), [], `${c.name}: a browser process exists`);

    const doctor = await run(stack.daemon.bin, ['doctor', '--agents', '-o', 'json'], stack.daemon.cliEnv);
    assert.equal(doctor.code, 1, `${c.name}: doctor --agents fails: ${doctor.stdout}${doctor.stderr}`);
    const report = JSON.parse(doctor.stdout);
    const check = report.data.checks.find(k => k.name === 'agent: browser_binary');
    assert.ok(check && check.passed === false, `${c.name}: browser_binary check: ${JSON.stringify(report.data.checks)}`);
    assert.match(check.message, c.expect);
  }

  // Positive control: the same setting with a supported browser launches, headless by default (no browser_command).
  const v = ctx.variant;
  const stack = await ctx.stack({
    rps: { a: { host: 'rp-a.test' } }, profiles, notify: false, noBrowserCommand: true, agents: { browser_path: v.browser.exe },
  });
  const lease = await stack.daemon.launchBrowser('agent');
  assert.equal(lease.interception, 'attached', JSON.stringify(lease));
  const doctor = await run(stack.daemon.bin, ['doctor', '--agents', '-o', 'json'], stack.daemon.cliEnv);
  const check = JSON.parse(doctor.stdout).data.checks.find(k => k.name === 'agent: browser_binary');
  assert.ok(check && check.passed, `${v.name}: browser_binary check: ${doctor.stdout}`);
  assert.match(check.message, /Chromium|Chrome for Testing/);
});
