'use strict';
const fs = require('node:fs');
const { scenario, assert } = require('../lib/scenario');
const { processesMentioning } = require('../lib/env');

// Catalogue: extension directory missing or unloadable: launch fails with an actionable error; no browser without
// interception (plan D6 layer 2). The daemon (debug build) drops the generated extension directory when
// PASSLESS_E2E_OMIT_AGENT_EXTENSION is set, which is what a missing or unreadable directory looks like to the launcher.
scenario({ id: 'E2E-47', title: 'missing extension directory is a launch error; no browser starts', ci: true }, async ctx => {
  const stack = await ctx.stack({
    rps: { a: { host: 'rp-a.test' } },
    profiles: { agent: { mode: 'same-user', rules: [{ rp: 'rp-a.test', authenticate: 'allow', register: 'deny' }] } },
    daemonEnv: { PASSLESS_E2E_OMIT_AGENT_EXTENSION: '1' },
  });

  for (let attempt = 1; attempt <= 2; attempt++) { // a retry must not slip through either
    const r = await stack.daemon.admin('browser', 'launch', '--profile', 'agent');
    const out = `${r.stderr}\n${r.stdout}`;
    assert.notEqual(r.code, 0, `launch must fail without the extension (attempt ${attempt}): ${out}`);
    assert.match(out, /extension/i, `error must name the extension: ${out}`);
    assert.match(out, /refusing to launch/i, `error must say the browser is not launched: ${out}`);
    assert.match(out, /reinstall|runtime root/i, `error must say what to do: ${out}`);
    assert.doesNotMatch(out, /cdp_endpoint/, 'no endpoint may be handed out');
  }

  // No browser process of this run exists: nothing with a profile or extension argument mentions this run's root.
  const cmdline = pid => { try { return fs.readFileSync(`/proc/${pid}/cmdline`, 'utf8'); } catch { return ''; } };
  const browsers = processesMentioning(stack.env.root).filter(pid => /--user-data-dir=|--load-extension=|--remote-debugging/.test(cmdline(pid)));
  assert.deepEqual(browsers, [], `a browser process exists: ${browsers.map(p => cmdline(p).split('\0').slice(0, 2).join(' ')).join('; ')}`);
});

// Catalogue E2E-47, unloadable: the launcher's checks pass, but the browser refuses to load the extension (the
// debug-only PASSLESS_E2E_UNLOADABLE_AGENT_EXTENSION writes a worker that loads but never connects; a manifest the
// browser refuses to load would block headed Chromium on a modal dialog before it opens its debugging port). The
// worker never says hello, so the launch fails closed at the attach timeout, the browser is stopped and no endpoint is
// handed out.
scenario({ id: 'E2E-47/unloadable', title: 'an extension the browser cannot load is a launch error; the browser is stopped', ci: true }, async ctx => {
  const stack = await ctx.stack({
    rps: { a: { host: 'rp-a.test' } },
    profiles: { agent: { mode: 'same-user', rules: [{ rp: 'rp-a.test', authenticate: 'allow', register: 'deny' }] } },
    daemonEnv: { PASSLESS_E2E_UNLOADABLE_AGENT_EXTENSION: '1' },
  });

  const r = await stack.daemon.admin('browser', 'launch', '--profile', 'agent');
  const out = `${r.stderr}\n${r.stdout}`;
  assert.notEqual(r.code, 0, `launch must fail when the browser cannot load the extension: ${out}`);
  assert.match(out, /did not attach the WebAuthn proxy/, out);
  assert.match(out, /never connected/, `the error says the worker never connected: ${out}`);
  assert.match(out, /browser was stopped/, out);
  assert.doesNotMatch(out, /cdp_endpoint/, 'no endpoint may be handed out');

  const cmdline = pid => { try { return fs.readFileSync(`/proc/${pid}/cmdline`, 'utf8'); } catch { return ''; } };
  const browsers = processesMentioning(stack.env.root).filter(pid => /--user-data-dir=|--load-extension=|--remote-debugging/.test(cmdline(pid)));
  assert.deepEqual(browsers, [], `a browser process survived the failed launch: ${browsers.map(p => cmdline(p).split('\0').slice(0, 2).join(' ')).join('; ')}`);
});
