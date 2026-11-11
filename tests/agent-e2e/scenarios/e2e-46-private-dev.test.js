'use strict';
const fs = require('node:fs');
const { scenario, assert } = require('../lib/scenario');
const { authenticate, assertVerifiedAssertion, assertInterceptionActive, assertAgentAllowed, HUMAN_CTAP_LOG } = require('../lib/helpers');
const { descendants, processesMentioning } = require('../lib/env');

// Catalogue E2E-46: the managed browser cannot open any /dev/hidraw* (ADR 0014 section 7, invariant 25; plan D6
// layer 3). The launcher runs it under `bwrap --dev-bind / / --dev /dev --die-with-parent`, so its /dev is private and
// has no hidraw node and no uhid, while this daemon's human hidraw node exists on the host and this user can open it
// (that is how stack.seedHuman reaches it). The probe reads the browser process's own /dev through /proc/<pid>/root,
// i.e. inside its mount namespace.
//
// E2E-46/refused: without bwrap (the debug-only PASSLESS_E2E_DISABLE_BWRAP) and with a hidraw node this user can open,
// the launch is refused with an actionable error and no browser starts.
// E2E-46/session-scope: defect B1 regression. A `browser_scope = "session"` browser used to be killed right after its
// launch (its parent-death signal followed the short-lived IPC thread that forked it); it now outlives the request.

const ONE_RP = {
  rps: { a: { host: 'rp-a.test' } },
  profiles: { agent: { mode: 'same-user', rules: [{ rp: 'rp-a.test', authenticate: 'allow', register: 'deny' }] } },
};

const cmdline = pid => { try { return fs.readFileSync(`/proc/${pid}/cmdline`, 'utf8').split('\0').filter(Boolean); } catch { return []; } };
const isBwrap = argv => /(^|\/)bwrap$/.test(argv[0] || '');

/** The managed browser's main process in the lease's process tree (not bwrap, not a Chromium child process). */
function browserMain(leasePid) {
  const pid = [leasePid, ...descendants(leasePid)].find(p => {
    const argv = cmdline(p);
    return !isBwrap(argv) && argv.some(a => a.startsWith('--user-data-dir=')) && !argv.some(a => a.startsWith('--type='));
  });
  if (!pid) throw new Error(`no browser process under lease pid ${leasePid}: ${JSON.stringify(descendants(leasePid).map(cmdline))}`);
  return pid;
}

/** This user can open `node` for reading and writing (what CTAP over HID needs). */
function accessible(node) {
  try { fs.accessSync(node, fs.constants.R_OK | fs.constants.W_OK); return true; } catch { return false; }
}

scenario({ id: 'E2E-46', title: 'the managed browser runs in a private /dev without hidraw or uhid', ci: true }, async ctx => {
  const stack = await ctx.stack(ONE_RP);
  const rp = stack.rp.a;
  await stack.seedHuman(rp, 'alice');
  assert.ok(stack.daemon.hidraw && accessible(stack.daemon.hidraw),
    `control: this daemon's human hidraw node exists and this user can open it (${stack.daemon.hidraw})`);
  const logBefore = stack.daemon.log().length;

  const b = await stack.open('agent', `${rp.origin}/raw`);
  assertInterceptionActive(b);

  const leasePid = b.lease.pid;
  assert.ok(isBwrap(cmdline(leasePid)), `the lease's process is bwrap: ${cmdline(leasePid).join(' ')}`);
  const bw = cmdline(leasePid);
  assert.deepEqual(bw.slice(1, 8), ['--dev-bind', '/', '/', '--dev', '/dev', '--die-with-parent', '--'], `bwrap argv: ${bw.join(' ')}`);

  const main = browserMain(leasePid);
  assert.notEqual(fs.readlinkSync(`/proc/${main}/ns/mnt`), fs.readlinkSync('/proc/self/ns/mnt'), 'the browser has its own mount namespace');
  const dev = fs.readdirSync(`/proc/${main}/root/dev`);
  assert.deepEqual(dev.filter(n => /^hidraw|^uhid$/.test(n)), [], `the browser's /dev has no hidraw or uhid: ${dev.join(' ')}`);
  assert.ok(!fs.existsSync(`/proc/${main}/root${stack.daemon.hidraw}`), 'the human hidraw node is not visible to the browser');
  assert.ok(!cmdline(main).includes('--no-sandbox'), "Chromium's own sandbox stays on");
  assert.match(stack.daemon.log().slice(logBefore), /native-path containment required and in place \(private \/dev through bwrap\)/,
    'the daemon logged the containment case');

  // Interception still works inside the private /dev (the native messaging relay and the sign socket are reachable).
  assertVerifiedAssertion(rp, await authenticate(b.page, { username: 'alice' }), { username: 'alice' });
  await assertAgentAllowed(stack, { rpId: 'rp-a.test', n: 1 });
  assert.doesNotMatch(stack.daemon.log().slice(logBefore), HUMAN_CTAP_LOG, 'the human authenticator handled no request');
});

scenario({ id: 'E2E-46/refused', title: 'no bwrap and an openable hidraw node: the launch is refused', ci: true }, async ctx => {
  const stack = await ctx.stack({ ...ONE_RP, daemonEnv: { PASSLESS_E2E_DISABLE_BWRAP: '1' } });
  assert.ok(stack.daemon.hidraw && accessible(stack.daemon.hidraw),
    `precondition: this user can open this daemon's human hidraw node (${stack.daemon.hidraw})`);

  const r = await stack.daemon.admin('browser', 'launch', '--profile', 'agent');
  const out = `${r.stderr}\n${r.stdout}`;
  assert.notEqual(r.code, 0, `the launch must be refused: ${out}`);
  assert.match(out, /refusing to launch the managed browser/i, out);
  assert.match(out, /hidraw/, `the error names the device: ${out}`);
  assert.match(out, /bubblewrap/i, `the error says what is missing: ${out}`);
  assert.match(out, /browser_user/, `the error gives the alternative: ${out}`);
  assert.doesNotMatch(out, /cdp_endpoint/, 'no endpoint is handed out');

  const browsers = processesMentioning(stack.env.root).filter(pid => cmdline(pid).some(a => /^--(user-data-dir|load-extension)=/.test(a)));
  assert.deepEqual(browsers, [], `a browser process exists: ${browsers.map(p => cmdline(p).slice(0, 2).join(' ')).join('; ')}`);
});

scenario({ id: 'E2E-46/session-scope', title: 'a session-scoped browser outlives its launch request (B1)', ci: true }, async ctx => {
  const stack = await ctx.stack({ ...ONE_RP, browserScope: 'session' });
  const rp = stack.rp.a;
  await stack.seedHuman(rp, 'alice');
  const b = await stack.open('agent', `${rp.origin}/raw`);
  assertInterceptionActive(b);

  // The admin request that launched it has returned; its IPC thread is gone.
  await new Promise(r => setTimeout(r, 3000));
  const leasePid = b.lease.pid;
  const state = (() => { try { const st = fs.readFileSync(`/proc/${leasePid}/stat`, 'utf8'); return st.slice(st.lastIndexOf(')') + 2).split(' ')[0]; } catch { return 'gone'; } })();
  assert.ok(!['Z', 'X', 'gone'].includes(state), `the browser process is still running after its launch request returned (state ${state})`);
  assert.ok(b.browser.isConnected(), 'the CDP connection is still up');
  assertVerifiedAssertion(rp, await authenticate(b.page, { username: 'alice' }), { username: 'alice' });
  await assertAgentAllowed(stack, { rpId: 'rp-a.test', n: 1 });
});
