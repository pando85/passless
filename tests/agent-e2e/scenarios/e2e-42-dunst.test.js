'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { spawn, execFile } = require('node:child_process');

const { scenario, assert, skipOptional } = require('../lib/scenario');
const { grantsStore, authenticate, assertVerifiedAssertion, assertInterceptionActive, waitFor, escalationEvents, grantedRuleEvents } = require('../lib/helpers');
const { requestProfile, start, settle, REGISTER_SUMMARY } = require('../lib/escalation');

const sleep = ms => new Promise(r => setTimeout(r, ms));
const which = name => (process.env.PATH || '').split(':').map(d => path.join(d, name)).find(p => { try { fs.accessSync(p, fs.constants.X_OK); return true; } catch { return false; } });
const run = (bin, args, env) => new Promise(resolve => {
  execFile(bin, args, { env, timeout: 15000 }, (error, stdout, stderr) => resolve({ code: error ? (error.code ?? 1) : 0, stdout, stderr }));
});

/** An Xvfb of the scenario's own (the variant has no display); returns its DISPLAY. Tracked, so it is killed with the stack. */
async function startXvfb(stack) {
  const xvfb = which('Xvfb');
  if (!xvfb) throw new Error('E2E-42 needs a display and neither DISPLAY nor Xvfb is available (install xorg-server-xvfb)');
  const child = stack.env.spawnTracked(spawn, xvfb, ['-displayfd', '3', '-screen', '0', '1024x768x24', '-nolisten', 'tcp'], { stdio: ['ignore', 'ignore', 'ignore', 'pipe'], detached: true });
  let out = '';
  child.stdio[3].on('data', d => { out += d; });
  for (let i = 0; i < 100 && !/\n/.test(out); i++) await sleep(100);
  if (!/^\d+\n/.test(out)) throw new Error(`Xvfb did not report a display number: ${JSON.stringify(out)}`);
  return `:${out.trim()}`;
}

/**
 * Start a real dunst on the scenario's private bus (the stack has `notify: false`, so it owns the notification name), with a
 * `dmenu` script that picks the context-menu entry matching `pick` the way a person would click it. Returns the dunst
 * control helper, the menu text dunst offered and `stop()`.
 */
async function startDunst(stack, pick) {
  const dir = path.join(stack.env.dirs.work, 'dunst');
  fs.mkdirSync(dir, { recursive: true });
  const menuFile = path.join(dir, 'menu.txt');
  const picker = path.join(dir, 'pick.sh');
  fs.writeFileSync(picker, `#!/bin/sh\ncat > ${JSON.stringify(menuFile)}\ngrep -i ${JSON.stringify(pick)} ${JSON.stringify(menuFile)} | head -n 1\n`, { mode: 0o755 });
  // A script rule records what dunst displays (appname, summary, body, ...): the text the human reads.
  const shownFile = path.join(dir, 'shown.txt');
  const logger = path.join(dir, 'log-shown.sh');
  fs.writeFileSync(logger, `#!/bin/sh\nprintf '%s\\n%s\\n' "$2" "$3" > ${JSON.stringify(shownFile)}\n`, { mode: 0o755 });
  const conf = path.join(dir, 'dunstrc');
  fs.writeFileSync(conf, `[global]\n    dmenu = ${picker}\n    follow = none\n    notification_limit = 5\n    idle_threshold = 0\n    sticky_history = no\n\n[record]\n    summary = "*"\n    script = ${logger}\n`);
  const logPath = path.join(dir, 'dunst.log');
  const logFd = fs.openSync(logPath, 'a');
  const display = process.env.DISPLAY ? process.env.DISPLAY : await startXvfb(stack);
  const dunstEnv = { ...stack.env.env, DISPLAY: display };
  const dunst = stack.env.spawnTracked(spawn, which('dunst'), ['-conf', conf], { env: dunstEnv, stdio: ['ignore', logFd, logFd], detached: true });
  fs.closeSync(logFd);
  let dunstExit = null;
  dunst.once('exit', (c, sig) => { dunstExit = { c, s: sig }; });
  const ctl = (...args) => run(which('dunstctl'), args, dunstEnv);
  await waitFor('dunst owns the notification name', async () => {
    if (dunstExit) throw new Error(`dunst exited (${JSON.stringify(dunstExit)}): ${fs.readFileSync(logPath, 'utf8').slice(-400)}`);
    return (await ctl('count', 'displayed')).code === 0;
  }, { timeoutMs: 15000 });
  return {
    ctl,
    menu: () => (fs.existsSync(menuFile) ? fs.readFileSync(menuFile, 'utf8') : ''),
    /** The summary and body of the notification dunst showed last (recorded by its script rule). */
    shown() {
      const [summary, ...body] = (fs.existsSync(shownFile) ? fs.readFileSync(shownFile, 'utf8') : '').split('\n');
      return { summary, body: body.join('\n').trim() };
    },
    stop() { try { process.kill(-dunst.pid, 'SIGTERM'); } catch { /* gone */ } },
  };
}

// Catalogue E2E-42 (local, optional): approval through a real notification server, `dunst`, driven with `dunstctl action`.
// The harness's notify double answers the other escalation scenarios; this one proves the prompt works against a server
// people actually run. dunst needs a display: the headed variants have Xvfb's, the others get an Xvfb of their own
// (the scenario fails if there is none); without dunst it skips (SKIP-OPT). The prompt has two actions, so `dunstctl action` opens dunst's context menu; the harness answers it
// through dunst's `dmenu` setting with a script that picks "Allow always", which is what a person would click.
// Port-only (axis-independent): exercises the real notification server (dunst), not the attach mode.
scenario({ id: 'E2E-42', title: 'real dunst: approval with `dunstctl action`', ci: false }, async ctx => {
  if (!which('dunst') || !which('dunstctl')) skipOptional('dunst/dunstctl are not installed');

  const stack = await ctx.stack({
    rps: { a: { host: 'rp-a.test' } }, profiles: { agent: requestProfile(['rp-a.test']) }, notify: false,
  });
  const rp = stack.rp.a;
  await stack.seedHuman(rp, 'alice');
  const dunst = await startDunst(stack, 'allow always');

  const b = await stack.open('agent', `${rp.origin}/sw`);
  assertInterceptionActive(b);
  const key = await start(b.page, 'authenticate', { username: 'alice' });

  // The prompt appears; the daemon accepts "Allow always" only 1 s after it was shown.
  await waitFor('dunst shows the escalation prompt', async () => Number((await dunst.ctl('count', 'displayed')).stdout.trim()) >= 1, { timeoutMs: 20000 });
  await sleep(1600);
  const act = await dunst.ctl('action', '0');
  assert.equal(act.code, 0, `dunstctl action failed: ${act.stderr}`);

  const result = await settle(b.page, key);
  assertVerifiedAssertion(rp, result, { username: 'alice' });
  assert.match(dunst.menu(), /Allow always/i, `dunst's context menu offered the daemon's action: ${dunst.menu()}`);
  assert.equal(escalationEvents(await stack.daemon.audit(), 'approved').length, 1, 'the approval came through dunst');
  assert.deepEqual(grantsStore(stack).grants.map(g => [g.rp_id, g.action, g.kind]), [['rp-a.test', 'authenticate', 'escalation']]);
  // The grant upgrades the rule: the next ceremony needs no prompt.
  assertVerifiedAssertion(rp, await authenticate(b.page, { username: 'alice' }), { username: 'alice' });
  assert.equal(Number((await dunst.ctl('count', 'displayed')).stdout.trim()), 0, 'no prompt is left on screen');
  dunst.stop();
});

// E2E-42/register (local, optional): the registration prompt against real dunst (amendment section 11.3). The summary says
// the passkey is being created, the menu offers "Register once" and "Deny" (never "Allow always"), and choosing "Register
// once" completes the registration; the credential lands in the human store and the grant is a registration grant.
scenario({ id: 'E2E-42/register', title: 'real dunst: a registration prompt approved with Register once', ci: false }, async ctx => {
  if (!which('dunst') || !which('dunstctl')) skipOptional('dunst/dunstctl are not installed');

  const stack = await ctx.stack({
    rps: { a: { host: 'rp-a.test' } },
    profiles: { agent: { mode: 'same-user', rules: [{ rp: 'rp-a.test', authenticate: 'allow', register: 'request' }] } },
    notify: false,
  });
  const rp = stack.rp.a;
  const dunst = await startDunst(stack, 'register once');
  const humanBefore = stack.daemon.humanStore().length;

  const b = await stack.open('agent', `${rp.origin}/raw`);
  assertInterceptionActive(b);
  await b.page.waitForFunction(() => window.e2e);
  const key = await start(b.page, 'register', { username: 'rae' });

  await waitFor('dunst shows the registration prompt', async () => Number((await dunst.ctl('count', 'displayed')).stdout.trim()) >= 1, { timeoutMs: 20000 });
  await waitFor('dunst to run its script rule for the prompt', () => dunst.shown().summary);
  assert.equal(dunst.shown().summary, REGISTER_SUMMARY, 'the summary says a passkey is being created, not a sign-in');
  assert.match(dunst.shown().body, /Site: rp-a\.test \(your rule for this site\)/);
  await sleep(1600);
  const act = await dunst.ctl('action', '0');
  assert.equal(act.code, 0, `dunstctl action failed: ${act.stderr}`);

  const result = await settle(b.page, key);
  assert.equal(result.ok, true, `the registration completes after Register once: ${JSON.stringify(result)}`);
  assert.match(dunst.menu(), /Register once/i, `dunst's context menu offered Register once: ${dunst.menu()}`);
  assert.match(dunst.menu(), /Deny/i);
  assert.doesNotMatch(dunst.menu(), /Allow always/i, `a registration prompt never offers "Allow always": ${dunst.menu()}`);
  assert.equal(stack.daemon.humanStore().length, humanBefore + 1, 'the credential is in the human store');
  const audit = await stack.daemon.audit();
  assert.equal(escalationEvents(audit, 'approved').length, 1, 'the approval came through dunst');
  assert.deepEqual(grantedRuleEvents(audit, 'add').map(e => [e.rp_id, e.grant_kind, e.rule]), [['rp-a.test', 'registration', 'exact']]);
  assert.equal(Number((await dunst.ctl('count', 'displayed')).stdout.trim()), 0, 'no prompt is left on screen');
  dunst.stop();
});
