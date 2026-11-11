'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { spawn, execFile } = require('node:child_process');

const { scenario, assert, skipOptional } = require('../lib/scenario');
const { grantsStore, authenticate, assertVerifiedAssertion, assertInterceptionActive, waitFor, escalationEvents } = require('../lib/helpers');
const { requestProfile, start, settle } = require('../lib/escalation');

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

// Catalogue E2E-42 (local, optional): approval through a real notification server, `dunst`, driven with `dunstctl action`.
// The harness's notify double answers the other escalation scenarios; this one proves the prompt works against a server
// people actually run. dunst needs a display: the headed variants have Xvfb's, the others get an Xvfb of their own
// (the scenario fails if there is none); without dunst it skips (SKIP-OPT). The prompt has two actions, so `dunstctl action` opens dunst's context menu; the harness answers it
// through dunst's `dmenu` setting with a script that picks "Allow always", which is what a person would click.
scenario({ id: 'E2E-42', title: 'real dunst: approval with `dunstctl action`', ci: false }, async ctx => {
  if (!which('dunst') || !which('dunstctl')) skipOptional('dunst/dunstctl are not installed');

  const stack = await ctx.stack({
    rps: { a: { host: 'rp-a.test' } }, profiles: { agent: requestProfile(['rp-a.test']) }, notify: false,
  });
  const rp = stack.rp.a;
  await stack.seedHuman(rp, 'alice');

  const dir = path.join(stack.env.dirs.work, 'dunst');
  fs.mkdirSync(dir, { recursive: true });
  const picker = path.join(dir, 'pick-allow-always.sh');
  fs.writeFileSync(picker, `#!/bin/sh\ncat > ${JSON.stringify(path.join(dir, 'menu.txt'))}\ngrep -i 'allow always' ${JSON.stringify(path.join(dir, 'menu.txt'))} | head -n 1\n`, { mode: 0o755 });
  const conf = path.join(dir, 'dunstrc');
  fs.writeFileSync(conf, `[global]\n    dmenu = ${picker}\n    follow = none\n    notification_limit = 5\n    idle_threshold = 0\n    sticky_history = no\n`);
  const logPath = path.join(dir, 'dunst.log');
  const logFd = fs.openSync(logPath, 'a');
  const display = process.env.DISPLAY ? process.env.DISPLAY : await startXvfb(stack);
  const dunstEnv = { ...stack.env.env, DISPLAY: display };
  const dunst = stack.env.spawnTracked(spawn, which('dunst'), ['-conf', conf], { env: dunstEnv, stdio: ['ignore', logFd, logFd], detached: true });
  fs.closeSync(logFd);
  let dunstExit = null;
  dunst.once('exit', (c, s) => { dunstExit = { c, s }; });
  const ctl = (...args) => run(which('dunstctl'), args, dunstEnv);
  await waitFor('dunst owns the notification name', async () => {
    if (dunstExit) throw new Error(`dunst exited (${JSON.stringify(dunstExit)}): ${fs.readFileSync(logPath, 'utf8').slice(-400)}`);
    return (await ctl('count', 'displayed')).code === 0;
  }, { timeoutMs: 15000 });

  const b = await stack.open('agent', `${rp.origin}/sw`);
  assertInterceptionActive(b);
  const key = await start(b.page, 'authenticate', { username: 'alice' });

  // The prompt appears; the daemon accepts "Allow always" only 1 s after it was shown.
  await waitFor('dunst shows the escalation prompt', async () => Number((await ctl('count', 'displayed')).stdout.trim()) >= 1, { timeoutMs: 20000 });
  await sleep(1600);
  const act = await ctl('action', '0');
  assert.equal(act.code, 0, `dunstctl action failed: ${act.stderr}`);

  const result = await settle(b.page, key);
  assertVerifiedAssertion(rp, result, { username: 'alice' });
  const menu = fs.existsSync(path.join(dir, 'menu.txt')) ? fs.readFileSync(path.join(dir, 'menu.txt'), 'utf8') : '';
  assert.match(menu, /Allow always/i, `dunst's context menu offered the daemon's action: ${menu}`);
  assert.equal(escalationEvents(await stack.daemon.audit(), 'approved').length, 1, 'the approval came through dunst');
  assert.deepEqual(grantsStore(stack).grants.map(g => [g.rp_id, g.action, g.kind]), [['rp-a.test', 'authenticate', 'escalation']]);
  // The grant upgrades the rule: the next ceremony needs no prompt.
  assertVerifiedAssertion(rp, await authenticate(b.page, { username: 'alice' }), { username: 'alice' });
  assert.equal(Number((await ctl('count', 'displayed')).stdout.trim()), 0, 'no prompt is left on screen');
  try { process.kill(-dunst.pid, 'SIGTERM'); } catch { /* gone */ }
});
