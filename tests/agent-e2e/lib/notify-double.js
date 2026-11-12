'use strict';
// Starts tools/notify-double on the private session bus and reads its JSON-lines log.

const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');

const { ensureBuilt } = require('./build');

const sleep = ms => new Promise(r => setTimeout(r, ms));

/**
 * @param {object} env  from createEnv()
 * @param {{script?: string[]}} opts  script steps, e.g. ['approve'], ['deny:200'], ['ignore'] (see
 *   tools/notify-double: approve (invokes the prompt's allow_always:<nonce> key)|deny|ignore|close|invoke=<key>, each with an
 *   optional :<delay_ms>)
 */
async function startNotifyDouble(env, opts = {}) {
  const bin = ensureBuilt().notifyDouble;
  // A restart (stack.restartNotify) is a new instance with its own log and ready file: `notify.jsonl`, then
  // `notify-2.jsonl`, ...
  env.notifyInstances = (env.notifyInstances || 0) + 1;
  const suffix = env.notifyInstances === 1 ? '' : `-${env.notifyInstances}`;
  const logFile = path.join(env.dirs.logs, `notify${suffix}.jsonl`);
  const readyFile = path.join(env.dirs.logs, `notify${suffix}.ready`);
  const args = ['--log', logFile, '--ready-file', readyFile];
  for (const s of opts.script || ['ignore']) args.push('--script', s);
  const stderrFile = path.join(env.dirs.logs, `notify${suffix}.stderr`);
  const err = fs.openSync(stderrFile, 'a');
  const child = env.spawnTracked(spawn, bin, args, { env: env.env, detached: true, stdio: ['ignore', 'ignore', err] });
  fs.closeSync(err);
  let exited = null;
  child.once('exit', (code, sig) => { exited = { code, sig }; });
  for (let i = 0; i < 100 && !fs.existsSync(readyFile); i++) {
    if (exited) break;
    await sleep(100);
  }
  if (!fs.existsSync(readyFile)) {
    throw new Error(`notify-double failed to start: ${exited ? JSON.stringify(exited) : 'timeout'}: ${fs.readFileSync(stderrFile, 'utf8').slice(-500)}`);
  }
  const uniqueName = fs.readFileSync(readyFile, 'utf8').trim();

  const events = () => {
    if (!fs.existsSync(logFile)) return [];
    return fs.readFileSync(logFile, 'utf8').split('\n').filter(Boolean).map(l => JSON.parse(l));
  };
  return {
    uniqueName, logFile,
    events,
    /** Every Notify call with its full arguments. */
    notifications: () => events().filter(e => e.event === 'Notify'),
    closes: () => events().filter(e => e.event === 'CloseNotification'),
    async waitForNotify(n = 1, timeoutMs = 10000) {
      const end = Date.now() + timeoutMs;
      while (Date.now() < end) { if (events().filter(e => e.event === 'Notify').length >= n) return true; await sleep(100); }
      return false;
    },
    /**
     * SIGTERM the double and wait for it to exit (it releases `org.freedesktop.Notifications` on the way out), falling
     * back to SIGKILL of its group. A new double started right after must not find the name still taken.
     */
    async stop(timeoutMs = 5000) {
      if (exited) return;
      try { process.kill(-child.pid, 'SIGTERM'); } catch { /* gone */ }
      const end = Date.now() + timeoutMs;
      while (!exited && Date.now() < end) await sleep(50);
      if (!exited) {
        try { process.kill(-child.pid, 'SIGKILL'); } catch { /* gone */ }
        for (let i = 0; i < 40 && !exited; i++) await sleep(50);
      }
    },
  };
}

module.exports = { startNotifyDouble };
