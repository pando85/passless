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
 *   tools/notify-double: approve (invokes allow_always)|deny|ignore|close|invoke=<key>, each with an
 *   optional :<delay_ms>)
 */
async function startNotifyDouble(env, opts = {}) {
  const bin = ensureBuilt().notifyDouble;
  const logFile = path.join(env.dirs.logs, 'notify.jsonl');
  const readyFile = path.join(env.dirs.logs, 'notify.ready');
  const args = ['--log', logFile, '--ready-file', readyFile];
  for (const s of opts.script || ['ignore']) args.push('--script', s);
  const stderrFile = path.join(env.dirs.logs, 'notify.stderr');
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
    stop() { try { process.kill(-child.pid, 'SIGTERM'); } catch { /* gone */ } },
  };
}

module.exports = { startNotifyDouble };
