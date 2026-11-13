'use strict';
// Drivers for agent pre-requests (ADR 0014 amendment section 2.3): `passless agent request-access` as an agent runs it,
// outside any principal session (a fresh one is started for the call) or inside the one that owns the browser, and an
// owned browser to register in.
//
// A `register` approval binds to the principal session that owns the browser, so a scenario that registers needs an agent
// session of its own: `stack.openOwned(profile, url)` starts one (`passless agent run`) that launches the browser with
// `agent browser --wait` and then serves two kinds of line on a FIFO: `run:<script>` (what `session.cli(...)` writes) and,
// in pipe mode, browser-control requests (lib/pipe-driver.js). The same `session.cli` works on a pipe-mode `stack.open`.

const fs = require('node:fs');
const path = require('node:path');
const { execFile } = require('node:child_process');

const { waitFor } = require('./helpers');

const shq = s => `'${String(s).replace(/'/g, "'\\''")}'`;

/** The `request-access` arguments of a call (always `--json`). */
function accessArgs(rp, { register = false, note, wait = 30 } = {}) {
  const args = ['request-access', rp, '--json', '--wait', String(wait)];
  if (register) args.push('--register');
  if (note !== undefined) args.push('--note', note);
  return args;
}

/** What a request-access run printed: the exit code, the streams and the parsed `--json` object (null when it printed none). */
function parsed({ code, stdout, stderr }) {
  let status = null;
  try { status = JSON.parse(stdout.trim().split('\n').filter(Boolean).pop() || ''); } catch { /* not JSON: an error exit */ }
  return { code, stdout, stderr, status };
}

/**
 * `passless agent --profile P <args>` outside any principal session, as an agent's shell tool would run it. For
 * `request-access` the command then starts a principal session of its own for the call.
 */
function agentCli(stack, profile, args, { timeoutMs = 180000 } = {}) {
  return new Promise(resolve => {
    execFile(stack.daemon.bin, ['agent', '--profile', profile, ...args],
      { env: stack.daemon.cliEnv, cwd: stack.env.dirs.work, timeout: timeoutMs, maxBuffer: 16 * 1024 * 1024 },
      (error, stdout, stderr) => resolve({ code: error ? (error.code ?? 1) : 0, stdout, stderr }));
  });
}

/** `request-access` outside a principal session. */
const requestAccess = async (stack, profile, rp, opts = {}) => parsed(await agentCli(stack, profile, accessArgs(rp, opts)));

/**
 * A runner for scripts inside a principal session that serves `run:<script>` lines from `<dir>/requests`.
 * `cli(args)` is `passless agent --profile P <args>` inside that session; `requestAccess(rp, opts)` is `request-access`.
 */
function sessionRunner(stack, profile, dir) {
  let seq = 0;
  const fifo = path.join(dir, 'requests');
  async function sh(script, { timeoutMs = 180000 } = {}) {
    seq += 1;
    const file = path.join(dir, `run-${seq}.sh`);
    fs.writeFileSync(file, `PASSLESS=${shq(stack.daemon.bin)}\n${script}\n`, { mode: 0o700 });
    fs.appendFileSync(fifo, `run:${file}\n`);
    await waitFor(`the agent session to run ${path.basename(file)}`, () => fs.existsSync(`${file}.rc`), { timeoutMs, intervalMs: 50 });
    return {
      code: Number(fs.readFileSync(`${file}.rc`, 'utf8').trim()),
      stdout: fs.readFileSync(`${file}.out`, 'utf8'),
      stderr: fs.readFileSync(`${file}.err`, 'utf8'),
    };
  }
  const cli = (args, opts) => sh(`exec "$PASSLESS" agent --profile ${shq(profile)} ${args.map(shq).join(' ')}`, opts);
  return { dir, sh, cli, requestAccess: async (rp, opts = {}) => parsed(await cli(accessArgs(rp, opts))) };
}

/** Lines of a shell that ensures the browser of `P` into `$D` and serves the FIFO; `mode` is `port` or `pipe`. */
function ownedSessionScript(dir, profile, url, mode) {
  const q = s => JSON.stringify(String(s));
  const lines = [
    `D=${q(dir)}`, `P=${q(profile)}`, 'mkfifo "$D/requests"',
    `"$PASSLESS" agent browser --profile "$P" --wait ${mode === 'port' ? '--env ' : ''}${url ? `--url ${q(url)}` : ''} >"$D/browser.out" 2>&1; echo $? >"$D/browser.rc"`,
    '"$PASSLESS" agent browser-status --profile "$P" >"$D/status.json" 2>&1',
    'echo AGENT-READY',
  ];
  return lines.join('\n');
}

module.exports = { accessArgs, agentCli, requestAccess, sessionRunner, ownedSessionScript, parsed, shq };
