'use strict';
// Drivers for the agent-browser "easy path" (ADR 0014 D4): `passless agent mcp playwright|chrome-devtools` as an MCP
// client would start it, and `passless agent browser` inside a principal session. They run the real CLI against the
// scenario's daemon; only npx is replaced by tests/agent-e2e/bin/npx, which runs the copy package.json pins (no
// network, no registry).

const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');

const { McpClient } = require('./mcp-client');
const { HARNESS_ROOT } = require('./paths');

const NPX_SHIM = path.join(HARNESS_ROOT, 'bin', 'npx');
const ADAPTERS = ['playwright', 'chrome-devtools'];

const sleep = ms => new Promise(r => setTimeout(r, ms));
const shq = s => `'${String(s).replace(/'/g, "'\\''")}'`;

/**
 * @param {object} stack
 * @param {'playwright'|'chrome-devtools'} kind
 * @param {{profile: string, flags?: string[], extra?: string[]}} o  `flags` go before `--`, `extra` after it (to the MCP server)
 */
function startAdapter(stack, kind, { profile, flags = [], extra = [], defaultNpx = false }) {
  if (!ADAPTERS.includes(kind)) throw new Error(`unknown adapter ${kind}`);
  const daemon = stack.daemon;
  let env = daemon.cliEnv;
  let npxArgs = ['--npx', NPX_SHIM];
  let shimDir = null;
  if (defaultNpx) {
    // As a real client config would: no --npx, `npx` found on the client's PATH.
    shimDir = path.join(stack.env.dirs.work, 'npx-on-path');
    fs.mkdirSync(shimDir, { recursive: true });
    const link = path.join(shimDir, 'npx');
    if (!fs.existsSync(link)) fs.symlinkSync(NPX_SHIM, link);
    env = { ...env, PATH: `${shimDir}:${env.PATH}` };
    npxArgs = [];
  }
  const args = ['agent', 'mcp', kind, '--profile', profile, ...npxArgs, ...flags, ...(extra.length ? ['--', ...extra] : [])];
  const client = McpClient.start({ command: daemon.bin, args, env, cwd: stack.env.dirs.work });
  const log = path.join(stack.env.dirs.logs, 'npx.jsonl');
  return {
    client, kind, args, shimDir,
    /** Argv of every npx invocation of this run (bearer values redacted), oldest first. */
    npxCalls: () => (fs.existsSync(log) ? fs.readFileSync(log, 'utf8').split('\n').filter(Boolean).map(l => JSON.parse(l)) : []),
    /** The `PLAYWRIGHT_MCP_CDP_HEADERS` value of every npx invocation (bearer redacted; null when the variable was absent). */
    npxCdpHeaders: () => (fs.existsSync(`${log}.headers`) ? fs.readFileSync(`${log}.headers`, 'utf8').split('\n').filter(Boolean).map(l => JSON.parse(l)) : []),
    /** The first PATH entry of every npx invocation (what the adapter forwarded). */
    npxPathHeads: () => (fs.existsSync(`${log}.path`) ? fs.readFileSync(`${log}.path`, 'utf8').split('\n').filter(Boolean) : []),
    close: () => client.close(),
  };
}

/**
 * An agent as the product runs one: `passless agent run --profile P -- /bin/bash -c <script>` starts a principal
 * session whose child (the script) holds the capability descriptor, so `passless agent browser` works inside it and the
 * browser lives as long as the session. `$PASSLESS` in the script is the passless binary. `close()` ends the session
 * (the client gets SIGTERM and revokes it).
 */
function startPrincipalShell(stack, profile, script) {
  // The daemon caps every argv element at 256 bytes, so the script goes into a file.
  const file = path.join(stack.env.dirs.work, `agent-session-${Date.now()}.sh`);
  fs.writeFileSync(file, `PASSLESS=${shq(stack.daemon.bin)}\n${script}\n`, { mode: 0o700 });
  const child = spawn(stack.daemon.bin, ['agent', 'run', '--profile', profile, '--', '/bin/bash', file], {
    env: stack.daemon.cliEnv, cwd: stack.env.dirs.work, stdio: ['ignore', 'pipe', 'pipe'], detached: true,
  });
  const out = { stdout: '', stderr: '', exited: null };
  child.stdout.on('data', d => { out.stdout += d; });
  child.stderr.on('data', d => { out.stderr += d; });
  child.on('exit', (code, sig) => { out.exited = { code, sig }; });
  return {
    out,
    lines: () => out.stdout.split('\n').filter(Boolean),
    async waitForLine(re, timeoutMs = 120000) {
      const end = Date.now() + timeoutMs;
      for (;;) {
        const hit = out.stdout.split('\n').find(l => re.test(l));
        if (hit) return hit;
        if (out.exited) throw new Error(`the principal session exited (${JSON.stringify(out.exited)}) before ${re}: stdout=${out.stdout.slice(-400)} stderr=${out.stderr.slice(-600)}`);
        if (Date.now() > end) throw new Error(`no line matching ${re} within ${timeoutMs} ms: stdout=${out.stdout.slice(-400)} stderr=${out.stderr.slice(-600)}`);
        await sleep(100);
      }
    },
    async close() {
      try { process.kill(child.pid, 'SIGTERM'); } catch { /* gone */ }
      for (let i = 0; i < 100 && !out.exited; i++) await sleep(100);
      try { process.kill(-child.pid, 'SIGKILL'); } catch { /* gone */ }
    },
  };
}

/**
 * An agent session that has run `passless agent browser --env --wait`: returns {url, agent} (`url` is PASSLESS_CDP_URL).
 * `agent.close()` ends the session and with it the browser.
 */
async function startAgentBrowser(stack, profile) {
  const agent = startPrincipalShell(stack, profile, `"$PASSLESS" agent browser --profile ${profile} --env --wait && echo AGENT-READY; exec sleep 900`);
  try {
    await agent.waitForLine(/^AGENT-READY$/);
  } catch (e) { await agent.close(); throw e; }
  const line = agent.lines().find(l => l.startsWith('PASSLESS_CDP_URL='));
  return { url: line.slice('PASSLESS_CDP_URL='.length), agent };
}

/** The text of an MCP tool result. */
const toolText = res => (res.content || []).filter(c => c.type === 'text').map(c => c.text).join('\n');

/** The JSON a page function returned through a Playwright MCP `browser_evaluate` ("### Result" section) or chrome-devtools `evaluate_script` (a fenced json block). */
function evalJson(res) {
  const text = toolText(res);
  if (res.isError) throw new Error(`tool error: ${text.slice(0, 400)}`);
  const m = text.match(/### Result\s*\n([\s\S]*?)(?:\n###|$)/) || text.match(/```json\s*\n([\s\S]*?)\n```/);
  const body = (m ? m[1] : text).trim();
  let value = JSON.parse(body);
  if (typeof value === 'string') { try { value = JSON.parse(value); } catch { /* a plain string */ } }
  return value;
}

/** Page function source that authenticates `username` through the RP page helper and returns the helper's result as JSON. */
const authenticateFn = username =>
  `async () => { await new Promise(r => { const t = setInterval(() => { if (window.e2e) { clearInterval(t); r(); } }, 50); }); return JSON.stringify(await window.e2e.authenticate({ username: ${JSON.stringify(username)}, userVerification: 'preferred', timeout: 20000 })); }`;

/** PIDs of browser processes of this run (a managed browser has `--user-data-dir` under the run's temp root). */
function browserProcesses(stack, processesMentioning) {
  const cmdline = pid => { try { return fs.readFileSync(`/proc/${pid}/cmdline`, 'utf8'); } catch { return ''; } };
  return processesMentioning(stack.env.root).filter(pid => /--user-data-dir=/.test(cmdline(pid)) && /--remote-debugging/.test(cmdline(pid)));
}

module.exports = { startAdapter, startPrincipalShell, startAgentBrowser, NPX_SHIM, toolText, evalJson, authenticateFn, browserProcesses };
