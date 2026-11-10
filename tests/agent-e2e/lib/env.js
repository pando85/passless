'use strict';
// Hermetic environment for one scenario run.
//
// Everything a scenario touches (HOME, XDG_*, PASSLESS_* paths, the human credential store, agent
// audit, runtime dir, browser profiles) lives under one temp root. The child environment is built
// from a small allow-list, never from process.env wholesale, and the harness refuses to run when a
// resolved path lands in the real user's config/state/data/runtime dirs or when the D-Bus session
// bus is not the private one created by run.sh.

const fs = require('node:fs');
const os = require('node:os');
const { execFileSync } = require('node:child_process');
const path = require('node:path');

const REAL_HOME = os.userInfo().homedir;
const REAL_UID = os.userInfo().uid;

// Captured at module load, before anything rewrites the environment.
const REAL_DIRS = [...new Set([
  process.env.XDG_CONFIG_HOME, process.env.XDG_STATE_HOME, process.env.XDG_DATA_HOME,
  process.env.XDG_RUNTIME_DIR,
  path.join(REAL_HOME, '.config'), path.join(REAL_HOME, '.local', 'state'),
  path.join(REAL_HOME, '.local', 'share'), path.join(REAL_HOME, '.password-store'),
  path.join(REAL_HOME, '.gnupg'), path.join(REAL_HOME, '.passless'),
  `/run/user/${REAL_UID}`,
].filter(Boolean).map(p => path.resolve(p)))];

function realpathLoose(p) {
  // Resolve symlinks in the deepest existing ancestor, then re-append the rest.
  let cur = path.resolve(p);
  const rest = [];
  while (!fs.existsSync(cur) && path.dirname(cur) !== cur) { rest.unshift(path.basename(cur)); cur = path.dirname(cur); }
  let real;
  try { real = fs.realpathSync(cur); } catch { real = cur; }
  return path.join(real, ...rest);
}

function isInside(child, parent) {
  const rel = path.relative(parent, child);
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
}

/** Throws when `p` resolves inside one of the real user's config/state/data/runtime dirs. */
function assertNotRealUserDir(p, what = 'path') {
  const real = realpathLoose(p);
  for (const dir of REAL_DIRS) {
    const realDir = realpathLoose(dir);
    // The temp root being a *parent* of nothing real is fine; only "inside" matters.
    if (isInside(real, realDir)) {
      throw new Error(`hermeticity violation: ${what} ${p} resolves to ${real}, inside real user dir ${realDir}`);
    }
  }
}

const PRIVATE_BUS_MARKER = 'AGENT_E2E_PRIVATE_BUS';

/**
 * The harness must run under run.sh's private `dbus-run-session`. run.sh exports the real session bus
 * address as AGENT_E2E_REAL_BUS before wrapping; refuse when the current bus is that one.
 */
function assertPrivateBus() {
  const addr = process.env.DBUS_SESSION_BUS_ADDRESS;
  if (process.env[PRIVATE_BUS_MARKER] !== '1' || !addr) {
    throw new Error('refusing to run: no private D-Bus session bus (use tests/agent-e2e/run.sh, which wraps dbus-run-session)');
  }
  const real = process.env.AGENT_E2E_REAL_BUS;
  if (real && (addr === real || addr.includes(real) || real.includes(addr))) {
    throw new Error(`refusing to run: DBUS_SESSION_BUS_ADDRESS is the real session bus (${addr})`);
  }
  return addr;
}

/** Direct and indirect children of `pid` (from /proc), deepest first. */
function descendants(pid) {
  const parents = new Map();
  for (const d of fs.readdirSync('/proc')) {
    if (!/^\d+$/.test(d)) continue;
    try {
      const stat = fs.readFileSync(`/proc/${d}/stat`, 'utf8');
      const ppid = Number(stat.slice(stat.lastIndexOf(')') + 2).split(' ')[1]);
      if (!parents.has(ppid)) parents.set(ppid, []);
      parents.get(ppid).push(Number(d));
    } catch { /* exited */ }
  }
  const out = [];
  const walk = p => { for (const c of parents.get(p) || []) { walk(c); out.push(c); } };
  walk(pid);
  return out;
}

/** SIGKILL a process, everything below it, and its process group. */
function killTree(pid) {
  if (!pid) return;
  for (const p of descendants(pid)) { try { process.kill(p, 'SIGKILL'); } catch { /* gone */ } }
  try { process.kill(-pid, 'SIGKILL'); } catch { /* not a group leader */ }
  try { process.kill(pid, 'SIGKILL'); } catch { /* gone */ }
}

/** PIDs whose command line mentions `needle` (leak detection only; never used to select what to kill by pattern). */
function processesMentioning(needle) {
  const out = [];
  for (const d of fs.readdirSync('/proc')) {
    if (!/^\d+$/.test(d) || Number(d) === process.pid) continue;
    try { if (fs.readFileSync(`/proc/${d}/cmdline`, 'utf8').includes(needle)) out.push(Number(d)); } catch { /* exited */ }
  }
  return out;
}

/** Well-known names currently owned on the private bus (via dbus-send); anything beyond the bus itself and notify-double is a bug. */
function busNames(childEnv) {
  const out = execFileSync('dbus-send', ['--session', '--print-reply', '--dest=org.freedesktop.DBus', '/org/freedesktop/DBus',
    'org.freedesktop.DBus.ListNames'], { encoding: 'utf8', env: childEnv });
  return out.split('\n').map(l => (l.match(/string "(.*)"/) || [])[1]).filter(n => n && !n.startsWith(':'));
}

const cleanups = [];
let handlersInstalled = false;
function installExitHandlers() {
  if (handlersInstalled) return;
  handlersInstalled = true;
  const run = () => { while (cleanups.length) { try { cleanups.pop()(); } catch { /* best effort */ } } };
  process.on('exit', run);
  for (const sig of ['SIGINT', 'SIGTERM', 'SIGHUP']) process.on(sig, () => { run(); process.exit(128); });
}

const ENV_PASSTHROUGH = ['PATH', 'LANG', 'LC_ALL', 'TZ', 'DISPLAY', 'XAUTHORITY', 'DBUS_SESSION_BUS_ADDRESS',
  PRIVATE_BUS_MARKER, 'AGENT_E2E_REAL_BUS', 'CARGO_TARGET_DIR'];

/**
 * Create a hermetic environment. Returns an object with the temp `root`, the child env (`env`),
 * well-known subdirectories, helper `spawnTracked`/`onCleanup`, and `cleanup()`.
 */
function createEnv(label = 'scenario') {
  assertPrivateBus();
  installExitHandlers();

  const base = process.env.AGENT_E2E_TMPDIR || os.tmpdir();
  assertNotRealUserDir(base, 'temp base');
  // Keep the root path short: unix socket paths (runtime dir) are limited to ~107 bytes.
  const root = fs.mkdtempSync(path.join(base, 'pl-e2e-'));
  fs.chmodSync(root, 0o700);
  assertNotRealUserDir(root, 'temp root');

  const dirs = {};
  for (const d of ['home', 'config', 'state', 'data', 'cache', 'run', 'store', 'audit', 'work', 'logs', 'bin']) {
    dirs[d] = path.join(root, d);
    fs.mkdirSync(dirs[d], { mode: 0o700 });
    assertNotRealUserDir(dirs[d], `dir ${d}`);
  }

  const env = {};
  for (const k of ENV_PASSTHROUGH) if (process.env[k] !== undefined) env[k] = process.env[k];
  Object.assign(env, {
    HOME: dirs.home,
    XDG_CONFIG_HOME: dirs.config,
    XDG_STATE_HOME: dirs.state,
    XDG_DATA_HOME: dirs.data,
    XDG_CACHE_HOME: dirs.cache,
    XDG_RUNTIME_DIR: dirs.run,
    TMPDIR: dirs.work,
    // Never let a child (e.g. @playwright/mcp) fall back to the shared ~/.cache/ms-playwright.
    PLAYWRIGHT_BROWSERS_PATH: path.join(require('./paths').CACHE_DIR, 'ms-playwright'),
    PASSLESS_CONFIG: path.join(dirs.config, 'passless', 'config.toml'),
    PASSLESS_BACKEND_TYPE: 'local',
    PASSLESS_LOCAL_PATH: dirs.store,
    PASSLESS_LOG_LEVEL: 'debug',
    PASSLESS_LOG_STYLE: 'never',
  });
  for (const [k, v] of Object.entries(env)) {
    if (/^(HOME|XDG_.*|PASSLESS_(CONFIG|LOCAL_PATH))$/.test(k)) assertNotRealUserDir(v, k);
  }

  const children = new Set();
  const extraPids = new Set(); // e.g. the browser pid reported by the daemon
  let cleaned = false;

  const handle = {
    label, root, dirs, env,
    /** Spawn a child in its own process group; the whole group/tree is killed on cleanup. */
    spawnTracked(spawnFn, bin, args, opts = {}) {
      const child = spawnFn(bin, args, { ...opts, detached: true });
      children.add(child);
      child.once('exit', () => children.delete(child));
      return child;
    },
    /** Track an externally started process (daemon-reported browser pid). */
    trackPid(pid) { if (pid) extraPids.add(pid); },
    onCleanup(fn) { cleanups.push(fn); },
    killTree,
    /** Synchronous kill of everything this run started. */
    killAll() {
      for (const c of children) killTree(c.pid);
      for (const p of extraPids) killTree(p);
      children.clear();
      extraPids.clear();
    },
    /** Copy logs worth keeping (on failure) to `dest`. */
    saveArtifacts(dest) {
      fs.mkdirSync(dest, { recursive: true });
      for (const sub of ['logs', 'audit']) {
        try { fs.cpSync(dirs[sub], path.join(dest, sub), { recursive: true }); } catch { /* optional */ }
      }
    },
    /** Kills tracked processes, removes the root, returns PIDs still mentioning the root (leaks). */
    cleanup() {
      if (cleaned) return [];
      cleaned = true;
      handle.killAll();
      // Verification, not selection: anything left was not reachable through tracked groups/trees.
      // Helpers such as Chromium's crashpad handler exit on their own once the browser is gone; give them a
      // moment before calling anything a leak.
      let leaks = processesMentioning(root);
      for (let i = 0; i < 30 && leaks.length; i++) { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 100); leaks = processesMentioning(root); }
      const described = leaks.map(p => { try { return `${p}:${fs.readFileSync(`/proc/${p}/cmdline`, 'utf8').split('\0').slice(0, 3).join(' ').slice(0, 120)}`; } catch { return String(p); } });
      for (const p of leaks) { try { process.kill(p, 'SIGKILL'); } catch { /* gone */ } }
      if (process.env.AGENT_E2E_KEEP === '1') { process.stderr.write(`[env] keeping ${root}\n`); return described; }
      try { fs.rmSync(root, { recursive: true, force: true }); } catch { /* best effort */ }
      return described;
    },
  };
  cleanups.push(() => handle.cleanup());
  return handle;
}

module.exports = { busNames, createEnv, killTree, descendants, processesMentioning, assertNotRealUserDir, assertPrivateBus, REAL_HOME, REAL_DIRS, PRIVATE_BUS_MARKER };
