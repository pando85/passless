'use strict';
// Starts the passless daemon (agent runtime enabled) against the hermetic env, writes the per-scenario
// agent config in the ADR 0014 schema (rules with `deny` / `allow` / `request` per action), launches the
// managed browser through the product's own `passless agent-admin browser launch`, and collects logs
// and the audit log.

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawn, execFile } = require('node:child_process');

const { ensureBuilt } = require('./build');

const sleep = ms => new Promise(r => setTimeout(r, ms));

const RULE_ACTIONS = ['deny', 'allow', 'request'];

class DaemonStartError extends Error {}

const q = s => JSON.stringify(String(s));
function tomlValue(v) {
  if (typeof v === 'string') return q(v);
  if (typeof v === 'number' || typeof v === 'boolean') return String(v);
  if (Array.isArray(v)) return `[${v.map(tomlValue).join(', ')}]`;
  throw new Error(`unsupported toml value ${v}`);
}

/**
 * @param {object} env
 * @param {object} o
 * @param {Object<string,object>} o.profiles  name -> {mode, rules:[{rp, authenticate, register, credential_selection}],
 *        credential_selection, max_operations, legacyDevice, extra:{...raw profile keys},
 *        legacyRules:[{rp, authenticate, register}] (raw TOML expressions, written verbatim: legacy vocabulary
 *        such as '"autonomous"' or '{ authorization = "confirm", ... }')}
 * `*` rules (same-user only) get the profile listed in `acknowledge_global_same_user` automatically.
 * @param {string[]} [o.browserArgs]  extra browser flags (variant + TLS), put after the executable
 * @param {string} o.browserExe
 * @param {object} [o.limits]  `[agents.limits]` keys
 * @param {object} [o.agents]  extra raw `[agents]` keys (`escalation_cooldown`, `escalation_timeout`, `state_dir`, ...)
 * @param {boolean} [o.noBrowserCommand]  write no `browser_command` (the daemon chooses the browser)
 * @param {string} [o.browserScope]  `browser_scope` of every profile (default "profile", see below)
 * Per profile: `max_granted_rules`, `cdpExpose` (`'pipe'` for pipe mode; port mode otherwise).
 */
function renderConfig(env, o) {
  const user = os.userInfo().username;
  const lines = [];
  lines.push('[local]', `path = ${q(env.dirs.store)}`, '');
  const sameUserRegisterAck = [];
  const globalAck = [];
  const profileBlocks = [];
  for (const [name, p] of Object.entries(o.profiles)) {
    const mode = p.mode || 'same-user';
    const b = [];
    b.push(`[agents.profiles.${name}]`);
    b.push(`mode = ${q(mode)}`, `principal_user = ${q(user)}`);
    b.push(`max_operations = ${p.max_operations || 16}`, `max_session_ttl = ${p.max_session_ttl || 300}`);
    if (p.max_granted_rules !== undefined) b.push(`max_granted_rules = ${p.max_granted_rules}`);
    if (p.credential_selection) b.push(`credential_selection = ${q(p.credential_selection)}`);
    // `noBrowserCommand`: the profile sets none, so the daemon picks the binary (`agents.browser_path`, else detection; E2E-41).
    if (!o.noBrowserCommand) b.push(`browser_command = ${tomlValue([o.browserExe, ...(o.browserArgs || [])])}`);
    // Isolated profiles take browser_runtime_root too (defect B7, fixed in P10b).
    b.push(`browser_runtime_root = ${q(path.join(env.dirs.run, 'browser'))}`);
    // browser_scope = "profile" by default: it was the only scope that survived its launch before defect B1 was
    // fixed in P10 (PR_SET_PDEATHSIG follows the thread that forked the browser, which was the short-lived IPC
    // handler thread). The daemon now forks browsers on a long-lived launcher thread; E2E-46/session-scope runs
    // `browserScope: 'session'` as the B1 regression.
    b.push(`browser_scope = ${q(o.browserScope || 'profile')}`);
    // `cdpExpose: 'pipe'` (E2E-52): CDP only through the daemon's `browser-control`; the default is port mode, which
    // the Playwright-driven scenarios connect to.
    if (p.cdpExpose === 'pipe') b.push('browser_cdp_expose = "pipe"');
    else b.push('browser_cdp_expose = "port"', 'browser_cdp_port = 0');
    if (mode === 'isolated') {
      const base = path.join(env.dirs.work, 'iso', name);
      fs.mkdirSync(path.join(base, 'credentials'), { recursive: true, mode: 0o700 });
      fs.mkdirSync(path.join(base, 'pin'), { recursive: true, mode: 0o700 });
      b.push('');
      b.push(`[agents.profiles.${name}.storage.local]`, `path = ${q(path.join(base, 'credentials'))}`, `pin_path = ${q(path.join(base, 'pin'))}`);
    }
    // No `[device]` table: agents have no UHID route (ADR 0014 section 5). `legacyDevice: true` writes the old
    // table anyway to prove it is warned about and ignored (R6).
    if (p.legacyDevice) {
      b.push('', `[agents.profiles.${name}.device]`, `name = ${q(`legacy-${name}`)}`, `phys = ${q(`legacy-${name}-phys`)}`,
        `uniq = ${q(`legacy-${name}-uniq`)}`, 'vendor_id = 4660', 'product_id = 22136');
    }
    for (const r of p.rules || []) {
      const reg = r.register || 'deny';
      const auth = r.authenticate || 'deny';
      if (!RULE_ACTIONS.includes(reg) || !RULE_ACTIONS.includes(auth)) throw new Error(`bad rule action in ${JSON.stringify(r)}`);
      b.push('', `[[agents.profiles.${name}.rules]]`, `rp_id = ${q(r.rp)}`, `authenticate = ${q(auth)}`, `register = ${q(reg)}`);
      if (r.credential_selection) b.push(`credential_selection = ${q(r.credential_selection)}`);
      if (mode === 'same-user' && reg !== 'deny' && !sameUserRegisterAck.includes(name)) sameUserRegisterAck.push(name);
      if (mode === 'same-user' && r.rp === '*' && !globalAck.includes(name)) globalAck.push(name);
    }
    for (const r of p.legacyRules || []) {
      if (mode === 'same-user' && r.register !== '"deny"' && !sameUserRegisterAck.includes(name)) sameUserRegisterAck.push(name);
      b.push('', `[[agents.profiles.${name}.rules]]`, `rp_id = ${q(r.rp)}`, `authenticate = ${r.authenticate}`, `register = ${r.register}`);
    }
    for (const [k, v] of Object.entries(p.extra || {})) b.splice(2, 0, `${k} = ${tomlValue(v)}`);
    profileBlocks.push(b.join('\n'));
  }
  lines.push('[agents]', 'enabled = true', `audit_path = ${q(env.dirs.audit)}`);
  if (globalAck.length) lines.push(`acknowledge_global_same_user = ${tomlValue(globalAck)}`);
  if (sameUserRegisterAck.length) lines.push(`acknowledge_same_user_registration = ${tomlValue(sameUserRegisterAck)}`);
  // Escalation keys (P7): `escalation_cooldown` (seconds; 1 is accepted by debug builds), `escalation_timeout` (seconds),
  // `state_dir` (absolute; default `$XDG_STATE_HOME/passless/agent`, inside the temp root here).
  for (const [k, v] of Object.entries(o.agents || {})) lines.push(`${k} = ${tomlValue(v)}`);
  // Request caps (plan R11), e.g. {max_requests_per_connection: 8}; omitted keys keep the daemon defaults.
  if (o.limits) {
    lines.push('', '[agents.limits]');
    for (const [k, v] of Object.entries(o.limits)) lines.push(`${k} = ${tomlValue(v)}`);
  }
  lines.push('', profileBlocks.join('\n\n'), '');
  return lines.join('\n');
}

function run(bin, args, env, timeout = 60000) {
  return new Promise(resolve => {
    execFile(bin, args, { env, timeout, maxBuffer: 16 * 1024 * 1024 }, (error, stdout, stderr) => {
      resolve({ code: error ? (error.code ?? 1) : 0, stdout, stderr });
    });
  });
}

/** hidraw nodes currently present, with the HID_* identity from sysfs. */
function hidrawNodes() {
  const out = new Map();
  let names = [];
  try { names = fs.readdirSync('/sys/class/hidraw'); } catch { return out; }
  for (const n of names) {
    let uevent = '';
    try { uevent = fs.readFileSync(`/sys/class/hidraw/${n}/device/uevent`, 'utf8'); } catch { /* raced */ }
    const get = k => (uevent.match(new RegExp(`^${k}=(.*)$`, 'm')) || [])[1] || '';
    out.set(n, { node: `/dev/${n}`, name: get('HID_NAME'), phys: get('HID_PHYS'), uniq: get('HID_UNIQ') });
  }
  return out;
}

// The human UHID identity as reported by sysfs (HID_NAME / HID_PHYS) for the daemon's human device.
const HUMAN_DEVICE = { name: 'Virtual FIDO2 Authenticator', phys: 'virtual-fido' };

/**
 * Identify THIS daemon's human hidraw node: a node that did not exist before the daemon started and
 * whose sysfs identity is the human UHID device. Returns {node} or {error} (ambiguous or not found).
 */
async function identifyHumanHidraw(before, timeoutMs = 8000) {
  const end = Date.now() + timeoutMs;
  let candidates = [];
  while (Date.now() < end) {
    candidates = [...hidrawNodes()].filter(([n, d]) => !before.has(n) && d.name === HUMAN_DEVICE.name && d.phys === HUMAN_DEVICE.phys);
    if (candidates.length) { await sleep(300); break; } // let a concurrent instance's node show up too
    await sleep(100);
  }
  candidates = [...hidrawNodes()].filter(([n, d]) => !before.has(n) && d.name === HUMAN_DEVICE.name && d.phys === HUMAN_DEVICE.phys);
  if (candidates.length === 1) return { node: candidates[0][1].node };
  if (candidates.length === 0) {
    const fresh = [...hidrawNodes()].filter(([n]) => !before.has(n)).map(([, d]) => `${d.node} name=${JSON.stringify(d.name)} phys=${JSON.stringify(d.phys)}`);
    return { error: `no new hidraw node with the human UHID identity (${JSON.stringify(HUMAN_DEVICE)}) appeared after the daemon started; new nodes: ${fresh.join('; ') || 'none'}` };
  }
  return { error: `ambiguous: ${candidates.length} new hidraw nodes (${candidates.map(c => c[1].node).join(', ')}) match the human UHID identity; another Passless instance started concurrently` };
}

function walkFiles(dir) {
  const out = [];
  if (!fs.existsSync(dir)) return out;
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) out.push(...walkFiles(p)); else out.push(p);
  }
  return out;
}

/**
 * Start the daemon. Throws DaemonStartError (with the relevant log lines) when the process exits or
 * the agent subsystem does not come up.
 */
async function startDaemon(env, o) {
  const bins = ensureBuilt();
  const configText = renderConfig(env, o);
  const configPath = env.env.PASSLESS_CONFIG;
  fs.mkdirSync(path.dirname(configPath), { recursive: true, mode: 0o700 });
  fs.writeFileSync(configPath, configText, { mode: 0o600 });
  fs.mkdirSync(path.join(env.dirs.run, 'browser'), { recursive: true, mode: 0o700 });
  fs.mkdirSync(path.join(env.dirs.run, 'passless', 'browser'), { recursive: true, mode: 0o700 }); // default root for isolated profiles

  const childEnv = {
    ...env.env,
    PASSLESS_E2E_AUTO_ACCEPT_UV: '1',
    PASSLESS_E2E_AUTO_ACCEPT_STORAGE: '1',
    ...(o.env || {}),
  };
  const hidrawBefore = new Set(hidrawNodes().keys());
  const logFile = path.join(env.dirs.logs, 'daemon.log');
  const logStart = fs.existsSync(logFile) ? fs.statSync(logFile).size : 0; // restarts append to the same file
  const out = fs.openSync(logFile, 'a');
  const child = env.spawnTracked(spawn, bins.passless,
    ['--config-path', configPath, '--backend-type', 'local', '--local-path', env.dirs.store, '--always-uv=false'],
    { env: childEnv, detached: true, stdio: ['ignore', out, out] });
  fs.closeSync(out);
  let exited = null;
  child.once('exit', (code, sig) => { exited = { code, sig }; });

  const readLog = () => (fs.existsSync(logFile) ? fs.readFileSync(logFile).subarray(logStart).toString('utf8') : '');
  const tail = () => readLog().split('\n').filter(l => /WARN|ERROR|failed|Error/.test(l)).slice(-6).join('\n');
  try {
    const deadline = Date.now() + 45000;
    for (;;) {
      const log = readLog();
      if (exited) {
        const why = (log.match(/Configuration error: .*/) || [tail().split('\n').pop() || 'no error logged'])[0];
        throw new DaemonStartError(`daemon exited early (code ${exited.code ?? exited.sig}): ${why}\n${tail()}`);
      }
      if (/Agent subsystem failed to start/.test(log)) {
        throw new DaemonStartError(`agent subsystem failed to start: ${log.split('\n').find(l => /Agent subsystem failed/.test(l))}`);
      }
      if (/Agent runtime loop started/.test(log) && /Authenticator is running/.test(log)) break;
      if (Date.now() > deadline) throw new DaemonStartError(`daemon not ready within 45s\n${tail()}`);
      await sleep(150);
    }

  } catch (e) {
    env.killTree(child.pid);
    throw e;
  }
  const human = await identifyHumanHidraw(hidrawBefore);

  const admin = (...args) => run(bins.passless, ['agent-admin', '--output', 'json', ...args], childEnv);
  const adminJson = async (...args) => {
    const r = await admin(...args);
    if (r.code !== 0) throw new Error(`agent-admin ${args.join(' ')} failed (${r.code}): ${r.stderr || r.stdout}`);
    return JSON.parse(r.stdout).data;
  };

  const daemon = {
    logFile, configPath, pid: child.pid,
    /** The passless binary and the environment the daemon runs with (CLI clients use the same runtime dir and config). */
    bin: bins.passless, cliEnv: childEnv,
    /** This daemon's own human hidraw node (or why it could not be identified). */
    hidraw: human.node || null, hidrawError: human.error || null,
    log: readLog,
    admin, adminJson,
    /** Launch the managed browser for a profile through the product path. */
    async launchBrowser(profile, startUrl) {
      const args = ['browser', 'launch', '--profile', profile];
      if (startUrl) args.push('--url', startUrl);
      const info = await adminJson(...args);
      if (!info.cdp_endpoint) throw new Error(`browser launch returned no cdp_endpoint: ${JSON.stringify(info)}`);
      env.trackPid(info.pid);
      const port = new URL(info.cdp_endpoint).port;
      return { ...info, cdpWs: info.cdp_endpoint, cdpUrl: `http://127.0.0.1:${port}` };
    },
    async audit() {
      const r = await adminJson('audit', 'export', '--format', 'json');
      const lines = fs.readFileSync(r.path, 'utf8').split('\n').filter(Boolean);
      return lines.map(l => JSON.parse(l));
    },
    auditStatus: () => adminJson('audit', 'status'),
    /** Credential files in the human store, with content hashes (used to prove nothing was touched). */
    humanStore() {
      return walkFiles(env.dirs.store).filter(f => f.endsWith('.bin'))
        .map(f => ({ file: path.relative(env.dirs.store, f), sha: crypto.createHash('sha256').update(fs.readFileSync(f)).digest('hex') }));
    },
    /** Credential files in an isolated profile's store. */
    profileStore(profile) {
      const dir = path.join(env.dirs.work, 'iso', profile, 'credentials');
      return walkFiles(dir).filter(f => f.endsWith('.bin')).map(f => path.relative(dir, f));
    },
    async stop() {
      try { process.kill(-child.pid, 'SIGTERM'); } catch { /* gone */ }
      for (let i = 0; i < 60 && !exited; i++) await sleep(100);
      env.killTree(child.pid);
    },
  };
  return daemon;
}

module.exports = { startDaemon, renderConfig, DaemonStartError };
