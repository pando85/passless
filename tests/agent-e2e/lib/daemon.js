'use strict';
// Starts the passless daemon (agent runtime enabled) against the hermetic env, writes the per-scenario
// agent config in today's schema, launches the managed browser through the product's own
// `passless agent-admin browser launch`, and collects logs and the audit log.
//
// Scenarios describe policy with ADR 0014 vocabulary (`allow` / `deny` / `request`); RULE_ACTION maps
// that onto today's config strings. P4 replaces this table with the new schema.

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawn, execFile } = require('node:child_process');

const { ensureBuilt } = require('./build');

const sleep = ms => new Promise(r => setTimeout(r, ms));

// ADR action -> today's alias. `request` has no equivalent before P7; `supervised` (human prompt via
// the trusted notification) is the closest, and is what `confirm` maps to.
const RULE_ACTION = { allow: 'autonomous', deny: 'deny', request: 'supervised' };

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
 *        credential_selection, max_operations, extra:{...raw profile keys}}
 * @param {string[]} [o.browserArgs]  extra browser flags (variant + TLS), put after the executable
 * @param {string} o.browserExe
 */
function renderConfig(env, o) {
  const user = os.userInfo().username;
  const lines = [];
  lines.push('[local]', `path = ${q(env.dirs.store)}`, '');
  const sameUserRegisterAck = [];
  const profileBlocks = [];
  for (const [name, p] of Object.entries(o.profiles)) {
    const mode = p.mode || 'same-user';
    const b = [];
    b.push(`[agents.profiles.${name}]`);
    b.push(`mode = ${q(mode)}`, `principal_user = ${q(user)}`);
    b.push(`max_operations = ${p.max_operations || 16}`, `max_session_ttl = ${p.max_session_ttl || 300}`);
    if (p.credential_selection) b.push(`credential_selection = ${q(p.credential_selection)}`);
    b.push(`browser_command = ${tomlValue([o.browserExe, ...(o.browserArgs || [])])}`);
    // Isolated profiles must not set browser_runtime_root; the daemon then uses $XDG_RUNTIME_DIR/passless/browser.
    if (mode === 'same-user') b.push(`browser_runtime_root = ${q(path.join(env.dirs.run, 'browser'))}`);
    // browser_scope = "profile": with the default "session" scope the browser gets PR_SET_PDEATHSIG, which
    // Linux delivers when the *thread* that spawned it exits, i.e. the short-lived IPC handler thread of
    // `agent-admin browser launch`. The browser would be SIGTERMed right after launch (baseline finding).
    b.push('browser_scope = "profile"', 'browser_cdp_expose = "port"', 'browser_cdp_port = 0');
    // Every profile needs a unique device identity: same-user profiles with the default identity
    // collide with each other ("device identity collides with another profile").
    const rnd = crypto.randomBytes(4).toString('hex');
    if (mode === 'isolated') {
      const base = path.join(env.dirs.work, 'iso', name);
      fs.mkdirSync(path.join(base, 'credentials'), { recursive: true, mode: 0o700 });
      fs.mkdirSync(path.join(base, 'pin'), { recursive: true, mode: 0o700 });
      b.push('');
      b.push(`[agents.profiles.${name}.storage.local]`, `path = ${q(path.join(base, 'credentials'))}`, `pin_path = ${q(path.join(base, 'pin'))}`);
    }
    b.push('', `[agents.profiles.${name}.device]`, `name = ${q(`e2e-${name}-${rnd}`)}`, `phys = ${q(`e2e-${name}-${rnd}-phys`)}`,
      `uniq = ${q(`e2e-${name}-${rnd}-uniq`)}`, 'vendor_id = 4660', 'product_id = 22136');
    for (const r of p.rules || []) {
      const reg = RULE_ACTION[r.register || 'deny'];
      const auth = RULE_ACTION[r.authenticate || 'deny'];
      if (!reg || !auth) throw new Error(`bad rule action in ${JSON.stringify(r)}`);
      b.push('', `[[agents.profiles.${name}.rules]]`, `rp_id = ${q(r.rp)}`, `authenticate = ${q(auth)}`, `register = ${q(reg)}`);
      if (r.credential_selection) b.push(`credential_selection = ${q(r.credential_selection)}`);
      if (mode === 'same-user' && reg !== 'deny' && !sameUserRegisterAck.includes(name)) sameUserRegisterAck.push(name);
    }
    for (const [k, v] of Object.entries(p.extra || {})) b.splice(2, 0, `${k} = ${tomlValue(v)}`);
    profileBlocks.push(b.join('\n'));
  }
  lines.push('[agents]', 'enabled = true', `audit_path = ${q(env.dirs.audit)}`);
  if (sameUserRegisterAck.length) lines.push(`acknowledge_same_user_registration = ${tomlValue(sameUserRegisterAck)}`);
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

module.exports = { startDaemon, renderConfig, DaemonStartError, RULE_ACTION };
