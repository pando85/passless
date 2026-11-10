'use strict';
// Locate or build the binaries under test.
//   AGENT_E2E_PASSLESS_BIN / AGENT_E2E_NOTIFY_DOUBLE_BIN  use these paths as-is (no build)
//   AGENT_E2E_NO_BUILD=1                                   fail instead of building
// Otherwise `cargo build` runs once with `--features agent` into a dedicated target dir
// (<repo>/target/agent-e2e-bin), so concurrent builds with other feature sets cannot replace the
// binary. The debug build is required: PASSLESS_E2E_AUTO_ACCEPT_* are debug-only.

const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const { REPO_ROOT, BIN_TARGET_DIR } = require('./paths');

let cached = null;

function ensureBuilt() {
  if (cached) return cached;
  const dir = path.join(BIN_TARGET_DIR, 'debug');
  const bins = {
    passless: process.env.AGENT_E2E_PASSLESS_BIN || path.join(dir, 'passless'),
    signProxy: process.env.AGENT_E2E_PASSLESS_BIN
      ? path.join(path.dirname(process.env.AGENT_E2E_PASSLESS_BIN), 'sign-proxy') : path.join(dir, 'sign-proxy'),
    notifyDouble: process.env.AGENT_E2E_NOTIFY_DOUBLE_BIN || path.join(dir, 'notify-double'),
  };
  const explicit = process.env.AGENT_E2E_PASSLESS_BIN && process.env.AGENT_E2E_NOTIFY_DOUBLE_BIN;
  if (!explicit && process.env.AGENT_E2E_NO_BUILD !== '1') {
    const env = { ...process.env, CARGO_TARGET_DIR: BIN_TARGET_DIR };
    // Two invocations: `--features agent` must not be applied to (or unify with) other packages.
    for (const args of [['-p', 'passless-rs', '--features', 'agent', '--bin', 'passless', '--bin', 'sign-proxy'], ['-p', 'notify-double']]) {
      const r = spawnSync('cargo', ['build', '-q', ...args], { cwd: REPO_ROOT, stdio: 'inherit', env });
      if (r.status !== 0) throw new Error(`cargo build ${args.join(' ')} failed (exit ${r.status})`);
    }
  }
  for (const [k, p] of Object.entries(bins)) {
    if (!fs.existsSync(p)) throw new Error(`missing ${k} binary at ${p}`);
  }
  cached = bins;
  return bins;
}

module.exports = { ensureBuilt };

if (require.main === module) {
  const b = ensureBuilt();
  // Machine-readable for run.sh: KEY=value lines.
  console.log(`AGENT_E2E_PASSLESS_BIN=${b.passless}`);
  console.log(`AGENT_E2E_NOTIFY_DOUBLE_BIN=${b.notifyDouble}`);
}
