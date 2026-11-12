'use strict';
// Runs inside the hermetic session before any scenario: a plain browser under bwrap must start for every selected,
// available variant. Without it, a runner that cannot host the browser sandbox (for example an Ubuntu 24.04+ host whose
// AppArmor confines everything inside bwrap) only shows up as one 30 s timeout per scenario.
const { preflightPlainBrowsers } = require('./browser');

preflightPlainBrowsers().then(failures => {
  if (!failures.length) return;
  for (const f of failures) console.error(`preflight: ${f.variant}: a browser under bwrap did not start: ${f.detail}`);
  console.error('preflight: the browser sandbox is unusable on this host. On Ubuntu 24.04+ check `sysctl kernel.apparmor_restrict_unprivileged_userns` and the AppArmor profiles for bwrap (`aa-status | grep bwrap`); see "CI runner setup" in tests/agent-e2e/README.md.');
  process.exit(1);
}, e => { console.error(`preflight: ${e.stack || e}`); process.exit(1); });
