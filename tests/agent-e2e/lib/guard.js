'use strict';
// Proves the run did not touch the real user's Passless config/state/store or browser native-messaging
// dirs. `node lib/guard.js snapshot <file>` before, `node lib/guard.js verify <file>` after.
// (Plain ~/.config/chromium is deliberately not fingerprinted: a browser the user is running changes
// it constantly. Only the directory where Passless installs its native-messaging manifest is.)

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const home = os.userInfo().homedir;
const uid = os.userInfo().uid;
const { execFileSync } = require('node:child_process');

const running = name => { try { return execFileSync('pgrep', ['-x', name], { encoding: 'utf8' }).trim().length > 0; } catch { return false; } };

// Always fingerprinted.
const ALWAYS = [
  path.join(home, '.config', 'passless'), path.join(home, '.local', 'state', 'passless'),
  path.join(home, '.local', 'share', 'passless'), path.join(home, '.password-store'),
  // Every Chrome-family config dir a native-messaging manifest could land in. The daemon writes it only into the
  // managed profile; nothing may write into the browser's own config dir (watched to prove it).
  ...['chromium', 'google-chrome', 'google-chrome-beta', 'google-chrome-unstable', 'google-chrome-for-testing']
    .map(d => path.join(home, '.config', d, 'NativeMessagingHosts')),
  path.join(home, '.cache', 'ms-playwright'),
];
// Only when nothing else legitimately changes them: a running real passless owns /run/user/UID/passless and
// /agent; a running Chromium owns its profile files.
function watchList() {
  const list = [...ALWAYS];
  if (!running('passless')) list.push(`/run/user/${uid}/passless`, `/run/user/${uid}/agent`);
  if (!running('chromium')) list.push(path.join(home, '.config', 'chromium', 'Default'), path.join(home, '.config', 'chromium', 'Local State'));
  return list;
}
const WATCH = watchList();

function fingerprint(p) {
  if (!fs.existsSync(p)) return 'absent';
  let n = 0; let newest = 0;
  const walk = d => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const f = path.join(d, e.name);
      try { const st = fs.lstatSync(f); n++; newest = Math.max(newest, st.mtimeMs); if (e.isDirectory()) walk(f); } catch { /* raced */ }
    }
  };
  try {
    const st = fs.lstatSync(p);
    if (!st.isDirectory()) return `file:${st.size}:${Math.round(st.mtimeMs)}`; // e.g. "Local State"
    walk(p);
  } catch { return 'unreadable'; }
  return `${n}:${Math.round(newest)}`;
}

const [cmd, file] = process.argv.slice(2);
const now = Object.fromEntries(WATCH.concat(cmd === 'verify' ? [...ALWAYS, `/run/user/${uid}/passless`, `/run/user/${uid}/agent`, path.join(home, '.config', 'chromium', 'Default'), path.join(home, '.config', 'chromium', 'Local State')] : []).map(p => [p, fingerprint(p)]));
if (cmd === 'snapshot') { fs.writeFileSync(file, JSON.stringify(now)); process.exit(0); }
if (cmd === 'verify') {
  const before = JSON.parse(fs.readFileSync(file, 'utf8'));
  // Only compare paths that were watched at snapshot time (a real passless/chromium may have started since).
  const changed = Object.keys(before).filter(p => p in now && before[p] !== now[p]);
  if (changed.length) { console.error(`HERMETICITY VIOLATION: changed during the run: ${changed.join(', ')}`); process.exit(1); }
  console.log('hermeticity guard: real user config/state/store untouched');
  process.exit(0);
}
console.error('usage: guard.js snapshot|verify <file>'); process.exit(2);
