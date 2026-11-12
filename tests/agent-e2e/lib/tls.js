'use strict';
// Generated test CA + leaf certificate for https://rp-a.test ... rp-j.test and https://evil.test.
// Trust is established per browser launch with --ignore-certificate-errors-spki-list (no system or
// NSS trust store is touched) and --host-resolver-rules (no /etc/hosts edits).
// Material is per run: run.sh sets AGENT_E2E_TLS_DIR (inside its temp dir, removed at the end); without it a
// per-process temp dir under the gitignored cache is created and removed at exit. Nothing is shared between
// concurrent runs.

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const { CACHE_DIR } = require('./paths');

// rp-c ... rp-j serve the escalation scenarios that need several distinct RP IDs (queue and waiter caps).
const TEST_HOSTS = ['rp-a.test', 'rp-b.test', 'evil.test', ...'cdefghij'.split('').map(c => `rp-${c}.test`)];

function spkiHash(pemFile) {
  const pub = execFileSync('openssl', ['x509', '-in', pemFile, '-pubkey', '-noout']);
  const der = execFileSync('openssl', ['pkey', '-pubin', '-outform', 'der'], { input: pub });
  return crypto.createHash('sha256').update(der).digest('base64');
}

function openssl(args, opts = {}) { execFileSync('openssl', args, { stdio: 'ignore', ...opts }); }

let perProcessDir = null;
function tlsDir() {
  if (process.env.AGENT_E2E_TLS_DIR) return process.env.AGENT_E2E_TLS_DIR;
  if (!perProcessDir) {
    fs.mkdirSync(CACHE_DIR, { recursive: true });
    perProcessDir = fs.mkdtempSync(path.join(CACHE_DIR, 'tls-run-'));
    process.on('exit', () => { try { fs.rmSync(perProcessDir, { recursive: true, force: true }); } catch { /* best effort */ } });
  }
  return perProcessDir;
}

/** Returns {key, cert, ca, spki: [leaf, ca]} for TEST_HOSTS. */
function ensureTestTls() {
  const dir = tlsDir();
  const f = n => path.join(dir, n);
  if (!fs.existsSync(f('chain.pem'))) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    openssl(['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-keyout', f('ca.key'),
      '-out', f('ca.pem'), '-days', '2', '-subj', '/CN=passless-e2e-test-ca',
      '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign']);
    openssl(['req', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-keyout', f('leaf.key'),
      '-out', f('leaf.csr'), '-subj', `/CN=${TEST_HOSTS[0]}`]);
    fs.writeFileSync(f('leaf.ext'), `subjectAltName=${TEST_HOSTS.map(h => 'DNS:' + h).join(',')}\n`
      + 'basicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\nkeyUsage=digitalSignature\n');
    openssl(['x509', '-req', '-in', f('leaf.csr'), '-CA', f('ca.pem'), '-CAkey', f('ca.key'), '-CAcreateserial',
      '-out', f('leaf.pem'), '-days', '2', '-extfile', f('leaf.ext')]);
    // Serve leaf + CA so the chain is complete. Written last: its existence marks the material complete.
    fs.writeFileSync(f('chain.pem'), fs.readFileSync(f('leaf.pem')) + fs.readFileSync(f('ca.pem')));
  }
  return { key: f('leaf.key'), cert: f('chain.pem'), ca: f('ca.pem'), spki: [spkiHash(f('leaf.pem')), spkiHash(f('ca.pem'))] };
}

/** Browser flags that make `https://<host>` (no port) reach the given RpServers over trusted TLS. */
function rpBrowserArgs(rpServers) {
  const tlsServers = rpServers.filter(r => r.isTls);
  if (!tlsServers.length) return [];
  const tls = ensureTestTls();
  const rules = tlsServers.map(r => `MAP ${r.host} ${r.listen}`).join(', ');
  return [`--host-resolver-rules=${rules}`, `--ignore-certificate-errors-spki-list=${tls.spki.join(',')}`];
}

module.exports = { ensureTestTls, rpBrowserArgs, TEST_HOSTS };
