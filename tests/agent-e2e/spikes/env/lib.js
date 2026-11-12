// Shared helpers for the environment spikes (Q4/Q5/Q7/Q8). Hermetic: everything lives under $SPIKE_SCRATCH.
const { createRequire } = require('module');
const fs = require('fs'), path = require('path'), os = require('os'), http = require('http'), https = require('https');
const { spawn, execFileSync } = require('child_process');
const PW_FROM = process.env.PW_FROM ||
  '/home/agil/.cache/tmp/claude-1000/-home-agil-passkeys-passless/d4df783e-bb62-4ca3-b59c-9946f1a7ed88/scratchpad/spike/x.js';
const { chromium } = createRequire(PW_FROM)('playwright-core');
const SCRATCH = process.env.SPIKE_SCRATCH ||
  '/home/agil/.cache/tmp/claude-1000/-home-agil-passkeys-passless/d4df783e-bb62-4ca3-b59c-9946f1a7ed88/scratchpad/envspike';
fs.mkdirSync(SCRATCH, { recursive: true });
const sleep = ms => new Promise(r => setTimeout(r, ms));

// Self-signed cert for the given DNS names; returns {key, cert, spki(base64 sha256 of SPKI DER)}.
function makeCert(names, tag) {
  const dir = path.join(SCRATCH, 'certs-' + tag); fs.mkdirSync(dir, { recursive: true });
  const key = path.join(dir, 'key.pem'), cert = path.join(dir, 'cert.pem');
  if (!fs.existsSync(cert)) {
    const san = names.map(n => 'DNS:' + n).join(',');
    execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes',
      '-keyout', key, '-out', cert, '-days', '30', '-subj', '/CN=' + names[0], '-addext', 'subjectAltName=' + san], { stdio: 'ignore' });
  }
  const pub = execFileSync('openssl', ['x509', '-in', cert, '-pubkey', '-noout']);
  const der = execFileSync('openssl', ['pkey', '-pubin', '-outform', 'der'], { input: pub });
  const spki = require('crypto').createHash('sha256').update(der).digest('base64');
  return { key, cert, spki };
}

const PAGE = '<!doctype html><title>t</title><body>probe</body>';
function serve(port, tls) {
  const h = (q, s) => { s.writeHead(200, { 'content-type': 'text/html' }); s.end(PAGE); };
  const srv = tls ? https.createServer({ key: fs.readFileSync(tls.key), cert: fs.readFileSync(tls.cert) }, h) : http.createServer(h);
  return new Promise(r => srv.listen(port, '127.0.0.1', () => r(srv)));
}

// Launch a browser with CDP and attach. opts: {exe, args, headless, prefix:[...], env, tag}
async function launch(o) {
  const prof = fs.mkdtempSync(path.join(SCRATCH, 'prof-' + (o.tag || 'x') + '-'));
  const args = ['--user-data-dir=' + prof, '--no-first-run', '--no-default-browser-check', '--disable-sync',
    '--password-store=basic', '--disable-background-networking', '--disable-component-update',
    '--remote-debugging-port=0', '--remote-debugging-address=127.0.0.1', '--remote-allow-origins=*',
    ...(o.headless ? ['--headless=new'] : []), ...(o.args || []), 'about:blank'];
  const cmd = [...(o.prefix || []), o.exe, ...args];
  const proc = spawn(cmd[0], cmd.slice(1), { detached: true, stdio: ['ignore', 'ignore', 'pipe'], env: { ...process.env, ...(o.env || {}) } });
  let stderr = ''; proc.stderr.on('data', d => { if (stderr.length < 20000) stderr += d; });
  let exited = false; proc.on('exit', () => exited = true);
  const pf = path.join(prof, 'DevToolsActivePort');
  for (let i = 0; i < 150 && !fs.existsSync(pf) && !exited; i++) await sleep(200);
  const kill = () => { try { process.kill(-proc.pid, 'SIGKILL'); } catch (e) {} };
  if (!fs.existsSync(pf)) { kill(); throw new Error('no DevToolsActivePort; exited=' + exited + ' stderr=' + stderr.split('\n').slice(0, 6).join(' | ')); }
  const port = fs.readFileSync(pf, 'utf8').split('\n')[0];
  const browser = await chromium.connectOverCDP('http://127.0.0.1:' + port);
  await sleep(800);
  return { browser, proc, prof, kill, stderr: () => stderr };
}

// WebAuthn create probe. Settled within waitMs => report outcome; still pending => accepted by browser (aborted afterwards).
async function probeCreate(page, rpId, waitMs = 3500) {
  return page.evaluate(async ({ rpId, waitMs }) => {
    const out = { isSecureContext: window.isSecureContext, origin: location.origin, hasPKC: typeof PublicKeyCredential };
    if (!navigator.credentials) return { ...out, settled: 'rejected', name: 'n/a', msg: 'navigator.credentials undefined (insecure context)' };
    const ac = new AbortController();
    const p = navigator.credentials.create({ signal: ac.signal, publicKey: {
      rp: { id: rpId, name: 'spike' }, user: { id: new Uint8Array(8), name: 'u', displayName: 'u' },
      challenge: crypto.getRandomValues(new Uint8Array(32)), pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      authenticatorSelection: { residentKey: 'required', userVerification: 'discouraged' } } })
      .then(c => ({ settled: 'created', type: c.type, id: c.id.slice(0, 8) }), e => ({ settled: 'rejected', name: e.name, msg: e.message }));
    const r = await Promise.race([p, new Promise(res => setTimeout(() => res({ settled: 'pending' }), waitMs))]);
    if (r.settled === 'pending') { ac.abort(); await p; }
    return { ...out, ...r };
  }, { rpId, waitMs });
}
async function probeGet(page, rpId, waitMs = 3500) {
  return page.evaluate(async ({ rpId, waitMs }) => {
    if (!navigator.credentials) return { settled: 'rejected', name: 'n/a', msg: 'navigator.credentials undefined (insecure context)' };
    const ac = new AbortController();
    const p = navigator.credentials.get({ signal: ac.signal, publicKey: { rpId, challenge: crypto.getRandomValues(new Uint8Array(32)),
      userVerification: 'discouraged', allowCredentials: [{ type: 'public-key', id: crypto.getRandomValues(new Uint8Array(32)) }] } })
      .then(c => ({ settled: 'got', id: c.id.slice(0, 8) }), e => ({ settled: 'rejected', name: e.name, msg: e.message }));
    const r = await Promise.race([p, new Promise(res => setTimeout(() => res({ settled: 'pending' }), waitMs))]);
    if (r.settled === 'pending') { ac.abort(); await p; }
    return r;
  }, { rpId, waitMs });
}
const fmt = r => r.settled === 'rejected' ? `rejected ${r.name}: ${r.msg}` : r.settled === 'pending' ? 'PENDING (accepted by browser, no authenticator answered)' : JSON.stringify(r);
module.exports = { SCRATCH, sleep, makeCert, serve, launch, probeCreate, probeGet, fmt, chromium, execFileSync, fs, path, os };
