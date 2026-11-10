'use strict';
// Test relying party. Verifies registrations and authentications for real with
// @simplewebauthn/server (signature, counter, UP/UV flags, origin, RP ID hash) and exposes every
// result to the test through `rp.registrations` / `rp.authentications` (and GET /api/state).
//
// One RpServer is one origin. Origins:
//   - kind 'localhost':  http://localhost:<port>        (default)
//   - kind 'test-https': https://<host> (e.g. rp-a.test) served over TLS, reached through
//     `--host-resolver-rules` and a generated test CA trusted via
//     `--ignore-certificate-errors-spki-list` (see lib/tls.js). Browser flags come from
//     `rpBrowserArgs()`.

const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const https = require('node:https');
const path = require('node:path');

const swServer = require('@simplewebauthn/server');

const PAGES_DIR = path.join(__dirname, '..', 'pages');
// Not reachable through the package `exports` map, so use the installed path (pinned by package-lock).
const BROWSER_BUNDLE = path.join(__dirname, '..', 'node_modules', '@simplewebauthn', 'browser', 'dist', 'bundle', 'index.umd.min.js');

const b64u = buf => Buffer.from(buf).toString('base64url');

/** Parse authenticatorData: rpIdHash, flags, counter. */
function parseAuthData(authData) {
  const buf = Buffer.from(authData);
  const flags = buf[32];
  return {
    rpIdHash: buf.subarray(0, 32),
    up: !!(flags & 0x01), uv: !!(flags & 0x04), be: !!(flags & 0x08), bs: !!(flags & 0x10), at: !!(flags & 0x40),
    counter: buf.readUInt32BE(33),
  };
}

class RpServer {
  /**
   * @param {object} o
   * @param {string} [o.name]      label for logs
   * @param {string} [o.host]      'localhost' (default) or a test host such as 'rp-a.test'
   * @param {{key:string,cert:string}} [o.tls]  required for non-localhost hosts
   * @param {boolean} [o.requireUV=true]
   */
  constructor(o = {}) {
    this.name = o.name || 'rp';
    this.host = o.host || 'localhost';
    this.tls = o.tls || null;
    this.requireUV = o.requireUV !== false;
    this.rpID = o.rpID || this.host;
    this.users = new Map();        // username -> {id: Buffer, name, credentials: [{id, publicKey, counter, transports}]}
    this.challenges = new Map();   // challenge -> {kind, username, requireUV}
    this.registrations = [];
    this.authentications = [];
    this.requests = [];
    this.port = 0;
    this.server = null;
  }

  get isTls() { return !!this.tls; }
  /** Origin as the browser sees it. For test hosts the port is implicit (443) via host-resolver-rules. */
  get origin() {
    if (this.isTls) return `https://${this.host}`;
    return `http://${this.host}:${this.port}`;
  }
  /** `host:port` of the real listener (what --host-resolver-rules maps to). */
  get listen() { return `127.0.0.1:${this.port}`; }

  async start() {
    const handler = (req, res) => this._handle(req, res).catch(err => {
      res.writeHead(500, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: String(err && err.message || err) }));
    });
    this.server = this.isTls
      ? https.createServer({ key: fs.readFileSync(this.tls.key), cert: fs.readFileSync(this.tls.cert) }, handler)
      : http.createServer(handler);
    await new Promise((resolve, reject) => {
      this.server.once('error', reject);
      this.server.listen(0, '127.0.0.1', resolve);
    });
    this.port = this.server.address().port;
    return this;
  }

  async stop() {
    if (!this.server) return;
    this.server.closeAllConnections?.();
    await new Promise(r => this.server.close(r));
    this.server = null;
  }

  /** Test helpers ----------------------------------------------------------------------------- */
  credentialsOf(username) { return (this.users.get(username)?.credentials || []).map(c => c.id); }
  allCredentialIds() { return [...this.users.values()].flatMap(u => u.credentials.map(c => c.id)); }
  usernameOfCredential(id) {
    for (const u of this.users.values()) if (u.credentials.some(c => c.id === id)) return u.name;
    return null;
  }
  lastAuth() { return this.authentications[this.authentications.length - 1]; }
  /** Seed a user without a credential (so options can be generated for it). */
  ensureUser(username) {
    if (!this.users.has(username)) this.users.set(username, { id: crypto.randomBytes(16), name: username, credentials: [] });
    return this.users.get(username);
  }

  /** HTTP ------------------------------------------------------------------------------------- */
  async _handle(req, res) {
    const url = new URL(req.url, 'http://x');
    this.requests.push({ method: req.method, path: url.pathname, ts: Date.now() });
    if (req.method === 'GET') {
      if (url.pathname === '/sw-bundle.js') return this._file(res, BROWSER_BUNDLE, 'text/javascript');
      if (url.pathname === '/api/state') return this._json(res, this.state());
      const map = { '/': 'index.html', '/sw': 'sw.html', '/raw': 'raw.html', '/rp.js': 'rp.js',
        '/popup-opener': 'popup-opener.html', '/iframe-host': 'iframe-host.html', '/embed': 'embed.html' };
      const f = map[url.pathname];
      if (f) return this._file(res, path.join(PAGES_DIR, f), f.endsWith('.js') ? 'text/javascript' : 'text/html');
      res.writeHead(404); return res.end('not found');
    }
    if (req.method === 'POST') {
      const body = await readJson(req);
      const routes = {
        '/api/register/options': () => this.registerOptions(body),
        '/api/register/verify': () => this.registerVerify(body),
        '/api/auth/options': () => this.authOptions(body),
        '/api/auth/verify': () => this.authVerify(body),
        '/api/reset': () => { this.registrations.length = 0; this.authentications.length = 0; return { ok: true }; },
      };
      const r = routes[url.pathname];
      if (!r) { res.writeHead(404); return res.end('not found'); }
      return this._json(res, await r());
    }
    res.writeHead(405); res.end();
  }

  _json(res, obj) { res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' }); res.end(JSON.stringify(obj)); }
  _file(res, file, type) { res.writeHead(200, { 'content-type': type, 'cache-control': 'no-store' }); res.end(fs.readFileSync(file)); }

  state() {
    return {
      rpID: this.rpID, origin: this.origin,
      users: [...this.users.values()].map(u => ({ name: u.name, credentials: u.credentials.map(c => ({ id: c.id, counter: c.counter })) })),
      registrations: this.registrations, authentications: this.authentications,
    };
  }

  async registerOptions({ username, userVerification = 'preferred', residentKey = 'required', attestation = 'none', timeout }) {
    const user = this.ensureUser(username);
    const options = await swServer.generateRegistrationOptions({
      rpName: `E2E ${this.name}`, rpID: this.rpID, userName: user.name, userID: user.id,
      attestationType: attestation, timeout,
      authenticatorSelection: { residentKey, userVerification },
      excludeCredentials: user.credentials.map(c => ({ id: c.id, transports: c.transports })),
    });
    this.challenges.set(options.challenge, { kind: 'register', username });
    return options;
  }

  async registerVerify({ response }) {
    const challenge = clientChallenge(response);
    const pending = this.challenges.get(challenge);
    const ev = { ts: Date.now(), username: pending?.username, ok: false };
    this.registrations.push(ev);
    if (!pending || pending.kind !== 'register') { ev.error = 'unknown challenge'; return ev; }
    this.challenges.delete(challenge);
    try {
      const v = await swServer.verifyRegistrationResponse({
        response, expectedChallenge: challenge, expectedOrigin: this.origin, expectedRPID: this.rpID,
        requireUserPresence: true, requireUserVerification: this.requireUV,
      });
      if (!v.verified) { ev.error = 'not verified'; return ev; }
      const info = v.registrationInfo;
      // Everything below comes from the verified result. SimpleWebAuthn has already checked the RP ID hash
      // (expectedRPID), UP (requireUserPresence) and UV (requireUserVerification) on the authData.
      const c = info.credential;
      this.users.get(pending.username).credentials.push({ id: c.id, publicKey: c.publicKey, counter: c.counter, transports: c.transports });
      Object.assign(ev, {
        ok: true, credentialId: c.id, fmt: info.fmt, aaguid: info.aaguid, origin: info.origin, rpID: info.rpID || this.rpID,
        flags: { up: true, uv: info.userVerified, be: info.credentialBackedUp, bs: info.credentialBackedUp }, counter: c.counter,
        rpIdHashOk: true, deviceType: info.credentialDeviceType,
      });
    } catch (e) { ev.error = String(e.message || e); }
    return ev;
  }

  async authOptions({ username, userVerification = 'preferred', allowCredentials, timeout }) {
    let allow;
    if (Array.isArray(allowCredentials)) allow = allowCredentials.map(id => ({ id }));
    else if (username) allow = (this.users.get(username)?.credentials || []).map(c => ({ id: c.id, transports: c.transports }));
    const options = await swServer.generateAuthenticationOptions({ rpID: this.rpID, userVerification, allowCredentials: allow, timeout });
    this.challenges.set(options.challenge, { kind: 'auth', username });
    return options;
  }

  async authVerify({ response }) {
    const challenge = clientChallenge(response);
    const pending = this.challenges.get(challenge);
    const ev = { ts: Date.now(), ok: false, credentialId: response.id };
    this.authentications.push(ev);
    if (!pending || pending.kind !== 'auth') { ev.error = 'unknown challenge'; return ev; }
    this.challenges.delete(challenge);
    let owner = null; let cred = null;
    for (const u of this.users.values()) { const c = u.credentials.find(x => x.id === response.id); if (c) { owner = u; cred = c; } }
    if (!cred) { ev.error = 'unknown credential'; return ev; }
    ev.username = owner.name;
    ev.previousCounter = cred.counter;
    ev.userHandle = response.response.userHandle || null;
    try {
      const v = await swServer.verifyAuthenticationResponse({
        response, expectedChallenge: challenge, expectedOrigin: this.origin, expectedRPID: this.rpID,
        credential: { id: cred.id, publicKey: cred.publicKey, counter: cred.counter, transports: cred.transports },
        requireUserVerification: this.requireUV,
      });
      if (!v.verified) { ev.error = 'not verified'; return ev; }
      // Flags, counter and RP ID hash are taken only now, from the signature-verified authenticator data:
      // SimpleWebAuthn verified the signature over it, the RP ID hash against expectedRPID, and UP (always
      // required); UV is reported by the verified result.
      const info = v.authenticationInfo;
      const ad = parseAuthData(Buffer.from(response.response.authenticatorData, 'base64url'));
      cred.counter = info.newCounter;
      Object.assign(ev, {
        ok: true, origin: info.origin, rpID: info.rpID, userVerified: info.userVerified,
        flags: { up: ad.up, uv: info.userVerified, be: info.credentialBackedUp, bs: ad.bs },
        counter: info.newCounter,
        rpIdHashOk: ad.rpIdHash.equals(crypto.createHash('sha256').update(this.rpID).digest()),
      });
      ev.counterIncreased = ev.counter > ev.previousCounter;
    } catch (e) { ev.error = String(e.message || e); }
    return ev;
  }
}

function clientChallenge(response) {
  const cd = JSON.parse(Buffer.from(response.response.clientDataJSON, 'base64url').toString('utf8'));
  return cd.challenge;
}


function readJson(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => { try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {}); } catch (e) { reject(e); } });
    req.on('error', reject);
  });
}

module.exports = { RpServer, parseAuthData, b64u };
