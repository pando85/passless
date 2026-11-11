'use strict';
// Shared assertions and page helpers for scenarios.

const assert = require('node:assert/strict');
const net = require('node:net');

const { EXTENSION_WORKER_URL } = require('./browser');

/** Audit event bodies (the `event` objects), in order. */
const auditEvents = audit => audit.map(e => e.event || e);

const policyEvents = (audit, kind) => auditEvents(audit).filter(e => e.kind === kind);

/** Run window.e2e.authenticate in `page` (or a frame) after the helper script is ready. */
async function authenticate(pageOrFrame, opts = {}) {
  await pageOrFrame.waitForFunction(() => window.e2e, null, { timeout: 15000 });
  return pageOrFrame.evaluate(o => window.e2e.authenticate(o), { timeout: 20000, userVerification: 'preferred', ...opts });
}

/** Sorted list of human-store credential files and hashes; used to prove nothing was signed or changed. */
const storeFingerprint = daemon => JSON.stringify(daemon.humanStore().sort((a, b) => a.file.localeCompare(b.file)));

/**
 * The RP accepted an assertion with UP and UV, the right RP ID hash and origin, and a higher counter.
 * Judged from the RP server's own verified record (`rp.authentications`), matched to the page's result by
 * timestamp, never from fields the page relayed.
 */
function assertVerifiedAssertion(rp, result, { username } = {}) {
  assert.equal(result.ok, true, `authentication failed: ${JSON.stringify(result)}`);
  const ev = rp.authentications.find(e => e.ts === result.ts);
  assert.ok(ev, 'the RP has no record of this assertion');
  assert.equal(ev.ok, true, `RP verification failed: ${ev.error}`);
  assert.equal(ev.flags.up, true, 'UP flag');
  assert.equal(ev.flags.uv, true, 'UV flag');
  assert.equal(ev.rpIdHashOk, true, 'RP ID hash');
  assert.equal(ev.origin, rp.origin, 'origin seen by the RP');
  assert.equal(ev.counterIncreased, true, `counter ${ev.previousCounter} -> ${ev.counter}`);
  assert.equal(result.credentialId, ev.credentialId);
  if (username) assert.equal(ev.username, username);
  return ev;
}

/**
 * WebAuthn interception is active in the managed browser before any result from it is trusted: the Passless
 * extension's service worker runs, and the daemon reported the lease's interception as attached (the launch only
 * returns once the worker said hello with `attached = true`, plan D6 layer 1).
 */
function assertInterceptionActive(b) {
  assert.equal(b.extensionWorker, true, 'the Passless extension service worker is not running');
  assert.equal(b.lease && b.lease.interception, 'attached', `the daemon does not report the lease as attached: ${JSON.stringify(b.lease)}`);
}

function assertNoNotification(stack) {
  assert.deepEqual(stack.notify.notifications(), [], 'a notification was shown');
}

/** The daemon's audit log shows `n` agent-path allows for authentication at `rpId` (proves the ceremony used the agent path, not a native fallback). */
async function assertAgentAllowed(stack, { rpId, profile = 'agent', n = 1, action = 'authenticate' }) {
  const audit = await stack.daemon.audit();
  const allows = policyEvents(audit, 'policy.allow').filter(e => e.profile_id === profile && e.action === action && e.rp_id === rpId);
  assert.equal(allows.length, n, `expected ${n} policy.allow(${action}) for ${profile}@${rpId}, audit: ${JSON.stringify(auditEvents(audit).map(e => e.kind))}`);
  return allows;
}


/**
 * The daemon endpoint the managed browser's extension was given: the sign socket, the lease-bound bearer and the
 * build version the daemon templated into `worker.js` (JSON string literals passed to the worker's IIFE). Read the way
 * the extension itself holds them, through the extension's own service worker, so no on-disk layout is assumed.
 * Test-only: a page can never do this.
 */
async function extensionEndpoint(b) {
  const worker = await waitFor('the extension service worker in Playwright', () =>
    b.context.serviceWorkers().find(w => w.url() === EXTENSION_WORKER_URL));
  const source = await worker.evaluate(async url => (await fetch(url)).text(), worker.url());
  const str = '"(?:[^"\\\\]|\\\\.)*"';
  const m = source.match(new RegExp(`\\}\\)\\(\\s*(${str})\\s*,\\s*(${str})\\s*,\\s*(${str})\\s*\\)\\s*;?\\s*$`));
  assert.ok(m, 'could not read the endpoint arguments (bearer, socket, build version) from the extension worker');
  return { bearer: JSON.parse(m[1]), socketPath: JSON.parse(m[2]), buildVersion: JSON.parse(m[3]) };
}

/**
 * A client of the daemon's sign socket that speaks the worker's wire protocol v2 directly (4-byte little-endian
 * length + one JSON object per frame): `hello`, then `request` / `abort` frames. Used where a scenario talks to the
 * daemon without the browser (E2E-06's direct check, E2E-11's revoked bearer).
 *
 * Note: the daemon keeps one connection per bearer; a hello from this client supersedes the worker's connection
 * (and the worker's reconnect supersedes this one), so stop the worker first when both must not race.
 */
class FramedClient {
  static connect(socketPath) {
    return new Promise((resolve, reject) => {
      const sock = net.createConnection(socketPath);
      sock.once('error', reject);
      sock.once('connect', () => { sock.off('error', reject); resolve(new FramedClient(sock)); });
    });
  }

  constructor(sock) {
    this.sock = sock;
    this.buf = Buffer.alloc(0);
    this.frames = [];
    this.waiters = [];
    this.closed = false;
    sock.on('data', d => {
      this.buf = Buffer.concat([this.buf, d]);
      while (this.buf.length >= 4) {
        const len = this.buf.readUInt32LE(0);
        if (this.buf.length < 4 + len) break;
        const frame = JSON.parse(this.buf.subarray(4, 4 + len).toString('utf8'));
        this.buf = this.buf.subarray(4 + len);
        if (frame.type === 'keepalive') continue;
        this.frames.push(frame);
        this._wake();
      }
    });
    const onClose = () => { this.closed = true; this._wake(); };
    sock.on('close', onClose);
    sock.on('error', onClose);
  }

  _wake() { const w = this.waiters; this.waiters = []; for (const f of w) f(); }

  send(frame) {
    const payload = Buffer.from(JSON.stringify(frame), 'utf8');
    const head = Buffer.alloc(4);
    head.writeUInt32LE(payload.length, 0);
    this.sock.write(Buffer.concat([head, payload]));
  }

  /** The next non-keepalive frame matching `pred`; `{type: 'eof'}` if the daemon closed the connection first. */
  async next(pred = () => true, timeoutMs = 15000) {
    const end = Date.now() + timeoutMs;
    for (;;) {
      const i = this.frames.findIndex(pred);
      if (i !== -1) return this.frames.splice(i, 1)[0];
      if (this.closed) return { type: 'eof' };
      const left = end - Date.now();
      if (left <= 0) throw new Error('timed out waiting for a frame from the daemon');
      await new Promise(r => { const t = setTimeout(r, left); this.waiters.push(() => { clearTimeout(t); r(); }); });
    }
  }

  /** Say hello; resolves with the daemon's answer (`hello` acknowledgement, or `error` before it closes). */
  async hello({ bearer, buildVersion, attached = true, incognitoAllowed = false }) {
    this.send({ type: 'hello', v: 2, build_version: buildVersion || 'e2e-harness', bearer, attached, incognito_allowed: incognitoAllowed });
    return this.next(f => f.type === 'hello' || f.type === 'error');
  }

  /** Send one request (`body` is a proxy-style requestDetailsJson string); resolves with its `result` frame. */
  async request(id, op, body, { timeoutMs = 20000 } = {}) {
    const details = JSON.parse(body);
    const override = details.extensions.remoteDesktopClientOverride;
    this.send({ type: 'request', id, op, timeout_ms: details.timeout ?? null, origin: override.origin, cross_origin: !override.sameOriginWithAncestors, body });
    return this.next(f => (f.type === 'result' && f.id === id) || f.type === 'error', timeoutMs);
  }

  close() { this.sock.destroy(); }
}

const b64u = b => Buffer.from(b).toString('base64url');
const override = (origin, sameOriginWithAncestors = true) => ({ remoteDesktopClientOverride: { origin, sameOriginWithAncestors } });

/**
 * A `create` requestDetailsJson the way Chromium's WebAuthn proxy hands it to the extension for a page on `rp`
 * (`extensions.remoteDesktopClientOverride` carries the browser-supplied origin). Distinct challenge per attempt.
 */
function registerRequest(rp, { username = 'dora', challenge, origin = rp.origin } = {}) {
  return JSON.stringify({
    rp: { id: rp.host, name: rp.host },
    user: { id: b64u(username), name: username, displayName: username },
    challenge: b64u(challenge || `challenge-${Date.now()}-${Math.random()}`),
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    timeout: 60000, excludeCredentials: [],
    authenticatorSelection: { residentKey: 'required', requireResidentKey: true, userVerification: 'preferred' },
    attestation: 'none', extensions: override(origin),
  });
}

/** A `get` requestDetailsJson (proxy shape) for `rpId` from `origin`. */
function signRequest({ origin, rpId, challenge, allowCredentials = [] }) {
  return JSON.stringify({
    rpId, challenge: b64u(challenge || `challenge-${Date.now()}-${Math.random()}`), timeout: 60000,
    allowCredentials: allowCredentials.map(id => ({ type: 'public-key', id })), userVerification: 'preferred',
    extensions: override(origin),
  });
}

/** Daemon log lines (debug) of the sign transport, see cmd/passless/src/agent/transport/mod.rs. */
const TRANSPORT_LOG = {
  hello: /sign transport: connection (\d+) hello accepted \(attached=(true|false)/g,
  admitted: /sign transport: connection (\d+) request (\d+) admitted/g,
  abort: /sign transport: connection (\d+) abort for request (\d+) \((in flight|not in flight)\)/g,
  closed: /sign transport: connection (\d+) closed; cancelling (\d+) in-flight request/g,
  answered: /sign transport: connection (\d+) request (\d+) (answered|not answered \(connection closed\)): (\w+)/g,
  refused: /sign transport: connection (\d+) request (\d+) refused: (\w+)/g,
};
/** All matches of a TRANSPORT_LOG pattern in `log` (arrays of capture groups). */
const logMatches = (log, re) => [...log.matchAll(new RegExp(re.source, 'g'))].map(m => m.slice(1));

/** CTAP traffic of the daemon's human UHID authenticator (debug log). Any match during an agent ceremony is a leak. */
const HUMAN_CTAP_LOG = /Worker received packet from host|CTAP response: \d+ bytes/;

/** Poll until `predicate()` is truthy, or fail with `what`. */
async function waitFor(what, predicate, { timeoutMs = 15000, intervalMs = 200 } = {}) {
  const end = Date.now() + timeoutMs;
  for (;;) {
    const v = await predicate();
    if (v) return v;
    if (Date.now() > end) assert.fail(`timed out waiting for ${what}`);
    await new Promise(r => setTimeout(r, intervalMs));
  }
}

module.exports = { extensionEndpoint, FramedClient, registerRequest, signRequest, TRANSPORT_LOG, logMatches, HUMAN_CTAP_LOG, waitFor, assertAgentAllowed, auditEvents, policyEvents, authenticate, storeFingerprint, assertVerifiedAssertion, assertInterceptionActive, assertNoNotification };
