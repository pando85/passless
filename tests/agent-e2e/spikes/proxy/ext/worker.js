// Spike worker: chrome.webAuthenticationProxy test harness.
// ctl.js (generated per run by lib.js) defines CTRL_BASE (the spike control server).
importScripts('ctl.js');

const b64u = (buf) => {
  const u = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = '';
  for (const b of u) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};
const unb64u = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
const concat = (...a) => { const o = new Uint8Array(a.reduce((n, x) => n + x.length, 0)); let p = 0; for (const x of a) { o.set(x, p); p += x.length; } return o; };
const enc = new TextEncoder();

function log(type, data) {
  return fetch(CTRL_BASE + '/log', { method: 'POST', body: JSON.stringify({ t: Date.now(), type, data }) }).catch(() => {});
}
async function getCfg() {
  try { return await (await fetch(CTRL_BASE + '/cfg')).json(); } catch { return {}; }
}

// ---- minimal CBOR encoder (uint/negint/bytes/text/map) ----
function cborHead(major, n) {
  if (n < 24) return Uint8Array.of((major << 5) | n);
  if (n < 256) return Uint8Array.of((major << 5) | 24, n);
  return Uint8Array.of((major << 5) | 25, n >> 8, n & 255);
}
function cbor(v) {
  if (v instanceof Uint8Array) return concat(cborHead(2, v.length), v);
  if (typeof v === 'string') { const b = enc.encode(v); return concat(cborHead(3, b.length), b); }
  if (typeof v === 'number') return v >= 0 ? cborHead(0, v) : cborHead(1, -1 - v);
  if (v instanceof Map) { const parts = [cborHead(5, v.size)]; for (const [k, x] of v) parts.push(cbor(k), cbor(x)); return concat(...parts); }
  throw new Error('cbor: unsupported');
}
function rawToDer(sig) {
  const f = (b) => { let i = 0; while (i < b.length - 1 && b[i] === 0) i++; b = b.slice(i); if (b[0] & 0x80) b = concat(Uint8Array.of(0), b); return concat(Uint8Array.of(2, b.length), b); };
  const r = f(sig.slice(0, 32)), s = f(sig.slice(32));
  return concat(Uint8Array.of(0x30, r.length + s.length), r, s);
}

const keys = new Map(); // credId(b64u) -> CryptoKeyPair
async function sha256(b) { return new Uint8Array(await crypto.subtle.digest('SHA-256', b)); }

function pickOrigin(cfg, details, evt) {
  if (cfg.clientDataOrigin) return cfg.clientDataOrigin;
  const rdo = details.extensions && details.extensions.remoteDesktopClientOverride;
  return (rdo && rdo.origin) || details.origin || evt.origin || 'http://UNKNOWN.invalid';
}

async function buildCreate(cfg, evt, details) {
  const rpId = (details.rp && details.rp.id) || 'unknown.invalid';
  const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const credId = crypto.getRandomValues(new Uint8Array(32));
  keys.set(b64u(credId), kp);
  const jwk = await crypto.subtle.exportKey('jwk', kp.publicKey);
  const x = unb64u(jwk.x), y = unb64u(jwk.y);
  const cose = new Map([[1, 2], [3, -7], [-1, 1], [-2, x], [-3, y]]);
  const authData = concat(await sha256(enc.encode(rpId)), Uint8Array.of(0x45 /* UP|UV|AT */), Uint8Array.of(0, 0, 0, 0),
    new Uint8Array(16), Uint8Array.of(credId.length >> 8, credId.length & 255), credId, cbor(cose));
  const att = cbor(new Map([['fmt', 'none'], ['attStmt', new Map()], ['authData', authData]]));
  const spki = new Uint8Array(await crypto.subtle.exportKey('spki', kp.publicKey));
  const clientData = JSON.stringify({ type: 'webauthn.create', challenge: cfg.clientDataChallenge || details.challenge,
    origin: pickOrigin(cfg, details, evt), crossOrigin: false });
  return {
    id: b64u(credId), rawId: b64u(credId), type: 'public-key', authenticatorAttachment: 'cross-platform',
    clientExtensionResults: {},
    response: { clientDataJSON: b64u(enc.encode(clientData)), attestationObject: b64u(att), transports: ['usb'],
      authenticatorData: b64u(authData), publicKey: b64u(spki), publicKeyAlgorithm: -7 },
    _clientData: clientData,
  };
}

async function buildGet(cfg, evt, details) {
  const rpId = details.rpId || 'unknown.invalid';
  const allow = (details.allowCredentials || [])[0];
  let credIdB64 = allow && allow.id, kp = credIdB64 && keys.get(credIdB64);
  if (!kp) {
    kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    credIdB64 = credIdB64 || b64u(crypto.getRandomValues(new Uint8Array(32)));
    keys.set(credIdB64, kp);
  }
  const clientData = enc.encode(JSON.stringify({ type: 'webauthn.get', challenge: cfg.clientDataChallenge || details.challenge,
    origin: pickOrigin(cfg, details, evt), crossOrigin: false }));
  const authData = concat(await sha256(enc.encode(rpId)), Uint8Array.of(0x05), Uint8Array.of(0, 0, 0, 1));
  const sig = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, kp.privateKey, concat(authData, await sha256(clientData))));
  return {
    id: credIdB64, rawId: credIdB64, type: 'public-key', authenticatorAttachment: 'cross-platform', clientExtensionResults: {},
    response: { clientDataJSON: b64u(clientData), authenticatorData: b64u(authData), signature: b64u(rawToDer(sig)), userHandle: b64u(enc.encode('uh')) },
    _clientData: new TextDecoder().decode(clientData),
  };
}

const done = (label, p) => new Promise((res) => p((r) => res(chrome.runtime.lastError ? 'lastError:' + chrome.runtime.lastError.message : (r === undefined ? 'ok' : r))));

async function handle(kind, evt) {
  const cfg = await getCfg();
  let details = {};
  try { details = JSON.parse(evt.requestDetailsJson); } catch (e) { details = { parseError: String(e) }; }
  await log(kind, { evt, details, cfg });
  if (cfg.mode === 'ignore') return;
  if (cfg.delayMs) await new Promise((r) => setTimeout(r, cfg.delayMs));
  if (cfg.mode === 'error') {
    const arg = { requestId: evt.requestId, error: { name: cfg.errorName || 'NotAllowedError', message: 'spike error' } };
    const res = await done('c', (cb) => (kind === 'onCreateRequest' ? chrome.webAuthenticationProxy.completeCreateRequest(arg, cb) : chrome.webAuthenticationProxy.completeGetRequest(arg, cb)));
    return log('complete', { kind, mode: 'error', res });
  }
  let cred, arg0;
  try { cred = kind === 'onCreateRequest' ? await buildCreate(cfg, evt, details) : await buildGet(cfg, evt, details); }
  catch (e) { return log('buildError', { e: String(e && e.stack || e) }); }
  const clientData = cred._clientData; delete cred._clientData;
  if (cfg.omitClientData) delete cred.response.clientDataJSON;
  if (cfg.garbage) { arg0 = '{"x":1}'; }
  if (cfg.rawResponseJson) Object.assign(cred, cfg.rawResponseJson);
  const arg = { requestId: evt.requestId, responseJson: typeof arg0 === 'string' ? arg0 : JSON.stringify(cred) };
  const res = await done('c', (cb) => (kind === 'onCreateRequest' ? chrome.webAuthenticationProxy.completeCreateRequest(arg, cb) : chrome.webAuthenticationProxy.completeGetRequest(arg, cb)));
  log('complete', { kind, mode: 'ok', res, clientData });
}

// Listeners MUST be registered synchronously at top level so events wake a stopped worker.
const P = chrome.webAuthenticationProxy;
P.onCreateRequest.addListener((e) => handle('onCreateRequest', e));
P.onGetRequest.addListener((e) => handle('onGetRequest', e));
P.onIsUvpaaRequest.addListener(async (e) => {
  const cfg = await getCfg();
  await log('onIsUvpaaRequest', { evt: e, cfg });
  if (cfg.uvpaa === 'ignore') return;
  const res = await done('u', (cb) => P.completeIsUvpaaRequest({ requestId: e.requestId, isUvpaa: cfg.uvpaa !== false }, cb));
  log('completeIsUvpaa', { res });
});
P.onRequestCanceled.addListener((id) => log('onRequestCanceled', { requestId: id }));
if (P.onRemoteSessionStateChange) P.onRemoteSessionStateChange.addListener((...a) => log('onRemoteSessionStateChange', a));

log('workerStart', { ua: navigator.userAgent });
(async () => {
  const cfg = await getCfg();
  if (cfg.noAttach) return log('attachSkipped', {});
  const res = await done('a', (cb) => P.attach(cb));
  log('attach', { res });
})();
