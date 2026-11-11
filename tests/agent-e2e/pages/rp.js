// Shared client helpers for the test RP pages. Everything is exposed on window.e2e; scenarios call
// it through page.evaluate. Failures are returned as {ok:false, name, message}, never thrown, so the
// DOMException name (NotAllowedError, ...) can be asserted.
(function () {
  const post = async (path, body) => (await fetch(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body || {}) })).json();
  const b64uToBuf = s => { s = s.replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '='; const b = atob(s); const a = new Uint8Array(b.length); for (let i = 0; i < b.length; i++) a[i] = b.charCodeAt(i); return a.buffer; };
  const bufToB64u = buf => { const a = new Uint8Array(buf); let s = ''; for (const c of a) s += String.fromCharCode(c); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); };
  const err = e => ({ ok: false, name: e && e.name, message: String(e && e.message || e) });

  // What the page actually received from navigator.credentials (checked by the harness).
  const describe = c => c && ({
    type: c.type, id: c.id, ctor: c.constructor && c.constructor.name,
    instanceOfPublicKeyCredential: typeof PublicKeyCredential !== 'undefined' && c instanceof PublicKeyCredential,
    hasToJSON: typeof c.toJSON === 'function',
    authenticatorAttachment: c.authenticatorAttachment || null,
    responseCtor: c.response && c.response.constructor && c.response.constructor.name,
    responseIsAttestation: typeof AuthenticatorAttestationResponse !== 'undefined' && c.response instanceof AuthenticatorAttestationResponse,
    responseIsAssertion: typeof AuthenticatorAssertionResponse !== 'undefined' && c.response instanceof AuthenticatorAssertionResponse,
  });

  const toCreationOptions = o => ({
    ...o, challenge: b64uToBuf(o.challenge), user: { ...o.user, id: b64uToBuf(o.user.id) },
    excludeCredentials: (o.excludeCredentials || []).map(c => ({ ...c, id: b64uToBuf(c.id) })),
  });
  const toRequestOptions = o => ({
    ...o, challenge: b64uToBuf(o.challenge),
    allowCredentials: (o.allowCredentials || []).map(c => ({ ...c, id: b64uToBuf(c.id) })),
  });
  const attJSON = c => ({
    id: c.id, rawId: bufToB64u(c.rawId), type: c.type, clientExtensionResults: c.getClientExtensionResults(),
    authenticatorAttachment: c.authenticatorAttachment || undefined,
    response: {
      clientDataJSON: bufToB64u(c.response.clientDataJSON), attestationObject: bufToB64u(c.response.attestationObject),
      authenticatorData: bufToB64u(c.response.getAuthenticatorData()), transports: c.response.getTransports ? c.response.getTransports() : [],
      publicKeyAlgorithm: c.response.getPublicKeyAlgorithm(),
    },
  });
  const assertJSON = c => ({
    id: c.id, rawId: bufToB64u(c.rawId), type: c.type, clientExtensionResults: c.getClientExtensionResults(),
    authenticatorAttachment: c.authenticatorAttachment || undefined,
    response: {
      clientDataJSON: bufToB64u(c.response.clientDataJSON), authenticatorData: bufToB64u(c.response.authenticatorData),
      signature: bufToB64u(c.response.signature), userHandle: c.response.userHandle ? bufToB64u(c.response.userHandle) : undefined,
    },
  });

  // `flavor` 'sw' uses @simplewebauthn/browser; 'raw' calls navigator.credentials directly.
  const flavor = () => (window.SimpleWebAuthnBrowser ? 'sw' : 'raw');
  const pending = new Map();
  let pendingSeq = 0;

  window.e2e = {
    describe, b64uToBuf, bufToB64u,
    // `viaToJSON`: send the browser's own PublicKeyCredential.toJSON() output to the RP (raw page only).
    async register({ username, userVerification, residentKey, timeout, signal, viaToJSON } = {}) {
      try {
        const options = await post('/api/register/options', { username, userVerification, residentKey, timeout });
        let response; let credential = null;
        if (flavor() === 'sw') {
          response = await SimpleWebAuthnBrowser.startRegistration({ optionsJSON: options });
        } else {
          credential = await navigator.credentials.create({ publicKey: toCreationOptions(options), signal });
          response = viaToJSON ? credential.toJSON() : attJSON(credential);
        }
        const verification = await post('/api/register/verify', { response });
        return { ...verification, received: describe(credential) };
      } catch (e) { return err(e); }
    },
    // allowCredentials: undefined -> by username (or discoverable when no username); array -> explicit ids.
    // `noVerify`: return the serialised assertion ({ok:true, response}) instead of posting it to the RP.
    async authenticate({ username, userVerification, allowCredentials, timeout, signal, mediation, viaToJSON, noVerify } = {}) {
      try {
        const options = await post('/api/auth/options', { username, userVerification, allowCredentials, timeout });
        let response; let credential = null;
        if (flavor() === 'sw') {
          response = await SimpleWebAuthnBrowser.startAuthentication({ optionsJSON: options });
        } else {
          credential = await navigator.credentials.get({ publicKey: toRequestOptions(options), signal, mediation });
          response = viaToJSON ? credential.toJSON() : assertJSON(credential);
        }
        if (noVerify) return { ok: true, response, received: describe(credential) };
        const verification = await post('/api/auth/verify', { response });
        return { ...verification, received: describe(credential), options };
      } catch (e) { return err(e); }
    },
    // Replay helpers (raw page): ONE set of options from the RP, then the same navigator.credentials.get call
    // issued `count` times with identical options, concurrently or one after the other. Each entry is the
    // serialised assertion ({ok:true, json}) or the error ({ok:false, name, message}); nothing is verified here.
    authOptions: ({ username, userVerification, allowCredentials, timeout } = {}) => post('/api/auth/options', { username, userVerification, allowCredentials, timeout }),
    async getIdentical(options, { count = 2, concurrent = false } = {}) {
      const one = () => navigator.credentials.get({ publicKey: toRequestOptions(options) }).then(c => ({ ok: true, json: assertJSON(c) }), err);
      if (concurrent) return Promise.all(Array.from({ length: count }, one));
      const out = [];
      for (let i = 0; i < count; i++) out.push(await one());
      return out;
    },
    verifyAuth: response => post('/api/auth/verify', { response }),
    // Background ceremonies that the harness can abort or poll: start() returns a key at once.
    start(kind, opts = {}) {
      const key = `c${++pendingSeq}`;
      const controller = new AbortController();
      const startedAt = Date.now();
      const entry = { controller, settled: false, result: null, startedAt, settledAt: null };
      const fn = kind === 'register' ? window.e2e.register : window.e2e.authenticate;
      entry.promise = fn({ ...opts, signal: controller.signal }).then(r => {
        entry.settled = true; entry.settledAt = Date.now(); entry.result = r; return r;
      });
      pending.set(key, entry);
      return key;
    },
    abort(key) { const e = pending.get(key); if (e) e.controller.abort(); return !!e; },
    /** {settled, result, elapsedMs} without waiting. */
    peek(key) {
      const e = pending.get(key);
      if (!e) return null;
      return { settled: e.settled, result: e.result, elapsedMs: (e.settledAt || Date.now()) - e.startedAt };
    },
    async result(key) { const e = pending.get(key); return e ? e.promise : null; },
    // What a MAIN-world shim would leave behind: a non-native navigator.credentials, a marker attribute, or a global.
    shimProbe() {
      const nativeFn = f => typeof f === 'function' && /\[native code\]/.test(Function.prototype.toString.call(f));
      return {
        getNative: nativeFn(navigator.credentials.get), createNative: nativeFn(navigator.credentials.create),
        credentialsProtoGetNative: nativeFn(CredentialsContainer.prototype.get),
        ownGet: Object.prototype.hasOwnProperty.call(navigator.credentials, 'get'),
        ownCreate: Object.prototype.hasOwnProperty.call(navigator.credentials, 'create'),
        markerAttributes: [...document.documentElement.attributes].map(a => a.name).filter(n => /passless/i.test(n)),
        passlessGlobals: Object.getOwnPropertyNames(window).filter(n => /passless/i.test(n)),
      };
    },
    state: () => fetch('/api/state').then(r => r.json()),
  };
  window.dispatchEvent(new Event('e2e-ready'));
})();
