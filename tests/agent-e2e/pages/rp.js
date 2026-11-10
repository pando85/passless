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

  window.e2e = {
    describe, b64uToBuf, bufToB64u,
    async register({ username, userVerification, residentKey, timeout, signal } = {}) {
      try {
        const options = await post('/api/register/options', { username, userVerification, residentKey, timeout });
        let response; let credential = null;
        if (flavor() === 'sw') {
          response = await SimpleWebAuthnBrowser.startRegistration({ optionsJSON: options });
        } else {
          credential = await navigator.credentials.create({ publicKey: toCreationOptions(options), signal });
          response = attJSON(credential);
        }
        const verification = await post('/api/register/verify', { response });
        return { ...verification, received: describe(credential) };
      } catch (e) { return err(e); }
    },
    // allowCredentials: undefined -> by username (or discoverable when no username); array -> explicit ids.
    async authenticate({ username, userVerification, allowCredentials, timeout, signal, mediation } = {}) {
      try {
        const options = await post('/api/auth/options', { username, userVerification, allowCredentials, timeout });
        let response; let credential = null;
        if (flavor() === 'sw') {
          response = await SimpleWebAuthnBrowser.startAuthentication({ optionsJSON: options });
        } else {
          credential = await navigator.credentials.get({ publicKey: toRequestOptions(options), signal, mediation });
          response = assertJSON(credential);
        }
        const verification = await post('/api/auth/verify', { response });
        return { ...verification, received: describe(credential), options };
      } catch (e) { return err(e); }
    },
    state: () => fetch('/api/state').then(r => r.json()),
  };
  window.dispatchEvent(new Event('e2e-ready'));
})();
