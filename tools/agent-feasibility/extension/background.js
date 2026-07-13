const COMPLETION_DELAY_MS = 500;
const AAGUID = hex("50c0c5fa3b7a4eeeb9061b3dd4aed297");
const pending = new Map();
const credentials = new Map();

const state = { attached: false, attachError: null, events: [], mode: "success" };

function hex(value) {
  return Uint8Array.from(value.match(/../g).map((byte) => Number.parseInt(byte, 16)));
}

function bytes(...values) {
  const length = values.reduce((sum, value) => sum + value.length, 0);
  const result = new Uint8Array(length);
  let offset = 0;
  for (const value of values) {
    result.set(value, offset);
    offset += value.length;
  }
  return result;
}

function base64url(value) {
  let binary = "";
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function fromBase64url(value) {
  const normalized = value.replaceAll("-", "+").replaceAll("_", "/");
  const binary = atob(normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "="));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function unsigned(value, major) {
  if (value < 24) return Uint8Array.of((major << 5) | value);
  if (value < 256) return Uint8Array.of((major << 5) | 24, value);
  if (value < 65536) return Uint8Array.of((major << 5) | 25, value >> 8, value & 255);
  return Uint8Array.of(
    (major << 5) | 26,
    (value >>> 24) & 255,
    (value >>> 16) & 255,
    (value >>> 8) & 255,
    value & 255,
  );
}

function cbor(value) {
  if (value instanceof Uint8Array) return bytes(unsigned(value.length, 2), value);
  if (typeof value === "string") {
    const encoded = new TextEncoder().encode(value);
    return bytes(unsigned(encoded.length, 3), encoded);
  }
  if (Number.isInteger(value)) return value >= 0 ? unsigned(value, 0) : unsigned(-1 - value, 1);
  if (value instanceof Map) {
    const parts = [unsigned(value.size, 5)];
    for (const [key, entry] of value) parts.push(cbor(key), cbor(entry));
    return bytes(...parts);
  }
  throw new Error(`unsupported CBOR value: ${typeof value}`);
}

function uint16(value) {
  return Uint8Array.of((value >> 8) & 255, value & 255);
}

function uint32(value) {
  return Uint8Array.of(
    (value >>> 24) & 255,
    (value >>> 16) & 255,
    (value >>> 8) & 255,
    value & 255,
  );
}

function derInteger(value) {
  let integer = value;
  while (integer.length > 1 && integer[0] === 0) integer = integer.slice(1);
  if ((integer[0] & 0x80) !== 0) integer = bytes(Uint8Array.of(0), integer);
  return bytes(Uint8Array.of(0x02, integer.length), integer);
}

function rawEcdsaToDer(raw) {
  if (raw.length !== 64) throw new Error(`expected 64-byte ECDSA signature, got ${raw.length}`);
  const r = derInteger(raw.slice(0, 32));
  const s = derInteger(raw.slice(32));
  return bytes(Uint8Array.of(0x30, r.length + s.length), r, s);
}

async function sha256(value) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", value));
}

async function persist() {
  await chrome.storage.local.set({ phase0: state });
}

async function record(type, details = {}) {
  state.events.push({ type, at: new Date().toISOString(), ...details });
  await persist();
}

async function deriveSoleTopDocument() {
  const windows = (await chrome.windows.getAll({ populate: true })).filter(
    (window) => window.type === "normal",
  );
  if (windows.length !== 1) throw new Error(`expected one normal window, found ${windows.length}`);
  const tabs = windows[0].tabs ?? [];
  if (tabs.length !== 1) throw new Error(`expected one tab, found ${tabs.length}`);
  const tab = tabs[0];
  const frames = await chrome.webNavigation.getAllFrames({ tabId: tab.id });
  if (!frames || frames.length !== 1 || frames[0].frameId !== 0) {
    throw new Error(`expected one top-level frame, found ${frames?.length ?? 0}`);
  }
  const frame = frames[0];
  if (!frame.documentId) throw new Error("top-level frame has no documentId");
  return {
    windowId: windows[0].id,
    tabId: tab.id,
    frameId: frame.frameId,
    documentId: frame.documentId,
    origin: new URL(frame.url).origin,
    frameCount: frames.length,
  };
}

async function createCredential(options, context) {
  const rpId = options.rp.id || new URL(context.origin).hostname;
  const rpHash = await sha256(new TextEncoder().encode(rpId));
  const keyPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const jwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
  const publicKeySpki = new Uint8Array(await crypto.subtle.exportKey("spki", keyPair.publicKey));
  const credentialId = crypto.getRandomValues(new Uint8Array(32));
  const coseKey = cbor(
    new Map([
      [1, 2],
      [3, -7],
      [-1, 1],
      [-2, fromBase64url(jwk.x)],
      [-3, fromBase64url(jwk.y)],
    ]),
  );
  const authenticatorData = bytes(
    rpHash,
    Uint8Array.of(0x41),
    uint32(0),
    AAGUID,
    uint16(credentialId.length),
    credentialId,
    coseKey,
  );
  const attestationObject = cbor(
    new Map([
      ["fmt", "none"],
      ["attStmt", new Map()],
      ["authData", authenticatorData],
    ]),
  );
  const clientData = new TextEncoder().encode(
    JSON.stringify({
      type: "webauthn.create",
      challenge: options.challenge,
      origin: context.origin,
      crossOrigin: false,
    }),
  );
  const id = base64url(credentialId);
  credentials.set(id, {
    id: credentialId,
    keyPair,
    rpId,
    signCount: 0,
    userHandle: options.user?.id ?? null,
  });
  return JSON.stringify({
    id,
    rawId: id,
    type: "public-key",
    authenticatorAttachment: "platform",
    clientExtensionResults: {},
    response: {
      clientDataJSON: base64url(clientData),
      attestationObject: base64url(attestationObject),
      authenticatorData: base64url(authenticatorData),
      publicKey: base64url(publicKeySpki),
      transports: ["internal"],
      publicKeyAlgorithm: -7,
    },
  });
}

async function getAssertion(options, context) {
  const allowed = options.allowCredentials?.map((entry) => entry.id) ?? [];
  const credential = allowed.length
    ? credentials.get(allowed.find((id) => credentials.has(id)))
    : [...credentials.values()].find(
        (entry) => entry.rpId === (options.rpId || new URL(context.origin).hostname),
      );
  if (!credential) throw new Error("no matching Phase 0 credential");
  const rpId = options.rpId || credential.rpId;
  if (rpId !== credential.rpId) throw new Error("RP ID does not match credential");
  credential.signCount += 1;
  const authenticatorData = bytes(
    await sha256(new TextEncoder().encode(rpId)),
    Uint8Array.of(0x01),
    uint32(credential.signCount),
  );
  const clientData = new TextEncoder().encode(
    JSON.stringify({
      type: "webauthn.get",
      challenge: options.challenge,
      origin: context.origin,
      crossOrigin: false,
    }),
  );
  const signed = bytes(authenticatorData, await sha256(clientData));
  const rawSignature = new Uint8Array(
    await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, credential.keyPair.privateKey, signed),
  );
  const id = base64url(credential.id);
  return JSON.stringify({
    id,
    rawId: id,
    type: "public-key",
    authenticatorAttachment: "platform",
    clientExtensionResults: {},
    response: {
      authenticatorData: base64url(authenticatorData),
      clientDataJSON: base64url(clientData),
      signature: base64url(rawEcdsaToDer(rawSignature)),
      userHandle: credential.userHandle,
    },
  });
}

async function completeWithError(kind, requestId, message) {
  const details = { requestId, error: { name: "NotAllowedError", message } };
  if (kind === "create") await chrome.webAuthenticationProxy.completeCreateRequest(details);
  else await chrome.webAuthenticationProxy.completeGetRequest(details);
}

async function handleRequest(kind, request) {
  const rawKeys = Object.keys(request).sort();
  let context;
  try {
    context = await deriveSoleTopDocument();
  } catch (error) {
    await record("context_rejected", { kind, requestId: request.requestId, rawKeys, reason: error.message });
    await completeWithError(kind, request.requestId, error.message);
    return;
  }
  pending.set(request.requestId, { kind, context });
  await record("request_received", { kind, requestId: request.requestId, rawKeys, context });

  if (state.mode === "success") {
    try {
      const options = JSON.parse(request.requestDetailsJson);
      const responseJson =
        kind === "create"
          ? await createCredential(options, context)
          : await getAssertion(options, context);
      if (!pending.has(request.requestId)) return;
      pending.delete(request.requestId);
      const details = { requestId: request.requestId, responseJson };
      if (kind === "create") await chrome.webAuthenticationProxy.completeCreateRequest(details);
      else await chrome.webAuthenticationProxy.completeGetRequest(details);
      await record("request_completed", { kind, requestId: request.requestId });
    } catch (error) {
      pending.delete(request.requestId);
      await completeWithError(kind, request.requestId, error.message);
      await record("request_failed", { kind, requestId: request.requestId, reason: error.message });
    }
    return;
  }

  setTimeout(async () => {
    if (!pending.has(request.requestId)) return;
    pending.delete(request.requestId);
    await completeWithError(kind, request.requestId, "Phase 0 probe rejection");
    await record("request_rejected", { kind, requestId: request.requestId });
  }, COMPLETION_DELAY_MS);
}

chrome.webAuthenticationProxy.onCreateRequest.addListener((request) => void handleRequest("create", request));
chrome.webAuthenticationProxy.onGetRequest.addListener((request) => void handleRequest("get", request));
chrome.webAuthenticationProxy.onIsUvpaaRequest.addListener((request) => {
  void chrome.webAuthenticationProxy.completeIsUvpaaRequest({ requestId: request.requestId, isUvpaa: false });
});
chrome.webAuthenticationProxy.onRequestCanceled.addListener((requestId) => {
  pending.delete(requestId);
  void record("browser_canceled", { requestId });
});
chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0 || pending.size === 0) return;
  for (const [requestId, request] of pending) {
    pending.delete(requestId);
    void completeWithError(request.kind, requestId, "Top-level document changed").finally(() =>
      record("navigation_canceled", { requestId, tabId: details.tabId }),
    );
  }
});
chrome.tabs.onRemoved.addListener((tabId) => {
  for (const [requestId, request] of pending) {
    if (request.context.tabId !== tabId) continue;
    pending.delete(requestId);
    void completeWithError(request.kind, requestId, "Managed tab closed").finally(() =>
      record("tab_canceled", { requestId, tabId }),
    );
  }
});

globalThis.phase0SetMode = async (mode) => {
  state.mode = mode;
  await record("mode_changed", { mode });
};

void chrome.webAuthenticationProxy.attach().then(
  async () => {
    state.attached = true;
    await record("proxy_attached");
  },
  async (error) => {
    state.attachError = error.message;
    await record("proxy_attach_failed", { reason: error.message });
  },
);
