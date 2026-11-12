"use strict";

// Behavioral tests for the agent extension service worker (cmd/passless/assets/agent-extension/).
// The worker runs in a node:vm context against a mock `chrome` and fake timers.
// Run: node cmd/passless/tests/agent_extension_behavioral.js (exits non-zero on failure).

const vm = require("vm");
const assert = require("assert");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const ASSETS = path.join(__dirname, "..", "assets", "agent-extension");
const WORKER_SRC = fs.readFileSync(path.join(ASSETS, "worker.js"), "utf8");
const MANIFEST_SRC = fs.readFileSync(path.join(ASSETS, "manifest.json"), "utf8");

// Extension ID derived from the manifest `key` (first 16 bytes of SHA-256 of the SPKI DER, a-p).
const EXPECTED_EXTENSION_ID = "lfbahamapdlbimlffmhiomfdemnjhjkc";

const BEARER = "bearer-0123456789abcdef";
const SOCKET = "/run/user/1000/passless/agent/sign/sock";
const BUILD = "0.9.0-test";
const PLACEHOLDERS = ["__PASSLESS_BEARER__", "__PASSLESS_SOCKET_PATH__", "__PASSLESS_BUILD_VERSION__"];

// Single-pass replacement with JSON string literals, as the daemon does.
function renderWorker(values) {
  const map = {
    __PASSLESS_BEARER__: JSON.stringify(values.bearer),
    __PASSLESS_SOCKET_PATH__: JSON.stringify(values.socket),
    __PASSLESS_BUILD_VERSION__: JSON.stringify(values.build)
  };
  return WORKER_SRC.replace(/__PASSLESS_(?:BEARER|SOCKET_PATH|BUILD_VERSION)__/g, (m) => map[m]);
}

// ---- test runner ---------------------------------------------------------------------------------

const tests = [];
function test(name, fn) {
  tests.push({ name, fn });
}

function flush() {
  return new Promise((resolve) => setImmediate(resolve));
}

function clone(v) {
  return v === undefined ? undefined : JSON.parse(JSON.stringify(v));
}

// ---- fake timers ---------------------------------------------------------------------------------

function makeClock() {
  let now = 0;
  let seq = 1;
  const timers = new Map();
  const clock = {
    setTimeout(fn, ms) {
      const id = seq++;
      timers.set(id, { fn, at: now + Math.max(0, Number(ms) || 0), every: null });
      return id;
    },
    setInterval(fn, ms) {
      const id = seq++;
      const every = Math.max(1, Number(ms) || 0);
      timers.set(id, { fn, at: now + every, every });
      return id;
    },
    clearTimeout(id) {
      timers.delete(id);
    },
    clearInterval(id) {
      timers.delete(id);
    },
    now() {
      return now;
    },
    async advance(ms) {
      const end = now + ms;
      for (;;) {
        let nextId = null;
        let next = null;
        for (const [id, t] of timers) {
          if (t.at <= end && (next === null || t.at < next.at || (t.at === next.at && id < nextId))) {
            next = t;
            nextId = id;
          }
        }
        if (next === null) break;
        now = next.at;
        if (next.every !== null) next.at += next.every;
        else timers.delete(nextId);
        next.fn();
        await flush();
      }
      now = end;
      await flush();
    }
  };
  return clock;
}

// ---- mock chrome ---------------------------------------------------------------------------------

function makeEvent() {
  const listeners = [];
  return {
    addListener(fn) {
      listeners.push(fn);
    },
    removeListener(fn) {
      const i = listeners.indexOf(fn);
      if (i !== -1) listeners.splice(i, 1);
    },
    hasListener(fn) {
      return listeners.includes(fn);
    },
    fire(...args) {
      for (const fn of listeners.slice()) fn(...args);
    },
    count() {
      return listeners.length;
    }
  };
}

// opts:
//   attach: "ok" | "error:<msg>" | "lastError:<msg>" | "throw" | "manual"
//   incognito: boolean
//   storage: Map shared across worker restarts
//   deferStorageGet: hold storage.session.get callbacks until env.releaseGets()
//   connectPlan: array of "ok" | "fail" | "throw", consumed one per connectNative call
function makeEnv(opts = {}) {
  const env = {
    clock: makeClock(),
    storage: opts.storage || new Map(),
    ports: [],
    completes: [],
    uvpaa: [],
    attachCalls: 0,
    reloadCalls: 0,
    connectNames: [],
    connectPlan: (opts.connectPlan || []).slice(),
    pendingAttach: null,
    pendingGets: [],
    nonce: opts.nonce || null
  };

  const chrome = {};
  function withLastError(message, fn) {
    chrome.runtime.lastError = message == null ? undefined : { message };
    try {
      fn();
    } finally {
      chrome.runtime.lastError = undefined;
    }
  }
  function later(fn) {
    queueMicrotask(fn);
  }

  function makePort(name) {
    const port = {
      name,
      posted: [],
      closed: false,
      disconnectCalls: 0,
      onMessage: makeEvent(),
      onDisconnect: makeEvent(),
      postMessage(m) {
        if (port.closed) throw new Error("Attempting to use a disconnected port object");
        port.posted.push(clone(m));
      },
      disconnect() {
        port.disconnectCalls++;
        port.closed = true;
      },
      // Chrome hands the extension the JSON the host wrote, parsed.
      deliver(m) {
        if (!port.closed) port.onMessage.fire(clone(m));
      },
      deliverRaw(m) {
        if (!port.closed) port.onMessage.fire(m);
      },
      drop(message) {
        if (port.closed) return;
        port.closed = true;
        withLastError(message || "Native host has exited.", () => port.onDisconnect.fire(port));
      },
      frames(type) {
        return type ? port.posted.filter((f) => f && f.type === type) : port.posted.slice();
      }
    };
    return port;
  }

  function completer(kind) {
    return function (arg, cb) {
      env.completes.push({ kind, arg: clone(arg), raw: arg });
      later(() => withLastError(opts.completeLastError || null, () => cb && cb()));
    };
  }

  chrome.runtime = {
    id: EXPECTED_EXTENSION_ID,
    lastError: undefined,
    onMessage: makeEvent(),
    onMessageExternal: makeEvent(),
    onConnect: makeEvent(),
    onConnectExternal: makeEvent(),
    reload() {
      env.reloadCalls++;
    },
    connectNative(name) {
      env.connectNames.push(name);
      const plan = env.connectPlan.shift() || "ok";
      if (plan === "throw") throw new Error("connectNative failed");
      const port = makePort(name);
      env.ports.push(port);
      if (plan === "fail") later(() => port.drop("Specified native messaging host not found."));
      return port;
    }
  };

  chrome.webAuthenticationProxy = {
    onCreateRequest: makeEvent(),
    onGetRequest: makeEvent(),
    onRequestCanceled: makeEvent(),
    onIsUvpaaRequest: makeEvent(),
    onRemoteSessionStateChange: makeEvent(),
    attach(cb) {
      env.attachCalls++;
      const mode = opts.attach || "ok";
      if (mode === "throw") throw new Error("attach exploded");
      if (mode === "manual") {
        env.pendingAttach = (result, lastError) => withLastError(lastError || null, () => cb(result));
        return;
      }
      later(() => {
        if (mode === "ok") withLastError(null, () => cb());
        else if (mode.startsWith("error:")) withLastError(null, () => cb(mode.slice("error:".length)));
        else if (mode.startsWith("lastError:")) withLastError(mode.slice("lastError:".length), () => cb());
      });
    },
    detach(cb) {
      later(() => cb && cb());
    },
    completeCreateRequest: completer("create"),
    completeGetRequest: completer("get"),
    completeIsUvpaaRequest(arg, cb) {
      env.uvpaa.push(clone(arg));
      later(() => withLastError(null, () => cb && cb()));
    }
  };

  chrome.extension = {
    isAllowedIncognitoAccess(cb) {
      const allowed = opts.incognito === undefined ? true : opts.incognito;
      later(() => withLastError(null, () => cb(allowed)));
    }
  };

  chrome.storage = {
    session: {
      get(keys, cb) {
        const snapshot = {};
        for (const [k, v] of env.storage) snapshot[k] = clone(v);
        const respond = () => withLastError(null, () => cb(snapshot));
        if (opts.deferStorageGet) env.pendingGets.push(respond);
        else later(respond);
      },
      set(items, cb) {
        for (const k of Object.keys(items)) env.storage.set(k, clone(items[k]));
        later(() => withLastError(null, () => cb && cb()));
      },
      remove(keys, cb) {
        for (const k of [].concat(keys)) env.storage.delete(k);
        later(() => withLastError(null, () => cb && cb()));
      }
    }
  };

  env.chrome = chrome;
  env.proxy = chrome.webAuthenticationProxy;
  env.releaseGets = () => {
    const gets = env.pendingGets.splice(0);
    gets.forEach((g) => g());
  };
  env.port = () => env.ports[env.ports.length - 1];
  env.create = (requestId, details) =>
    env.proxy.onCreateRequest.fire({ requestId, requestDetailsJson: typeof details === "string" ? details : JSON.stringify(details) });
  env.get = (requestId, details) =>
    env.proxy.onGetRequest.fire({ requestId, requestDetailsJson: typeof details === "string" ? details : JSON.stringify(details) });
  env.completesFor = (requestId) => env.completes.filter((c) => c.arg.requestId === requestId);
  env.pendingKeys = () => [...env.storage.keys()].filter((k) => k.startsWith("pending:"));
  return env;
}

function startWorker(env, values = { bearer: BEARER, socket: SOCKET, build: BUILD }) {
  // A fixed instance nonce lets a test seed entries that belong to the current instance.
  const webcrypto = env.nonce
    ? { randomUUID: () => env.nonce, getRandomValues: (a) => crypto.webcrypto.getRandomValues(a) }
    : crypto.webcrypto;
  const sandbox = {
    chrome: env.chrome,
    setTimeout: env.clock.setTimeout,
    setInterval: env.clock.setInterval,
    clearTimeout: env.clock.clearTimeout,
    clearInterval: env.clock.clearInterval,
    crypto: webcrypto,
    console
  };
  vm.createContext(sandbox);
  vm.runInContext(renderWorker(values), sandbox, { filename: "worker.js" });
  return sandbox;
}

async function boot(opts = {}, values) {
  const env = makeEnv(opts);
  startWorker(env, values);
  await flush();
  return env;
}

// ---- request details fixtures --------------------------------------------------------------------

const RP_ORIGIN = "https://rp.example";

function override(origin = RP_ORIGIN, same = true) {
  return { remoteDesktopClientOverride: { origin, sameOriginWithAncestors: same } };
}

function getDetails(extra = {}) {
  return Object.assign(
    {
      allowCredentials: [],
      challenge: "Y2hhbGxlbmdlLWNoYWxsZW5nZQ",
      extensions: override(),
      rpId: "rp.example",
      timeout: 180000,
      userVerification: "preferred"
    },
    extra
  );
}

function createDetails(extra = {}) {
  return Object.assign(
    {
      attestation: "none",
      authenticatorSelection: { residentKey: "required", userVerification: "preferred" },
      challenge: "Y3JlYXRlLWNoYWxsZW5nZQ",
      excludeCredentials: [],
      extensions: override(),
      pubKeyCredParams: [{ alg: -7, type: "public-key" }],
      rp: { id: "rp.example", name: "rp" },
      timeout: 180000,
      user: { displayName: "Alice", id: "dXNlcg", name: "alice" }
    },
    extra
  );
}

function assertNotAllowed(env, requestId, kind) {
  const c = env.completesFor(requestId);
  assert.strictEqual(c.length, 1, `exactly one completion for ${requestId}, got ${c.length}`);
  if (kind) assert.strictEqual(c[0].kind, kind);
  assert.ok(c[0].arg.error, "completion carries an error");
  assert.strictEqual(c[0].arg.error.name, "NotAllowedError");
  assert.strictEqual(typeof c[0].arg.error.message, "string");
  assert.strictEqual(c[0].arg.responseJson, undefined);
}

function requestFrames(env) {
  return env.ports.flatMap((p) => p.frames("request"));
}

// ---- hello and lifecycle -------------------------------------------------------------------------

test("hello is the first frame and carries bearer, attached, incognito_allowed, build_version, socket", async () => {
  const env = await boot();
  assert.deepStrictEqual(env.connectNames, ["rs.passless.sign_proxy"]);
  const port = env.port();
  assert.ok(port.posted.length >= 1);
  assert.deepStrictEqual(port.posted[0], {
    type: "hello",
    v: 2,
    build_version: BUILD,
    bearer: BEARER,
    attached: true,
    incognito_allowed: true,
    socket: SOCKET
  });
  assert.strictEqual(port.frames("hello").length, 1);
});

test("hello reports incognito_allowed=false from isAllowedIncognitoAccess", async () => {
  const env = await boot({ incognito: false });
  const hello = env.port().posted[0];
  assert.strictEqual(hello.type, "hello");
  assert.strictEqual(hello.incognito_allowed, false);
  assert.strictEqual(hello.attached, true);
});

test("attach() is called on every worker start", async () => {
  const storage = new Map();
  const env1 = await boot({ storage });
  assert.strictEqual(env1.attachCalls, 1);
  const env2 = await boot({ storage });
  assert.strictEqual(env2.attachCalls, 1);
  assert.strictEqual(env2.port().posted[0].attached, true);
});

test("an 'already attached' attach error counts as attached; another extension does not", async () => {
  const a = await boot({ attach: "lastError:This extension is already attached" });
  assert.strictEqual(a.port().posted[0].attached, true);
  const b = await boot({ attach: "error:Another extension is already attached" });
  assert.strictEqual(b.port().posted[0].attached, false);
  const c = await boot({ attach: "error:Some failure" });
  assert.strictEqual(c.port().posted[0].attached, false);
  const d = await boot({ attach: "throw" });
  assert.strictEqual(d.port().posted[0].attached, false);
});

test("hello waits for the attach result; a later attach change re-sends hello", async () => {
  const env = await boot({ attach: "manual" });
  const port = env.port();
  assert.strictEqual(port.posted.length, 0, "no frame before the attach state is known");
  await env.clock.advance(2000);
  assert.strictEqual(port.posted.length, 1);
  assert.strictEqual(port.posted[0].type, "hello");
  assert.strictEqual(port.posted[0].attached, false);
  env.pendingAttach(undefined);
  await flush();
  const hellos = port.frames("hello");
  assert.strictEqual(hellos.length, 2);
  assert.strictEqual(hellos[1].attached, true);
  assert.strictEqual(hellos[1].bearer, BEARER);
  // An unchanged state does not re-send.
  env.pendingAttach(undefined);
  await flush();
  assert.strictEqual(port.frames("hello").length, 2);
});

test("requests arriving before the hello are queued behind it", async () => {
  const env = await boot({ attach: "manual" });
  env.get(10, getDetails());
  await flush();
  const port = env.port();
  assert.strictEqual(port.posted.length, 0);
  env.pendingAttach(undefined);
  await flush();
  assert.deepStrictEqual(port.posted.map((f) => f.type), ["hello", "request"]);
  assert.strictEqual(port.posted[0].attached, true);
});

test("a request cancelled before the hello is dropped, not sent", async () => {
  const env = await boot({ attach: "manual" });
  env.get(10, getDetails());
  env.proxy.onRequestCanceled.fire(10);
  env.pendingAttach(undefined);
  await flush();
  assert.deepStrictEqual(env.port().posted.map((f) => f.type), ["hello"]);
  assert.strictEqual(env.completes.length, 0);
});

test("the template has each placeholder once and renders a special-character bearer", async () => {
  for (const p of PLACEHOLDERS) {
    assert.strictEqual(WORKER_SRC.split(p).length - 1, 1, `${p} appears exactly once`);
  }
  const bearer = "tok\"en\\with\nspecialé </script>'`${x}";
  const socket = "/tmp/so ck\"et";
  const build = "1.2.3+\"x\"";
  const src = renderWorker({ bearer, socket, build });
  assert.doesNotThrow(() => new vm.Script(src));
  const env = makeEnv();
  startWorker(env, { bearer, socket, build });
  await flush();
  const hello = env.port().posted[0];
  assert.strictEqual(hello.bearer, bearer);
  assert.strictEqual(hello.socket, socket);
  assert.strictEqual(hello.build_version, build);
});

// ---- request framing -----------------------------------------------------------------------------

test("request frame: verbatim body, origin and cross_origin from the override, timeout_ms", async () => {
  const env = await boot();
  // Odd spacing and key order: the body must be the exact event string.
  const body =
    '{ "rpId":"rp.example",  "challenge":"Y2g","timeout":180000,\n' +
    '"extensions":{"remoteDesktopClientOverride":{"sameOriginWithAncestors":true,"origin":"https://rp.example:8443"}},' +
    '"allowCredentials":[] , "userVerification":"required"}';
  env.get(-1381853939, body);
  await flush();
  const frames = env.port().frames("request");
  assert.strictEqual(frames.length, 1);
  assert.deepStrictEqual(frames[0], {
    type: "request",
    id: 1,
    op: "get",
    timeout_ms: 180000,
    origin: "https://rp.example:8443",
    cross_origin: false,
    body
  });
  assert.strictEqual(frames[0].bearer, undefined);
});

test("request frame: create op, cross_origin from sameOriginWithAncestors=false, null timeout", async () => {
  const env = await boot();
  const details = createDetails({ extensions: override("https://frame.example", false) });
  delete details.timeout;
  env.create(7, details);
  await flush();
  const f = env.port().frames("request")[0];
  assert.strictEqual(f.op, "create");
  assert.strictEqual(f.origin, "https://frame.example");
  assert.strictEqual(f.cross_origin, true);
  assert.strictEqual(f.timeout_ms, null);
  assert.strictEqual(f.body, JSON.stringify(details));
});

test("origin comes only from the override, never from rp.id, rpId or a top-level origin", async () => {
  const env = await boot();
  env.get(1, getDetails({ rpId: "evil.example", origin: "https://evil.example", topOrigin: "https://evil.example" }));
  env.create(2, createDetails({ rp: { id: "evil.example", name: "evil" }, origin: "https://evil.example" }));
  await flush();
  const frames = env.port().frames("request");
  assert.strictEqual(frames.length, 2);
  for (const f of frames) assert.strictEqual(f.origin, RP_ORIGIN);
});

test("a missing or malformed override is rejected without contacting the daemon", async () => {
  const env = await boot();
  const bad = [
    getDetails({ extensions: undefined, origin: RP_ORIGIN }),
    getDetails({ extensions: {} }),
    getDetails({ extensions: { remoteDesktopClientOverride: null } }),
    getDetails({ extensions: { remoteDesktopClientOverride: "https://rp.example" } }),
    getDetails({ extensions: { remoteDesktopClientOverride: { origin: 42, sameOriginWithAncestors: true } } }),
    getDetails({ extensions: { remoteDesktopClientOverride: { origin: "", sameOriginWithAncestors: true } } }),
    getDetails({ extensions: { remoteDesktopClientOverride: { origin: RP_ORIGIN } } }),
    getDetails({ extensions: { remoteDesktopClientOverride: { origin: RP_ORIGIN, sameOriginWithAncestors: "true" } } }),
    getDetails({ extensions: [] })
  ];
  bad.forEach((d, i) => env.get(100 + i, d));
  env.get(200, "{not json");
  env.get(201, "null");
  env.create(202, createDetails({ extensions: undefined }));
  env.proxy.onGetRequest.fire({ requestId: 203, requestDetailsJson: { extensions: override() } });
  await flush();
  assert.strictEqual(requestFrames(env).length, 0, "no request frame sent");
  bad.forEach((_, i) => assertNotAllowed(env, 100 + i, "get"));
  assertNotAllowed(env, 200, "get");
  assertNotAllowed(env, 201, "get");
  assertNotAllowed(env, 202, "create");
  assertNotAllowed(env, 203, "get");
  assert.deepStrictEqual(env.pendingKeys(), []);
});

test("conditional-mediation get is rejected without a daemon frame", async () => {
  const env = await boot();
  env.get(5, getDetails({ mediation: "conditional" }));
  await flush();
  assert.strictEqual(requestFrames(env).length, 0);
  assertNotAllowed(env, 5, "get");
});

test("an oversize request is refused locally instead of breaking the port", async () => {
  const env = await boot();
  env.get(6, getDetails({ challenge: "A".repeat(1048576) }));
  await flush();
  assert.strictEqual(requestFrames(env).length, 0);
  assertNotAllowed(env, 6, "get");
  assert.strictEqual(env.port().closed, false);
});

test("a duplicate event for an in-flight requestId is not sent twice", async () => {
  const env = await boot();
  env.get(9, getDetails());
  env.get(9, getDetails());
  await flush();
  assert.strictEqual(requestFrames(env).length, 1);
  assert.strictEqual(env.completes.length, 0);
});

test("wire ids are a monotonic counter starting at 1", async () => {
  const env = await boot();
  env.get(50, getDetails());
  env.create(51, createDetails());
  env.get(52, getDetails());
  await flush();
  assert.deepStrictEqual(requestFrames(env).map((f) => f.id), [1, 2, 3]);
});

// ---- results -------------------------------------------------------------------------------------

test("multiplexing: two concurrent requests completed out of order with the right responseJson", async () => {
  const env = await boot();
  env.get(111, getDetails());
  env.create(222, createDetails());
  await flush();
  const [f1, f2] = requestFrames(env);
  const port = env.port();
  port.deliver({ type: "result", id: f2.id, ok: true, body: '{"id":"create-222"}' });
  await flush();
  port.deliver({ type: "result", id: f1.id, ok: true, body: '{"id":"get-111"}' });
  await flush();
  assert.strictEqual(env.completes.length, 2);
  assert.deepStrictEqual(env.completes[0].arg, { requestId: 222, responseJson: '{"id":"create-222"}' });
  assert.strictEqual(env.completes[0].kind, "create");
  assert.deepStrictEqual(env.completes[1].arg, { requestId: 111, responseJson: '{"id":"get-111"}' });
  assert.strictEqual(env.completes[1].kind, "get");
});

test("responseJson is passed verbatim (byte-identical string)", async () => {
  const env = await boot();
  env.get(1, getDetails());
  await flush();
  const body =
    '{"type":"public-key",  "id":"AAEC","rawId":"AAEC","authenticatorAttachment":"cross-platform",\n' +
    '"clientExtensionResults":{},"response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0",' +
    '"authenticatorData":"YWJj","signature":"c2ln","userHandle":null},"z":"é \\u0000","a":1.50}';
  env.port().deliver({ type: "result", id: 1, ok: true, body });
  await flush();
  const c = env.completesFor(1);
  assert.strictEqual(c.length, 1);
  assert.strictEqual(typeof c[0].raw.responseJson, "string");
  assert.strictEqual(c[0].raw.responseJson, body);
  assert.ok(Buffer.from(c[0].raw.responseJson, "utf8").equals(Buffer.from(body, "utf8")));
  assert.strictEqual(c[0].raw.error, undefined);
});

test("error mapping: allowed dom names pass through, anything else becomes NotAllowedError", async () => {
  const env = await boot();
  const cases = [
    { dom: "NotAllowedError", want: "NotAllowedError" },
    { dom: "NotSupportedError", want: "NotSupportedError" },
    { dom: "InvalidStateError", want: "InvalidStateError" },
    { dom: "SecurityError", want: "SecurityError" },
    { dom: "AbortError", want: "AbortError" },
    { dom: "WhateverError", want: "NotAllowedError" },
    { dom: "TypeError", want: "NotAllowedError" },
    { dom: undefined, want: "NotAllowedError" },
    { dom: 7, want: "NotAllowedError" }
  ];
  cases.forEach((_, i) => env.create(1000 + i, createDetails()));
  await flush();
  const frames = requestFrames(env);
  cases.forEach((c, i) => env.port().deliver({ type: "result", id: frames[i].id, ok: false, error: { code: "x", dom: c.dom } }));
  await flush();
  cases.forEach((c, i) => {
    const done = env.completesFor(1000 + i);
    assert.strictEqual(done.length, 1);
    assert.strictEqual(done[0].kind, "create");
    assert.strictEqual(done[0].arg.error.name, c.want, `dom ${c.dom}`);
    assert.strictEqual(typeof done[0].arg.error.message, "string");
    assert.strictEqual(done[0].arg.responseJson, undefined);
  });
  assert.deepStrictEqual(env.pendingKeys(), []);
});

test("a malformed result for a known id fails it with NotAllowedError", async () => {
  const env = await boot();
  const malformed = [
    { ok: "yes", body: "{}" },
    { ok: true },
    { ok: true, body: { id: "x" } },
    { ok: false },
    { ok: false, error: "busy" }
  ];
  malformed.forEach((_, i) => env.get(300 + i, getDetails()));
  await flush();
  const frames = requestFrames(env);
  malformed.forEach((m, i) => env.port().deliver(Object.assign({ type: "result", id: frames[i].id }, m)));
  await flush();
  malformed.forEach((_, i) => assertNotAllowed(env, 300 + i, "get"));
});

test("unknown or malformed daemon frames are ignored", async () => {
  const env = await boot();
  env.get(1, getDetails());
  await flush();
  const port = env.port();
  for (const raw of [null, 42, "result", [], { id: 1 }, { type: 5 }, { type: "bogus", id: 1 }, { type: "result" },
    { type: "result", id: "1", ok: true, body: "{}" }, { type: "result", id: 99, ok: true, body: "{}" },
    { type: "keepalive" }, { type: "hello", v: 2, build_version: "x" }]) {
    port.deliverRaw(raw);
  }
  await flush();
  assert.strictEqual(env.completes.length, 0, "nothing completed");
  assert.strictEqual(port.closed, false);
  port.deliver({ type: "result", id: 1, ok: true, body: "{\"ok\":1}" });
  await flush();
  assert.deepStrictEqual(env.completesFor(1).map((c) => c.arg.responseJson), ["{\"ok\":1}"]);
});

test("a second result for the same id is ignored", async () => {
  const env = await boot();
  env.get(1, getDetails());
  await flush();
  env.port().deliver({ type: "result", id: 1, ok: true, body: "{\"a\":1}" });
  env.port().deliver({ type: "result", id: 1, ok: false, error: { code: "x", dom: "SecurityError" } });
  await flush();
  assert.strictEqual(env.completes.length, 1);
});

// ---- abort and UVPAA -----------------------------------------------------------------------------

test("onRequestCanceled sends abort for the mapped wire id and the late result is ignored", async () => {
  const env = await boot();
  env.get(40, getDetails());
  env.create(41, createDetails());
  await flush();
  const [, f41] = requestFrames(env);
  env.proxy.onRequestCanceled.fire(41);
  await flush();
  const aborts = env.port().frames("abort");
  assert.deepStrictEqual(aborts, [{ type: "abort", id: f41.id }]);
  assert.ok(!env.pendingKeys().includes("pending:41"));
  assert.ok(env.pendingKeys().includes("pending:40"));
  env.port().deliver({ type: "result", id: f41.id, ok: false, error: { code: "aborted", dom: "AbortError" } });
  await flush();
  assert.strictEqual(env.completes.length, 0, "no completion after cancel");
  env.proxy.onRequestCanceled.fire(41);
  env.proxy.onRequestCanceled.fire(12345);
  await flush();
  assert.strictEqual(env.port().frames("abort").length, 1, "unknown requestIds send nothing");
});

test("onIsUvpaaRequest is always answered with isUvpaa=false", async () => {
  const env = await boot();
  env.proxy.onIsUvpaaRequest.fire({ requestId: 77 });
  env.proxy.onIsUvpaaRequest.fire({ requestId: -3 });
  await flush();
  assert.deepStrictEqual(env.uvpaa, [{ requestId: 77, isUvpaa: false }, { requestId: -3, isUvpaa: false }]);
  assert.deepStrictEqual(env.port().posted.map((f) => f.type), ["hello"]);
});

// ---- keepalive -----------------------------------------------------------------------------------

test("keepalive is sent every 20 s while the port is open", async () => {
  const env = await boot();
  const port = env.port();
  await env.clock.advance(19999);
  assert.strictEqual(port.frames("keepalive").length, 0);
  await env.clock.advance(1);
  assert.strictEqual(port.frames("keepalive").length, 1);
  await env.clock.advance(20000);
  assert.strictEqual(port.frames("keepalive").length, 2);
  await env.clock.advance(60000);
  assert.strictEqual(port.frames("keepalive").length, 5);
  assert.deepStrictEqual(port.frames("keepalive")[0], { type: "keepalive" });
  port.drop();
  await flush();
  await env.clock.advance(19000);
  assert.strictEqual(port.frames("keepalive").length, 5, "no keepalive on a dropped port");
});

// ---- disconnect and reconnect --------------------------------------------------------------------

test("disconnect fails in-flight requests, then reconnects with backoff and says hello again", async () => {
  const env = await boot();
  env.get(1, getDetails());
  env.create(2, createDetails());
  await flush();
  assert.strictEqual(env.pendingKeys().length, 2);
  const first = env.port();
  first.drop("Native host has exited.");
  await flush();
  assertNotAllowed(env, 1, "get");
  assertNotAllowed(env, 2, "create");
  assert.deepStrictEqual(env.pendingKeys(), []);
  assert.strictEqual(env.ports.length, 1, "no immediate reconnect");
  await env.clock.advance(249);
  assert.strictEqual(env.ports.length, 1);
  await env.clock.advance(1);
  assert.strictEqual(env.ports.length, 2);
  const second = env.port();
  assert.strictEqual(second.posted[0].type, "hello");
  assert.strictEqual(second.posted[0].bearer, BEARER);
  // A late result from the dead port cannot complete anything twice.
  first.onMessage.fire({ type: "result", id: 1, ok: true, body: "{}" });
  await flush();
  assert.strictEqual(env.completes.length, 2);
});

test("backoff doubles to a 10 s cap and resets after a hello ack", async () => {
  const env = await boot();
  const delays = [];
  for (let i = 0; i < 8; i++) {
    env.port().drop();
    await flush();
    const before = env.ports.length;
    const start = env.clock.now();
    let waited = 0;
    while (env.ports.length === before && waited < 20000) {
      await env.clock.advance(50);
      waited += 50;
    }
    assert.strictEqual(env.ports.length, before + 1, "reconnected");
    delays.push(env.clock.now() - start);
  }
  assert.deepStrictEqual(delays, [250, 500, 1000, 2000, 4000, 8000, 10000, 10000]);
  env.port().deliver({ type: "hello", v: 2, build_version: "daemon" });
  await flush();
  env.port().drop();
  await flush();
  const before = env.ports.length;
  await env.clock.advance(249);
  assert.strictEqual(env.ports.length, before);
  await env.clock.advance(1);
  assert.strictEqual(env.ports.length, before + 1, "backoff reset to 250 ms");
});

test("a request while disconnected connects immediately and is sent after the hello", async () => {
  const env = await boot();
  env.port().drop();
  await flush();
  assert.strictEqual(env.ports.length, 1);
  env.get(8, getDetails());
  await flush();
  assert.strictEqual(env.ports.length, 2, "immediate connect attempt");
  const port = env.port();
  assert.deepStrictEqual(port.posted.map((f) => f.type), ["hello", "request"]);
  assert.strictEqual(port.posted[1].id, 1);
  // The pending backoff timer was replaced by this connection: no extra port appears.
  await env.clock.advance(1000);
  assert.strictEqual(env.ports.length, 2);
  port.deliver({ type: "result", id: 1, ok: true, body: "{\"x\":1}" });
  await flush();
  assert.strictEqual(env.completesFor(8)[0].arg.responseJson, "{\"x\":1}");
});

test("a request whose connect fails gets NotAllowedError, never a native fallback", async () => {
  const env = await boot({ connectPlan: ["ok", "fail", "throw"] });
  env.port().drop();
  await flush();
  env.get(20, getDetails());
  await flush();
  assertNotAllowed(env, 20, "get");
  // connectNative throwing (the next attempt) fails the request synchronously.
  env.get(21, getDetails());
  await flush();
  assertNotAllowed(env, 21, "get");
  assert.deepStrictEqual(env.pendingKeys(), []);
  assert.strictEqual(env.completes.length, 2);
});

test("a daemon error frame is fatal for the port: disconnect, fail in-flight, backoff", async () => {
  const env = await boot();
  env.get(1, getDetails());
  await flush();
  const port = env.port();
  port.deliver({ type: "error", code: "superseded" });
  await flush();
  assert.strictEqual(port.disconnectCalls, 1, "worker disconnected the port");
  assertNotAllowed(env, 1, "get");
  assert.strictEqual(env.ports.length, 1);
  await env.clock.advance(250);
  assert.strictEqual(env.ports.length, 2);
  assert.strictEqual(env.port().posted[0].type, "hello");
});

test("a postMessage failure is treated as a disconnect", async () => {
  const env = await boot();
  const port = env.port();
  port.closed = true; // the port died without onDisconnect yet
  env.get(3, getDetails());
  await flush();
  assertNotAllowed(env, 3, "get");
  await env.clock.advance(250);
  assert.strictEqual(env.ports.length, 2);
});

// ---- storage.session (V-M4) ----------------------------------------------------------------------

test("in-flight ids are recorded in storage.session and removed on completion", async () => {
  const env = await boot();
  env.create(-5, createDetails());
  await flush();
  const entry = env.storage.get("pending:-5");
  assert.ok(entry, "recorded");
  assert.strictEqual(entry.op, "create");
  assert.strictEqual(typeof entry.instance, "string");
  assert.ok(entry.instance.length >= 16);
  env.port().deliver({ type: "result", id: 1, ok: true, body: "{}" });
  await flush();
  assert.deepStrictEqual(env.pendingKeys(), []);
});

test("restart fails another instance's leftovers but not the current instance's entries", async () => {
  const storage = new Map([
    ["pending:111", { op: "create", instance: "old-instance" }],
    ["pending:222", { op: "get", instance: "old-instance" }],
    ["pending:333", { op: "get", instance: "old-instance" }],
    ["pending:444", { op: "weird" }],
    ["pending:666", { op: "get", instance: "current-instance-nonce" }],
    ["unrelated", { keep: true }]
  ]);
  const env = await boot({ storage, deferStorageGet: true, nonce: "current-instance-nonce" });
  // The request that woke the worker is recorded before the cleanup read completes, and 333 is
  // re-delivered live by the browser to this instance.
  env.get(555, getDetails());
  env.get(333, getDetails());
  await flush();
  const current = env.storage.get("pending:555").instance;
  assert.notStrictEqual(current, "old-instance");
  env.releaseGets();
  await flush();
  assertNotAllowed(env, 111, "create");
  assertNotAllowed(env, 222, "get");
  assertNotAllowed(env, 444, "get");
  assert.strictEqual(env.completesFor(555).length, 0, "current instance entry not failed");
  assert.strictEqual(env.completesFor(333).length, 0, "live request not failed");
  assert.strictEqual(env.completesFor(666).length, 0, "current instance entry (not live) not failed");
  assert.deepStrictEqual(env.pendingKeys().sort(), ["pending:333", "pending:555", "pending:666"]);
  assert.strictEqual(env.storage.get("pending:333").instance, current);
  assert.ok(env.storage.has("unrelated"));
  // The live requests still complete normally.
  const frames = env.port().frames("request");
  env.port().deliver({ type: "result", id: frames[0].id, ok: true, body: "{\"r\":555}" });
  await flush();
  assert.strictEqual(env.completesFor(555)[0].arg.responseJson, "{\"r\":555}");
});

test("a worker restart leaves the dead instance's in-flight request failed on the next start", async () => {
  const storage = new Map();
  const env1 = await boot({ storage });
  env1.get(900, getDetails());
  await flush();
  assert.ok(storage.has("pending:900"));
  // Worker dies; the browser starts a new instance with the same session storage.
  const env2 = await boot({ storage });
  await flush();
  assertNotAllowed(env2, 900, "get");
  assert.ok(!storage.has("pending:900"));
});

// ---- forbidden surfaces --------------------------------------------------------------------------

test("no runtime.reload, onMessage or onMessageExternal (source and spies)", async () => {
  assert.ok(!/\.reload\s*\(/.test(WORKER_SRC), "no reload()");
  assert.ok(!/onMessageExternal/.test(WORKER_SRC), "no onMessageExternal");
  assert.ok(!/runtime\s*\.\s*onMessage/.test(WORKER_SRC), "no runtime.onMessage");
  assert.ok(!/onConnect(External)?\b/.test(WORKER_SRC), "no onConnect listeners");
  assert.ok(!/sendNativeMessage|sendMessage|externally_connectable/.test(WORKER_SRC));
  assert.ok(!/main\.js|broker\.js|importScripts/.test(WORKER_SRC), "no MAIN-world path");
  assert.ok(!/fetch\s*\(|XMLHttpRequest|WebSocket/.test(WORKER_SRC), "no network transport");

  const env = await boot();
  env.get(1, getDetails());
  env.create(2, createDetails());
  env.proxy.onIsUvpaaRequest.fire({ requestId: 3 });
  await flush();
  env.port().deliver({ type: "result", id: 1, ok: true, body: "{}" });
  env.port().deliver({ type: "error", code: "bad_frame" });
  await flush();
  await env.clock.advance(60000);
  const rt = env.chrome.runtime;
  assert.strictEqual(env.reloadCalls, 0);
  assert.strictEqual(rt.onMessage.count(), 0);
  assert.strictEqual(rt.onMessageExternal.count(), 0);
  assert.strictEqual(rt.onConnect.count(), 0);
  assert.strictEqual(rt.onConnectExternal.count(), 0);
  // All four proxy listeners registered synchronously during the first run.
  for (const ev of ["onCreateRequest", "onGetRequest", "onRequestCanceled", "onIsUvpaaRequest"]) {
    assert.strictEqual(env.proxy[ev].count(), 1, ev);
  }
});

test("proxy listeners are registered synchronously at top level", () => {
  const env = makeEnv();
  startWorker(env); // no await: listeners must exist before any callback runs
  for (const ev of ["onCreateRequest", "onGetRequest", "onRequestCanceled", "onIsUvpaaRequest"]) {
    assert.strictEqual(env.proxy[ev].count(), 1, ev);
  }
  assert.strictEqual(env.attachCalls, 1);
  assert.strictEqual(env.ports.length, 1, "port opened at start");
});

test("the bearer appears only in hello frames", async () => {
  const env = await boot();
  env.get(1, getDetails());
  env.create(2, createDetails());
  await flush();
  env.proxy.onRequestCanceled.fire(2);
  await env.clock.advance(20000);
  for (const f of env.port().posted) {
    if (f.type === "hello") continue;
    assert.ok(!JSON.stringify(f).includes(BEARER), `bearer leaked in ${f.type}`);
  }
});

// ---- manifest ------------------------------------------------------------------------------------

test("manifest: worker-only proxy extension with exactly the required permissions", () => {
  const m = JSON.parse(MANIFEST_SRC);
  assert.strictEqual(m.manifest_version, 3);
  assert.deepStrictEqual([...m.permissions].sort(), ["nativeMessaging", "storage", "webAuthenticationProxy"]);
  assert.strictEqual(m.permissions.length, 3);
  for (const k of ["host_permissions", "optional_permissions", "optional_host_permissions", "content_scripts",
    "web_accessible_resources", "externally_connectable", "background_page", "action", "side_panel",
    "devtools_page", "options_page", "options_ui", "chrome_url_overrides"]) {
    assert.strictEqual(m[k], undefined, `${k} must be absent`);
  }
  assert.deepStrictEqual(m.background, { service_worker: "worker.js" });
  assert.strictEqual(m.incognito, "spanning");
  assert.ok(Number(m.minimum_chrome_version) >= 116, "proxy API needs a recent Chrome");
  assert.ok(!/main\.js|broker\.js/.test(MANIFEST_SRC));
});

test("manifest: key is an RSA-2048 public SPKI giving the expected extension ID", () => {
  const m = JSON.parse(MANIFEST_SRC);
  assert.strictEqual(typeof m.key, "string");
  const der = Buffer.from(m.key, "base64");
  assert.strictEqual(der.toString("base64"), m.key, "canonical base64");
  const pub = crypto.createPublicKey({ key: der, format: "der", type: "spki" });
  assert.strictEqual(pub.type, "public");
  assert.strictEqual(pub.asymmetricKeyType, "rsa");
  assert.strictEqual(pub.asymmetricKeyDetails.modulusLength, 2048);
  const id = crypto
    .createHash("sha256")
    .update(der)
    .digest("hex")
    .slice(0, 32)
    .replace(/[0-9a-f]/g, (c) => String.fromCharCode(97 + parseInt(c, 16)));
  assert.strictEqual(id, EXPECTED_EXTENSION_ID);
});

// ---- main ----------------------------------------------------------------------------------------

(async () => {
  let passed = 0;
  const failures = [];
  for (const t of tests) {
    try {
      await t.fn();
      passed++;
      console.log(`ok   ${t.name}`);
    } catch (e) {
      failures.push(t.name);
      console.log(`FAIL ${t.name}\n     ${(e && e.stack) || e}`);
    }
  }
  console.log(`\n${passed} passed, ${failures.length} failed`);
  process.exitCode = failures.length === 0 ? 0 : 1;
})().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
