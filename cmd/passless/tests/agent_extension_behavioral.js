"use strict";

const vm = require("vm");
const assert = require("assert");
const fs = require("fs");
const path = require("path");

const ASSETS = path.join(__dirname, "..", "assets", "agent-extension");

function readTemplate(name) {
  return fs.readFileSync(path.join(ASSETS, name), "utf8");
}

function renderMain(channel) {
  return readTemplate("main.js").replace(/__PASSLESS_CHANNEL__/g, channel);
}

function renderBroker(channel) {
  return readTemplate("broker.js").replace(/__PASSLESS_CHANNEL__/g, channel);
}

function renderWorker(socketPath, bearer) {
  const bearerLiteral = JSON.stringify(bearer);
  const socketPathLiteral = JSON.stringify(socketPath);
  return readTemplate("worker.js")
    .replace(/__PASSLESS_SOCKET_PATH__/g, socketPathLiteral)
    .replace(/__PASSLESS_BEARER__/g, bearerLiteral);
}

function b64url(buf) {
  const bytes = Buffer.isBuffer(buf) ? buf : Buffer.from(buf);
  return bytes.toString("base64url");
}

let passed = 0;
let failed = 0;
const failures = [];
const pendingTests = [];

function test(name, fn) {
  pendingTests.push({ name, fn });
}

async function runAllTests() {
  for (const t of pendingTests) {
    try {
      await t.fn();
      passed++;
    } catch (e) {
      failed++;
      failures.push({ name: t.name, error: e.message || String(e) });
    }
  }
}

function flushPromises() {
  return new Promise(function(resolve) { setTimeout(resolve, 10); });
}

function makeChallenge(len) {
  return new Uint8Array(len || 32);
}

function makeCredentialId(len) {
  return new Uint8Array(len || 32);
}

function runMainTest(channel, setupFn) {
  const sandbox = {
    _originalCalled: false,
    _originalCreateCalled: false,
    _originalOptions: null,
    _postMessageCalls: [],
    _setTimeoutCalls: [],
    _clearTimeoutCalls: [],
    _timerId: 0,
  };

  const cryptoObj = {
    getRandomValues: function(arr) {
      for (let i = 0; i < arr.length; i++) arr[i] = (i * 7 + 13) & 0xff;
      return arr;
    },
  };

  // Like the browser: the methods live on CredentialsContainer.prototype, not on the instance.
  const credentialsProto = {
    get: function(options) {
      sandbox._originalCalled = true;
      sandbox._originalOptions = options;
      return Promise.resolve({ id: "original-credential" });
    },
    create: function(options) {
      sandbox._originalCreateCalled = true;
      sandbox._originalOptions = options;
      return Promise.resolve({ id: "original-created-credential" });
    },
  };
  const credentials = Object.create(credentialsProto);
  sandbox._credentialsProto = credentialsProto;

  const navigatorObj = { credentials: credentials };

  const windowListeners = {};
  const windowObj = {
    addEventListener: function(type, fn) {
      windowListeners[type] = fn;
    },
    postMessage: function(data, origin) {
      sandbox._postMessageCalls.push({ data, origin });
    },
  };

  sandbox.window = windowObj;
  sandbox.navigator = navigatorObj;
  sandbox.crypto = cryptoObj;
  sandbox.location = { hostname: "example.com", origin: "https://example.com" };
  sandbox.setTimeout = function(fn, ms) {
    const id = ++sandbox._timerId;
    sandbox._setTimeoutCalls.push({ id, fn, ms });
    return id;
  };
  sandbox.clearTimeout = function(id) {
    sandbox._clearTimeoutCalls.push(id);
  };
  sandbox.DOMException = class DOMException extends Error {
    constructor(msg, name) {
      super(msg);
      this.name = name || "DOMException";
    }
  };
  sandbox.ArrayBuffer = ArrayBuffer;
  sandbox.Uint8Array = Uint8Array;
  sandbox.Buffer = Buffer;
  sandbox.btoa = function(s) { return Buffer.from(s, "binary").toString("base64"); };
  sandbox.atob = function(s) { return Buffer.from(s, "base64").toString("binary"); };
  sandbox.Map = Map;
  sandbox.Promise = Promise;
  sandbox.TypeError = TypeError;
  sandbox.Array = Array;
  sandbox.Object = Object;
  sandbox.String = String;
  sandbox.Boolean = Boolean;
  sandbox.Number = Number;
  sandbox.JSON = JSON;
  sandbox.Math = Math;
  sandbox.parseInt = parseInt;
  sandbox.parseFloat = parseFloat;
  sandbox.undefined = undefined;
  sandbox.NaN = NaN;
  sandbox.Infinity = Infinity;

  const ctx = vm.createContext(sandbox);
  const code = renderMain(channel);
  vm.runInContext(code, ctx);

  if (setupFn) setupFn(sandbox, windowListeners, credentials);

  return sandbox;
}

function runBrokerCode(sandbox, channel) {
  const ctx = vm.createContext(sandbox);
  const code = renderBroker(channel);
  vm.runInContext(code, ctx);
}

function runBrokerTest(channel, setupFn) {
  const sandbox = {
    _chromeSendResponse: null,
    _chromeLastError: null,
  };

  const chromeObj = {
    runtime: {
      sendMessage: function(msg, cb) {
        sandbox._chromeSendMessage = msg;
        if (sandbox._chromeSendResponse) {
          cb(sandbox._chromeSendResponse);
        }
      },
      get lastError() {
        return sandbox._chromeLastError;
      },
    },
  };

  const windowListeners = {};
  const windowObj = {
    addEventListener: function(type, fn) {
      windowListeners[type] = fn;
    },
    postMessage: function(data, origin) {
      sandbox._postMessageCalls = sandbox._postMessageCalls || [];
      sandbox._postMessageCalls.push({ data, origin });
    },
  };

  const documentElement = {
    _attributes: new Set(),
    hasAttribute: function(name) { return this._attributes.has(name); },
    setAttribute: function(name) { this._attributes.add(name); },
  };
  sandbox._windowListeners = windowListeners;
  sandbox.window = windowObj;
  sandbox.document = { documentElement: documentElement };
  sandbox.chrome = chromeObj;
  sandbox.location = { origin: "https://example.com" };
  sandbox.Array = Array;
  sandbox.Set = Set;
  sandbox.Object = Object;
  sandbox.String = String;
  sandbox.Boolean = Boolean;
  sandbox.Number = Number;
  sandbox.JSON = JSON;
  sandbox.TypeError = TypeError;

  runBrokerCode(sandbox, channel);

  if (setupFn) setupFn(sandbox, windowListeners);

  return sandbox;
}

function runWorkerTest(socketPath, bearer, setupFn) {
  const sandbox = {
    _listeners: [],
    _sendResponses: [],
    _nativeMessageCalls: [],
  };

  const chromeObj = {
    runtime: {
      id: "test-extension-id",
      lastError: null,
      onMessage: {
        addListener: function(fn) {
          sandbox._listeners.push(fn);
        },
      },
      sendNativeMessage: function(host, message, callback) {
        sandbox._nativeMessageCalls.push({ host, message, callback });
        if (sandbox._nativeMessageResponse) {
          callback(sandbox._nativeMessageResponse);
        }
      },
    },
  };

  sandbox.chrome = chromeObj;
  sandbox.URL = URL;
  sandbox.Array = Array;
  sandbox.Object = Object;
  sandbox.String = String;
  sandbox.Boolean = Boolean;
  sandbox.Number = Number;
  sandbox.JSON = JSON;
  sandbox.TypeError = TypeError;
  sandbox.Error = Error;
  sandbox.Promise = Promise;

  const ctx = vm.createContext(sandbox);
  const code = renderWorker(socketPath || "/tmp/test/sock", bearer);
  vm.runInContext(code, ctx);

  if (setupFn) setupFn(sandbox);

  return sandbox;
}

function simulateMessage(listener, eventData, eventSource, eventOrigin) {
  listener({
    data: eventData,
    source: eventSource,
    origin: eventOrigin || "https://example.com",
  });
}

// ======================== MAIN.JS BEHAVIORAL TESTS ========================

test("main: intercepts publicKey get and posts to broker", async function() {
  const ch = "testchannel1";
  const sandbox = runMainTest(ch, function(sandbox, listeners, creds) {
    const p = creds.get({
      publicKey: {
        challenge: makeChallenge(32),
        rpId: "example.com",
        userVerification: "preferred",
      },
    });
    p.catch(function() {});
  });

  assert.strictEqual(sandbox._originalCalled, false);
  assert.strictEqual(sandbox._postMessageCalls.length, 1);
  const posted = sandbox._postMessageCalls[0];
  assert.strictEqual(posted.data.source, "passless-agent-main");
  assert.strictEqual(posted.data.channel, ch);
  assert.strictEqual(posted.data.request.rp_id, "example.com");
  assert.strictEqual(posted.data.request.user_verification, false);
});

test("main: passes through non-publicKey options to original get", async function() {
  const ch = "testchannel2";
  const sandbox = runMainTest(ch, function(sandbox, listeners, creds) {
    creds.get({ password: "test" });
  });
  assert.strictEqual(sandbox._originalCalled, true);
  assert.strictEqual(sandbox._postMessageCalls.length, 0);
});

test("main: base64url encoding produces correct output", async function() {
  const ch = "testchannel3";
  const challengeBytes = new Uint8Array([0xff, 0xfe, 0xfd, 0x00, 0x01, 0x02]);
  const sandbox = runMainTest(ch, function(sandbox, listeners, creds) {
    const p = creds.get({
      publicKey: {
        challenge: challengeBytes,
        rpId: "example.com",
        userVerification: "preferred",
      },
    });
    p.catch(function() {});
  });

  const expected = b64url(challengeBytes);
  const posted = sandbox._postMessageCalls[0];
  assert.strictEqual(posted.data.request.challenge_b64u, expected);
  assert.ok(!posted.data.request.challenge_b64u.includes("+"));
  assert.ok(!posted.data.request.challenge_b64u.includes("/"));
  assert.ok(!posted.data.request.challenge_b64u.includes("="));
});

test("main: rejects allowCredentials exceeding MAX_ALLOW_CREDENTIALS", async function() {
  const ch = "testchannel4";
  const tooMany = [];
  for (let i = 0; i < 65; i++) {
    tooMany.push({ type: "public-key", id: makeCredentialId(16) });
  }

  let rejected = false;
  const sandbox = runMainTest(ch, function(sandbox, listeners, creds) {
    const p = creds.get({
      publicKey: {
        challenge: makeChallenge(32),
        rpId: "example.com",
        allowCredentials: tooMany,
        userVerification: "preferred",
      },
    });
    p.catch(function(e) {
      rejected = true;
      assert.strictEqual(e.name, "NotAllowedError");
    });
  });

  await flushPromises();
  assert.strictEqual(rejected, true);
  assert.strictEqual(sandbox._postMessageCalls.length, 0);
});

test("main: rejects malformed allowCredentials entries", async function() {
  const ch = "testchannel5";

  let rejected = false;
  const sandbox = runMainTest(ch, function(sandbox, listeners, creds) {
    const p = creds.get({
      publicKey: {
        challenge: makeChallenge(32),
        rpId: "example.com",
        allowCredentials: [{ type: "public-key", id: null }],
        userVerification: "preferred",
      },
    });
    p.catch(function(e) { rejected = true; assert.strictEqual(e.name, "NotAllowedError"); });
  });

  await flushPromises();
  assert.strictEqual(rejected, true);
  assert.strictEqual(sandbox._postMessageCalls.length, 0);
});

test("main: rejects empty challenge", async function() {
  const ch = "testchannel6";

  let rejected = false;
  const sandbox = runMainTest(ch, function(sandbox, listeners, creds) {
    const p = creds.get({
      publicKey: {
        challenge: new Uint8Array(0),
        rpId: "example.com",
        userVerification: "preferred",
      },
    });
    p.catch(function(e) { rejected = true; assert.strictEqual(e.name, "NotAllowedError"); });
  });

  await flushPromises();
  assert.strictEqual(rejected, true);
  assert.strictEqual(sandbox._postMessageCalls.length, 0);
});

test("main: rejects challenge exceeding MAX_CHALLENGE_BYTES", async function() {
  const ch = "testchannel7";

  let rejected = false;
  const sandbox = runMainTest(ch, function(sandbox, listeners, creds) {
    const p = creds.get({
      publicKey: {
        challenge: makeChallenge(1025),
        rpId: "example.com",
        userVerification: "preferred",
      },
    });
    p.catch(function(e) { rejected = true; assert.strictEqual(e.name, "NotAllowedError"); });
  });

  await flushPromises();
  assert.strictEqual(rejected, true);
  assert.strictEqual(sandbox._postMessageCalls.length, 0);
});

test("main: rejects empty rpId", async function() {
  const ch = "testchannel8";

  let rejected = false;
  const sandbox = runMainTest(ch, function(sandbox, listeners, creds) {
    const p = creds.get({
      publicKey: {
        challenge: makeChallenge(32),
        rpId: "",
        userVerification: "preferred",
      },
    });
    p.catch(function(e) { rejected = true; assert.strictEqual(e.name, "NotAllowedError"); });
  });

  await flushPromises();
  assert.strictEqual(sandbox._postMessageCalls.length, 1, "empty rpId defaults to hostname");
  assert.strictEqual(sandbox._postMessageCalls[0].data.request.rp_id, "example.com");
});

test("main: rejects non-public-key credential type", async function() {
  const ch = "testchannel9";

  let rejected = false;
  const sandbox = runMainTest(ch, function(sandbox, listeners, creds) {
    const p = creds.get({
      publicKey: {
        challenge: makeChallenge(32),
        rpId: "example.com",
        allowCredentials: [{ type: "password", id: makeCredentialId(16) }],
        userVerification: "preferred",
      },
    });
    p.catch(function(e) { rejected = true; assert.strictEqual(e.name, "NotAllowedError"); });
  });

  await flushPromises();
  assert.strictEqual(rejected, true);
  assert.strictEqual(sandbox._postMessageCalls.length, 0);
});

test("main: rejects credential id exceeding MAX_CREDENTIAL_ID_BYTES", async function() {
  const ch = "testchannel10";

  let rejected = false;
  const sandbox = runMainTest(ch, function(sandbox, listeners, creds) {
    const p = creds.get({
      publicKey: {
        challenge: makeChallenge(32),
        rpId: "example.com",
        allowCredentials: [{ type: "public-key", id: makeCredentialId(257) }],
        userVerification: "preferred",
      },
    });
    p.catch(function(e) { rejected = true; assert.strictEqual(e.name, "NotAllowedError"); });
  });

  await flushPromises();
  assert.strictEqual(rejected, true);
  assert.strictEqual(sandbox._postMessageCalls.length, 0);
});

test("main: rejects invalid userVerification value", async function() {
  const ch = "testchannel11";

  let rejected = false;
  const sandbox = runMainTest(ch, function(sandbox, listeners, creds) {
    const p = creds.get({
      publicKey: {
        challenge: makeChallenge(32),
        rpId: "example.com",
        userVerification: "mandatory",
      },
    });
    p.catch(function(e) { rejected = true; assert.strictEqual(e.name, "NotAllowedError"); });
  });

  await flushPromises();
  assert.strictEqual(rejected, true);
  assert.strictEqual(sandbox._postMessageCalls.length, 0);
});

test("main: accepts all valid userVerification values", async function() {
  for (const uv of ["required", "preferred", "discouraged"]) {
    const ch = "testchannel12_" + uv;
    const sandbox = runMainTest(ch, function(sandbox, listeners, creds) {
      const p = creds.get({
        publicKey: {
          challenge: makeChallenge(32),
          rpId: "example.com",
          userVerification: uv,
        },
      });
      p.catch(function() {});
    });
    assert.strictEqual(sandbox._postMessageCalls.length, 1, "should post for uv=" + uv);
    assert.strictEqual(sandbox._postMessageCalls[0].data.request.user_verification, uv === "required");
  }
});

test("main: constructs Gitea-compatible credential from daemon response", async function() {
  const ch = "testchannel13";
  let resolvedCredential = null;

  const sandbox = runMainTest(ch, function(sandbox, listeners, creds) {
    const p = creds.get({
      publicKey: {
        challenge: makeChallenge(32),
        rpId: "example.com",
        userVerification: "preferred",
      },
    });
    p.then(function(cred) { resolvedCredential = cred; }).catch(function() {});

    const requestId = sandbox._postMessageCalls[0].data.id;
    const messageHandler = listeners["message"];
    assert.ok(messageHandler, "message listener should be registered");

    const daemonResponse = {
      credential_id_b64u: b64url(new Uint8Array([1, 2, 3])),
      authenticator_data_b64u: b64url(new Uint8Array([4, 5, 6])),
      signature_b64u: b64url(new Uint8Array([7, 8, 9])),
      client_data_json_b64u: b64url(new Uint8Array([10, 11, 12])),
      user_handle_b64u: b64url(new Uint8Array([13, 14, 15])),
    };

    simulateMessage(
      messageHandler,
      {
        source: "passless-agent-broker",
        request_id: "request-1",
        channel: ch,
        id: requestId,
        ok: true,
        response: daemonResponse,
      },
      sandbox.window,
      "https://example.com"
    );
  });

  await flushPromises();
  assert.ok(resolvedCredential, "credential should be resolved");
  assert.strictEqual(resolvedCredential.type, "public-key");
  assert.strictEqual(resolvedCredential.id, b64url(new Uint8Array([1, 2, 3])));
  assert.ok(resolvedCredential.rawId instanceof ArrayBuffer, "rawId should be ArrayBuffer");
  assert.ok(resolvedCredential.response.authenticatorData instanceof ArrayBuffer);
  assert.ok(resolvedCredential.response.clientDataJSON instanceof ArrayBuffer);
  assert.ok(resolvedCredential.response.signature instanceof ArrayBuffer);
  assert.ok(resolvedCredential.response.userHandle instanceof ArrayBuffer);
  assert.deepStrictEqual(Object.keys(resolvedCredential.getClientExtensionResults()), []);
});

test("main: malformed daemon response becomes NotAllowedError", async function() {
  const ch = "testchannel14";
  let rejectedError = null;

  const sandbox = runMainTest(ch, function(sandbox, listeners, creds) {
    const p = creds.get({
      publicKey: {
        challenge: makeChallenge(32),
        rpId: "example.com",
        userVerification: "preferred",
      },
    });
    p.catch(function(e) { rejectedError = e; });

    const requestId = sandbox._postMessageCalls[0].data.id;
    const messageHandler = listeners["message"];

    simulateMessage(
      messageHandler,
      {
        source: "passless-agent-broker",
        request_id: "request-1",
        channel: ch,
        id: requestId,
        ok: true,
        response: { bad: "data" },
      },
      sandbox.window,
      "https://example.com"
    );
  });

  await flushPromises();
  assert.ok(rejectedError, "should reject");
  assert.strictEqual(rejectedError.name, "NotAllowedError");
});

test("main: broker ok=false becomes NotAllowedError", async function() {
  const ch = "testchannel15";
  let rejectedError = null;

  const sandbox = runMainTest(ch, function(sandbox, listeners, creds) {
    const p = creds.get({
      publicKey: {
        challenge: makeChallenge(32),
        rpId: "example.com",
        userVerification: "preferred",
      },
    });
    p.catch(function(e) { rejectedError = e; });

    const requestId = sandbox._postMessageCalls[0].data.id;
    const messageHandler = listeners["message"];

    simulateMessage(
      messageHandler,
      {
        source: "passless-agent-broker",
        request_id: "request-1",
        channel: ch,
        id: requestId,
        ok: false,
        response: null,
      },
      sandbox.window,
      "https://example.com"
    );
  });

  await flushPromises();
  assert.ok(rejectedError);
  assert.strictEqual(rejectedError.name, "NotAllowedError");
});

test("main: ignores messages from wrong source", async function() {
  const ch = "testchannel16";

  const sandbox = runMainTest(ch, function(sandbox, listeners, creds) {
    const p = creds.get({
      publicKey: {
        challenge: makeChallenge(32),
        rpId: "example.com",
        userVerification: "preferred",
      },
    });
    p.catch(function() {});

    const requestId = sandbox._postMessageCalls[0].data.id;
    const messageHandler = listeners["message"];

    simulateMessage(
      messageHandler,
      {
        source: "passless-agent-broker",
        request_id: "request-1",
        channel: ch,
        id: requestId,
        ok: true,
        response: {
          credential_id_b64u: b64url(new Uint8Array([1])),
          authenticator_data_b64u: b64url(new Uint8Array([2])),
          signature_b64u: b64url(new Uint8Array([3])),
          client_data_json_b64u: b64url(new Uint8Array([4])),
        },
      },
      {},
      "https://example.com"
    );
  });

  await flushPromises();
  assert.strictEqual(sandbox._clearTimeoutCalls.length, 0);
});

test("main: ignores messages with wrong channel", async function() {
  const ch = "testchannel17";

  const sandbox = runMainTest(ch, function(sandbox, listeners, creds) {
    const p = creds.get({
      publicKey: {
        challenge: makeChallenge(32),
        rpId: "example.com",
        userVerification: "preferred",
      },
    });
    p.catch(function() {});

    const requestId = sandbox._postMessageCalls[0].data.id;
    const messageHandler = listeners["message"];

    simulateMessage(
      messageHandler,
      {
        source: "passless-agent-broker",
        request_id: "request-1",
        channel: "wrong-channel",
        id: requestId,
        ok: true,
        response: {
          credential_id_b64u: b64url(new Uint8Array([1])),
          authenticator_data_b64u: b64url(new Uint8Array([2])),
          signature_b64u: b64url(new Uint8Array([3])),
          client_data_json_b64u: b64url(new Uint8Array([4])),
        },
      },
      sandbox.window,
      "https://example.com"
    );
  });

  await flushPromises();
  assert.strictEqual(sandbox._clearTimeoutCalls.length, 0);
});

test("main: fresh object construction for each credential response", async function() {
  const credentials = [];

  for (let attempt = 0; attempt < 2; attempt++) {
    const ch = "testchannel18_" + attempt;
    const sandbox = runMainTest(ch, function(sandbox, listeners, creds) {
      let resolved = null;
      const p = creds.get({
        publicKey: {
          challenge: makeChallenge(32),
          rpId: "example.com",
          userVerification: "preferred",
        },
      });
      p.then(function(c) { resolved = c; }).catch(function() {});

      const requestId = sandbox._postMessageCalls[0].data.id;
      const messageHandler = listeners["message"];

      simulateMessage(
        messageHandler,
        {
          source: "passless-agent-broker",
        request_id: "request-1",
          channel: ch,
          id: requestId,
          ok: true,
          response: {
            credential_id_b64u: b64url(new Uint8Array([1, 2, 3])),
            authenticator_data_b64u: b64url(new Uint8Array([4, 5, 6])),
            signature_b64u: b64url(new Uint8Array([7, 8, 9])),
            client_data_json_b64u: b64url(new Uint8Array([10, 11, 12])),
          },
        },
        sandbox.window,
        "https://example.com"
      );

      credentials.push({ sandbox, getResolved: function() { return resolved; } });
    });
  }

  await flushPromises();
  assert.ok(credentials[0].getResolved() !== credentials[1].getResolved(), "each credential should be a fresh object");
  assert.ok(credentials[0].getResolved().response !== credentials[1].getResolved().response, "response objects should be distinct");
});

test("main: timeout cleanup fires NotAllowedError", async function() {
  const ch = "testchannel19";
  let rejectedError = null;
  let timerFn = null;

  const sandbox = runMainTest(ch, function(sandbox, listeners, creds) {
    const p = creds.get({
      publicKey: {
        challenge: makeChallenge(32),
        rpId: "example.com",
        userVerification: "preferred",
      },
    });
    p.catch(function(e) { rejectedError = e; });

    assert.strictEqual(sandbox._setTimeoutCalls.length, 1);
    timerFn = sandbox._setTimeoutCalls[0].fn;
    assert.strictEqual(sandbox._setTimeoutCalls[0].ms, 30000);
  });

  assert.ok(timerFn);
  timerFn();
  await flushPromises();
  assert.ok(rejectedError, "timeout should cause rejection");
  assert.strictEqual(rejectedError.name, "NotAllowedError");
});

test("main: allowCredentials with empty id rejected", async function() {
  const ch = "testchannel20";
  let rejected = false;

  const sandbox = runMainTest(ch, function(sandbox, listeners, creds) {
    const p = creds.get({
      publicKey: {
        challenge: makeChallenge(32),
        rpId: "example.com",
        allowCredentials: [{ type: "public-key", id: new Uint8Array(0) }],
        userVerification: "preferred",
      },
    });
    p.catch(function(e) { rejected = true; assert.strictEqual(e.name, "NotAllowedError"); });
  });

  await flushPromises();
  assert.strictEqual(rejected, true);
  assert.strictEqual(sandbox._postMessageCalls.length, 0);
});

test("main: valid allowCredentials are serialized correctly", async function() {
  const ch = "testchannel21";
  const credId = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);

  const sandbox = runMainTest(ch, function(sandbox, listeners, creds) {
    const p = creds.get({
      publicKey: {
        challenge: makeChallenge(32),
        rpId: "example.com",
        allowCredentials: [{ type: "public-key", id: credId }],
        userVerification: "required",
      },
    });
    p.catch(function() {});
  });

  const posted = sandbox._postMessageCalls[0];
  assert.strictEqual(posted.data.request.allow_credentials.length, 1);
  assert.strictEqual(posted.data.request.allow_credentials[0], b64url(credId));
  assert.strictEqual(posted.data.request.user_verification, true);
});

test("main: defaults userVerification to preferred when omitted", async function() {
  const ch = "testchannel22";

  const sandbox = runMainTest(ch, function(sandbox, listeners, creds) {
    const p = creds.get({
      publicKey: {
        challenge: makeChallenge(32),
        rpId: "example.com",
      },
    });
    p.catch(function() {});
  });

  const posted = sandbox._postMessageCalls[0];
  assert.strictEqual(posted.data.request.user_verification, false);
});

// ======================== BROKER.JS BEHAVIORAL TESTS ========================

test("broker: forwards valid request to chrome.runtime.sendMessage", async function() {
  const ch = "broker-ch1";
  const sandbox = runBrokerTest(ch, function(sandbox, listeners) {
    sandbox._chromeSendResponse = { ok: true, response: { data: "test" } };

    const messageHandler = listeners["message"];
    assert.ok(messageHandler);

    simulateMessage(
      messageHandler,
      {
        source: "passless-agent-main",
        channel: ch,
        id: "req-1",
        request: {
          rp_id: "example.com",
          challenge_b64u: b64url(makeChallenge(32)),
          allow_credentials: [],
          user_verification: false,
        },
      },
      sandbox.window,
      "https://example.com"
    );
  });

  assert.ok(sandbox._chromeSendMessage);
  assert.strictEqual(sandbox._chromeSendMessage.source, "passless-agent-broker");
  assert.strictEqual(sandbox._chromeSendMessage.request.rp_id, "example.com");
});

test("broker: ignores duplicate injection for the same channel", async function() {
  const ch = "broker-duplicate";
  let sendCount = 0;
  const sandbox = runBrokerTest(ch, function(sandbox) {
    sandbox.chrome.runtime.sendMessage = function(message, callback) {
      sendCount++;
      callback({ ok: true, response: { data: "test" } });
    };
  });

  runBrokerCode(sandbox, ch);

  simulateMessage(
    sandbox._windowListeners.message,
    {
      source: "passless-agent-main",
      channel: ch,
      id: "req-1",
      request: {
        rp_id: "example.com",
        challenge_b64u: b64url(makeChallenge(32)),
        allow_credentials: [],
        user_verification: false,
      },
    },
    sandbox.window,
    "https://example.com"
  );

  assert.strictEqual(sendCount, 1);
});
test("broker: rejects message from wrong source", async function() {
  const ch = "broker-ch2";
  const sandbox = runBrokerTest(ch, function(sandbox, listeners) {
    const messageHandler = listeners["message"];
    simulateMessage(
      messageHandler,
      {
        source: "passless-agent-main",
        channel: ch,
        id: "req-1",
        request: {
          rp_id: "example.com",
          challenge_b64u: "aaa",
          allow_credentials: [],
          user_verification: false,
        },
      },
      {},
      "https://example.com"
    );
  });

  assert.strictEqual(sandbox._chromeSendMessage, undefined);
});

test("broker: rejects message with wrong channel", async function() {
  const ch = "broker-ch3";
  const sandbox = runBrokerTest(ch, function(sandbox, listeners) {
    const messageHandler = listeners["message"];
    simulateMessage(
      messageHandler,
      {
        source: "passless-agent-main",
        channel: "wrong-channel",
        id: "req-1",
        request: {
          rp_id: "example.com",
          challenge_b64u: "aaa",
          allow_credentials: [],
          user_verification: false,
        },
      },
      sandbox.window,
      "https://example.com"
    );
  });

  assert.strictEqual(sandbox._chromeSendMessage, undefined);
});

test("broker: rejects message from wrong origin", async function() {
  const ch = "broker-ch4";
  const sandbox = runBrokerTest(ch, function(sandbox, listeners) {
    const messageHandler = listeners["message"];
    simulateMessage(
      messageHandler,
      {
        source: "passless-agent-main",
        channel: ch,
        id: "req-1",
        request: {
          rp_id: "example.com",
          challenge_b64u: "aaa",
          allow_credentials: [],
          user_verification: false,
        },
      },
      sandbox.window,
      "https://evil.com"
    );
  });

  assert.strictEqual(sandbox._chromeSendMessage, undefined);
});

test("broker: rejects request with invalid rp_id", async function() {
  const ch = "broker-ch5";
  const sandbox = runBrokerTest(ch, function(sandbox, listeners) {
    const messageHandler = listeners["message"];
    simulateMessage(
      messageHandler,
      {
        source: "passless-agent-main",
        channel: ch,
        id: "req-1",
        request: {
          rp_id: "",
          challenge_b64u: "aaa",
          allow_credentials: [],
          user_verification: false,
        },
      },
      sandbox.window,
      "https://example.com"
    );
  });

  assert.strictEqual(sandbox._chromeSendMessage, undefined);
});

test("broker: rejects request with too many allow_credentials", async function() {
  const ch = "broker-ch6";
  const creds = [];
  for (let i = 0; i < 65; i++) {
    creds.push("abc");
  }

  const sandbox = runBrokerTest(ch, function(sandbox, listeners) {
    const messageHandler = listeners["message"];
    simulateMessage(
      messageHandler,
      {
        source: "passless-agent-main",
        channel: ch,
        id: "req-1",
        request: {
          rp_id: "example.com",
          challenge_b64u: "aaa",
          allow_credentials: creds,
          user_verification: false,
        },
      },
      sandbox.window,
      "https://example.com"
    );
  });

  assert.strictEqual(sandbox._chromeSendMessage, undefined);
});

test("broker: rejects request with invalid user_verification", async function() {
  const ch = "broker-ch7";
  const sandbox = runBrokerTest(ch, function(sandbox, listeners) {
    const messageHandler = listeners["message"];
    simulateMessage(
      messageHandler,
      {
        source: "passless-agent-main",
        channel: ch,
        id: "req-1",
        request: {
          rp_id: "example.com",
          challenge_b64u: "aaa",
          allow_credentials: [],
          user_verification: "mandatory",
        },
      },
      sandbox.window,
      "https://example.com"
    );
  });

  assert.strictEqual(sandbox._chromeSendMessage, undefined);
});

test("broker: relays failure response back to main", async function() {
  const ch = "broker-ch8";
  const sandbox = runBrokerTest(ch, function(sandbox, listeners) {
    sandbox._chromeSendResponse = { ok: false };

    const messageHandler = listeners["message"];
    simulateMessage(
      messageHandler,
      {
        source: "passless-agent-main",
        channel: ch,
        id: "req-1",
        request: {
          rp_id: "example.com",
          challenge_b64u: b64url(makeChallenge(32)),
          allow_credentials: [],
          user_verification: false,
        },
      },
      sandbox.window,
      "https://example.com"
    );
  });

  assert.ok(sandbox._postMessageCalls);
  const relayed = sandbox._postMessageCalls[0];
  assert.strictEqual(relayed.data.ok, false);
  assert.strictEqual(relayed.data.source, "passless-agent-broker");
  assert.strictEqual(relayed.data.channel, ch);
  assert.strictEqual(relayed.data.id, "req-1");
});

test("broker: rejects oversized message JSON", async function() {
  const ch = "broker-ch9";
  const bigCreds = [];
  for (let i = 0; i < 64; i++) {
    bigCreds.push("x".repeat(512));
  }

  const sandbox = runBrokerTest(ch, function(sandbox, listeners) {
    const messageHandler = listeners["message"];
    simulateMessage(
      messageHandler,
      {
        source: "passless-agent-main",
        channel: ch,
        id: "req-1",
        request: {
          rp_id: "example.com",
          challenge_b64u: "x".repeat(2048),
          allow_credentials: bigCreds,
          user_verification: false,
        },
      },
      sandbox.window,
      "https://example.com"
    );
  });

  assert.strictEqual(sandbox._chromeSendMessage, undefined);
});

test("broker: rejects message with empty id", async function() {
  const ch = "broker-ch10";
  const sandbox = runBrokerTest(ch, function(sandbox, listeners) {
    const messageHandler = listeners["message"];
    simulateMessage(
      messageHandler,
      {
        source: "passless-agent-main",
        channel: ch,
        id: "",
        request: {
          rp_id: "example.com",
          challenge_b64u: "aaa",
          allow_credentials: [],
          user_verification: false,
        },
      },
      sandbox.window,
      "https://example.com"
    );
  });

  assert.strictEqual(sandbox._chromeSendMessage, undefined);
});

test("broker: rejects credential id that is not a string", async function() {
  const ch = "broker-ch11";
  const sandbox = runBrokerTest(ch, function(sandbox, listeners) {
    const messageHandler = listeners["message"];
    simulateMessage(
      messageHandler,
      {
        source: "passless-agent-main",
        channel: ch,
        id: "req-1",
        request: {
          rp_id: "example.com",
          challenge_b64u: "aaa",
          allow_credentials: [42],
          user_verification: false,
        },
      },
      sandbox.window,
      "https://example.com"
    );
  });

  assert.strictEqual(sandbox._chromeSendMessage, undefined);
});

// ======================== WORKER.JS BEHAVIORAL TESTS ========================

test("worker: validates sender.url must be valid URL", async function() {
  const sandbox = runWorkerTest("/tmp/test/sock", "testtoken", function(sandbox) {
    const listener = sandbox._listeners[0];
    assert.ok(listener);

    let response = null;
    const sender = { url: "not-a-url" };
    listener(
      {
        source: "passless-agent-broker",
        request_id: "request-1",
        request: {
          rp_id: "example.com",
          challenge_b64u: "aaa",
          allow_credentials: [],
          user_verification: false,
        },
      },
      sender,
      function(r) { response = r; }
    );

    assert.ok(response);
    assert.strictEqual(response.ok, false);
  });
});

test("worker: validates sender.url must be https:", async function() {
  const sandbox = runWorkerTest("/tmp/test/sock", "testtoken", function(sandbox) {
    const listener = sandbox._listeners[0];

    let response = null;
    const sender = { url: "http://example.com/page" };
    listener(
      {
        source: "passless-agent-broker",
        request_id: "request-1",
        request: {
          rp_id: "example.com",
          challenge_b64u: "aaa",
          allow_credentials: [],
          user_verification: false,
        },
      },
      sender,
      function(r) { response = r; }
    );

    assert.strictEqual(response.ok, false);
  });
});

test("worker: validates sender.id against chrome.runtime.id", async function() {
  const sandbox = runWorkerTest("/tmp/test/sock", "testtoken", function(sandbox) {
    const listener = sandbox._listeners[0];

    let response = null;
    const sender = { url: "https://example.com/page", id: "wrong-extension-id" };
    listener(
      {
        source: "passless-agent-broker",
        request_id: "request-1",
        request: {
          rp_id: "example.com",
          challenge_b64u: "aaa",
          allow_credentials: [],
          user_verification: false,
        },
      },
      sender,
      function(r) { response = r; }
    );

    assert.strictEqual(response.ok, false);
  });
});

test("worker: accepts matching sender.id", async function() {
  const sandbox = runWorkerTest("/tmp/test/sock", "testtoken", function(sandbox) {
    sandbox._nativeMessageResponse = {
      ok: true,
      json: function() { return Promise.resolve({ sign_assertion_result: { credential_id_b64u: "abc" } }); },
    };

    const listener = sandbox._listeners[0];
    const sender = { url: "https://example.com/page", id: "test-extension-id" };
    listener(
      {
        source: "passless-agent-broker",
        request_id: "request-1",
        request: {
          rp_id: "example.com",
          challenge_b64u: "aaa",
          allow_credentials: [],
          user_verification: false,
        },
      },
      sender,
      function() {}
    );
  });

  await flushPromises();
  assert.strictEqual(sandbox._nativeMessageCalls.length, 1);
});

test("worker: coalesces duplicate request IDs", async function() {
  const sandbox = runWorkerTest("/tmp/test/sock", "testtoken");
  const listener = sandbox._listeners[0];
  const sender = { url: "https://example.com/page", id: "test-extension-id" };
  const message = {
    source: "passless-agent-broker",
    request_id: "duplicate-request",
    request: {
      rp_id: "example.com",
      challenge_b64u: "aaa",
      allow_credentials: [],
      user_verification: false,
    },
  };
  const responses = [];

  assert.strictEqual(listener(message, sender, function(response) { responses.push(response); }), true);
  assert.strictEqual(listener(message, sender, function(response) { responses.push(response); }), true);
  assert.strictEqual(sandbox._nativeMessageCalls.length, 1);

  sandbox._nativeMessageCalls[0].callback({
    body: JSON.stringify({ sign_assertion_result: { credential_id_b64u: "abc" } }),
  });

  assert.strictEqual(responses.length, 2);
  assert.deepStrictEqual(responses[0], responses[1]);
});
test("worker: derives origin and cross_origin from sender.url", async function() {
  const sandbox = runWorkerTest("/tmp/test/sock", "testtoken", function(sandbox) {
    sandbox._nativeMessageResponse = {
      ok: true,
      json: function() { return Promise.resolve({}); },
    };

    const listener = sandbox._listeners[0];
    const sender = {
      url: "https://sub.example.com/page",
      tab: { url: "https://sub.example.com/top" },
      frameId: 0,
    };
    listener(
      {
        source: "passless-agent-broker",
        request_id: "request-1",
        request: {
          rp_id: "example.com",
          challenge_b64u: "aaa",
          allow_credentials: [],
          user_verification: false,
        },
      },
      sender,
      function() {}
    );
  });

  await flushPromises();
  assert.strictEqual(sandbox._nativeMessageCalls.length, 1);
  const body = JSON.parse(sandbox._nativeMessageCalls[0].message.body);
  assert.strictEqual(body.origin, "https://sub.example.com");
  assert.strictEqual(body.top_origin, "https://sub.example.com");
  assert.strictEqual(body.cross_origin, false);
});

test("worker: computes cross_origin=true for a cross-origin subframe", async function() {
  const sandbox = runWorkerTest("/tmp/test/sock", "testtoken", function(sandbox) {
    sandbox._nativeMessageResponse = {
      ok: true,
      json: function() { return Promise.resolve({}); },
    };

    const listener = sandbox._listeners[0];
    const sender = {
      url: "https://evil.com/page",
      tab: { url: "https://example.com/top" },
      frameId: 7,
    };
    listener(
      {
        source: "passless-agent-broker",
        request_id: "request-1",
        request: {
          rp_id: "example.com",
          challenge_b64u: "aaa",
          allow_credentials: [],
          user_verification: false,
        },
      },
      sender,
      function() {}
    );
  });

  await flushPromises();
  const body = JSON.parse(sandbox._nativeMessageCalls[0].message.body);
  assert.strictEqual(body.origin, "https://evil.com");
  assert.strictEqual(body.top_origin, "https://example.com");
  assert.strictEqual(body.cross_origin, true);
});

test("worker: constructs fresh request object (not passthrough)", async function() {
  const sandbox = runWorkerTest("/tmp/test/sock", "testtoken", function(sandbox) {
    sandbox._nativeMessageResponse = {
      ok: true,
      json: function() { return Promise.resolve({}); },
    };

    const listener = sandbox._listeners[0];
    const originalRequest = {
      rp_id: "example.com",
      challenge_b64u: "aaa",
      allow_credentials: [],
      user_verification: false,
      extra_field: "should_not_appear",
    };
    const sender = { url: "https://example.com/page" };
    listener(
      { source: "passless-agent-broker",
        request_id: "request-1", request: originalRequest },
      sender,
      function() {}
    );
  });

  await flushPromises();
  const body = JSON.parse(sandbox._nativeMessageCalls[0].message.body);
  assert.strictEqual(body.extra_field, undefined);
  assert.ok(body.origin);
  assert.ok(typeof body.cross_origin === "boolean");
});

test("worker: sends bearer token in native message", async function() {
  const bearerToken = "my-secret-bearer-token";
  const sandbox = runWorkerTest("/tmp/test/sock", bearerToken, function(sandbox) {
    sandbox._nativeMessageResponse = { body: "{}" };

    const listener = sandbox._listeners[0];
    const sender = { url: "https://example.com/page" };
    listener(
      {
        source: "passless-agent-broker",
        request_id: "request-1",
        request: {
          rp_id: "example.com",
          challenge_b64u: "aaa",
          allow_credentials: [],
          user_verification: false,
        },
      },
      sender,
      function() {}
    );
  });

  await flushPromises();
  assert.strictEqual(sandbox._nativeMessageCalls.length, 1);
  assert.strictEqual(sandbox._nativeMessageCalls[0].message.bearer, bearerToken);
});

test("worker: bearer token with special characters is safely injected", async function() {
  const bearerToken = 'tok"en\\with\nspecial\u00e9';
  const sandbox = runWorkerTest("/tmp/test/sock", bearerToken, function(sandbox) {
    sandbox._nativeMessageResponse = { body: "{}" };

    const listener = sandbox._listeners[0];
    const sender = { url: "https://example.com/page" };
    listener(
      {
        source: "passless-agent-broker",
        request_id: "request-1",
        request: {
          rp_id: "example.com",
          challenge_b64u: "aaa",
          allow_credentials: [],
          user_verification: false,
        },
      },
      sender,
      function() {}
    );
  });

  await flushPromises();
  assert.strictEqual(sandbox._nativeMessageCalls.length, 1);
  assert.strictEqual(sandbox._nativeMessageCalls[0].message.bearer, bearerToken);
});

test("worker: sends correct socket path in native message", async function() {
  const sandbox = runWorkerTest("/var/run/passless/sign/sock", "tok", function(sandbox) {
    sandbox._nativeMessageResponse = { body: "{}" };

    const listener = sandbox._listeners[0];
    const sender = { url: "https://example.com/page" };
    listener(
      {
        source: "passless-agent-broker",
        request_id: "request-1",
        request: {
          rp_id: "example.com",
          challenge_b64u: "aaa",
          allow_credentials: [],
          user_verification: false,
        },
      },
      sender,
      function() {}
    );
  });

  await flushPromises();
  assert.strictEqual(sandbox._nativeMessageCalls[0].message.socket_path, "/var/run/passless/sign/sock");
  assert.strictEqual(sandbox._nativeMessageCalls[0].message.path, "/sign");
});

test("worker: rejects rp_id exceeding MAX_RP_ID_LEN", async function() {
  const sandbox = runWorkerTest("/tmp/test/sock", "tok", function(sandbox) {
    const listener = sandbox._listeners[0];
    let response = null;
    const sender = { url: "https://example.com/page" };
    listener(
      {
        source: "passless-agent-broker",
        request_id: "request-1",
        request: {
          rp_id: "x".repeat(254),
          challenge_b64u: "aaa",
          allow_credentials: [],
          user_verification: false,
        },
      },
      sender,
      function(r) { response = r; }
    );

    assert.strictEqual(response.ok, false);
  });
});

test("worker: rejects challenge_b64u exceeding MAX_CHALLENGE_B64U_LEN", async function() {
  const sandbox = runWorkerTest("/tmp/test/sock", "tok", function(sandbox) {
    const listener = sandbox._listeners[0];
    let response = null;
    const sender = { url: "https://example.com/page" };
    listener(
      {
        source: "passless-agent-broker",
        request_id: "request-1",
        request: {
          rp_id: "example.com",
          challenge_b64u: "x".repeat(2049),
          allow_credentials: [],
          user_verification: false,
        },
      },
      sender,
      function(r) { response = r; }
    );

    assert.strictEqual(response.ok, false);
  });
});

test("worker: rejects allow_credentials exceeding MAX_ALLOW_CREDENTIALS", async function() {
  const sandbox = runWorkerTest("/tmp/test/sock", "tok", function(sandbox) {
    const listener = sandbox._listeners[0];
    let response = null;
    const creds = [];
    for (let i = 0; i < 65; i++) {
      creds.push("abc");
    }
    const sender = { url: "https://example.com/page" };
    listener(
      {
        source: "passless-agent-broker",
        request_id: "request-1",
        request: {
          rp_id: "example.com",
          challenge_b64u: "aaa",
          allow_credentials: creds,
          user_verification: false,
        },
      },
      sender,
      function(r) { response = r; }
    );

    assert.strictEqual(response.ok, false);
  });
});

test("worker: rejects invalid user_verification", async function() {
  const sandbox = runWorkerTest("/tmp/test/sock", "tok", function(sandbox) {
    const listener = sandbox._listeners[0];
    let response = null;
    const sender = { url: "https://example.com/page" };
    listener(
      {
        source: "passless-agent-broker",
        request_id: "request-1",
        request: {
          rp_id: "example.com",
          challenge_b64u: "aaa",
          allow_credentials: [],
          user_verification: "mandatory",
        },
      },
      sender,
      function(r) { response = r; }
    );

    assert.strictEqual(response.ok, false);
  });
});

test("worker: accepts all valid user_verification values", async function() {
  for (const uv of ["required", "preferred", "discouraged"]) {
    const sandbox = runWorkerTest("/tmp/test/sock", "tok", function(sandbox) {
      sandbox._nativeMessageResponse = {
        ok: true,
        json: function() { return Promise.resolve({}); },
      };

      const listener = sandbox._listeners[0];
      const sender = { url: "https://example.com/page" };
      listener(
        {
          source: "passless-agent-broker",
        request_id: "request-1",
          request: {
            rp_id: "example.com",
            challenge_b64u: "aaa",
            allow_credentials: [],
            user_verification: uv === "required",
          },
        },
        sender,
        function() {}
      );
    });

    await flushPromises();
    assert.strictEqual(sandbox._nativeMessageCalls.length, 1, "should send native message for uv=" + uv);
    const body = JSON.parse(sandbox._nativeMessageCalls[0].message.body);
    assert.strictEqual(body.user_verification, uv === "required");
  }
});

test("worker: malformed daemon response results in ok:false", async function() {
  let asyncResponse = null;
  const sandbox = runWorkerTest("/tmp/test/sock", "tok", function(sandbox) {
    sandbox._nativeMessageResponse = {
      error: "invalid_daemon_response",
    };

    const listener = sandbox._listeners[0];
    const sender = { url: "https://example.com/page" };
    listener(
      {
        source: "passless-agent-broker",
        request_id: "request-1",
        request: {
          rp_id: "example.com",
          challenge_b64u: "aaa",
          allow_credentials: [],
          user_verification: false,
        },
      },
      sender,
      function(r) { asyncResponse = r; }
    );
  });

  await flushPromises();
  assert.ok(asyncResponse, "should have sent a response");
  assert.strictEqual(asyncResponse.ok, false);
});

test("worker: native messaging error results in ok:false", async function() {
  let asyncResponse = null;
  const sandbox = runWorkerTest("/tmp/test/sock", "tok", function(sandbox) {
    sandbox.chrome.runtime.sendNativeMessage = function(host, message, callback) {
      sandbox.chrome.runtime.lastError = { message: "host not found" };
      callback(null);
      sandbox.chrome.runtime.lastError = null;
    };

    const listener = sandbox._listeners[0];
    const sender = { url: "https://example.com/page" };
    const result = listener(
      {
        source: "passless-agent-broker",
        request_id: "request-1",
        request: {
          rp_id: "example.com",
          challenge_b64u: "aaa",
          allow_credentials: [],
          user_verification: false,
        },
      },
      sender,
      function(r) { asyncResponse = r; }
    );

    assert.strictEqual(result, true);
  });

  await flushPromises();
  assert.ok(asyncResponse, "should have sent async response");
  assert.strictEqual(asyncResponse.ok, false);
});

test("worker: rejects request body exceeding MAX_REQUEST_BYTES", async function() {
  const sandbox = runWorkerTest("/tmp/test/sock", "tok", function(sandbox) {
    const listener = sandbox._listeners[0];
    let response = null;
    const bigCreds = [];
    for (let i = 0; i < 64; i++) {
      bigCreds.push("x".repeat(512));
    }
    const sender = { url: "https://example.com/page" };
    listener(
      {
        source: "passless-agent-broker",
        request_id: "request-1",
        request: {
          rp_id: "example.com",
          challenge_b64u: "x".repeat(2048),
          allow_credentials: bigCreds,
          user_verification: false,
        },
      },
      sender,
      function(r) { response = r; }
    );

    assert.strictEqual(response.ok, false);
  });
});

test("worker: rejects message from wrong source", async function() {
  const sandbox = runWorkerTest("/tmp/test/sock", "tok", function(sandbox) {
    const listener = sandbox._listeners[0];
    let called = false;
    const sender = { url: "https://example.com/page" };
    listener(
      {
        source: "wrong-source",
        request: {
          rp_id: "example.com",
          challenge_b64u: "aaa",
          allow_credentials: [],
          user_verification: false,
        },
      },
      sender,
      function() { called = true; }
    );

    assert.strictEqual(called, false);
  });
});

test("worker: rejects message without request", async function() {
  const sandbox = runWorkerTest("/tmp/test/sock", "tok", function(sandbox) {
    const listener = sandbox._listeners[0];
    let called = false;
    const sender = { url: "https://example.com/page" };
    listener(
      { source: "passless-agent-broker" },
      sender,
      function() { called = true; }
    );

    assert.strictEqual(called, false);
  });
});

test("worker: rejects credential id exceeding MAX_CREDENTIAL_ID_B64U_LEN", async function() {
  const sandbox = runWorkerTest("/tmp/test/sock", "tok", function(sandbox) {
    const listener = sandbox._listeners[0];
    let response = null;
    const sender = { url: "https://example.com/page" };
    listener(
      {
        source: "passless-agent-broker",
        request_id: "request-1",
        request: {
          rp_id: "example.com",
          challenge_b64u: "aaa",
          allow_credentials: ["x".repeat(513)],
          user_verification: false,
        },
      },
      sender,
      function(r) { response = r; }
    );

    assert.strictEqual(response.ok, false);
  });
});

test("worker: rejects credential id that is not a string", async function() {
  const sandbox = runWorkerTest("/tmp/test/sock", "tok", function(sandbox) {
    const listener = sandbox._listeners[0];
    let response = null;
    const sender = { url: "https://example.com/page" };
    listener(
      {
        source: "passless-agent-broker",
        request_id: "request-1",
        request: {
          rp_id: "example.com",
          challenge_b64u: "aaa",
          allow_credentials: [42],
          user_verification: false,
        },
      },
      sender,
      function(r) { response = r; }
    );

    assert.strictEqual(response.ok, false);
  });
});

// ======================== BEARER ESCAPING TESTS ========================

test("bearer: generated worker JS parses with special-character token", async function() {
  const token = 'tok"with\\special\nchars\u00e9';
  const rendered = renderWorker("/tmp/test/sock", token);
  const sandbox = { chrome: { runtime: { id: "x", onMessage: { addListener: function() {} } } } };
  const ctx = vm.createContext(sandbox);
  vm.runInContext(rendered, ctx);
});

test("bearer: token does not appear literally in main.js or broker.js", async function() {
  const token = "super-secret-bearer-xyz";
  const mainRendered = renderMain("somechannel");
  const brokerRendered = renderBroker("somechannel");
  assert.ok(!mainRendered.includes(token), "main.js should not contain bearer token");
  assert.ok(!brokerRendered.includes(token), "broker.js should not contain bearer token");
});

// ======================== USER VERIFICATION BOUNDS ========================

test("uv: main defaults empty string userVerification to preferred", async function() {
  const ch = "uv-test-1";
  const sandbox = runMainTest(ch, function(sandbox, listeners, creds) {
    const p = creds.get({
      publicKey: {
        challenge: makeChallenge(32),
        rpId: "example.com",
        userVerification: "",
      },
    });
    p.catch(function() {});
  });
  await flushPromises();
  assert.strictEqual(sandbox._postMessageCalls.length, 1);
  assert.strictEqual(sandbox._postMessageCalls[0].data.request.user_verification, false);
});

test("uv: broker rejects numeric user_verification", async function() {
  const ch = "uv-test-2";
  const sandbox = runBrokerTest(ch, function(sandbox, listeners) {
    const messageHandler = listeners["message"];
    simulateMessage(
      messageHandler,
      {
        source: "passless-agent-main",
        channel: ch,
        id: "req-1",
        request: {
          rp_id: "example.com",
          challenge_b64u: "aaa",
          allow_credentials: [],
          user_verification: 42,
        },
      },
      sandbox.window,
      "https://example.com"
    );
  });
  assert.strictEqual(sandbox._chromeSendMessage, undefined);
});

// ---- P2: no native fallback, fail closed (ADR 0014 §7, invariant 25) ----

function publicKeyGetOptions() {
  return {
    publicKey: {
      challenge: makeChallenge(32),
      rpId: "example.com",
      userVerification: "preferred",
    },
  };
}

function publicKeyCreateOptions() {
  return {
    publicKey: {
      challenge: makeChallenge(32),
      rp: { id: "example.com", name: "Example" },
      user: { id: new Uint8Array([1, 2, 3, 4]), name: "alice", displayName: "Alice" },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      userVerification: "preferred",
    },
  };
}

const DAEMON_FAILURES = [
  { ok: false, error: "transport_error" },
  { ok: false, error: "broker_unavailable" },
  { ok: false, error: "invalid_daemon_response" },
  { ok: false, error: "forbidden" },
  { ok: false, error: "human_interaction_required", fallback: true },
  { ok: false, response: null, fallback: true },
];

for (const kind of ["get", "create"]) {
  DAEMON_FAILURES.forEach(function(failure, index) {
    test("main: " + kind + " never calls the original after daemon failure #" + index, async function() {
      const ch = "nofallback-" + kind + "-" + index;
      let rejectedError = null;
      let resolved = false;

      const sandbox = runMainTest(ch, function(sandbox, listeners, creds) {
        const p = kind === "get" ? creds.get(publicKeyGetOptions()) : creds.create(publicKeyCreateOptions());
        p.then(function() { resolved = true; }, function(e) { rejectedError = e; });

        simulateMessage(
          listeners["message"],
          Object.assign({
            source: "passless-agent-broker",
            channel: ch,
            id: sandbox._postMessageCalls[0].data.id,
            type: kind,
          }, failure),
          sandbox.window,
          "https://example.com"
        );
      });

      await flushPromises();
      assert.strictEqual(resolved, false);
      assert.ok(rejectedError, "must reject");
      assert.strictEqual(rejectedError.name, "NotAllowedError");
      assert.strictEqual(sandbox._originalCalled, false, "original get must not be called");
      assert.strictEqual(sandbox._originalCreateCalled, false, "original create must not be called");
    });
  });

  test("main: " + kind + " never calls the original after a timeout", async function() {
    const ch = "nofallback-timeout-" + kind;
    let rejectedError = null;
    let timerFn = null;
    const sandbox = runMainTest(ch, function(sandbox, listeners, creds) {
      const p = kind === "get" ? creds.get(publicKeyGetOptions()) : creds.create(publicKeyCreateOptions());
      p.catch(function(e) { rejectedError = e; });
      timerFn = sandbox._setTimeoutCalls[0].fn;
    });
    timerFn();
    await flushPromises();
    assert.ok(rejectedError);
    assert.strictEqual(rejectedError.name, "NotAllowedError");
    assert.strictEqual(sandbox._originalCalled, false);
    assert.strictEqual(sandbox._originalCreateCalled, false);
  });

  test("main: " + kind + " in a frame without proven delegation is rejected, not native", async function() {
    const ch = "nofallback-frame-" + kind;
    let rejectedError = null;
    const sandbox = runMainTest(ch, function(sandbox, listeners, creds) {
      sandbox.window.top = {};
      sandbox.window.self = sandbox.window;
      sandbox.document = {};
      const p = kind === "get" ? creds.get(publicKeyGetOptions()) : creds.create(publicKeyCreateOptions());
      p.catch(function(e) { rejectedError = e; });
    });
    await flushPromises();
    assert.ok(rejectedError);
    assert.strictEqual(rejectedError.name, "NotAllowedError");
    assert.strictEqual(sandbox._originalCalled, false);
    assert.strictEqual(sandbox._originalCreateCalled, false);
    assert.strictEqual(sandbox._postMessageCalls.length, 0);
  });
}

test("main: conditional mediation is rejected, not native", async function() {
  const ch = "nofallback-conditional";
  let rejectedError = null;
  const sandbox = runMainTest(ch, function(sandbox, listeners, creds) {
    const options = publicKeyGetOptions();
    options.mediation = "conditional";
    creds.get(options).catch(function(e) { rejectedError = e; });
  });
  await flushPromises();
  assert.ok(rejectedError);
  assert.strictEqual(rejectedError.name, "NotAllowedError");
  assert.strictEqual(sandbox._originalCalled, false);
  assert.strictEqual(sandbox._postMessageCalls.length, 0);
});

test("main: non-WebAuthn create passes through (not an authenticator path)", async function() {
  const sandbox = runMainTest("passthrough-create", function(sandbox, listeners, creds) {
    creds.create({ password: { id: "x" } });
  });
  assert.strictEqual(sandbox._originalCreateCalled, true);
});

test("broker: never forwards a fallback flag and forwards ancestor origins", async function() {
  const ch = "p2-broker-1";
  const sandbox = runBrokerTest(ch, function(sandbox, listeners) {
    sandbox.location.ancestorOrigins = ["https://top.example"];
    sandbox._chromeSendResponse = { ok: false, error: "human_interaction_required", fallback: true };
    simulateMessage(
      listeners["message"],
      {
        source: "passless-agent-main",
        channel: ch,
        id: "req-1",
        request: { rp_id: "example.com", challenge_b64u: "aaa", allow_credentials: [], user_verification: false },
      },
      sandbox.window,
      "https://example.com"
    );
  });
  assert.deepStrictEqual(Array.from(sandbox._chromeSendMessage.ancestor_origins), ["https://top.example"]);
  const reply = sandbox._postMessageCalls[0].data;
  assert.strictEqual(reply.ok, false);
  assert.ok(!("fallback" in reply), "fallback must not be relayed");
});

test("worker: daemon human_interaction_required is a plain failure without fallback", async function() {
  const sandbox = runWorkerTest("/tmp/test/sock", "testtoken", function(sandbox) {
    sandbox._nativeMessageResponse = { error: "human_interaction_required" };
  });
  let response = null;
  sandbox._listeners[0](
    {
      source: "passless-agent-broker",
      request_id: "p2-fallback-1",
      request: { rp_id: "example.com", challenge_b64u: "aaa", allow_credentials: [], user_verification: false },
    },
    { url: "https://example.com/page", tab: { url: "https://example.com/top" }, frameId: 0 },
    function(r) { response = r; }
  );
  await flushPromises();
  assert.ok(response);
  assert.strictEqual(response.ok, false);
  assert.ok(!("fallback" in response));
});

function workerCrossOrigin(sender, ancestorOrigins) {
  const sandbox = runWorkerTest("/tmp/test/sock", "testtoken", function(sandbox) {
    sandbox._nativeMessageResponse = { body: "{}" };
  });
  sandbox._listeners[0](
    {
      source: "passless-agent-broker",
      request_id: "p2-cross-" + Math.random(),
      ancestor_origins: ancestorOrigins,
      request: { rp_id: "example.com", challenge_b64u: "aaa", allow_credentials: [], user_verification: false },
    },
    sender,
    function() {}
  );
  assert.strictEqual(sandbox._nativeMessageCalls.length, 1);
  return JSON.parse(sandbox._nativeMessageCalls[0].message.body);
}

test("worker: same-origin subframe with matching ancestors is not cross-origin", async function() {
  const body = workerCrossOrigin(
    { url: "https://example.com/frame", tab: { url: "https://example.com/top" }, frameId: 3 },
    ["https://example.com"]
  );
  assert.strictEqual(body.cross_origin, false);
});

test("worker: an intermediate cross-origin ancestor makes a same-origin leaf cross-origin", async function() {
  const body = workerCrossOrigin(
    { url: "https://example.com/frame", tab: { url: "https://example.com/top" }, frameId: 3 },
    ["https://other.example", "https://example.com"]
  );
  assert.strictEqual(body.cross_origin, true);
});

test("worker: unknown ancestors or top origin in a subframe fail closed", async function() {
  assert.strictEqual(
    workerCrossOrigin({ url: "https://example.com/f", tab: { url: "https://example.com/t" }, frameId: 3 }, null).cross_origin,
    true
  );
  assert.strictEqual(
    workerCrossOrigin({ url: "https://example.com/f", frameId: 3 }, ["https://example.com"]).cross_origin,
    true
  );
  assert.strictEqual(
    workerCrossOrigin({ url: "https://example.com/f" }, ["https://example.com"]).cross_origin,
    true
  );
});

test("worker: top-level frame is never cross-origin", async function() {
  const body = workerCrossOrigin(
    { url: "https://example.com/page", tab: { url: "https://example.com/page" }, frameId: 0 },
    []
  );
  assert.strictEqual(body.cross_origin, false);
});

// ---- Interim MAIN-world hardening (H1, H2, L1) ----

test("main: CredentialsContainer.prototype.get/create are overridden too", async function() {
  let getError = null;
  let createError = null;
  const sandbox = runMainTest("proto-1", function(sandbox, listeners, creds) {
    const proto = sandbox._credentialsProto;
    proto.get.call(creds, publicKeyGetOptions()).catch(function(e) { getError = e; });
    proto.create.call(creds, publicKeyCreateOptions()).catch(function(e) { createError = e; });
  });
  assert.strictEqual(sandbox._originalCalled, false, "prototype get must not reach native");
  assert.strictEqual(sandbox._originalCreateCalled, false, "prototype create must not reach native");
  assert.strictEqual(sandbox._postMessageCalls.length, 2, "both went to the broker");
});

test("main: overrides cannot be deleted or reassigned", async function() {
  const sandbox = runMainTest("lock-1", function(sandbox, listeners, creds) {
    const proto = sandbox._credentialsProto;
    for (const target of [creds, proto]) {
      for (const name of ["get", "create"]) {
        const installed = target[name];
        assert.strictEqual(Reflect.deleteProperty(target, name), false, "delete " + name);
        assert.throws(function() { target[name] = function() { return "page"; }; }, TypeError);
        assert.throws(function() {
          Object.defineProperty(target, name, { value: function() {} });
        }, TypeError);
        assert.strictEqual(target[name], installed);
      }
    }
    // After the failed delete, the call still goes through the override.
    assert.throws(function() { delete creds.get; }, TypeError); // strict mode
    creds.get(publicKeyGetOptions()).catch(function() {});
  });
  assert.strictEqual(sandbox._originalCalled, false);
  assert.strictEqual(sandbox._postMessageCalls.length, 1);
});

test("main: publicKey getter that returns undefined first never reaches native with a publicKey", async function() {
  let reads = 0;
  const sandbox = runMainTest("getter-1", function(sandbox, listeners, creds) {
    const real = publicKeyGetOptions().publicKey;
    const options = {};
    Object.defineProperty(options, "publicKey", {
      enumerable: true,
      get: function() { reads++; return reads === 1 ? undefined : real; },
    });
    creds.get(options).catch(function() {});
  });
  assert.strictEqual(reads, 1, "publicKey must be read exactly once");
  assert.strictEqual(sandbox._originalCalled, true, "the page said there is no publicKey: non-WebAuthn passthrough");
  assert.ok(!("publicKey" in sandbox._originalOptions), "native must get a copy without publicKey");
});

test("main: Proxy that hides publicKey from `in` never hands it to native", async function() {
  const real = publicKeyGetOptions().publicKey;
  const sandbox = runMainTest("getter-2", function(sandbox, listeners, creds) {
    const options = new Proxy({ mediation: "optional" }, {
      has: function(t, k) { return k === "publicKey" ? false : k in t; },
      get: function(t, k) { return k === "publicKey" ? real : t[k]; },
    });
    creds.get(options).catch(function() {});
  });
  assert.strictEqual(sandbox._originalCalled, true);
  assert.ok(!("publicKey" in sandbox._originalOptions));
  assert.strictEqual(sandbox._originalOptions.mediation, "optional");
});

test("main: publicKey and signal are read once and the page object never reaches native", async function() {
  let pkReads = 0;
  let signalReads = 0;
  const sandbox = runMainTest("getter-3", function(sandbox, listeners, creds) {
    const options = {};
    Object.defineProperty(options, "publicKey", {
      enumerable: true,
      get: function() { pkReads++; return publicKeyGetOptions().publicKey; },
    });
    Object.defineProperty(options, "signal", {
      enumerable: true,
      get: function() { signalReads++; return undefined; },
    });
    creds.get(options).catch(function() {});
  });
  assert.strictEqual(pkReads, 1);
  assert.strictEqual(signalReads, 1);
  assert.strictEqual(sandbox._originalCalled, false);
  assert.strictEqual(sandbox._postMessageCalls.length, 1);
});

test("main: publicKey present as null or garbage is refused, never native", async function() {
  const errors = [];
  const sandbox = runMainTest("garbage-1", function(sandbox, listeners, creds) {
    creds.get({ publicKey: null }).catch(function(e) { errors.push(e); });
    creds.get({ publicKey: 5 }).catch(function(e) { errors.push(e); });
  });
  await flushPromises();
  assert.strictEqual(sandbox._originalCalled, false);
  assert.strictEqual(errors.length, 2);
});

test("main: postMessage failure (opaque origin) rejects NotAllowedError and clears the timer", async function() {
  let rejected = null;
  const sandbox = runMainTest("opaque-1", function(sandbox, listeners, creds) {
    sandbox.window.postMessage = function() { throw new Error("SyntaxError: target origin 'null'"); };
    creds.get(publicKeyGetOptions()).catch(function(e) { rejected = e; });
  });
  await flushPromises();
  assert.ok(rejected, "must reject");
  assert.strictEqual(rejected.name, "NotAllowedError");
  assert.strictEqual(sandbox._setTimeoutCalls.length, 1);
  assert.deepStrictEqual(sandbox._clearTimeoutCalls, [sandbox._setTimeoutCalls[0].id], "timer cleared immediately");
  assert.strictEqual(sandbox._originalCalled, false);
});

test("manifest: injects into about:blank, srcdoc, blob and localhost frames", async function() {
  const manifest = JSON.parse(readTemplate("manifest.json"));
  assert.ok(parseInt(manifest.minimum_chrome_version, 10) >= 119);
  for (const entry of manifest.content_scripts) {
    assert.strictEqual(entry.all_frames, true);
    assert.strictEqual(entry.match_about_blank, true);
    assert.strictEqual(entry.match_origin_as_fallback, true);
    assert.strictEqual(entry.run_at, "document_start");
    assert.ok(entry.matches.indexOf("https://*/*") !== -1);
    assert.ok(entry.matches.indexOf("http://localhost/*") !== -1);
    assert.ok(entry.matches.indexOf("http://127.0.0.1/*") !== -1);
  }
  assert.ok(manifest.host_permissions.indexOf("http://localhost/*") !== -1);
});

// ======================== REPORT ========================

(async function() {
  await runAllTests();
  console.log("\n=== Agent Extension Behavioral Tests ===");
  console.log("Passed: " + passed);
  console.log("Failed: " + failed);
  if (failures.length > 0) {
    console.log("\nFailures:");
    for (const f of failures) {
      console.log("  FAIL: " + f.name);
      console.log("    " + f.error);
    }
  }
  process.exit(failed > 0 ? 1 : 0);
})();
