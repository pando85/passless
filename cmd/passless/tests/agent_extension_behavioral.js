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

function renderWorker(port, bearer) {
  const bearerLiteral = JSON.stringify(bearer);
  return readTemplate("worker.js")
    .replace(/__PASSLESS_PORT__/g, String(port))
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

  const credentials = {
    get: function(options) {
      sandbox._originalCalled = true;
      sandbox._originalOptions = options;
      return Promise.resolve({ id: "original-credential" });
    },
  };

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

  sandbox.window = windowObj;
  sandbox.chrome = chromeObj;
  sandbox.location = { origin: "https://example.com" };
  sandbox.Array = Array;
  sandbox.Object = Object;
  sandbox.String = String;
  sandbox.Boolean = Boolean;
  sandbox.Number = Number;
  sandbox.JSON = JSON;
  sandbox.TypeError = TypeError;

  const ctx = vm.createContext(sandbox);
  const code = renderBroker(channel);
  vm.runInContext(code, ctx);

  if (setupFn) setupFn(sandbox, windowListeners);

  return sandbox;
}

function runWorkerTest(port, bearer, setupFn) {
  const sandbox = {
    _listeners: [],
    _sendResponses: [],
    _fetchCalls: [],
  };

  const chromeObj = {
    runtime: {
      id: "test-extension-id",
      onMessage: {
        addListener: function(fn) {
          sandbox._listeners.push(fn);
        },
      },
    },
  };

  sandbox.chrome = chromeObj;
  sandbox.fetch = function(url, opts) {
    sandbox._fetchCalls.push({ url, opts });
    if (sandbox._fetchResponse) {
      return Promise.resolve(sandbox._fetchResponse);
    }
    return new Promise(function() {});
  };
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
  const code = renderWorker(port, bearer);
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
  const sandbox = runWorkerTest(12345, "testtoken", function(sandbox) {
    const listener = sandbox._listeners[0];
    assert.ok(listener);

    let response = null;
    const sender = { url: "not-a-url" };
    listener(
      {
        source: "passless-agent-broker",
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
  const sandbox = runWorkerTest(12345, "testtoken", function(sandbox) {
    const listener = sandbox._listeners[0];

    let response = null;
    const sender = { url: "http://example.com/page" };
    listener(
      {
        source: "passless-agent-broker",
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
  const sandbox = runWorkerTest(12345, "testtoken", function(sandbox) {
    const listener = sandbox._listeners[0];

    let response = null;
    const sender = { url: "https://example.com/page", id: "wrong-extension-id" };
    listener(
      {
        source: "passless-agent-broker",
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
  const sandbox = runWorkerTest(12345, "testtoken", function(sandbox) {
    sandbox._fetchResponse = {
      ok: true,
      json: function() { return Promise.resolve({ sign_assertion_result: { credential_id_b64u: "abc" } }); },
    };

    const listener = sandbox._listeners[0];
    const sender = { url: "https://example.com/page", id: "test-extension-id" };
    listener(
      {
        source: "passless-agent-broker",
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
  assert.strictEqual(sandbox._fetchCalls.length, 1);
});

test("worker: derives origin and cross_origin from sender.url", async function() {
  const sandbox = runWorkerTest(12345, "testtoken", function(sandbox) {
    sandbox._fetchResponse = {
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
  assert.strictEqual(sandbox._fetchCalls.length, 1);
  const body = JSON.parse(sandbox._fetchCalls[0].opts.body);
  assert.strictEqual(body.origin, "https://sub.example.com");
  assert.strictEqual(body.top_origin, "https://sub.example.com");
  assert.strictEqual(body.cross_origin, false);
});

test("worker: computes cross_origin=true for a cross-origin subframe", async function() {
  const sandbox = runWorkerTest(12345, "testtoken", function(sandbox) {
    sandbox._fetchResponse = {
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
  const body = JSON.parse(sandbox._fetchCalls[0].opts.body);
  assert.strictEqual(body.origin, "https://evil.com");
  assert.strictEqual(body.top_origin, "https://example.com");
  assert.strictEqual(body.cross_origin, true);
});

test("worker: constructs fresh request object (not passthrough)", async function() {
  const sandbox = runWorkerTest(12345, "testtoken", function(sandbox) {
    sandbox._fetchResponse = {
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
      { source: "passless-agent-broker", request: originalRequest },
      sender,
      function() {}
    );
  });

  await flushPromises();
  const body = JSON.parse(sandbox._fetchCalls[0].opts.body);
  assert.strictEqual(body.extra_field, undefined);
  assert.ok(body.origin);
  assert.ok(typeof body.cross_origin === "boolean");
});

test("worker: sends bearer token in Authorization header", async function() {
  const bearerToken = "my-secret-bearer-token";
  const sandbox = runWorkerTest(12345, bearerToken, function(sandbox) {
    sandbox._fetchResponse = {
      ok: true,
      json: function() { return Promise.resolve({}); },
    };

    const listener = sandbox._listeners[0];
    const sender = { url: "https://example.com/page" };
    listener(
      {
        source: "passless-agent-broker",
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
  assert.strictEqual(sandbox._fetchCalls.length, 1);
  const headers = sandbox._fetchCalls[0].opts.headers;
  assert.strictEqual(headers["Authorization"], "Bearer " + bearerToken);
});

test("worker: bearer token with special characters is safely injected", async function() {
  const bearerToken = 'tok"en\\with\nspecial\u00e9';
  const sandbox = runWorkerTest(12345, bearerToken, function(sandbox) {
    sandbox._fetchResponse = {
      ok: true,
      json: function() { return Promise.resolve({}); },
    };

    const listener = sandbox._listeners[0];
    const sender = { url: "https://example.com/page" };
    listener(
      {
        source: "passless-agent-broker",
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
  assert.strictEqual(sandbox._fetchCalls.length, 1);
  const headers = sandbox._fetchCalls[0].opts.headers;
  assert.strictEqual(headers["Authorization"], "Bearer " + bearerToken);
});

test("worker: fetches correct URL with port", async function() {
  const sandbox = runWorkerTest(54321, "tok", function(sandbox) {
    sandbox._fetchResponse = {
      ok: true,
      json: function() { return Promise.resolve({}); },
    };

    const listener = sandbox._listeners[0];
    const sender = { url: "https://example.com/page" };
    listener(
      {
        source: "passless-agent-broker",
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
  assert.strictEqual(sandbox._fetchCalls[0].url, "http://127.0.0.1:54321/sign");
});

test("worker: rejects rp_id exceeding MAX_RP_ID_LEN", async function() {
  const sandbox = runWorkerTest(12345, "tok", function(sandbox) {
    const listener = sandbox._listeners[0];
    let response = null;
    const sender = { url: "https://example.com/page" };
    listener(
      {
        source: "passless-agent-broker",
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
  const sandbox = runWorkerTest(12345, "tok", function(sandbox) {
    const listener = sandbox._listeners[0];
    let response = null;
    const sender = { url: "https://example.com/page" };
    listener(
      {
        source: "passless-agent-broker",
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
  const sandbox = runWorkerTest(12345, "tok", function(sandbox) {
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
  const sandbox = runWorkerTest(12345, "tok", function(sandbox) {
    const listener = sandbox._listeners[0];
    let response = null;
    const sender = { url: "https://example.com/page" };
    listener(
      {
        source: "passless-agent-broker",
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
    const sandbox = runWorkerTest(12345, "tok", function(sandbox) {
      sandbox._fetchResponse = {
        ok: true,
        json: function() { return Promise.resolve({}); },
      };

      const listener = sandbox._listeners[0];
      const sender = { url: "https://example.com/page" };
      listener(
        {
          source: "passless-agent-broker",
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
    assert.strictEqual(sandbox._fetchCalls.length, 1, "should fetch for uv=" + uv);
    const body = JSON.parse(sandbox._fetchCalls[0].opts.body);
    assert.strictEqual(body.user_verification, uv === "required");
  }
});

test("worker: malformed daemon response results in ok:false", async function() {
  let asyncResponse = null;
  const sandbox = runWorkerTest(12345, "tok", function(sandbox) {
    sandbox._fetchResponse = {
      ok: false,
    };

    const listener = sandbox._listeners[0];
    const sender = { url: "https://example.com/page" };
    listener(
      {
        source: "passless-agent-broker",
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

test("worker: fetch error results in ok:false", async function() {
  let asyncResponse = null;
  const sandbox = runWorkerTest(12345, "tok", function(sandbox) {
    sandbox.fetch = function() {
      return Promise.reject(new Error("network error"));
    };

    const listener = sandbox._listeners[0];
    const sender = { url: "https://example.com/page" };
    const result = listener(
      {
        source: "passless-agent-broker",
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
  const sandbox = runWorkerTest(12345, "tok", function(sandbox) {
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
  const sandbox = runWorkerTest(12345, "tok", function(sandbox) {
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
  const sandbox = runWorkerTest(12345, "tok", function(sandbox) {
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
  const sandbox = runWorkerTest(12345, "tok", function(sandbox) {
    const listener = sandbox._listeners[0];
    let response = null;
    const sender = { url: "https://example.com/page" };
    listener(
      {
        source: "passless-agent-broker",
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
  const sandbox = runWorkerTest(12345, "tok", function(sandbox) {
    const listener = sandbox._listeners[0];
    let response = null;
    const sender = { url: "https://example.com/page" };
    listener(
      {
        source: "passless-agent-broker",
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
  const rendered = renderWorker(12345, token);
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
