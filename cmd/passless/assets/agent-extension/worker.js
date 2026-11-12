// Passless agent extension: service worker (ADR 0014 §4.4, §11; wire protocol v2).
//
// The worker is the only part of the extension. It intercepts WebAuthn through
// chrome.webAuthenticationProxy and relays every request to the Passless daemon over one
// chrome.runtime.connectNative port. It never builds or edits a response: the daemon's responseJson
// is passed to complete*Request verbatim. It registers no runtime message listeners, so the bearer is
// never reachable from a page or another extension.
//
// The daemon templates the three constants below with JSON string literals when it writes the file.
(function (bearer, socketPath, buildVersion) {
  "use strict";

  var NATIVE_HOST = "rs.passless.sign_proxy";
  var PROTOCOL_VERSION = 2;
  var KEEPALIVE_MS = 20000;
  var BACKOFF_INITIAL_MS = 250;
  var BACKOFF_MAX_MS = 10000;
  var STATE_PROBE_TIMEOUT_MS = 2000;
  // Wire frames are capped at 1 MiB (UTF-8 JSON). A larger request would make the relay close the
  // port and fail every other in-flight request, so it is refused locally.
  var MAX_FRAME_BYTES = 1048576;
  var MAX_WIRE_ID = 0xffffffff;
  var PENDING_PREFIX = "pending:";
  var DOM_NAMES = ["NotAllowedError", "NotSupportedError", "InvalidStateError", "SecurityError", "AbortError"];
  var ERROR_MESSAGE = "The operation either timed out or was not allowed.";

  var proxy = {};
  try {
    proxy = chrome.webAuthenticationProxy || {};
  } catch (e) {
    proxy = {};
  }
  var instance = randomNonce();

  var attached = false;
  var incognitoAllowed = false;
  var stateKnown = false;
  var attachDone = false;
  var incognitoDone = false;
  var stateTimer = null;

  var conn = null; // {port, helloSent, outbox, keepaliveTimer, reported}
  var reconnectTimer = null;
  var backoffMs = BACKOFF_INITIAL_MS;

  var nextWireId = 1;
  var byWireId = new Map(); // wire id -> entry
  var byRequestId = new Map(); // proxy requestId -> entry

  // ---- helpers ----------------------------------------------------------------------------------

  function randomNonce() {
    try {
      if (typeof crypto !== "undefined" && crypto.randomUUID) return crypto.randomUUID();
      var bytes = new Uint8Array(16);
      crypto.getRandomValues(bytes);
      var hex = "";
      for (var i = 0; i < bytes.length; i++) hex += (bytes[i] < 16 ? "0" : "") + bytes[i].toString(16);
      return hex;
    } catch (e) {
      // No CSPRNG: the nonce only separates worker instances, it is not a secret.
      return String(Date.now()) + "-" + String(Math.random()).slice(2);
    }
  }

  // Reads (and thereby consumes) chrome.runtime.lastError inside a callback.
  function lastErrorMessage() {
    try {
      var le = chrome.runtime && chrome.runtime.lastError;
      if (!le) return null;
      return typeof le.message === "string" ? le.message : String(le);
    } catch (e) {
      return "lastError unreadable";
    }
  }

  function utf8Length(s) {
    var n = 0;
    for (var i = 0; i < s.length; i++) {
      var c = s.charCodeAt(i);
      if (c < 0x80) n += 1;
      else if (c < 0x800) n += 2;
      else if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length) {
        var d = s.charCodeAt(i + 1);
        if (d >= 0xdc00 && d <= 0xdfff) {
          n += 4;
          i++;
        } else n += 3;
      } else n += 3;
    }
    return n;
  }

  function isPlainObject(v) {
    return v !== null && typeof v === "object" && !Array.isArray(v);
  }

  // ---- completion -------------------------------------------------------------------------------

  function callComplete(op, arg) {
    var fn = op === "create" ? "completeCreateRequest" : "completeGetRequest";
    try {
      proxy[fn](arg, function () {
        lastErrorMessage(); // "Invalid requestId" after a cancel or a browser-side timeout is expected
      });
    } catch (e) {
      // The request may already be gone; nothing else to do.
    }
  }

  function completeError(op, requestId, name) {
    var dom = DOM_NAMES.indexOf(name) !== -1 ? name : "NotAllowedError";
    callComplete(op, { requestId: requestId, error: { name: dom, message: ERROR_MESSAGE } });
  }

  function completeOk(op, requestId, responseJson) {
    callComplete(op, { requestId: requestId, responseJson: responseJson });
  }

  // ---- pending ids in storage.session (V-M4) ----------------------------------------------------

  function storageArea() {
    try {
      return chrome.storage && chrome.storage.session ? chrome.storage.session : null;
    } catch (e) {
      return null;
    }
  }

  function recordPending(requestId, op) {
    var area = storageArea();
    if (!area) return;
    var item = {};
    item[PENDING_PREFIX + requestId] = { op: op, instance: instance };
    try {
      area.set(item, function () {
        lastErrorMessage();
      });
    } catch (e) {
      // Best effort: losing the record only loses the restart cleanup for this id.
    }
  }

  function forgetPending(keys) {
    var area = storageArea();
    if (!area || keys.length === 0) return;
    try {
      area.remove(keys, function () {
        lastErrorMessage();
      });
    } catch (e) {
      // Best effort.
    }
  }

  // Fails the requests a previous worker instance left in flight. Entries of this instance are kept:
  // the request that woke this worker may already be recorded.
  function failStaleRequests() {
    var area = storageArea();
    if (!area) return;
    try {
      area.get(null, function (items) {
        if (lastErrorMessage() || !isPlainObject(items)) return;
        var stale = [];
        Object.keys(items).forEach(function (key) {
          if (key.indexOf(PENDING_PREFIX) !== 0) return;
          var value = items[key];
          if (isPlainObject(value) && value.instance === instance) return;
          var requestId = Number(key.slice(PENDING_PREFIX.length));
          // A live request of this instance may reuse the key; its record now belongs to us.
          if (byRequestId.has(requestId)) return;
          stale.push(key);
          if (!Number.isInteger(requestId)) return;
          var op = isPlainObject(value) && value.op === "create" ? "create" : "get";
          completeError(op, requestId, "NotAllowedError");
        });
        forgetPending(stale);
      });
    } catch (e) {
      // Best effort.
    }
  }

  // ---- in-flight bookkeeping --------------------------------------------------------------------

  function forget(entry) {
    if (byWireId.get(entry.wireId) === entry) byWireId.delete(entry.wireId);
    if (byRequestId.get(entry.requestId) === entry) byRequestId.delete(entry.requestId);
    forgetPending([PENDING_PREFIX + entry.requestId]);
  }

  function failEntry(entry) {
    forget(entry);
    completeError(entry.op, entry.requestId, "NotAllowedError");
  }

  // ---- native port ------------------------------------------------------------------------------

  function helloFrame() {
    return {
      type: "hello",
      v: PROTOCOL_VERSION,
      build_version: buildVersion,
      bearer: bearer,
      attached: attached,
      incognito_allowed: incognitoAllowed,
      socket: socketPath
    };
  }

  function post(c, frame) {
    try {
      c.port.postMessage(frame);
      return true;
    } catch (e) {
      handleDisconnect(c);
      return false;
    }
  }

  function sendHello(c) {
    c.reported = { attached: attached, incognitoAllowed: incognitoAllowed };
    if (!post(c, helloFrame())) return;
    c.helloSent = true;
    var queued = c.outbox;
    c.outbox = [];
    for (var i = 0; i < queued.length; i++) {
      if (conn !== c) return;
      if (!post(c, queued[i])) return;
    }
  }

  // Frames posted before the hello are queued and flushed right after it.
  function send(c, frame) {
    if (!c.helloSent) {
      c.outbox.push(frame);
      return;
    }
    post(c, frame);
  }

  function connect() {
    if (conn) return conn;
    if (reconnectTimer !== null) {
      clearTimeout(reconnectTimer);
      reconnectTimer = null;
    }
    var port;
    try {
      port = chrome.runtime.connectNative(NATIVE_HOST);
    } catch (e) {
      port = null;
    }
    if (!port) {
      scheduleReconnect();
      return null;
    }
    var c = { port: port, helloSent: false, outbox: [], keepaliveTimer: null, reported: null };
    conn = c;
    try {
      port.onMessage.addListener(function (msg) {
        handleMessage(c, msg);
      });
      port.onDisconnect.addListener(function () {
        lastErrorMessage();
        handleDisconnect(c);
      });
    } catch (e) {
      handleDisconnect(c);
      return null;
    }
    c.keepaliveTimer = setInterval(function () {
      if (conn === c && c.helloSent) post(c, { type: "keepalive" });
    }, KEEPALIVE_MS);
    if (stateKnown) sendHello(c);
    return conn === c ? c : null;
  }

  function scheduleReconnect() {
    if (reconnectTimer !== null || conn) return;
    var delay = backoffMs;
    backoffMs = Math.min(backoffMs * 2, BACKOFF_MAX_MS);
    reconnectTimer = setTimeout(function () {
      reconnectTimer = null;
      connect();
    }, delay);
  }

  // Port closed by the browser or the relay, a failed post, or a fatal daemon error. Every in-flight
  // request fails with NotAllowedError; nothing is resumed (the daemon consumed their replay keys).
  function handleDisconnect(c) {
    if (conn !== c) return;
    conn = null;
    if (c.keepaliveTimer !== null) clearInterval(c.keepaliveTimer);
    c.keepaliveTimer = null;
    c.outbox = [];
    try {
      c.port.disconnect();
    } catch (e) {
      // Already disconnected.
    }
    var entries = [];
    byWireId.forEach(function (entry) {
      if (entry.conn === c) entries.push(entry);
    });
    entries.forEach(failEntry);
    scheduleReconnect();
  }

  function handleMessage(c, msg) {
    if (conn !== c || !isPlainObject(msg) || typeof msg.type !== "string") return;
    switch (msg.type) {
      case "hello":
        if (msg.v === PROTOCOL_VERSION) backoffMs = BACKOFF_INITIAL_MS;
        return;
      case "keepalive":
        return;
      case "error":
        handleDisconnect(c);
        return;
      case "result":
        handleResult(c, msg);
        return;
      default:
        return;
    }
  }

  function handleResult(c, msg) {
    if (typeof msg.id !== "number") return;
    var entry = byWireId.get(msg.id);
    if (!entry || entry.conn !== c) return;
    forget(entry);
    if (msg.ok === true && typeof msg.body === "string") {
      completeOk(entry.op, entry.requestId, msg.body);
      return;
    }
    if (msg.ok === false && isPlainObject(msg.error)) {
      completeError(entry.op, entry.requestId, msg.error.dom);
      return;
    }
    completeError(entry.op, entry.requestId, "NotAllowedError");
  }

  // ---- attach and incognito state ---------------------------------------------------------------

  function isAlreadyAttached(message) {
    return typeof message === "string" && /already attached/i.test(message) && !/another/i.test(message);
  }

  function markStateKnown() {
    if (stateTimer !== null) {
      clearTimeout(stateTimer);
      stateTimer = null;
    }
    if (!stateKnown) {
      stateKnown = true;
      if (conn && !conn.helloSent) sendHello(conn);
      return;
    }
    // A state change after the hello is reported with a repeated hello on the same port.
    if (conn && conn.helloSent && conn.reported &&
        (conn.reported.attached !== attached || conn.reported.incognitoAllowed !== incognitoAllowed)) {
      sendHello(conn);
    }
  }

  function probeDone() {
    if ((attachDone && incognitoDone) || stateKnown) markStateKnown();
  }

  function probeState() {
    stateTimer = setTimeout(function () {
      stateTimer = null;
      markStateKnown();
    }, STATE_PROBE_TIMEOUT_MS);

    try {
      proxy.attach(function (error) {
        var le = lastErrorMessage();
        if (le) attached = isAlreadyAttached(le);
        else attached = error === undefined || error === null || error === "" || isAlreadyAttached(error);
        attachDone = true;
        probeDone();
      });
    } catch (e) {
      attached = false;
      attachDone = true;
      probeDone();
    }

    try {
      chrome.extension.isAllowedIncognitoAccess(function (allowed) {
        incognitoAllowed = !lastErrorMessage() && allowed === true;
        incognitoDone = true;
        probeDone();
      });
    } catch (e) {
      incognitoAllowed = false;
      incognitoDone = true;
      probeDone();
    }
  }

  // ---- proxy events -----------------------------------------------------------------------------

  // Extracts only what the request frame carries besides the verbatim body. The origin comes from
  // the browser-supplied remoteDesktopClientOverride and nowhere else.
  function extract(op, json) {
    var details;
    try {
      details = JSON.parse(json);
    } catch (e) {
      return null;
    }
    if (!isPlainObject(details) || !isPlainObject(details.extensions)) return null;
    var override = details.extensions.remoteDesktopClientOverride;
    if (!isPlainObject(override)) return null;
    if (typeof override.origin !== "string" || override.origin.length === 0) return null;
    if (typeof override.sameOriginWithAncestors !== "boolean") return null;
    if (op === "get" && details.mediation === "conditional") return null;
    var timeout = details.timeout;
    return {
      origin: override.origin,
      crossOrigin: !override.sameOriginWithAncestors,
      timeoutMs: Number.isSafeInteger(timeout) && timeout >= 0 ? timeout : null
    };
  }

  function handleRequest(op, info) {
    if (!isPlainObject(info) || !Number.isInteger(info.requestId)) return;
    var requestId = info.requestId;
    if (byRequestId.has(requestId)) return; // duplicate delivery of a request already in flight
    if (typeof info.requestDetailsJson !== "string") {
      completeError(op, requestId, "NotAllowedError");
      return;
    }
    var fields = extract(op, info.requestDetailsJson);
    if (!fields || nextWireId > MAX_WIRE_ID) {
      completeError(op, requestId, "NotAllowedError");
      return;
    }
    var frame = {
      type: "request",
      id: nextWireId,
      op: op,
      timeout_ms: fields.timeoutMs,
      origin: fields.origin,
      cross_origin: fields.crossOrigin,
      body: info.requestDetailsJson
    };
    if (utf8Length(JSON.stringify(frame)) > MAX_FRAME_BYTES) {
      completeError(op, requestId, "NotAllowedError");
      return;
    }
    nextWireId++;

    var c = connect();
    if (!c) {
      completeError(op, requestId, "NotAllowedError");
      return;
    }
    var entry = { wireId: frame.id, requestId: requestId, op: op, conn: c };
    byWireId.set(entry.wireId, entry);
    byRequestId.set(requestId, entry);
    recordPending(requestId, op);
    send(c, frame);
  }

  function handleCanceled(requestId) {
    var entry = byRequestId.get(requestId);
    if (!entry) return;
    forget(entry);
    var c = entry.conn;
    if (conn !== c) return;
    if (!c.helloSent) {
      // Not sent yet: drop it instead of sending a request followed by its abort.
      c.outbox = c.outbox.filter(function (frame) {
        return !(frame.type === "request" && frame.id === entry.wireId);
      });
      return;
    }
    post(c, { type: "abort", id: entry.wireId });
  }

  function handleIsUvpaa(info) {
    if (!isPlainObject(info) || !Number.isInteger(info.requestId)) return;
    try {
      proxy.completeIsUvpaaRequest({ requestId: info.requestId, isUvpaa: false }, function () {
        lastErrorMessage();
      });
    } catch (e) {
      // Nothing else to do.
    }
  }

  // Listeners are registered synchronously at top level, so a request wakes a stopped worker.
  function addListener(name, fn) {
    try {
      proxy[name].addListener(fn);
    } catch (e) {
      // The event is missing in this browser; the request it carries cannot reach us.
    }
  }

  addListener("onCreateRequest", function (info) {
    handleRequest("create", info);
  });
  addListener("onGetRequest", function (info) {
    handleRequest("get", info);
  });
  addListener("onRequestCanceled", handleCanceled);
  addListener("onIsUvpaaRequest", handleIsUvpaa);

  failStaleRequests();
  probeState();
  connect();
})(__PASSLESS_BEARER__, __PASSLESS_SOCKET_PATH__, __PASSLESS_BUILD_VERSION__);
