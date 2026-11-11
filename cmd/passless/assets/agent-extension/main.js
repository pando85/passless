(function(channel) {
  "use strict";

  var MAX_ALLOW_CREDENTIALS = 64;
  var MAX_CHALLENGE_BYTES = 1024;
  var MAX_RP_ID_LEN = 253;
  var MAX_CREDENTIAL_ID_BYTES = 256;
  var MAX_ALGORITHMS = 16;
  var DEFAULT_TIMEOUT_MS = 30000;
  var MAX_TIMEOUT_MS = 120000;
  var MAX_EXTENSIONS = 32;
  var MAX_EXTENSION_NAME_LEN = 64;

  var credentials = navigator.credentials;
  if (!credentials || typeof credentials.get !== "function") return;

  // The native functions are captured once, in this closure. Only non-WebAuthn calls ever reach them.
  var originalGet = credentials.get;
  var originalCreate = typeof credentials.create === "function" ? credentials.create : null;
  var pending = new Map();

  function b64urlEncode(bytes) {
    var binary = "";
    for (var i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function b64urlDecode(value) {
    var encoded = value.replace(/-/g, "+").replace(/_/g, "/");
    while (encoded.length % 4) encoded += "=";
    var binary = atob(encoded);
    var bytes = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
  }

  function toBytes(value) {
    if (value instanceof ArrayBuffer) return new Uint8Array(value);
    if (ArrayBuffer.isView(value)) {
      return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    }
    throw new TypeError("expected BufferSource");
  }

  function domError(name, message) {
    return new DOMException(message, name);
  }

  function notAllowed() {
    return domError("NotAllowedError", "The operation either timed out or was not allowed.");
  }

  // DOMException names the daemon may choose (ADR 0014 sections 10.2-10.3 and 11). Anything else, and every
  // transport failure, is NotAllowedError. Each name has one fixed message, so the page cannot tell a policy denial,
  // a used-up budget, a replay or a busy daemon apart.
  var DAEMON_DOM_NAMES = ["NotAllowedError", "NotSupportedError", "InvalidStateError", "SecurityError", "AbortError"];
  var DOM_MESSAGES = {
    NotSupportedError: "The authenticator does not support a requested option.",
    InvalidStateError: "The authenticator already contains a credential in excludeCredentials.",
    SecurityError: "The origin is not valid for the relying party.",
    AbortError: "The operation was aborted."
  };

  function daemonError(message) {
    var name = typeof message.dom === "string" && DAEMON_DOM_NAMES.indexOf(message.dom) !== -1 ? message.dom : "NotAllowedError";
    if (name === "NotAllowedError") return notAllowed();
    return domError(name, DOM_MESSAGES[name]);
  }

  // Names of the requested client extensions (never their inputs); the daemon rejects ones it cannot honor.
  function extensionNames(extensions) {
    if (extensions === undefined || extensions === null) return [];
    if (typeof extensions !== "object") throw new TypeError("invalid extensions");
    var names = Object.keys(extensions);
    if (names.length > MAX_EXTENSIONS) throw new TypeError("too many extensions");
    for (var i = 0; i < names.length; i++) {
      if (names[i].length === 0 || names[i].length > MAX_EXTENSION_NAME_LEN) throw new TypeError("invalid extension name");
    }
    return names;
  }

  function abortError() {
    return domError("AbortError", "The operation was aborted.");
  }

  function requestId() {
    var bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return b64urlEncode(bytes);
  }

  function timeoutFor(timeout) {
    if (!Number.isFinite(timeout) || timeout <= 0) return DEFAULT_TIMEOUT_MS;
    return Math.min(Math.floor(timeout), MAX_TIMEOUT_MS);
  }

  function policyAllowsWebAuthn(feature) {
    if (window.top === window.self) return true;
    var policy = document.permissionsPolicy || document.featurePolicy;
    // Cross-origin autonomous authentication is security-sensitive. If the
    // browser cannot prove that WebAuthn was delegated to this frame, the
    // request is refused (never handed to the native browser, ADR 0014 §7).
    if (!policy || typeof policy.allowsFeature !== "function") return false;
    return policy.allowsFeature(feature);
  }

  function serialize(publicKey) {
    var challenge = toBytes(publicKey.challenge);
    if (challenge.length === 0 || challenge.length > MAX_CHALLENGE_BYTES) {
      throw new TypeError("invalid challenge length");
    }

    var rpId = publicKey.rpId || location.hostname;
    if (typeof rpId !== "string" || rpId.length === 0 || rpId.length > MAX_RP_ID_LEN) {
      throw new TypeError("invalid rpId");
    }

    var allowedUv = ["required", "preferred", "discouraged"];
    var uv = publicKey.userVerification || "preferred";
    if (allowedUv.indexOf(uv) === -1) throw new TypeError("invalid userVerification");

    var allowCredentials = [];
    if (Array.isArray(publicKey.allowCredentials)) {
      if (publicKey.allowCredentials.length > MAX_ALLOW_CREDENTIALS) {
        throw new TypeError("too many allowCredentials");
      }
      for (var i = 0; i < publicKey.allowCredentials.length; i++) {
        var credential = publicKey.allowCredentials[i];
        if (!credential || credential.type !== "public-key" || !credential.id) {
          throw new TypeError("malformed allowCredentials entry");
        }
        var idBytes = toBytes(credential.id);
        if (idBytes.length === 0 || idBytes.length > MAX_CREDENTIAL_ID_BYTES) {
          throw new TypeError("invalid credential id length");
        }
        allowCredentials.push(b64urlEncode(idBytes));
      }
    }

    return {
      rp_id: rpId,
      challenge_b64u: b64urlEncode(challenge),
      allow_credentials: allowCredentials,
      user_verification: uv === "required",
      extensions: extensionNames(publicKey.extensions),
      timeout_ms: timeoutFor(publicKey.timeout)
    };
  }

  function serializeCreate(publicKey) {
    if (!publicKey.rp || !publicKey.user) throw new TypeError("missing RP or user");
    var challenge = toBytes(publicKey.challenge);
    if (challenge.length === 0 || challenge.length > MAX_CHALLENGE_BYTES) {
      throw new TypeError("invalid challenge length");
    }

    var rpId = publicKey.rp.id || location.hostname;
    if (typeof rpId !== "string" || rpId.length === 0 || rpId.length > MAX_RP_ID_LEN) {
      throw new TypeError("invalid rpId");
    }

    var userId = toBytes(publicKey.user.id);
    if (userId.length === 0 || userId.length > 64) throw new TypeError("invalid userId length");

    var allowedUv = ["required", "preferred", "discouraged"];
    var selection = publicKey.authenticatorSelection || {};
    var uv = selection.userVerification || "preferred";
    if (allowedUv.indexOf(uv) === -1) throw new TypeError("invalid userVerification");

    if (!Array.isArray(publicKey.pubKeyCredParams) || publicKey.pubKeyCredParams.length === 0 || publicKey.pubKeyCredParams.length > MAX_ALGORITHMS) {
      throw new TypeError("invalid pubKeyCredParams");
    }
    var algorithms = [];
    for (var p = 0; p < publicKey.pubKeyCredParams.length; p++) {
      var param = publicKey.pubKeyCredParams[p];
      if (!param || param.type !== "public-key" || !Number.isInteger(param.alg)) {
        throw new TypeError("malformed pubKeyCredParams entry");
      }
      algorithms.push(param.alg);
    }

    var excludeCredentials = [];
    if (Array.isArray(publicKey.excludeCredentials)) {
      if (publicKey.excludeCredentials.length > MAX_ALLOW_CREDENTIALS) {
        throw new TypeError("too many excludeCredentials");
      }
      for (var i = 0; i < publicKey.excludeCredentials.length; i++) {
        var credential = publicKey.excludeCredentials[i];
        if (!credential || credential.type !== "public-key" || !credential.id) {
          throw new TypeError("malformed excludeCredentials entry");
        }
        var idBytes = toBytes(credential.id);
        if (idBytes.length === 0 || idBytes.length > MAX_CREDENTIAL_ID_BYTES) {
          throw new TypeError("invalid credential id length");
        }
        excludeCredentials.push(b64urlEncode(idBytes));
      }
    }

    return {
      rp_id: rpId,
      rp_name: publicKey.rp.name || null,
      challenge_b64u: b64urlEncode(challenge),
      user_id_b64u: b64urlEncode(userId),
      user_name: publicKey.user.name,
      user_display_name: publicKey.user.displayName || null,
      exclude_credentials: excludeCredentials,
      pub_key_cred_params: algorithms,
      user_verification: uv === "required",
      extensions: extensionNames(publicKey.extensions),
      attestation: typeof publicKey.attestation === "string" ? publicKey.attestation.slice(0, 32) : null,
      timeout_ms: timeoutFor(publicKey.timeout)
    };
  }

  function credentialFrom(data) {
    if (!data || typeof data.credential_id_b64u !== "string" ||
        typeof data.authenticator_data_b64u !== "string" ||
        typeof data.signature_b64u !== "string" ||
        typeof data.client_data_json_b64u !== "string") {
      throw new TypeError("malformed daemon response");
    }

    var credential = {
      id: data.credential_id_b64u,
      rawId: b64urlDecode(data.credential_id_b64u),
      type: "public-key",
      authenticatorAttachment: "platform",
      getClientExtensionResults: function() { return {}; },
      response: {
        authenticatorData: b64urlDecode(data.authenticator_data_b64u),
        clientDataJSON: b64urlDecode(data.client_data_json_b64u),
        signature: b64urlDecode(data.signature_b64u),
        userHandle: data.user_handle_b64u ? b64urlDecode(data.user_handle_b64u) : null
      }
    };
    credential.toJSON = function() {
      return {
        id: credential.id,
        rawId: credential.id,
        type: credential.type,
        authenticatorAttachment: credential.authenticatorAttachment,
        clientExtensionResults: {},
        response: {
          authenticatorData: data.authenticator_data_b64u,
          clientDataJSON: data.client_data_json_b64u,
          signature: data.signature_b64u,
          userHandle: data.user_handle_b64u || null
        }
      };
    };
    return credential;
  }

  function credentialFromCreate(data) {
    if (!data || typeof data.credential_id_b64u !== "string" ||
        typeof data.public_key_algorithm !== "number" ||
        typeof data.authenticator_data_b64u !== "string" ||
        typeof data.attestation_object_b64u !== "string" ||
        typeof data.client_data_json_b64u !== "string") {
      throw new TypeError("malformed daemon response");
    }

    var credential = {
      id: data.credential_id_b64u,
      rawId: b64urlDecode(data.credential_id_b64u),
      type: "public-key",
      authenticatorAttachment: "platform",
      getClientExtensionResults: function() { return {}; },
      response: {
        attestationObject: b64urlDecode(data.attestation_object_b64u),
        clientDataJSON: b64urlDecode(data.client_data_json_b64u),
        getTransports: function() { return ["internal"]; },
        getAuthenticatorData: function() { return b64urlDecode(data.authenticator_data_b64u); },
        getPublicKey: function() { return null; },
        getPublicKeyAlgorithm: function() { return data.public_key_algorithm; }
      }
    };
    credential.toJSON = function() {
      return {
        id: credential.id,
        rawId: credential.id,
        type: credential.type,
        authenticatorAttachment: credential.authenticatorAttachment,
        clientExtensionResults: {},
        response: {
          attestationObject: data.attestation_object_b64u,
          clientDataJSON: data.client_data_json_b64u,
          transports: ["internal"],
          authenticatorData: data.authenticator_data_b64u,
          publicKey: null,
          publicKeyAlgorithm: data.public_key_algorithm
        }
      };
    };
    return credential;
  }

  function finishOperation(id) {
    var operation = pending.get(id);
    if (!operation) return null;
    pending.delete(id);
    clearTimeout(operation.timer);
    if (operation.signal && operation.abortListener) {
      operation.signal.removeEventListener("abort", operation.abortListener);
    }
    return operation;
  }

  window.addEventListener("message", function(event) {
    var message = event.data;
    if (event.source !== window || !message || message.source !== "passless-agent-broker" ||
        message.channel !== channel || typeof message.id !== "string") return;

    var operation = finishOperation(message.id);
    if (!operation) return;

    // Fail closed: whatever went wrong (daemon error, denial, transport failure, timeout), the page gets
    // NotAllowedError. The original navigator.credentials.get/create is never called for a WebAuthn
    // request (ADR 0014 §7, invariant 25).
    if (!message.ok) {
      operation.reject(daemonError(message));
      return;
    }

    try {
      operation.resolve(message.type === "create"
        ? credentialFromCreate(message.response)
        : credentialFrom(message.response));
    } catch (error) {
      operation.reject(notAllowed());
    }
  });

  function runOperation(type, publicKey, signal, request) {
    return new Promise(function(resolve, reject) {
      if (signal && signal.aborted) {
        reject(abortError());
        return;
      }

      var id = requestId();
      var timeout = timeoutFor(publicKey.timeout);
      var operation = {
        resolve: resolve,
        reject: reject,
        signal: signal || null,
        abortListener: null,
        timer: null
      };
      operation.timer = setTimeout(function() {
        if (finishOperation(id)) reject(notAllowed());
      }, timeout);
      pending.set(id, operation);
      try {
        if (operation.signal) {
          operation.abortListener = function() {
            if (finishOperation(id)) reject(abortError());
          };
          operation.signal.addEventListener("abort", operation.abortListener, { once: true });
        }
        window.postMessage({
          source: "passless-agent-main",
          channel: channel,
          id: id,
          request: request,
          type: type
        }, location.origin);
      } catch (error) {
        // For example an opaque origin ("null"), where postMessage throws. Clear the pending entry and timer
        // now and fail closed.
        finishOperation(id);
        reject(notAllowed());
      }
    });
  }

  // A copy of `options` that has no `publicKey` key, for the non-WebAuthn passthrough. The page's own object is
  // never handed to the native function, so a getter or Proxy cannot show a different `publicKey` to it.
  function withoutPublicKey(options) {
    var copy = {};
    var names = ["mediation", "signal", "password", "federated", "otp", "identity", "unmediated"];
    var keys = Object.keys(options);
    for (var i = 0; i < keys.length; i++) {
      if (names.indexOf(keys[i]) === -1) names.push(keys[i]);
    }
    for (var j = 0; j < names.length; j++) {
      var name = names[j];
      if (name === "publicKey") continue;
      if (name in options) copy[name] = options[name];
    }
    return copy;
  }

  function intercept(type, self, options) {
    var native = type === "get" ? originalGet : originalCreate;
    var feature = type === "get" ? "publickey-credentials-get" : "publickey-credentials-create";
    // Not an options dictionary: the native function rejects it itself, without any authenticator.
    if (options === null || (typeof options !== "object" && typeof options !== "function")) {
      return native.call(self, options);
    }
    // Read `publicKey` exactly once. The path is chosen with `in`, not truthiness, and everything below uses `pk`.
    var hasPublicKey = "publicKey" in options;
    var pk = hasPublicKey ? options.publicKey : undefined;
    if (!hasPublicKey || pk === undefined) {
      // Only non-WebAuthn calls (passwords, federated credentials) go to the original; they never reach an
      // authenticator.
      return native.call(self, withoutPublicKey(options));
    }
    // Conditional mediation is passive passkey autofill. It is not supported for agents and must not reach
    // the native path either, so it is rejected (ADR 0014 §11).
    var mediation = options.mediation;
    var signal = options.signal;
    if (mediation === "conditional") return Promise.reject(notAllowed());
    // A subframe that was not delegated WebAuthn is refused here, without a daemon call or an audit record.
    // Chromium itself refuses undelegated frames, so nothing is lost.
    if (!policyAllowsWebAuthn(feature)) return Promise.reject(notAllowed());
    var request;
    try {
      request = type === "get" ? serialize(pk) : serializeCreate(pk);
    } catch (error) {
      return Promise.reject(error instanceof DOMException ? error : notAllowed());
    }
    return runOperation(type, pk, signal, request);
  }

  // Override on the instance and on the prototype, non-writable and non-configurable, so that neither
  // `CredentialsContainer.prototype.get.call(...)`, `delete navigator.credentials.get` nor a reassignment
  // reaches the native function.
  function lock(target, name, fn) {
    try {
      Object.defineProperty(target, name, { value: fn, writable: false, configurable: false, enumerable: true });
    } catch (error) {
      // Already locked (the script ran before): keep the existing override.
    }
  }

  var proto = Object.getPrototypeOf(credentials);
  var targets = [credentials];
  if (proto && proto !== Object.prototype) targets.push(proto);

  function overrideGet(options) { return intercept("get", this, options); }
  function overrideCreate(options) { return intercept("create", this, options); }

  for (var t = 0; t < targets.length; t++) {
    lock(targets[t], "get", overrideGet);
    if (originalCreate) lock(targets[t], "create", overrideCreate);
  }
})("__PASSLESS_CHANNEL__");
