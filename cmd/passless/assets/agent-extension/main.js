(function(channel) {
  "use strict";

  var MAX_ALLOW_CREDENTIALS = 64;
  var MAX_CHALLENGE_BYTES = 1024;
  var MAX_RP_ID_LEN = 253;
  var MAX_CREDENTIAL_ID_BYTES = 256;
  var MAX_ALGORITHMS = 16;
  var DEFAULT_TIMEOUT_MS = 30000;
  var MAX_TIMEOUT_MS = 120000;

  var credentials = navigator.credentials;
  if (!credentials || typeof credentials.get !== "function") return;

  var originalGet = credentials.get.bind(credentials);
  var originalCreate = credentials.create ? credentials.create.bind(credentials) : null;
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

  function abortError() {
    return domError("AbortError", "The operation was aborted.");
  }

  function requestId() {
    var bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return b64urlEncode(bytes);
  }

  function timeoutFor(publicKey) {
    if (!Number.isFinite(publicKey.timeout) || publicKey.timeout <= 0) return DEFAULT_TIMEOUT_MS;
    return Math.min(Math.floor(publicKey.timeout), MAX_TIMEOUT_MS);
  }

  function policyAllowsWebAuthn(feature) {
    if (window.top === window.self) return true;
    var policy = document.permissionsPolicy || document.featurePolicy;
    // Cross-origin autonomous authentication is security-sensitive. If the
    // browser cannot prove that WebAuthn was delegated to this frame, leave
    // the request to the native browser instead of assuming permission.
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
      user_verification: uv === "required"
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
      user_verification: uv === "required"
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

    if (!message.ok) {
      if (message.fallback && operation.native) {
        Promise.resolve(operation.native(operation.options)).then(operation.resolve, operation.reject);
      } else {
        operation.reject(notAllowed());
      }
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

  function runOperation(type, options, request, nativeOperation) {
    return new Promise(function(resolve, reject) {
      if (options.signal && options.signal.aborted) {
        reject(abortError());
        return;
      }

      var id = requestId();
      var timeout = timeoutFor(options.publicKey);
      var operation = {
        resolve: resolve,
        reject: reject,
        native: nativeOperation,
        options: options,
        signal: options.signal || null,
        abortListener: null,
        timer: null
      };
      operation.timer = setTimeout(function() {
        if (finishOperation(id)) reject(notAllowed());
      }, timeout);
      if (operation.signal) {
        operation.abortListener = function() {
          if (finishOperation(id)) reject(abortError());
        };
        operation.signal.addEventListener("abort", operation.abortListener, { once: true });
      }
      pending.set(id, operation);
      window.postMessage({
        source: "passless-agent-main",
        channel: channel,
        id: id,
        request: request,
        type: type
      }, location.origin);
    });
  }

  credentials.get = function(options) {
    // Conditional mediation is passive passkey autofill. Do not turn merely
    // visiting a page into an autonomous same-user login; keep it native.
    if (options && options.mediation === "conditional") return originalGet(options);
    if (!options || !options.publicKey || !policyAllowsWebAuthn("publickey-credentials-get")) return originalGet(options);
    var request;
    try {
      request = serialize(options.publicKey);
    } catch (error) {
      return Promise.reject(error instanceof DOMException ? error : notAllowed());
    }
    return runOperation("get", options, request, originalGet);
  };

  if (originalCreate) {
    credentials.create = function(options) {
      if (!options || !options.publicKey || !policyAllowsWebAuthn("publickey-credentials-create")) return originalCreate(options);
      var request;
      try {
        request = serializeCreate(options.publicKey);
      } catch (error) {
        return Promise.reject(error instanceof DOMException ? error : notAllowed());
      }
      return runOperation("create", options, request, originalCreate);
    };
  }
})("__PASSLESS_CHANNEL__");
