(function(channel) {
  "use strict";

  var MAX_ALLOW_CREDENTIALS = 64;
  var MAX_CHALLENGE_BYTES = 1024;
  var MAX_RP_ID_LEN = 253;
  var MAX_CREDENTIAL_ID_BYTES = 256;

  var credentials = navigator.credentials;
  if (!credentials || typeof credentials.get !== "function") return;

  var originalGet = credentials.get.bind(credentials);
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

  function notAllowed() {
    return new DOMException(
      "The operation either timed out or was not allowed.",
      "NotAllowedError"
    );
  }

  function requestId() {
    var bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return b64urlEncode(bytes);
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

    var UV_ALLOWED = ["required", "preferred", "discouraged"];
    var uv = publicKey.userVerification || "preferred";
    if (UV_ALLOWED.indexOf(uv) === -1) {
      throw new TypeError("invalid userVerification");
    }

    var allowCredentials = [];
    if (Array.isArray(publicKey.allowCredentials)) {
      if (publicKey.allowCredentials.length > MAX_ALLOW_CREDENTIALS) {
        throw new TypeError("too many allowCredentials");
      }
      for (var i = 0; i < publicKey.allowCredentials.length; i++) {
        var credential = publicKey.allowCredentials[i];
        if (!credential || typeof credential !== "object") {
          throw new TypeError("malformed allowCredentials entry");
        }
        if (credential.type !== "public-key") {
          throw new TypeError("unsupported credential type");
        }
        if (!credential.id) {
          throw new TypeError("missing credential id");
        }
        var idBytes;
        try {
          idBytes = toBytes(credential.id);
        } catch (e) {
          throw new TypeError("invalid credential id");
        }
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

  function credentialFrom(data) {
    if (
      !data ||
      typeof data.credential_id_b64u !== "string" ||
      typeof data.authenticator_data_b64u !== "string" ||
      typeof data.signature_b64u !== "string" ||
      typeof data.client_data_json_b64u !== "string"
    ) {
      throw new TypeError("malformed daemon response");
    }

    return {
      id: data.credential_id_b64u,
      rawId: b64urlDecode(data.credential_id_b64u),
      type: "public-key",
      getClientExtensionResults: function() {
        return {};
      },
      response: {
        authenticatorData: b64urlDecode(data.authenticator_data_b64u),
        clientDataJSON: b64urlDecode(data.client_data_json_b64u),
        signature: b64urlDecode(data.signature_b64u),
        userHandle: data.user_handle_b64u ? b64urlDecode(data.user_handle_b64u) : null
      }
    };
  }

  window.addEventListener("message", function(event) {
    var message = event.data;
    if (
      event.source !== window ||
      !message ||
      message.source !== "passless-agent-broker" ||
      message.channel !== channel ||
      typeof message.id !== "string"
    ) return;

    var operation = pending.get(message.id);
    if (!operation) return;
    pending.delete(message.id);
    clearTimeout(operation.timer);

    if (!message.ok) {
      operation.reject(notAllowed());
      return;
    }

    try {
      operation.resolve(credentialFrom(message.response));
    } catch (error) {
      operation.reject(notAllowed());
    }
  });

  credentials.get = function(options) {
    if (!options || !options.publicKey) return originalGet(options);

    var request;
    try {
      request = serialize(options.publicKey);
    } catch (error) {
      return Promise.reject(notAllowed());
    }

    return new Promise(function(resolve, reject) {
      var id = requestId();
      var timer = setTimeout(function() {
        pending.delete(id);
        reject(notAllowed());
      }, 30000);
      pending.set(id, { resolve: resolve, reject: reject, timer: timer });
      window.postMessage({
        source: "passless-agent-main",
        channel: channel,
        id: id,
        request: request
      }, location.origin);
    });
  };
})("__PASSLESS_CHANNEL__");
