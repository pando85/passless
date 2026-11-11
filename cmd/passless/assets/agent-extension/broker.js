(function(channel) {
  "use strict";

  var MAX_MESSAGE_JSON_LEN = 16384;
  var MAX_REQUEST_ID_LEN = 128;
  var MAX_ALLOW_CREDENTIALS = 64;
  var MAX_EXCLUDE_CREDENTIALS = 64;
  var MAX_CREDENTIAL_ID_B64U_LEN = 512;
  var MAX_RP_ID_LEN = 253;
  var MAX_CHALLENGE_B64U_LEN = 2048;
  var MAX_USER_NAME_LEN = 256;
  var MAX_USER_ID_B64U_LEN = 128;
  var MAX_ALGORITHMS = 16;
  var MAX_EXTENSIONS = 32;
  var MAX_EXTENSION_NAME_LEN = 64;
  var MAX_TIMEOUT_MS = 120000;
  var DOM_NAMES = ["NotAllowedError", "NotSupportedError", "InvalidStateError", "SecurityError", "AbortError"];
  var marker = document.documentElement;
  if (marker && marker.hasAttribute("data-passless-agent-broker")) return;
  if (marker) marker.setAttribute("data-passless-agent-broker", "");
  var initialized = window.__passlessAgentBrokerChannels;
  if (!(initialized instanceof Set)) {
    initialized = new Set();
    window.__passlessAgentBrokerChannels = initialized;
  }
  if (initialized.has(channel)) return;
  initialized.add(channel);

  // `extensions`, `attestation` and `timeout_ms` are optional; absent ones are not forwarded.
  function isValidCommon(req) {
    if (req.extensions !== undefined) {
      if (!Array.isArray(req.extensions) || req.extensions.length > MAX_EXTENSIONS) return false;
      for (var i = 0; i < req.extensions.length; i++) {
        var name = req.extensions[i];
        if (typeof name !== "string" || name.length === 0 || name.length > MAX_EXTENSION_NAME_LEN) return false;
      }
    }
    if (req.attestation !== undefined && req.attestation !== null &&
        (typeof req.attestation !== "string" || req.attestation.length > 32)) return false;
    if (req.timeout_ms === undefined) return true;
    return Number.isInteger(req.timeout_ms) && req.timeout_ms > 0 && req.timeout_ms <= MAX_TIMEOUT_MS;
  }

  function isValidGetRequest(req) {
    if (!req || typeof req !== "object") return false;
    if (typeof req.rp_id !== "string" || req.rp_id.length === 0 || req.rp_id.length > MAX_RP_ID_LEN) return false;
    if (typeof req.challenge_b64u !== "string" || req.challenge_b64u.length === 0 || req.challenge_b64u.length > MAX_CHALLENGE_B64U_LEN) return false;
    if (!Array.isArray(req.allow_credentials)) return false;
    if (req.allow_credentials.length > MAX_ALLOW_CREDENTIALS) return false;
    for (var i = 0; i < req.allow_credentials.length; i++) {
      var c = req.allow_credentials[i];
      if (typeof c !== "string" || c.length === 0 || c.length > MAX_CREDENTIAL_ID_B64U_LEN) return false;
    }
    if (typeof req.user_verification !== "boolean") return false;
    return isValidCommon(req);
  }

  function isValidCreateRequest(req) {
    if (!req || typeof req !== "object") return false;
    if (typeof req.rp_id !== "string" || req.rp_id.length === 0 || req.rp_id.length > MAX_RP_ID_LEN) return false;
    if (typeof req.challenge_b64u !== "string" || req.challenge_b64u.length === 0 || req.challenge_b64u.length > MAX_CHALLENGE_B64U_LEN) return false;
    if (typeof req.user_id_b64u !== "string" || req.user_id_b64u.length === 0 || req.user_id_b64u.length > MAX_USER_ID_B64U_LEN) return false;
    if (typeof req.user_name !== "string" || req.user_name.length === 0 || req.user_name.length > MAX_USER_NAME_LEN) return false;
    if (!Array.isArray(req.exclude_credentials)) return false;
    if (req.exclude_credentials.length > MAX_EXCLUDE_CREDENTIALS) return false;
    for (var i = 0; i < req.exclude_credentials.length; i++) {
      var c = req.exclude_credentials[i];
      if (typeof c !== "string" || c.length === 0 || c.length > MAX_CREDENTIAL_ID_B64U_LEN) return false;
    }
    if (!Array.isArray(req.pub_key_cred_params) || req.pub_key_cred_params.length === 0 || req.pub_key_cred_params.length > MAX_ALGORITHMS) return false;
    for (var j = 0; j < req.pub_key_cred_params.length; j++) {
      if (!Number.isInteger(req.pub_key_cred_params[j])) return false;
    }
    if (typeof req.user_verification !== "boolean") return false;
    return isValidCommon(req);
  }

  window.addEventListener("message", function(event) {
    var message = event.data;
    if (
      event.source !== window ||
      event.origin !== location.origin ||
      !message ||
      message.source !== "passless-agent-main" ||
      message.channel !== channel ||
      typeof message.id !== "string" ||
      message.id.length === 0 ||
      message.id.length > MAX_REQUEST_ID_LEN ||
      !message.request
    ) return;

    var messageType = message.type === "create" ? "create" : "get";
    var valid = messageType === "create"
      ? isValidCreateRequest(message.request)
      : isValidGetRequest(message.request);
    if (!valid) return;

    try {
      if (JSON.stringify(message.request).length > MAX_MESSAGE_JSON_LEN) return;
    } catch (e) {
      return;
    }

    // Every ancestor frame origin (Chromium only). The worker treats a frame as cross-origin when any
    // ancestor differs from its own origin, or when the list is unavailable (fail closed).
    var ancestors = null;
    try {
      if (location.ancestorOrigins) ancestors = Array.prototype.slice.call(location.ancestorOrigins);
    } catch (e) {
      ancestors = null;
    }

    chrome.runtime.sendMessage({
      source: "passless-agent-broker",
      request_id: message.id,
      type: messageType,
      ancestor_origins: ancestors,
      request: message.request
    }, function(response) {
      var failed = Boolean(chrome.runtime.lastError) || !response;
      window.postMessage({
        source: "passless-agent-broker",
        channel: channel,
        id: message.id,
        // Only the outcome and the DOMException name reach the page: the daemon's wire error code
        // (budget, replay, busy, bearer state) is not page-visible.
        ok: !failed && response.ok === true,
        response: failed ? null : response.response,
        dom: !failed && DOM_NAMES.indexOf(response.dom) !== -1 ? response.dom : null,
        type: messageType
      }, location.origin);
    });
  });
})("__PASSLESS_CHANNEL__");
