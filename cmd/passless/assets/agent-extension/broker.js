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
    return true;
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
    return true;
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

    chrome.runtime.sendMessage({
      source: "passless-agent-broker",
      type: messageType,
      request: message.request
    }, function(response) {
      var failed = Boolean(chrome.runtime.lastError) || !response;
      window.postMessage({
        source: "passless-agent-broker",
        channel: channel,
        id: message.id,
        ok: !failed && response.ok === true,
        response: failed ? null : response.response,
        fallback: !failed && response.fallback === true,
        error: failed ? "broker_unavailable" : response.error,
        type: messageType
      }, location.origin);
    });
  });
})("__PASSLESS_CHANNEL__");
