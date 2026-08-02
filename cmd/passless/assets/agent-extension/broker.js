(function(channel) {
  "use strict";

  var MAX_MESSAGE_JSON_LEN = 16384;
  var MAX_REQUEST_ID_LEN = 128;
  var MAX_ALLOW_CREDENTIALS = 64;
  var MAX_CREDENTIAL_ID_B64U_LEN = 512;
  var MAX_RP_ID_LEN = 253;
  var MAX_CHALLENGE_B64U_LEN = 2048;

  function isValidRequest(req) {
    if (!req || typeof req !== "object") return false;
    if (typeof req.rp_id !== "string" || req.rp_id.length === 0 || req.rp_id.length > MAX_RP_ID_LEN) return false;
    if (typeof req.challenge_b64u !== "string" || req.challenge_b64u.length === 0 || req.challenge_b64u.length > MAX_CHALLENGE_B64U_LEN) return false;
    if (!Array.isArray(req.allow_credentials)) return false;
    if (req.allow_credentials.length > MAX_ALLOW_CREDENTIALS) return false;
    for (var i = 0; i < req.allow_credentials.length; i++) {
      var c = req.allow_credentials[i];
      if (!c || typeof c !== "object") return false;
      if (typeof c.id_b64u !== "string" || c.id_b64u.length === 0 || c.id_b64u.length > MAX_CREDENTIAL_ID_B64U_LEN) return false;
      if (c.type !== "public-key") return false;
    }
    if (req.user_verification !== "required" && req.user_verification !== "preferred" && req.user_verification !== "discouraged") return false;
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

    if (!isValidRequest(message.request)) return;

    try {
      if (JSON.stringify(message.request).length > MAX_MESSAGE_JSON_LEN) return;
    } catch (e) {
      return;
    }

    chrome.runtime.sendMessage({
      source: "passless-agent-broker",
      request: message.request
    }, function(response) {
      var failed = Boolean(chrome.runtime.lastError) || !response;
      window.postMessage({
        source: "passless-agent-broker",
        channel: channel,
        id: message.id,
        ok: !failed && response.ok === true,
        response: failed ? null : response.response
      }, location.origin);
    });
  });
})("__PASSLESS_CHANNEL__");
