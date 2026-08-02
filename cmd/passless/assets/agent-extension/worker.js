(function(port, bearer) {
  "use strict";

  var MAX_REQUEST_BYTES = 16384;
  var MAX_RP_ID_LEN = 253;
  var MAX_CHALLENGE_B64U_LEN = 2048;
  var MAX_ALLOW_CREDENTIALS = 64;
  var MAX_CREDENTIAL_ID_B64U_LEN = 512;
  var MAX_ORIGIN_LEN = 512;

  chrome.runtime.onMessage.addListener(function(message, sender, sendResponse) {
    if (
      !message ||
      message.source !== "passless-agent-broker" ||
      !message.request ||
      typeof sender.url !== "string"
    ) return false;

    if (typeof sender.id === "string" && sender.id !== chrome.runtime.id) {
      sendResponse({ ok: false });
      return false;
    }

    var frameUrl;
    try {
      frameUrl = new URL(sender.url);
    } catch (error) {
      sendResponse({ ok: false });
      return false;
    }
    if (frameUrl.protocol !== "https:") {
      sendResponse({ ok: false });
      return false;
    }

    var req = message.request;

    if (typeof req.rp_id !== "string" || req.rp_id.length === 0 || req.rp_id.length > MAX_RP_ID_LEN) {
      sendResponse({ ok: false });
      return false;
    }
    if (typeof req.challenge_b64u !== "string" || req.challenge_b64u.length === 0 || req.challenge_b64u.length > MAX_CHALLENGE_B64U_LEN) {
      sendResponse({ ok: false });
      return false;
    }
    if (!Array.isArray(req.allow_credentials) || req.allow_credentials.length > MAX_ALLOW_CREDENTIALS) {
      sendResponse({ ok: false });
      return false;
    }
    for (var i = 0; i < req.allow_credentials.length; i++) {
      var c = req.allow_credentials[i];
      if (!c || typeof c !== "object") {
        sendResponse({ ok: false });
        return false;
      }
      if (typeof c.id_b64u !== "string" || c.id_b64u.length === 0 || c.id_b64u.length > MAX_CREDENTIAL_ID_B64U_LEN) {
        sendResponse({ ok: false });
        return false;
      }
      if (c.type !== "public-key") {
        sendResponse({ ok: false });
        return false;
      }
    }
    if (req.user_verification !== "required" && req.user_verification !== "preferred" && req.user_verification !== "discouraged") {
      sendResponse({ ok: false });
      return false;
    }

    var origin = frameUrl.origin;
    if (origin.length > MAX_ORIGIN_LEN) {
      sendResponse({ ok: false });
      return false;
    }
    var cross_origin =
      frameUrl.hostname !== req.rp_id &&
      !frameUrl.hostname.endsWith("." + req.rp_id);

    var safeRequest = {
      origin: origin,
      rp_id: req.rp_id,
      challenge_b64u: req.challenge_b64u,
      allow_credentials: req.allow_credentials,
      user_verification: req.user_verification,
      cross_origin: cross_origin
    };

    var body;
    try {
      body = JSON.stringify(safeRequest);
    } catch (e) {
      sendResponse({ ok: false });
      return false;
    }
    if (body.length > MAX_REQUEST_BYTES) {
      sendResponse({ ok: false });
      return false;
    }

    fetch("http://127.0.0.1:" + port + "/sign", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + bearer
      },
      body: body
    }).then(function(response) {
      if (!response.ok) throw new Error("request denied");
      return response.json();
    }).then(function(response) {
      sendResponse({ ok: true, response: response });
    }).catch(function() {
      sendResponse({ ok: false });
    });
    return true;
  });
})(__PASSLESS_PORT__, __PASSLESS_BEARER__);
