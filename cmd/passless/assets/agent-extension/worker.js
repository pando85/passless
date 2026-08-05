(function(port, bearer) {
  "use strict";

  var MAX_REQUEST_BYTES = 16384;
  var MAX_RP_ID_LEN = 253;
  var MAX_CHALLENGE_B64U_LEN = 2048;
  var MAX_ALLOW_CREDENTIALS = 64;
  var MAX_EXCLUDE_CREDENTIALS = 64;
  var MAX_CREDENTIAL_ID_B64U_LEN = 512;
  var MAX_ORIGIN_LEN = 512;
  var MAX_USER_NAME_LEN = 256;
  var MAX_USER_ID_B64U_LEN = 128;

  function validateOrigin(sender) {
    if (typeof sender.url !== "string") return null;

    var frameUrl;
    try {
      frameUrl = new URL(sender.url);
    } catch (error) {
      return null;
    }
    if (frameUrl.protocol !== "https:") return null;

    var origin = frameUrl.origin;
    if (origin.length > MAX_ORIGIN_LEN) return null;

    return { origin: origin, hostname: frameUrl.hostname };
  }

  function validateGetRequest(req) {
    if (typeof req.rp_id !== "string" || req.rp_id.length === 0 || req.rp_id.length > MAX_RP_ID_LEN) return false;
    if (typeof req.challenge_b64u !== "string" || req.challenge_b64u.length === 0 || req.challenge_b64u.length > MAX_CHALLENGE_B64U_LEN) return false;
    if (!Array.isArray(req.allow_credentials) || req.allow_credentials.length > MAX_ALLOW_CREDENTIALS) return false;
    for (var i = 0; i < req.allow_credentials.length; i++) {
      var c = req.allow_credentials[i];
      if (typeof c !== "string" || c.length === 0 || c.length > MAX_CREDENTIAL_ID_B64U_LEN) return false;
    }
    if (typeof req.user_verification !== "boolean") return false;
    return true;
  }

  function validateCreateRequest(req) {
    if (typeof req.rp_id !== "string" || req.rp_id.length === 0 || req.rp_id.length > MAX_RP_ID_LEN) return false;
    if (typeof req.challenge_b64u !== "string" || req.challenge_b64u.length === 0 || req.challenge_b64u.length > MAX_CHALLENGE_B64U_LEN) return false;
    if (typeof req.user_id_b64u !== "string" || req.user_id_b64u.length === 0 || req.user_id_b64u.length > MAX_USER_ID_B64U_LEN) return false;
    if (typeof req.user_name !== "string" || req.user_name.length === 0 || req.user_name.length > MAX_USER_NAME_LEN) return false;
    if (!Array.isArray(req.exclude_credentials) || req.exclude_credentials.length > MAX_EXCLUDE_CREDENTIALS) return false;
    for (var i = 0; i < req.exclude_credentials.length; i++) {
      var c = req.exclude_credentials[i];
      if (typeof c !== "string" || c.length === 0 || c.length > MAX_CREDENTIAL_ID_B64U_LEN) return false;
    }
    if (typeof req.user_verification !== "boolean") return false;
    return true;
  }

  function handleGetRequest(req, originInfo, sendResponse) {
    var cross_origin =
      originInfo.hostname !== req.rp_id &&
      !originInfo.hostname.endsWith("." + req.rp_id);

    var safeRequest = {
      origin: originInfo.origin,
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
      if (!response || typeof response !== "object" || !response.sign_assertion_result) {
        throw new Error("malformed daemon response");
      }
      sendResponse({ ok: true, response: response.sign_assertion_result });
    }).catch(function() {
      sendResponse({ ok: false });
    });
    return true;
  }

  function handleCreateRequest(req, originInfo, sendResponse) {
    var cross_origin =
      originInfo.hostname !== req.rp_id &&
      !originInfo.hostname.endsWith("." + req.rp_id);

    var safeRequest = {
      origin: originInfo.origin,
      rp_id: req.rp_id,
      rp_name: req.rp_name || null,
      challenge_b64u: req.challenge_b64u,
      user_id_b64u: req.user_id_b64u,
      user_name: req.user_name,
      user_display_name: req.user_display_name || null,
      exclude_credentials: req.exclude_credentials,
      user_verification: req.user_verification,
      cross_origin: cross_origin
    };

    var body;
    try {
      body = JSON.stringify(safeRequest);
    } catch (e) {
      sendResponse({ ok: false, type: "create" });
      return false;
    }
    if (body.length > MAX_REQUEST_BYTES) {
      sendResponse({ ok: false, type: "create" });
      return false;
    }

    fetch("http://127.0.0.1:" + port + "/register", {
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
      if (!response || typeof response !== "object" || !response.create_attestation_result) {
        throw new Error("malformed daemon response");
      }
      sendResponse({ ok: true, response: response.create_attestation_result, type: "create" });
    }).catch(function() {
      sendResponse({ ok: false, type: "create" });
    });
    return true;
  }

  chrome.runtime.onMessage.addListener(function(message, sender, sendResponse) {
    if (
      !message ||
      message.source !== "passless-agent-broker" ||
      !message.request
    ) return false;

    if (typeof sender.id === "string" && sender.id !== chrome.runtime.id) {
      sendResponse({ ok: false });
      return false;
    }

    var originInfo = validateOrigin(sender);
    if (!originInfo) {
      sendResponse({ ok: false });
      return false;
    }

    var req = message.request;
    var messageType = message.type === "create" ? "create" : "get";

    if (messageType === "create") {
      if (!validateCreateRequest(req)) {
        sendResponse({ ok: false, type: "create" });
        return false;
      }
      return handleCreateRequest(req, originInfo, sendResponse);
    }

    if (!validateGetRequest(req)) {
      sendResponse({ ok: false });
      return false;
    }
    return handleGetRequest(req, originInfo, sendResponse);
  });
})(__PASSLESS_PORT__, __PASSLESS_BEARER__);
