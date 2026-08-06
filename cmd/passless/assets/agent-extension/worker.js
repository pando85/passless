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
  var MAX_ALGORITHMS = 16;

  function parseHttpsOrigin(url) {
    if (typeof url !== "string") return null;
    var parsed;
    try {
      parsed = new URL(url);
    } catch (error) {
      return null;
    }
    if (parsed.protocol !== "https:") return null;
    if (parsed.origin.length > MAX_ORIGIN_LEN) return null;
    return parsed.origin;
  }

  function validateOrigins(sender) {
    var origin = parseHttpsOrigin(sender.url);
    if (!origin) return null;

    var topOrigin = origin;
    if (sender.tab && typeof sender.tab.url === "string") {
      topOrigin = parseHttpsOrigin(sender.tab.url);
      if (!topOrigin) return null;
    }

    var crossOrigin = sender.frameId !== 0 && origin !== topOrigin;
    return {
      origin: origin,
      top_origin: topOrigin,
      cross_origin: crossOrigin
    };
  }

  function validateGetRequest(req) {
    if (typeof req.rp_id !== "string" || req.rp_id.length === 0 || req.rp_id.length > MAX_RP_ID_LEN) return false;
    if (typeof req.challenge_b64u !== "string" || req.challenge_b64u.length === 0 || req.challenge_b64u.length > MAX_CHALLENGE_B64U_LEN) return false;
    if (!Array.isArray(req.allow_credentials) || req.allow_credentials.length > MAX_ALLOW_CREDENTIALS) return false;
    for (var i = 0; i < req.allow_credentials.length; i++) {
      var c = req.allow_credentials[i];
      if (typeof c !== "string" || c.length === 0 || c.length > MAX_CREDENTIAL_ID_B64U_LEN) return false;
    }
    return typeof req.user_verification === "boolean";
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
    if (!Array.isArray(req.pub_key_cred_params) || req.pub_key_cred_params.length === 0 || req.pub_key_cred_params.length > MAX_ALGORITHMS) return false;
    for (var j = 0; j < req.pub_key_cred_params.length; j++) {
      if (!Number.isInteger(req.pub_key_cred_params[j])) return false;
    }
    return typeof req.user_verification === "boolean";
  }

  function daemonRequest(path, request, sendResponse, responseField, type) {
    var body;
    try {
      body = JSON.stringify(request);
    } catch (error) {
      sendResponse({ ok: false, type: type, error: "invalid_request" });
      return false;
    }
    if (body.length > MAX_REQUEST_BYTES) {
      sendResponse({ ok: false, type: type, error: "request_too_large" });
      return false;
    }

    fetch("http://127.0.0.1:" + port + path, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + bearer
      },
      body: body
    }).then(function(response) {
      return response.json().catch(function() {
        return { error: "invalid_daemon_response" };
      }).then(function(payload) {
        return { ok: response.ok, payload: payload };
      });
    }).then(function(result) {
      if (!result.ok) {
        var code = result.payload && typeof result.payload.error === "string"
          ? result.payload.error
          : "request_denied";
        sendResponse({
          ok: false,
          type: type,
          error: code,
          fallback: code === "human_interaction_required"
        });
        return;
      }
      if (!result.payload || typeof result.payload !== "object" || !result.payload[responseField]) {
        throw new Error("malformed daemon response");
      }
      sendResponse({ ok: true, response: result.payload[responseField], type: type });
    }).catch(function() {
      sendResponse({ ok: false, type: type, error: "transport_error" });
    });
    return true;
  }

  function handleGetRequest(req, origins, sendResponse) {
    return daemonRequest("/sign", {
      origin: origins.origin,
      top_origin: origins.top_origin,
      rp_id: req.rp_id,
      challenge_b64u: req.challenge_b64u,
      allow_credentials: req.allow_credentials,
      user_verification: req.user_verification,
      cross_origin: origins.cross_origin
    }, sendResponse, "sign_assertion_result", "get");
  }

  function handleCreateRequest(req, origins, sendResponse) {
    return daemonRequest("/register", {
      origin: origins.origin,
      top_origin: origins.top_origin,
      rp_id: req.rp_id,
      rp_name: req.rp_name || null,
      challenge_b64u: req.challenge_b64u,
      user_id_b64u: req.user_id_b64u,
      user_name: req.user_name,
      user_display_name: req.user_display_name || null,
      exclude_credentials: req.exclude_credentials,
      pub_key_cred_params: req.pub_key_cred_params,
      user_verification: req.user_verification,
      cross_origin: origins.cross_origin
    }, sendResponse, "create_attestation_result", "create");
  }

  chrome.runtime.onMessage.addListener(function(message, sender, sendResponse) {
    if (!message || message.source !== "passless-agent-broker" || !message.request) return false;

    if (typeof sender.id === "string" && sender.id !== chrome.runtime.id) {
      sendResponse({ ok: false, error: "invalid_sender" });
      return false;
    }

    var origins = validateOrigins(sender);
    if (!origins) {
      sendResponse({ ok: false, error: "invalid_origin" });
      return false;
    }

    var req = message.request;
    var messageType = message.type === "create" ? "create" : "get";
    if (messageType === "create") {
      if (!validateCreateRequest(req)) {
        sendResponse({ ok: false, type: "create", error: "invalid_request" });
        return false;
      }
      return handleCreateRequest(req, origins, sendResponse);
    }

    if (!validateGetRequest(req)) {
      sendResponse({ ok: false, type: "get", error: "invalid_request" });
      return false;
    }
    return handleGetRequest(req, origins, sendResponse);
  });
})(__PASSLESS_PORT__, __PASSLESS_BEARER__);
