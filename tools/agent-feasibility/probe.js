#!/usr/bin/env node

const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const { chromium } = require("playwright");

const root = __dirname;
const extensionPath = path.join(root, "extension");
const htmlTemplate = fs.readFileSync(path.join(root, "test-rp.html"), "utf8");
const profilePath = fs.mkdtempSync(path.join(os.tmpdir(), "passless-phase0-"));

function createServer(html) {
  return http.createServer((request, response) => {
    response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    response.end(html);
  });
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function fromBase64url(value) {
  return Buffer.from(value.replaceAll("-", "+").replaceAll("_", "/"), "base64");
}

function toBase64url(value) {
  return value.toString("base64url");
}

function decodeCbor(buffer, start = 0) {
  let offset = start;
  const first = buffer[offset++];
  const major = first >> 5;
  const additional = first & 31;
  let value;
  if (additional < 24) value = additional;
  else if (additional === 24) value = buffer[offset++];
  else if (additional === 25) { value = buffer.readUInt16BE(offset); offset += 2; }
  else if (additional === 26) { value = buffer.readUInt32BE(offset); offset += 4; }
  else throw new Error(`unsupported CBOR additional info ${additional}`);
  if (major === 0) return { value, offset };
  if (major === 1) return { value: -1 - value, offset };
  if (major === 2) return { value: buffer.subarray(offset, offset + value), offset: offset + value };
  if (major === 3) return { value: buffer.subarray(offset, offset + value).toString("utf8"), offset: offset + value };
  if (major === 5) {
    const map = new Map();
    for (let index = 0; index < value; index += 1) {
      const key = decodeCbor(buffer, offset); offset = key.offset;
      const entry = decodeCbor(buffer, offset); offset = entry.offset;
      map.set(key.value, entry.value);
    }
    return { value: map, offset };
  }
  throw new Error(`unsupported CBOR major type ${major}`);
}

function verifyCeremony(registration, assertion, origin) {
  const attestation = decodeCbor(fromBase64url(registration.response.attestationObject)).value;
  const registrationAuthData = attestation.get("authData");
  assert(attestation.get("fmt") === "none", "registration attestation format is not none");
  assert((registrationAuthData[32] & 0x41) === 0x41, "registration is missing UP or AT");
  const rpId = new URL(origin).hostname;
  const rpHash = crypto.createHash("sha256").update(rpId).digest();
  assert(registrationAuthData.subarray(0, 32).equals(rpHash), "registration RP hash mismatch");
  const credentialLength = registrationAuthData.readUInt16BE(53);
  const coseOffset = 55 + credentialLength;
  const cose = decodeCbor(registrationAuthData, coseOffset).value;
  const publicKey = crypto.createPublicKey({
    key: {
      kty: "EC",
      crv: "P-256",
      x: toBase64url(cose.get(-2)),
      y: toBase64url(cose.get(-3)),
    },
    format: "jwk",
  });
  const authData = fromBase64url(assertion.response.authenticatorData);
  assert((authData[32] & 0x01) === 0x01, "assertion is missing UP");
  assert(authData.subarray(0, 32).equals(rpHash), "assertion RP hash mismatch");
  const clientData = fromBase64url(assertion.response.clientDataJSON);
  const parsedClientData = JSON.parse(clientData.toString("utf8"));
  assert(parsedClientData.origin === origin, "assertion clientData origin mismatch");
  assert(parsedClientData.type === "webauthn.get", "assertion clientData type mismatch");
  const signed = Buffer.concat([
    authData,
    crypto.createHash("sha256").update(clientData).digest(),
  ]);
  assert(
    crypto.verify("sha256", signed, publicKey, fromBase64url(assertion.response.signature)),
    "assertion signature verification failed",
  );
}

async function extensionState(worker) {
  return worker.evaluate(async () => (await chrome.storage.local.get("phase0")).phase0);
}

async function waitForEvent(worker, type, count = 1) {
  const deadline = Date.now() + 10000;
  while (Date.now() < deadline) {
    const state = await extensionState(worker);
    if ((state?.events ?? []).filter((event) => event.type === type).length >= count) {
      return state;
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error(`timed out waiting for extension event ${type}`);
}

async function main() {
  const alternateServer = createServer("<!doctype html><title>alternate origin</title>");
  await new Promise((resolve) => alternateServer.listen(0, "127.0.0.1", resolve));
  const alternateOrigin = `http://localhost:${alternateServer.address().port}`;
  const server = createServer(htmlTemplate.replace("__ALT_ORIGIN__", alternateOrigin));
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = server.address().port;
  const origin = `http://localhost:${port}`;

  const context = await chromium.launchPersistentContext(profilePath, {
    executablePath: process.env.CHROMIUM_PATH || "/usr/bin/chromium",
    headless: false,
    args: [
      `--disable-extensions-except=${extensionPath}`,
      `--load-extension=${extensionPath}`,
      "--no-first-run",
      "--no-default-browser-check",
    ],
  });

  try {
    let workers = context.serviceWorkers();
    if (workers.length === 0) workers = [await context.waitForEvent("serviceworker")];
    const worker = workers[0];
    const attached = await waitForEvent(worker, "proxy_attached");
    assert(attached.attached === true, `proxy attach failed: ${attached.attachError}`);

    const pages = context.pages();
    const page = pages[0] ?? (await context.newPage());
    for (const extra of pages.slice(1)) await extra.close();
    await page.goto(origin);

    await worker.evaluate(() => globalThis.phase0SetMode("reject"));
    await page.click("#create");
    await page.waitForFunction(() => document.querySelector("#result").textContent !== "idle");
    const result = await page.locator("#result").textContent();
    assert(result.startsWith("NotAllowedError:"), `unexpected page result: ${result}`);

    let state = await waitForEvent(worker, "request_rejected");
    const requestEvent = state.events.find((event) => event.type === "request_received");
    assert(requestEvent, "proxy did not record create request");
    assert(
      JSON.stringify(requestEvent.rawKeys) === JSON.stringify(["requestDetailsJson", "requestId"]),
      `unexpected proxy payload keys: ${requestEvent.rawKeys}`,
    );
    assert(requestEvent.context.origin === origin, "derived origin does not match top document");
    assert(requestEvent.context.frameId === 0, "derived frame is not top-level");
    assert(requestEvent.context.frameCount === 1, "derived context contains subframes");
    assert(Boolean(requestEvent.context.documentId), "derived context has no documentId");

    await worker.evaluate(() => globalThis.phase0SetMode("success"));
    await page.goto(origin);
    await page.click("#create");
    try {
      await page.waitForFunction(
        () => document.querySelector("#result").textContent === "create-success",
        { timeout: 10000 },
      );
    } catch (error) {
      console.error("registration result:", await page.locator("#result").textContent());
      console.error("extension state:", JSON.stringify(await extensionState(worker), null, 2));
      throw error;
    }
    const registration = await page.evaluate(() => window.phase0Credential);
    await page.click("#get");
    await page.waitForFunction(() => document.querySelector("#result").textContent === "get-success");
    const assertion = await page.evaluate(() => window.phase0Assertion);
    verifyCeremony(registration, assertion, origin);

    await worker.evaluate(() => globalThis.phase0SetMode("reject"));
    await page.goto(origin);
    await page.click("#create-and-navigate");
    state = await waitForEvent(worker, "navigation_canceled");
    assert(
      state.events.some((event) => event.type === "navigation_canceled"),
      "navigation did not cancel pending request",
    );

    await page.goto(origin);
    const requestsBeforeRace = state.events.filter(
      (event) => event.type === "request_received",
    ).length;
    await page.click("#create-and-switch-origin");
    state = await waitForEvent(worker, "request_received", requestsBeforeRace + 1);
    const raceRequest = state.events.filter(
      (event) => event.type === "request_received",
    )[requestsBeforeRace];
    const raceBoundToWrongDocument = raceRequest.context.origin === alternateOrigin;

    const proxyAttachedBeforeNavigation = attached.attached === true;
    const navigationCanceled = state.events.some(
      (event) => event.type === "navigation_canceled",
    );
    const validRegistrationAndAuthentication = Boolean(registration && assertion);
    const relyingPartyVerifiedAssertionSignature = validRegistrationAndAuthentication;
    const evidence = {
      generatedAt: new Date().toISOString(),
      chromium: await chromiumVersion(context),
      origin,
      rawProxyEventKeys: requestEvent.rawKeys,
      derivedContext: requestEvent.context,
      pageResult: result,
      proxyAttachedBeforeNavigation,
      navigationCanceled,
      validRegistrationAndAuthentication,
      relyingPartyVerifiedAssertionSignature,
      crossOriginNavigationRace: {
        requestOrigin: origin,
        derivedOrigin: raceRequest.context.origin,
        alternateOrigin,
        falselyBoundToNewDocument: raceBoundToWrongDocument,
      },
      overallPhase0: "NO-GO",
      completedSubgate: "origin-document-no-fallback-probe",
      blockingReason:
        "webAuthenticationProxy does not bind a request to a source tab, frame, or document; querying current browser state cannot prove the request origin",
    };
    fs.writeFileSync(path.join(root, "evidence.json"), `${JSON.stringify(evidence, null, 2)}\n`);
    console.log(JSON.stringify(evidence, null, 2));
  } finally {
    await context.close();
    await new Promise((resolve) => server.close(resolve));
    await new Promise((resolve) => alternateServer.close(resolve));
    fs.rmSync(profilePath, { recursive: true, force: true });
  }
}

async function chromiumVersion(context) {
  const browser = context.browser();
  return browser ? browser.version() : "persistent-context";
}

main().catch((error) => {
  console.error(error.stack || error.message);
  process.exitCode = 1;
});
