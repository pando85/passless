#!/usr/bin/env node

import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';

import { createServer } from 'node:http';
import { readFileSync, existsSync } from 'node:fs';
import { join, extname } from 'node:path';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const __dirname = fileURLToPath(new URL('.', import.meta.url));

const RP_ID = 'localhost';
const RP_NAME = 'Passless Controlled RP';
const ORIGIN_HTTP = 'http://localhost:8443';
const ORIGIN_HTTPS = 'https://localhost:8443';
const EXPECTED_ORIGIN = [ORIGIN_HTTP, ORIGIN_HTTPS];

const MIME_TYPES = {
  '.html': 'text/html',
  '.js': 'application/javascript',
  '.css': 'text/css',
  '.json': 'application/json',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
};

const challengeStore = new Map();
const CHALLENGE_TTL_MS = 5 * 60 * 1000;

const credentialStore = new Map();
const registrationUserStore = new Map();

function storeChallenge(sessionId, challenge) {
  challengeStore.set(sessionId, { challenge, created: Date.now() });
  evictExpiredChallenges();
}

function consumeChallenge(sessionId) {
  const entry = challengeStore.get(sessionId);
  if (!entry) return null;
  challengeStore.delete(sessionId);
  if (Date.now() - entry.created > CHALLENGE_TTL_MS) return null;
  return entry.challenge;
}

function evictExpiredChallenges() {
  const now = Date.now();
  for (const [key, val] of challengeStore) {
    if (now - val.created > CHALLENGE_TTL_MS) challengeStore.delete(key);
  }
  for (const [key, val] of registrationUserStore) {
    if (now - val.created > CHALLENGE_TTL_MS) registrationUserStore.delete(key);
  }
}

function uint8ToBase64url(uint8) {
  return Buffer.from(uint8).toString('base64url');
}

function base64urlToUint8(b64) {
  return new Uint8Array(Buffer.from(b64, 'base64url'));
}

function storeCredential(credential, userId) {
  credentialStore.set(credential.id, {
    ...credential,
    publicKey: uint8ToBase64url(credential.publicKey),
    userId,
  });
}

function getCredential(credentialId) {
  const stored = credentialStore.get(credentialId);
  if (!stored) return null;
  return {
    id: stored.id,
    publicKey: base64urlToUint8(stored.publicKey),
    counter: stored.counter,
    transports: stored.transports,
  };
}

function getCredentialsForUser(userId) {
  const results = [];
  for (const [id, cred] of credentialStore) {
    if (cred.userId === userId) {
      results.push({ id, ...cred });
    }
  }
  return results;
}

function updateCredentialCounter(credentialId, newCounter) {
  const stored = credentialStore.get(credentialId);
  if (stored) stored.counter = newCounter;
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => {
      try {
        const body = Buffer.concat(chunks).toString();
        resolve(body ? JSON.parse(body) : {});
      } catch {
        reject(new Error('invalid JSON'));
      }
    });
    req.on('error', reject);
  });
}

function sendJson(res, status, data) {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
  });
  res.end(body);
}

function serveStatic(res, filePath) {
  if (!existsSync(filePath)) {
    res.writeHead(404);
    res.end('Not found');
    return;
  }
  const ext = extname(filePath);
  const mime = MIME_TYPES[ext] || 'application/octet-stream';
  const content = readFileSync(filePath);
  res.writeHead(200, { 'Content-Type': mime });
  res.end(content);
}

async function handleRegisterBegin(body) {
  const userName = body.userName || 'testuser';
  const userId = body.userId || 'default-user';

  const existingCreds = getCredentialsForUser(userId).map((c) => ({
    id: c.id,
    transports: c.transports,
  }));

  const userIDBytes = new Uint8Array(
    Buffer.from(userId.padEnd(64, '\0').slice(0, 64)),
  );

  const options = await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID: RP_ID,
    userName,
    userID: userIDBytes,
    userDisplayName: userName,
    attestationType: 'none',
    excludeCredentials: existingCreds,
    authenticatorSelection: {
      residentKey: 'required',
      userVerification: 'preferred',
    },
    supportedAlgorithmIDs: [-7, -257],
    timeout: 60000,
  });

  const sessionId = randomBytes(16).toString('hex');
  storeChallenge(sessionId, options.challenge);
  registrationUserStore.set(sessionId, { userId, created: Date.now() });

  return { ...options, session_id: sessionId };
}

async function handleRegisterFinish(body) {
  const sessionId = body.session_id;
  if (!sessionId) return { ok: false, error: 'missing session_id' };

  const regUserEntry = registrationUserStore.get(sessionId);
  registrationUserStore.delete(sessionId);

  const expectedChallenge = consumeChallenge(sessionId);
  if (!expectedChallenge) {
    return { ok: false, error: 'invalid or expired session' };
  }
  const userId = regUserEntry ? regUserEntry.userId : undefined;

  const response = {
    id: body.id,
    rawId: body.rawId,
    response: {
      clientDataJSON: body.response?.clientDataJSON,
      attestationObject: body.response?.attestationObject,
      transports: body.response?.transports,
    },
    type: body.type || 'public-key',
    clientExtensionResults: body.clientExtensionResults || {},
  };

  try {
    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge,
      expectedOrigin: EXPECTED_ORIGIN,
      expectedRPID: RP_ID,
    });

    if (!verification.verified) {
      return { ok: false, error: 'verification failed' };
    }

    const { credential } = verification.registrationInfo;
    credential.transports = response.response.transports || [];
    storeCredential(credential, userId || 'unknown');

    return {
      ok: true,
      credentialId: credential.id,
      message: 'Registration verified',
      details: {
        origin: verification.registrationInfo.origin,
        rpID: verification.registrationInfo.rpID,
        aaguid: verification.registrationInfo.aaguid,
        fmt: verification.registrationInfo.fmt,
        userVerified: verification.registrationInfo.userVerified,
        credentialDeviceType: verification.registrationInfo.credentialDeviceType,
        credentialBackedUp: verification.registrationInfo.credentialBackedUp,
        counter: credential.counter,
        totalCredentials: credentialStore.size,
      },
    };
  } catch (err) {
    return { ok: false, error: err.message || String(err) };
  }
}

async function handleAuthenticateBegin(body) {
  const userId = body.userId;

  let allowCredentials;
  if (userId) {
    const creds = getCredentialsForUser(userId);
    if (creds.length > 0) {
      allowCredentials = creds.map((c) => ({
        id: c.id,
        transports: c.transports,
      }));
    }
  }

  const options = await generateAuthenticationOptions({
    rpID: RP_ID,
    allowCredentials,
    userVerification: 'preferred',
    timeout: 60000,
  });

  const sessionId = randomBytes(16).toString('hex');
  storeChallenge(sessionId, options.challenge);

  return { ...options, session_id: sessionId };
}

async function handleAuthenticateFinish(body) {
  const sessionId = body.session_id;
  if (!sessionId) return { ok: false, error: 'missing session_id' };

  const expectedChallenge = consumeChallenge(sessionId);
  if (!expectedChallenge) {
    return { ok: false, error: 'invalid or expired session' };
  }

  const credentialId = body.id;
  const storedCred = getCredential(credentialId);
  if (!storedCred) {
    return { ok: false, error: `credential not found: ${credentialId}` };
  }

  const response = {
    id: body.id,
    rawId: body.rawId,
    response: {
      clientDataJSON: body.response?.clientDataJSON,
      authenticatorData: body.response?.authenticatorData,
      signature: body.response?.signature,
      userHandle: body.response?.userHandle,
    },
    type: body.type || 'public-key',
    clientExtensionResults: body.clientExtensionResults || {},
  };

  try {
    const verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge,
      expectedOrigin: EXPECTED_ORIGIN,
      expectedRPID: RP_ID,
      credential: storedCred,
    });

    if (!verification.verified) {
      return { ok: false, error: 'verification failed' };
    }

    updateCredentialCounter(credentialId, verification.authenticationInfo.newCounter);

    return {
      ok: true,
      credentialId,
      message: 'Authentication verified',
      details: {
        origin: verification.authenticationInfo.origin,
        rpID: verification.authenticationInfo.rpID,
        userVerified: verification.authenticationInfo.userVerified,
        credentialDeviceType: verification.authenticationInfo.credentialDeviceType,
        credentialBackedUp: verification.authenticationInfo.credentialBackedUp,
        counter: verification.authenticationInfo.newCounter,
      },
    };
  } catch (err) {
    return { ok: false, error: err.message || String(err) };
  }
}

const routes = {
  'GET /': (req, res) => serveStatic(res, join(__dirname, 'static', 'index.html')),
  'GET /api/status': (_req, res) => {
    sendJson(res, 200, {
      status: 'ok',
      rp_id: RP_ID,
      credentials_registered: credentialStore.size,
    });
  },
  'POST /api/register/begin': async (_req, res, body) => {
    const result = await handleRegisterBegin(body);
    sendJson(res, 200, result);
  },
  'POST /api/register/finish': async (_req, res, body) => {
    const result = await handleRegisterFinish(body);
    sendJson(res, result.ok ? 200 : 400, result);
  },
  'POST /api/authenticate/begin': async (_req, res, body) => {
    const result = await handleAuthenticateBegin(body);
    sendJson(res, 200, result);
  },
  'POST /api/authenticate/finish': async (_req, res, body) => {
    const result = await handleAuthenticateFinish(body);
    sendJson(res, result.ok ? 200 : 400, result);
  },
};

async function requestHandler(req, res) {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const method = req.method;
  const key = `${method} ${url.pathname}`;

  if (method === 'GET' && !routes[key]) {
    const filePath = join(__dirname, 'static', url.pathname);
    if (existsSync(filePath) && !filePath.includes('..')) {
      serveStatic(res, filePath);
      return;
    }
    sendJson(res, 404, { ok: false, error: 'not found' });
    return;
  }

  const handler = routes[key];
  if (!handler) {
    sendJson(res, 404, { ok: false, error: 'not found' });
    return;
  }

  try {
    let body = {};
    if (method === 'POST') {
      body = await parseBody(req);
    }
    await handler(req, res, body);
  } catch (err) {
    sendJson(res, 500, { ok: false, error: err.message || String(err) });
  }
}

function startServer(port = 8443, host = '127.0.0.1') {
  const server = createServer(requestHandler);
  server.listen(port, host, () => {
    console.log(`Controlled RP listening on http://${host}:${port}`);
    console.log(`RP ID: ${RP_ID}`);
    console.log(`Expected origins: ${EXPECTED_ORIGIN.join(', ')}`);
    console.log('Press Ctrl+C to stop.\n');
  });
  return server;
}

const port = parseInt(process.argv[2] || process.env.PORT || '8443', 10);
const host = process.env.HOST || '127.0.0.1';

export {
  challengeStore,
  credentialStore,
  registrationUserStore,
  storeChallenge,
  consumeChallenge,
  storeCredential,
  getCredential,
  getCredentialsForUser,
  updateCredentialCounter,
  handleRegisterBegin,
  handleRegisterFinish,
  handleAuthenticateBegin,
  handleAuthenticateFinish,
  uint8ToBase64url,
  base64urlToUint8,
  startServer,
  RP_ID,
  RP_NAME,
  EXPECTED_ORIGIN,
  ORIGIN_HTTP,
  ORIGIN_HTTPS,
};

const isMain =
  process.argv[1] &&
  (fileURLToPath(import.meta.url) === join(process.argv[1]) ||
   fileURLToPath(import.meta.url) === process.argv[1]);

if (isMain) {
  startServer(port, host);
}
