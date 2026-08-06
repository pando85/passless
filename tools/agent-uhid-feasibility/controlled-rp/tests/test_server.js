import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';

const serverModule = await import('../server.js');

const {
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
  RP_ID,
  RP_NAME,
  EXPECTED_ORIGIN,
  ORIGIN_HTTP,
} = serverModule;

describe('base64url helpers', () => {
  it('roundtrips Uint8Array through base64url', () => {
    const original = new Uint8Array([0, 1, 2, 255, 128, 64]);
    const encoded = uint8ToBase64url(original);
    const decoded = base64urlToUint8(encoded);
    assert.deepStrictEqual(decoded, original);
  });

  it('produces url-safe characters', () => {
    const data = new Uint8Array(256);
    for (let i = 0; i < 256; i++) data[i] = i;
    const encoded = uint8ToBase64url(data);
    assert.ok(!encoded.includes('+'));
    assert.ok(!encoded.includes('/'));
    assert.ok(!encoded.includes('='));
  });
});

describe('challenge store', () => {
  beforeEach(() => {
    challengeStore.clear();
  });

  it('stores and retrieves a challenge', () => {
    storeChallenge('sess1', 'challenge-value');
    const result = consumeChallenge('sess1');
    assert.equal(result, 'challenge-value');
  });

  it('consumes (removes) the challenge after retrieval', () => {
    storeChallenge('sess2', 'value');
    consumeChallenge('sess2');
    const result = consumeChallenge('sess2');
    assert.equal(result, null);
  });

  it('returns null for nonexistent session', () => {
    assert.equal(consumeChallenge('nope'), null);
  });
});

describe('credential store', () => {
  beforeEach(() => {
    credentialStore.clear();
  });

  it('stores and retrieves a credential', () => {
    const cred = {
      id: 'cred-1',
      publicKey: new Uint8Array([1, 2, 3]),
      counter: 0,
      transports: ['internal'],
    };
    storeCredential(cred, 'user-a');
    const retrieved = getCredential('cred-1');
    assert.ok(retrieved);
    assert.equal(retrieved.id, 'cred-1');
    assert.equal(retrieved.counter, 0);
    assert.deepStrictEqual(retrieved.publicKey, new Uint8Array([1, 2, 3]));
    assert.deepStrictEqual(retrieved.transports, ['internal']);
  });

  it('returns null for unknown credential', () => {
    assert.equal(getCredential('unknown'), null);
  });

  it('lists credentials for a user', () => {
    storeCredential({ id: 'c1', publicKey: new Uint8Array([1]), counter: 0 }, 'userA');
    storeCredential({ id: 'c2', publicKey: new Uint8Array([2]), counter: 0 }, 'userA');
    storeCredential({ id: 'c3', publicKey: new Uint8Array([3]), counter: 0 }, 'userB');
    const results = getCredentialsForUser('userA');
    assert.equal(results.length, 2);
    const ids = new Set(results.map((r) => r.id));
    assert.ok(ids.has('c1'));
    assert.ok(ids.has('c2'));
  });

  it('updates credential counter', () => {
    storeCredential({ id: 'c-upd', publicKey: new Uint8Array([1]), counter: 5 }, 'userX');
    updateCredentialCounter('c-upd', 10);
    const retrieved = getCredential('c-upd');
    assert.equal(retrieved.counter, 10);
  });
});

describe('handleRegisterBegin', () => {
  beforeEach(() => {
    challengeStore.clear();
    credentialStore.clear();
    registrationUserStore.clear();
  });

  it('returns valid registration options structure', async () => {
    const result = await handleRegisterBegin({ userName: 'alice', userId: 'user-1' });
    assert.ok(result.challenge);
    assert.ok(result.session_id);
    assert.equal(result.rp.id, RP_ID);
    assert.equal(result.rp.name, RP_NAME);
    assert.equal(result.user.name, 'alice');
    assert.ok(result.user.id);
    assert.ok(Array.isArray(result.pubKeyCredParams));
    assert.equal(result.attestation, 'none');
    assert.equal(result.authenticatorSelection.residentKey, 'required');
    assert.equal(result.authenticatorSelection.userVerification, 'preferred');
    assert.equal(result.authenticatorSelection.authenticatorAttachment, undefined);
  });

  it('stores the challenge for later verification', async () => {
    const result = await handleRegisterBegin({ userName: 'bob' });
    const stored = consumeChallenge(result.session_id);
    assert.equal(stored, result.challenge);
  });

  it('includes excludeCredentials for existing user credentials', async () => {
    storeCredential(
      { id: 'existing-cred', publicKey: new Uint8Array([1]), counter: 0, transports: ['internal'] },
      'user-existing',
    );
    const result = await handleRegisterBegin({ userName: 'bob', userId: 'user-existing' });
    assert.ok(result.excludeCredentials);
    assert.equal(result.excludeCredentials.length, 1);
    assert.equal(result.excludeCredentials[0].id, 'existing-cred');
  });
});

describe('handleRegisterFinish', () => {
  beforeEach(() => {
    challengeStore.clear();
    credentialStore.clear();
    registrationUserStore.clear();
  });

  it('rejects missing session_id', async () => {
    const result = await handleRegisterFinish({});
    assert.equal(result.ok, false);
    assert.match(result.error, /missing session_id/);
  });

  it('rejects expired/invalid session', async () => {
    const result = await handleRegisterFinish({ session_id: 'nonexistent' });
    assert.equal(result.ok, false);
    assert.match(result.error, /invalid or expired/);
  });

  it('rejects response with missing fields', async () => {
    storeChallenge('sess-reg', 'test-challenge');
    const result = await handleRegisterFinish({
      session_id: 'sess-reg',
      id: 'some-id',
      rawId: 'some-id',
    });
    assert.equal(result.ok, false);
  });
});

describe('handleAuthenticateBegin', () => {
  beforeEach(() => {
    challengeStore.clear();
    credentialStore.clear();
  });

  it('returns valid authentication options', async () => {
    const result = await handleAuthenticateBegin({});
    assert.ok(result.challenge);
    assert.ok(result.session_id);
    assert.equal(result.rpId, RP_ID);
    assert.equal(result.userVerification, 'preferred');
  });

  it('includes allowCredentials when user has credentials', async () => {
    storeCredential(
      { id: 'auth-cred', publicKey: new Uint8Array([1]), counter: 0, transports: ['internal'] },
      'user-auth',
    );
    const result = await handleAuthenticateBegin({ userId: 'user-auth' });
    assert.ok(result.allowCredentials);
    assert.equal(result.allowCredentials.length, 1);
    assert.equal(result.allowCredentials[0].id, 'auth-cred');
  });

  it('omits allowCredentials when user has no credentials', async () => {
    const result = await handleAuthenticateBegin({ userId: 'nobody' });
    assert.ok(!result.allowCredentials);
  });
});

describe('handleAuthenticateFinish', () => {
  beforeEach(() => {
    challengeStore.clear();
    credentialStore.clear();
  });

  it('rejects missing session_id', async () => {
    const result = await handleAuthenticateFinish({});
    assert.equal(result.ok, false);
    assert.match(result.error, /missing session_id/);
  });

  it('rejects expired/invalid session', async () => {
    const result = await handleAuthenticateFinish({ session_id: 'nonexistent' });
    assert.equal(result.ok, false);
    assert.match(result.error, /invalid or expired/);
  });

  it('rejects unknown credential', async () => {
    storeChallenge('sess-auth', 'challenge');
    const result = await handleAuthenticateFinish({
      session_id: 'sess-auth',
      id: 'unknown-cred',
      rawId: 'unknown-cred',
      response: {
        clientDataJSON: 'something',
        authenticatorData: 'something',
        signature: 'something',
      },
    });
    assert.equal(result.ok, false);
    assert.match(result.error, /credential not found/);
  });
});

describe('HTTP endpoint integration', () => {
  let server;
  let baseUrl;

  beforeEach(async () => {
    challengeStore.clear();
    credentialStore.clear();
    registrationUserStore.clear();
    server = serverModule.startServer(0, '127.0.0.1');
    await new Promise((resolve) => server.on('listening', resolve));
    const addr = server.address();
    baseUrl = `http://127.0.0.1:${addr.port}`;
  });

  afterEach(async () => {
    await new Promise((resolve) => server.close(resolve));
  });

  it('serves GET /api/status', async () => {
    const resp = await fetch(`${baseUrl}/api/status`);
    const data = await resp.json();
    assert.equal(data.status, 'ok');
    assert.equal(data.rp_id, RP_ID);
    assert.equal(data.credentials_registered, 0);
  });

  it('serves static index.html at /', async () => {
    const resp = await fetch(`${baseUrl}/`);
    assert.equal(resp.status, 200);
    const html = await resp.text();
    assert.ok(html.includes('navigator.credentials'));
  });

  it('returns 404 for unknown paths', async () => {
    const resp = await fetch(`${baseUrl}/nonexistent`);
    assert.equal(resp.status, 404);
  });

  it('POST /api/register/begin returns options', async () => {
    const resp = await fetch(`${baseUrl}/api/register/begin`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ userName: 'testuser', userId: 'user1' }),
    });
    const data = await resp.json();
    assert.ok(data.challenge);
    assert.ok(data.session_id);
    assert.equal(data.rp.id, RP_ID);
  });

  it('POST /api/register/finish rejects invalid session', async () => {
    const resp = await fetch(`${baseUrl}/api/register/finish`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ session_id: 'bad' }),
    });
    const data = await resp.json();
    assert.equal(data.ok, false);
  });

  it('POST /api/authenticate/begin returns options', async () => {
    const resp = await fetch(`${baseUrl}/api/authenticate/begin`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });
    const data = await resp.json();
    assert.ok(data.challenge);
    assert.ok(data.session_id);
    assert.equal(data.rpId, RP_ID);
  });

  it('POST /api/authenticate/finish rejects invalid session', async () => {
    const resp = await fetch(`${baseUrl}/api/authenticate/finish`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ session_id: 'bad' }),
    });
    const data = await resp.json();
    assert.equal(data.ok, false);
  });

  it('registration begin → finish rejects malformed attestation', async () => {
    const beginResp = await fetch(`${baseUrl}/api/register/begin`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ userName: 'test', userId: 'u1' }),
    });
    const options = await beginResp.json();

    const finishResp = await fetch(`${baseUrl}/api/register/finish`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        session_id: options.session_id,
        id: 'ZmFrZS1jcmVkLWlk',
        rawId: 'ZmFrZS1jcmVkLWlk',
        type: 'public-key',
        response: {
          clientDataJSON: Buffer.from(JSON.stringify({
            type: 'webauthn.create',
            challenge: options.challenge,
            origin: ORIGIN_HTTP,
          })).toString('base64url'),
          attestationObject: Buffer.from('not-valid-cbor').toString('base64url'),
        },
        clientExtensionResults: {},
      }),
    });
    const result = await finishResp.json();
    assert.equal(result.ok, false);
    assert.ok(result.error);
  });

  it('authentication finish rejects unknown credential with valid session', async () => {
    const beginResp = await fetch(`${baseUrl}/api/authenticate/begin`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });
    const options = await beginResp.json();

    const finishResp = await fetch(`${baseUrl}/api/authenticate/finish`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        session_id: options.session_id,
        id: 'bm9uZXhpc3RlbnQ',
        rawId: 'bm9uZXhpc3RlbnQ',
        type: 'public-key',
        response: {
          clientDataJSON: Buffer.from('test').toString('base64url'),
          authenticatorData: Buffer.from('test').toString('base64url'),
          signature: Buffer.from('test').toString('base64url'),
        },
        clientExtensionResults: {},
      }),
    });
    const result = await finishResp.json();
    assert.equal(result.ok, false);
    assert.match(result.error, /credential not found/);
  });

});

describe('registrationUserStore binding', () => {
  beforeEach(() => {
    challengeStore.clear();
    credentialStore.clear();
    registrationUserStore.clear();
  });

  it('binds userId to session at registration begin', async () => {
    const result = await handleRegisterBegin({ userName: 'alice', userId: 'user-A' });
    const entry = registrationUserStore.get(result.session_id);
    assert.ok(entry, 'registrationUserStore should have an entry for the session');
    assert.equal(entry.userId, 'user-A');
    assert.ok(entry.created, 'entry should have a created timestamp');
  });

  it('does not allow finish payload to override bound userId', async () => {
    const beginResult = await handleRegisterBegin({ userName: 'alice', userId: 'user-A' });
    const sessionId = beginResult.session_id;

    const finishResult = await handleRegisterFinish({
      session_id: sessionId,
      userId: 'user-EVIL',
      id: 'ZmFrZS1jcmVkLWlk',
      rawId: 'ZmFrZS1jcmVkLWlk',
      type: 'public-key',
      response: {
        clientDataJSON: Buffer.from('fake').toString('base64url'),
        attestationObject: Buffer.from('fake').toString('base64url'),
      },
    });

    assert.equal(finishResult.ok, false);
    assert.equal(
      registrationUserStore.has(sessionId),
      false,
      'registrationUserStore entry must be cleaned up even on failed finish',
    );
  });

  it('cleans up registrationUserStore on expired session', async () => {
    const beginResult = await handleRegisterBegin({ userName: 'bob', userId: 'user-B' });
    const sessionId = beginResult.session_id;

    assert.ok(registrationUserStore.has(sessionId));

    challengeStore.delete(sessionId);

    const finishResult = await handleRegisterFinish({
      session_id: sessionId,
      id: 'ZmFrZQ',
      rawId: 'ZmFrZQ',
      type: 'public-key',
      response: {
        clientDataJSON: Buffer.from('x').toString('base64url'),
        attestationObject: Buffer.from('x').toString('base64url'),
      },
    });

    assert.equal(finishResult.ok, false);
    assert.match(finishResult.error, /invalid or expired/);
    assert.equal(
      registrationUserStore.has(sessionId),
      false,
      'registrationUserStore must be cleaned up even when challenge is expired',
    );
  });

  it('does not affect other sessions when finish has missing session_id', async () => {
    const beginResult = await handleRegisterBegin({ userName: 'carol', userId: 'user-C' });
    const sessionId = beginResult.session_id;
    assert.ok(registrationUserStore.has(sessionId));

    const finishResult = await handleRegisterFinish({});
    assert.equal(finishResult.ok, false);
    assert.match(finishResult.error, /missing session_id/);

    assert.equal(
      registrationUserStore.has(sessionId),
      true,
      'unrelated failed finish must not affect other sessions',
    );
  });

  it('evicts stale registrationUserStore entries via TTL', async () => {
    const beginResult = await handleRegisterBegin({ userName: 'dave', userId: 'user-D' });
    const sessionId = beginResult.session_id;
    assert.ok(registrationUserStore.has(sessionId));

    registrationUserStore.get(sessionId).created = Date.now() - (6 * 60 * 1000);

    await handleRegisterBegin({ userName: 'eve', userId: 'user-E' });

    assert.equal(
      registrationUserStore.has(sessionId),
      false,
      'stale entry should be evicted when evictExpiredChallenges runs',
    );
  });

  it('no stale registrationUserStore entries remain after multiple begin/finish cycles', async () => {
    for (let i = 0; i < 5; i++) {
      const beginResult = await handleRegisterBegin({
        userName: `user-${i}`,
        userId: `uid-${i}`,
      });
      await handleRegisterFinish({
        session_id: beginResult.session_id,
        id: 'ZmFrZQ',
        rawId: 'ZmFrZQ',
        type: 'public-key',
        response: {
          clientDataJSON: Buffer.from('x').toString('base64url'),
          attestationObject: Buffer.from('x').toString('base64url'),
        },
      });
    }

    assert.equal(
      registrationUserStore.size,
      0,
      'registrationUserStore should be empty after all sessions complete or fail',
    );
  });
});

describe('registration → authentication round-trip', () => {
  beforeEach(() => {
    challengeStore.clear();
    credentialStore.clear();
    registrationUserStore.clear();
  });

  it('registration begin includes excludeCredentials for the bound user', async () => {
    storeCredential(
      { id: 'existing-1', publicKey: new Uint8Array([1]), counter: 0, transports: ['internal'] },
      'roundtrip-user',
    );
    storeCredential(
      { id: 'other-cred', publicKey: new Uint8Array([2]), counter: 0, transports: ['usb'] },
      'different-user',
    );

    const result = await handleRegisterBegin({
      userName: 'roundtrip',
      userId: 'roundtrip-user',
    });

    assert.ok(result.excludeCredentials);
    assert.equal(result.excludeCredentials.length, 1);
    assert.equal(result.excludeCredentials[0].id, 'existing-1');
  });

  it('authentication begin includes allowCredentials for a registered user', async () => {
    storeCredential(
      { id: 'cred-rt-1', publicKey: new Uint8Array([1]), counter: 0, transports: ['internal'] },
      'rt-user',
    );
    storeCredential(
      { id: 'cred-rt-2', publicKey: new Uint8Array([2]), counter: 0, transports: ['internal'] },
      'rt-user',
    );

    const result = await handleAuthenticateBegin({ userId: 'rt-user' });

    assert.ok(result.allowCredentials);
    assert.equal(result.allowCredentials.length, 2);
    const ids = new Set(result.allowCredentials.map((c) => c.id));
    assert.ok(ids.has('cred-rt-1'));
    assert.ok(ids.has('cred-rt-2'));
  });

  it('authentication begin omits allowCredentials when userId is not provided', async () => {
    storeCredential(
      { id: 'cred-x', publicKey: new Uint8Array([1]), counter: 0, transports: ['internal'] },
      'some-user',
    );

    const result = await handleAuthenticateBegin({});
    assert.ok(!result.allowCredentials);
  });

  it('full round-trip: register then authenticate targets the correct user credentials', async () => {
    const regOptions = await handleRegisterBegin({
      userName: 'alice',
      userId: 'alice-id',
    });

    assert.ok(regOptions.session_id);
    assert.ok(registrationUserStore.has(regOptions.session_id));
    assert.equal(registrationUserStore.get(regOptions.session_id).userId, 'alice-id');

    storeCredential(
      { id: 'alice-cred', publicKey: new Uint8Array([10]), counter: 0, transports: ['internal'] },
      'alice-id',
    );

    const authOptions = await handleAuthenticateBegin({ userId: 'alice-id' });
    assert.ok(authOptions.allowCredentials);
    assert.equal(authOptions.allowCredentials.length, 1);
    assert.equal(authOptions.allowCredentials[0].id, 'alice-cred');
  });
});
