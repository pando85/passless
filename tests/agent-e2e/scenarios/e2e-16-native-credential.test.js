'use strict';
const { scenario, assert } = require('../lib/scenario');
const { policyEvents, assertVerifiedAssertion, assertInterceptionActive, assertNoNotification } = require('../lib/helpers');

// Catalogue: the page receives a native PublicKeyCredential (plan D1, ADR 0014 §11). The extension completes the
// browser's WebAuthn proxy request with the daemon's responseJson, and Chromium itself builds the credential object:
// `instanceof PublicKeyCredential`, an AuthenticatorAttestationResponse / AuthenticatorAssertionResponse, and a working
// `toJSON()`, whose output (not a page-built serialisation) the RP verifies. No MAIN-world shim exists: the
// navigator.credentials methods are the browser's own and no Passless attribute or global is present.
scenario({ id: 'E2E-16', title: 'native PublicKeyCredential for create and get; no MAIN-world shim', ci: true }, async ctx => {
  const stack = await ctx.stack({
    rps: { a: { host: 'rp-a.test' } },
    profiles: { iso: { mode: 'isolated', rules: [{ rp: 'rp-a.test', register: 'allow', authenticate: 'allow' }] } },
  });
  const rp = stack.rp.a;
  const b = await stack.open('iso', `${rp.origin}/raw`);
  assertInterceptionActive(b);
  await b.page.waitForFunction(() => window.e2e);

  const probe = await b.page.evaluate(() => window.e2e.shimProbe());
  assert.deepEqual(probe, {
    getNative: true, createNative: true, credentialsProtoGetNative: true, ownGet: false, ownCreate: false,
    markerAttributes: [], passlessGlobals: [],
  }, 'no MAIN-world shim may be present');

  // create: the browser's toJSON() output is what the RP verifies.
  const reg = await b.page.evaluate(() => window.e2e.register({ username: 'carol', userVerification: 'preferred', timeout: 20000, viaToJSON: true }));
  assert.equal(reg.ok, true, `registration failed: ${JSON.stringify(reg)}`);
  assert.deepEqual(reg.received && {
    ctor: reg.received.ctor, pkc: reg.received.instanceOfPublicKeyCredential, toJSON: reg.received.hasToJSON,
    response: reg.received.responseCtor, attestation: reg.received.responseIsAttestation, assertion: reg.received.responseIsAssertion,
    type: reg.received.type,
  }, {
    ctor: 'PublicKeyCredential', pkc: true, toJSON: true, response: 'AuthenticatorAttestationResponse', attestation: true, assertion: false, type: 'public-key',
  }, `create() must yield a native PublicKeyCredential: ${JSON.stringify(reg.received)}`);
  assert.equal(reg.origin, rp.origin);
  assert.equal(reg.flags.uv, true);

  // get, likewise.
  const auth = await b.page.evaluate(() => window.e2e.authenticate({ username: 'carol', timeout: 20000, viaToJSON: true }));
  assertVerifiedAssertion(rp, auth, { username: 'carol' });
  assert.deepEqual(auth.received && {
    ctor: auth.received.ctor, pkc: auth.received.instanceOfPublicKeyCredential, toJSON: auth.received.hasToJSON,
    response: auth.received.responseCtor, attestation: auth.received.responseIsAttestation, assertion: auth.received.responseIsAssertion,
    attachment: auth.received.authenticatorAttachment,
  }, {
    ctor: 'PublicKeyCredential', pkc: true, toJSON: true, response: 'AuthenticatorAssertionResponse', attestation: false, assertion: true, attachment: 'cross-platform',
  }, `get() must yield a native PublicKeyCredential: ${JSON.stringify(auth.received)}`);

  // Still no shim after the ceremonies.
  assert.deepEqual(await b.page.evaluate(() => window.e2e.shimProbe()), probe);

  const audit = await stack.daemon.audit();
  assert.equal(policyEvents(audit, 'policy.allow').filter(e => e.profile_id === 'iso').length, 2, 'both ceremonies on the agent path');

  // ADR 0014 §7 (E-03): credential types other than `public-key` (passwords, federated) are the browser's own business and
  // never reach an authenticator, so neither the extension nor the daemon sees them. The page may get null or an error
  // (what the browser does with them is not Passless's concern); what matters is that no operation record appears.
  const operationRecords = events => events.filter(e => /^(policy|operation)\./.test(e.kind || '')).length;
  const nonPublicKey = await b.page.evaluate(async () => {
    const outcome = {};
    const attempts = [
      ['password', { password: true }],
      ['federated', { federated: { providers: ['https://idp.example'] } }],
    ];
    for (const [name, options] of attempts) {
      try {
        const credential = await Promise.race([
          navigator.credentials.get(options),
          new Promise(resolve => setTimeout(() => resolve('timeout'), 5000)),
        ]);
        outcome[name] = credential === null ? 'null' : typeof credential === 'string' ? credential : credential.type;
      } catch (e) {
        outcome[name] = `error:${e && e.name}`;
      }
    }
    return outcome;
  });
  const afterNonPublicKey = await stack.daemon.audit();
  assert.equal(operationRecords(afterNonPublicKey), operationRecords(audit),
    `a non-public-key credential call must not reach the daemon (page saw ${JSON.stringify(nonPublicKey)})`);
  assertNoNotification(stack);
});
