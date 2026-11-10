'use strict';
const { scenario, assert } = require('../lib/scenario');
const { authenticate, assertVerifiedAssertion, assertInterceptionActive, assertAgentAllowed } = require('../lib/helpers');

// Catalogue: popup and same-origin iframe both work.
scenario({ id: 'E2E-08', title: 'popup and same-origin iframe' }, async ctx => {
  const stack = await ctx.stack({
    rps: { a: { host: 'rp-a.test' } },
    profiles: { agent: { mode: 'same-user', rules: [{ rp: 'rp-a.test', authenticate: 'allow', register: 'deny' }] } },
  });
  const rp = stack.rp.a;
  await stack.seedHuman(rp, 'alice');

  // Same-origin iframe.
  const b = await stack.open('agent', `${rp.origin}/iframe-host`);
  assertInterceptionActive(b);
  await b.page.waitForLoadState('load');
  const frame = b.page.frames().find(f => f.name() === 'f');
  assert.ok(frame, 'iframe not found');
  assertVerifiedAssertion(rp, await authenticate(frame, { username: 'alice' }), { username: 'alice' });

  // Popup opened by the page.
  await b.page.goto(`${rp.origin}/popup-opener`);
  const [popup] = await Promise.all([
    b.context.waitForEvent('page', { timeout: 15000 }),
    b.page.evaluate(() => window.openPopup('/sw')),
  ]);
  await popup.waitForLoadState('load');
  const injected = await popup.evaluate(() => document.documentElement.hasAttribute('data-passless-agent-broker'));
  assert.equal(injected, true, 'extension content script not injected into the popup');
  assertVerifiedAssertion(rp, await authenticate(popup, { username: 'alice' }), { username: 'alice' });

  await assertAgentAllowed(stack, { rpId: 'rp-a.test', n: 2 });
});
