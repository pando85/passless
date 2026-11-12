'use strict';
const { chromium } = require('playwright-core');

const { scenario, assert } = require('../lib/scenario');
const { assertVerifiedAssertion, assertAgentAllowed, assertNoNotification, authenticate } = require('../lib/helpers');
const { startPrincipalShell } = require('../lib/adapters');

// Catalogue E2E-37: the Playwright library over the endpoint `passless agent browser` prints: an agent (a principal session
// started by `agent run`) calls `agent browser --env --wait`, gets PASSLESS_CDP_URL and connects with connectOverCDP(); the
// page it drives, in the default context and in a context it creates over CDP, is intercepted. The second `agent browser`
// call (--json) prints the same endpoint: the browser is ensured, not restarted.
// Port-only: connectOverCDP(PASSLESS_CDP_URL) needs a CDP endpoint, which pipe mode never prints (ADR 0014 §4.3, E2E-52).
scenario({ id: 'E2E-37', title: 'Playwright connectOverCDP(PASSLESS_CDP_URL) from `agent browser`', ci: true }, async ctx => {
  const stack = await ctx.stack({
    rps: { a: { host: 'rp-a.test' } },
    profiles: { agent: { mode: 'same-user', rules: [{ rp: 'rp-a.test', authenticate: 'allow', register: 'deny' }] } },
  });
  const rp = stack.rp.a;
  await stack.seedHuman(rp, 'alice');

  const agent = startPrincipalShell(stack, 'agent',
    '"$PASSLESS" agent browser --profile agent --env --wait && "$PASSLESS" agent browser --profile agent --json && echo AGENT-READY; exec sleep 900');
  let browser;
  try {
    await agent.waitForLine(/^AGENT-READY$/);
    const lines = agent.lines();
    const envLine = lines.find(l => l.startsWith('PASSLESS_CDP_URL='));
    assert.match(envLine, /^PASSLESS_CDP_URL=http:\/\/127\.0\.0\.1:\d+$/, lines.join('\n'));
    const url = envLine.slice('PASSLESS_CDP_URL='.length);
    const json = JSON.parse(lines.find(l => l.startsWith('{')));
    assert.equal(json.status, 'ok');
    assert.equal(json.data.endpoint, url, 'agent browser is idempotent: the same endpoint');
    assert.equal(json.data.interception, 'attached', 'the endpoint is only handed out once the worker attached');
    assert.equal(json.data.incognito_allowed, true, 'and once incognito access is confirmed');
    assert.equal(json.data.profile, 'agent');

    browser = await chromium.connectOverCDP(url);
    // The default context.
    const page = browser.contexts()[0].pages()[0] || await browser.contexts()[0].newPage();
    await page.goto(`${rp.origin}/sw`);
    await page.bringToFront();
    assertVerifiedAssertion(rp, await authenticate(page, { username: 'alice' }), { username: 'alice' });

    // A context created over CDP (Playwright `newContext()`).
    const isolated = await browser.newContext({ ignoreHTTPSErrors: true });
    const page2 = await isolated.newPage();
    await page2.goto(`${rp.origin}/sw`);
    await page2.bringToFront();
    assertVerifiedAssertion(rp, await authenticate(page2, { username: 'alice' }), { username: 'alice' });

    await assertAgentAllowed(stack, { rpId: 'rp-a.test', n: 2 });
    assertNoNotification(stack);
  } finally {
    try { await browser?.close(); } catch { /* gone */ }
    await agent.close();
  }
});
