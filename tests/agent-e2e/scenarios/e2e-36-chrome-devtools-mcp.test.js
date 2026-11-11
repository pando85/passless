'use strict';
const { scenario, assert } = require('../lib/scenario');
const { assertVerifiedAssertion, assertAgentAllowed, assertNoNotification } = require('../lib/helpers');
const { toolText, evalJson, authenticateFn } = require('../lib/adapters');

/** chrome-devtools-mcp tools take a numeric `pageId`; the page tools answer with the page list, the selected one marked `[selected]`. */
const selectedPageId = res => {
  const m = toolText(res).match(/^(\d+): .*\[selected\]/m);
  assert.ok(m, `no selected page in: ${toolText(res)}`);
  return Number(m[1]);
};

// Catalogue E2E-36: chrome-devtools-mcp through `passless agent mcp chrome-devtools`, including `isolatedContext` (a page in
// a browser context of its own, created over CDP). The adapter ensures the browser first and runs
// `npx --yes chrome-devtools-mcp --browserUrl http://127.0.0.1:<port>`: puppeteer cannot send the bootstrap's bearer header, so
// discovery cannot be lazy and authenticated here.
scenario({ id: 'E2E-36', title: 'chrome-devtools-mcp via `agent mcp chrome-devtools`, including isolatedContext', ci: false }, async ctx => {
  const stack = await ctx.stack({
    rps: { a: { host: 'rp-a.test' } },
    profiles: { agent: { mode: 'same-user', rules: [{ rp: 'rp-a.test', authenticate: 'allow', register: 'deny' }] } },
  });
  const rp = stack.rp.a;
  await stack.seedHuman(rp, 'alice');

  const mcp = stack.adapter('chrome-devtools', { profile: 'agent' });
  const init = await mcp.client.initialize();
  assert.ok(init.serverInfo, 'the adapter speaks MCP on stdio');
  const tools = (await mcp.client.listTools()).map(t => t.name);
  for (const t of ['navigate_page', 'new_page', 'evaluate_script']) assert.ok(tools.includes(t), `${t} in ${tools.join(', ')}`);

  const pages = await mcp.client.callTool('list_pages', {});
  const nav = await mcp.client.callTool('navigate_page', { pageId: selectedPageId(pages), type: 'url', url: `${rp.origin}/sw` }, 120000);
  assert.ok(!nav.isError, toolText(nav));
  assertVerifiedAssertion(rp, evalJson(await mcp.client.callTool('evaluate_script', { pageId: selectedPageId(pages), function: authenticateFn('alice') }, 120000)), { username: 'alice' });

  // isolatedContext: a CDP-created browser context, intercepted through the incognito seed.
  const page = await mcp.client.callTool('new_page', { url: `${rp.origin}/sw`, isolatedContext: 'agent-iso' }, 120000);
  assert.ok(!page.isError, toolText(page));
  assert.match(toolText(page), /isolatedContext=agent-iso/, 'the page is in the named isolated context');
  assertVerifiedAssertion(rp, evalJson(await mcp.client.callTool('evaluate_script', { pageId: selectedPageId(page), function: authenticateFn('alice') }, 120000)), { username: 'alice' });

  await assertAgentAllowed(stack, { rpId: 'rp-a.test', n: 2 });
  assertNoNotification(stack);
  const b = await stack.launch('agent');
  const cdp = await b.browser.newBrowserCDPSession();
  const { browserContextIds } = await cdp.send('Target.getBrowserContexts');
  assert.ok(browserContextIds.length >= 1, `new_page isolatedContext created no browser context: ${JSON.stringify(browserContextIds)}`);
  await cdp.detach();

  const [argv] = mcp.npxCalls();
  assert.deepEqual(argv.slice(0, 2), ['--yes', 'chrome-devtools-mcp']);
  assert.match(argv[argv.indexOf('--browserUrl') + 1], /^http:\/\/127\.0\.0\.1:\d+$/);
});
