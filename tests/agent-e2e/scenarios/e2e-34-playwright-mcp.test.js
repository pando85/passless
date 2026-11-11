'use strict';
const { scenario, assert } = require('../lib/scenario');
const { assertVerifiedAssertion, assertAgentAllowed, assertNoNotification } = require('../lib/helpers');
const { processesMentioning } = require('../lib/env');
const { toolText, evalJson, authenticateFn, browserProcesses } = require('../lib/adapters');
const { extensionWorkerTargets } = require('../lib/browser');

const profiles = { agent: { mode: 'same-user', rules: [{ rp: 'rp-a.test', authenticate: 'allow', register: 'deny' }] } };

// Catalogue E2E-34: Playwright MCP through `passless agent mcp playwright`: navigate, log in with a passkey. The adapter runs
// `npx --yes @playwright/mcp --cdp-endpoint <bootstrap> --cdp-header 'Authorization: Bearer ...'`; the bootstrap starts the
// managed browser lazily, on the first discovery request, which @playwright/mcp makes at its first browser tool call.
scenario({ id: 'E2E-34', title: 'Playwright MCP via `agent mcp playwright`: navigate and log in with a passkey', ci: true }, async ctx => {
  const stack = await ctx.stack({ rps: { a: { host: 'rp-a.test' } }, profiles });
  const rp = stack.rp.a;
  await stack.seedHuman(rp, 'alice');

  const mcp = stack.adapter('playwright', { profile: 'agent' });
  const init = await mcp.client.initialize();
  assert.ok(init.serverInfo, 'the adapter speaks MCP on stdio');
  const tools = (await mcp.client.listTools()).map(t => t.name);
  assert.ok(tools.includes('browser_navigate') && tools.includes('browser_evaluate'), tools.join(', '));

  // Lazy: initialize and tools/list start no browser.
  assert.deepEqual(browserProcesses(stack, processesMentioning), [], 'a browser was started before the first browser tool call');

  const nav = await mcp.client.callTool('browser_navigate', { url: `${rp.origin}/sw` }, 120000);
  assert.ok(!nav.isError, toolText(nav));
  assert.ok(browserProcesses(stack, processesMentioning).length > 0, 'the first browser tool call started the managed browser');

  const first = assertVerifiedAssertion(rp, evalJson(await mcp.client.callTool('browser_evaluate', { function: authenticateFn('alice') })), { username: 'alice' });
  const second = assertVerifiedAssertion(rp, evalJson(await mcp.client.callTool('browser_evaluate', { function: authenticateFn('alice') })), { username: 'alice' });
  assert.ok(second.counter > first.counter, 'counter increases');
  await assertAgentAllowed(stack, { rpId: 'rp-a.test', n: 2 });
  assertNoNotification(stack);

  // The adapter's command line: package, endpoint and bearer header (redacted by the shim).
  const calls = mcp.npxCalls();
  assert.equal(calls.length, 1, JSON.stringify(calls));
  const [argv] = calls;
  assert.deepEqual(argv.slice(0, 2), ['--yes', '@playwright/mcp']);
  const at = flag => argv[argv.indexOf(flag) + 1];
  assert.match(at('--cdp-endpoint'), /^http:\/\/127\.0\.0\.1:\d+$/, 'the loopback discovery endpoint');
  assert.equal(at('--cdp-header'), 'Authorization: Bearer <redacted>');
});

// Catalogue E2E-35: Playwright MCP with `--isolated`: the MCP server creates a browser context of its own
// (Target.createBrowserContext), which is off the record to the extension; it is intercepted only because the launcher
// seeded incognito access for it (plan D4).
scenario({ id: 'E2E-35', title: 'Playwright MCP with --isolated: the CDP-created context is intercepted', ci: true }, async ctx => {
  const stack = await ctx.stack({ rps: { a: { host: 'rp-a.test' } }, profiles });
  const rp = stack.rp.a;
  await stack.seedHuman(rp, 'alice');

  const mcp = stack.adapter('playwright', { profile: 'agent', extra: ['--isolated'] });
  await mcp.client.initialize();
  const nav = await mcp.client.callTool('browser_navigate', { url: `${rp.origin}/sw` }, 120000);
  assert.ok(!nav.isError, toolText(nav));
  assert.ok(mcp.npxCalls()[0].includes('--isolated'), `--isolated reached @playwright/mcp: ${JSON.stringify(mcp.npxCalls())}`);

  assertVerifiedAssertion(rp, evalJson(await mcp.client.callTool('browser_evaluate', { function: authenticateFn('alice') })), { username: 'alice' });
  await assertAgentAllowed(stack, { rpId: 'rp-a.test', n: 1 });
  assertNoNotification(stack);

  // The page is not in the default context: the browser has a CDP-created one.
  const b = await stack.launch('agent'); // the admin launch returns the live lease
  const cdp = await b.browser.newBrowserCDPSession();
  const { browserContextIds } = await cdp.send('Target.getBrowserContexts');
  assert.ok(browserContextIds.length >= 1, `@playwright/mcp --isolated created no browser context: ${JSON.stringify(browserContextIds)}`);
  assert.equal((await extensionWorkerTargets(b.browser)).length, 1, 'the extension worker runs once');
  await cdp.detach();
});

// P10b review L3: the default npx resolution, as a real MCP client configuration runs it: no `--npx`, `npx` found on the
// client's PATH (here a symlink to the harness shim in a directory of its own), and that directory forwarded first into
// the principal session's PATH, whose daemon environment need not have it (an nvm-installed node).
scenario({ id: 'E2E-34/default-npx', title: 'Playwright MCP without --npx: npx from PATH, its directory forwarded', ci: true }, async ctx => {
  const stack = await ctx.stack({ rps: { a: { host: 'rp-a.test' } }, profiles });
  const rp = stack.rp.a;
  await stack.seedHuman(rp, 'alice');

  const mcp = stack.adapter('playwright', { profile: 'agent', defaultNpx: true });
  assert.ok(!mcp.args.includes('--npx'), `the client configuration names no npx: ${mcp.args.join(' ')}`);
  await mcp.client.initialize();
  const nav = await mcp.client.callTool('browser_navigate', { url: `${rp.origin}/sw` }, 120000);
  assert.ok(!nav.isError, toolText(nav));
  assertVerifiedAssertion(rp, evalJson(await mcp.client.callTool('browser_evaluate', { function: authenticateFn('alice') })), { username: 'alice' });
  await assertAgentAllowed(stack, { rpId: 'rp-a.test', n: 1 });

  const calls = mcp.npxCalls();
  assert.equal(calls.length, 1, `npx from PATH ran once: ${JSON.stringify(calls)}`);
  assert.deepEqual(calls[0].slice(0, 2), ['--yes', '@playwright/mcp']);
  assert.deepEqual(mcp.npxPathHeads(), [mcp.shimDir], "npx's directory leads the PATH the adapter gave the server");
});
