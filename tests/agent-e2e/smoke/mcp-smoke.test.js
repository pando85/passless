'use strict';
// Harness smoke test: the minimal MCP client can list tools of the pinned @playwright/mcp attached to a
// running browser over CDP. Independent of Passless (plain, hidraw-less browser), so a failure points at the harness.

const { smoke, assert } = require('../lib/scenario');
const { createEnv } = require('../lib/env');
const { matrix, launchPlain } = require('../lib/browser');
const { McpClient, playwrightMcpCommand } = require('../lib/mcp-client');

smoke('SMOKE-01', 'MCP client lists @playwright/mcp tools against a running browser', async () => {
  const v = matrix().variants.find(x => !x.skip && x.mode === 'new');
  assert.ok(v, 'no headless browser available for the MCP smoke test');
  const env = createEnv('mcp-smoke');
  let client; let browser;
  try {
    browser = await launchPlain(env, v);
    const { command, args } = playwrightMcpCommand({ cdpUrl: browser.cdpUrl });
    client = McpClient.start({ command, args, env: env.env, cwd: env.dirs.work });
    const init = await client.initialize();
    assert.ok(init.serverInfo, 'initialize returned no serverInfo');
    const tools = (await client.listTools()).map(t => t.name);
    assert.ok(tools.includes('browser_navigate'), `browser_navigate missing in ${tools.join(', ')}`);
    assert.ok(tools.length >= 10, `unexpectedly few tools: ${tools.length}`);
    const res = await client.callTool('browser_navigate', { url: 'data:text/html,<title>mcp-smoke</title>ok' });
    assert.ok(JSON.stringify(res).includes('mcp-smoke'), `navigate result did not mention the page: ${JSON.stringify(res).slice(0, 300)}`);
  } finally {
    client?.close();
    browser?.kill();
    const leaks = env.cleanup();
    assert.deepEqual(leaks, [], 'leaked processes');
  }
});
