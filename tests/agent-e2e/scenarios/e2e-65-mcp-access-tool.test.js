'use strict';
const fs = require('node:fs');
const path = require('node:path');

const { scenario, assert } = require('../lib/scenario');
const { assertVerifiedAssertion, escalationEvents, policyEvents, grantsStore } = require('../lib/helpers');
const { toolText, evalJson, authenticateFn } = require('../lib/adapters');
const { REGISTER_SUMMARY, preRequestRegistrationBody, humanStoreLine, SIGN_IN_SUMMARY, preRequestSignInBody } = require('../lib/escalation');

// ADR 0014 amendment section 6: `passless agent mcp playwright --with-access-tool` relays the MCP stdio and adds one tool,
// `passless_request_access`, answered by the wrapper's broker (the principal session that owns the browser). Without the flag
// the tool is absent and Playwright MCP inherits the client's stdio as before.
//
//   off     tools/list is Playwright's own, and the tool is not callable
//   on      tools/list is Playwright's tools plus the tool, whose definition is the ADR's; a call before any browser exists
//           returns approved with expires_in_secs (state, every one is a normal result); a malformed call is an error with a
//           ProtocolError; the approved registration is then consumed by the browser's own ceremony (Playwright MCP starts
//           the browser lazily, in the same principal session), with no second prompt; Playwright's tools are unaffected
//   restart the daemon is stopped and started again (as E2E-57): the tool fails fast while it is down, and works again on the
//           same stdio session, in a new principal session
// Port-only: Playwright MCP needs a CDP endpoint, which a pipe-mode profile refuses (ADR 0014 section 4.3; the refusal is E2E-53).
const TOOL = 'passless_request_access';
const profiles = {
  agent: {
    mode: 'same-user',
    extra: { pre_request_actions: ['authenticate', 'register'] },
    rules: ['rp-a.test', 'rp-b.test'].map(rp => ({ rp, authenticate: 'request', register: 'request' })),
  },
};
const parse = res => JSON.parse(toolText(res));

scenario({ id: 'E2E-65', title: 'agent mcp playwright --with-access-tool: the tool is listed and works, Playwright tools are unaffected, it survives a daemon restart; without the flag it is absent', ci: true, timeoutMs: 360000 }, async ctx => {
  const stack = await ctx.stack({
    rps: { a: { host: 'rp-a.test' }, b: { host: 'rp-b.test' } },
    profiles,
    notify: { script: ['approve:1500', 'approve:1500'] },
  });
  const rp = stack.rp.a;
  await stack.seedHuman(rp, 'alice');
  const prompts = () => stack.notify.notifications();

  // ---- without the flag: nothing is added, and the tool cannot be called.
  const off = stack.adapter('playwright', { profile: 'agent' });
  await off.client.initialize();
  const offNames = (await off.client.listTools()).map(t => t.name);
  assert.ok(offNames.includes('browser_navigate') && offNames.includes('browser_evaluate'), offNames.join(', '));
  assert.ok(!offNames.includes(TOOL), `the tool is opt-in: ${offNames.join(', ')}`);
  const refused = await off.client.callTool(TOOL, { rp_id: 'rp-a.test' }).then(r => r, e => ({ isError: true, text: e.message }));
  assert.ok(refused.isError || /not found|unknown/i.test(String(refused.text || '')), 'Playwright MCP does not know the tool');
  off.client.close();

  // ---- with the flag.
  const mcp = stack.adapter('playwright', { profile: 'agent', flags: ['--with-access-tool'] });
  const wrapperPid = mcp.client.child.pid;
  const init = await mcp.client.initialize();
  assert.ok(init.serverInfo, 'the relay passes the initialize exchange through');
  const tools = await mcp.client.listTools();
  const names = tools.map(t => t.name);
  assert.deepEqual(names.filter(n => n !== TOOL), offNames, 'Playwright\'s own tools, in their own order, unchanged');
  assert.equal(names[names.length - 1], TOOL, 'the tool is appended');
  const tool = tools.find(t => t.name === TOOL);
  assert.deepEqual(tool.inputSchema.required, ['rp_id']);
  assert.equal(tool.inputSchema.additionalProperties, false);
  assert.deepEqual(tool.inputSchema.properties.action.enum, ['authenticate', 'register']);
  assert.equal(tool.inputSchema.properties.note.maxLength, 200);
  assert.equal(tool.inputSchema.properties.wait_seconds.maximum, 120);
  assert.match(tool.description, /NOT shown to them/, 'the description says the note is not shown');

  // A call before any browser exists: the broker's principal session asks, and every state is a normal result.
  const granted = await mcp.client.callTool(TOOL, { rp_id: 'rp-a.test', action: 'register', note: 'register an account at rp-a' });
  assert.ok(!granted.isError, toolText(granted));
  assert.equal(granted.content.length, 1);
  assert.equal(granted.content[0].type, 'text');
  const status = parse(granted);
  assert.equal(status.state, 'approved', JSON.stringify(status));
  assert.equal(status.rp_id, 'rp-a.test');
  assert.equal(status.action, 'register');
  assert.ok(status.expires_in_secs > 0 && status.expires_in_secs <= 600, `expires_in_secs: ${status.expires_in_secs}`);
  assert.equal(prompts().length, 1);
  assert.equal(prompts()[0].summary, REGISTER_SUMMARY);
  assert.equal(prompts()[0].body, preRequestRegistrationBody({ site: 'rp-a.test', stored: humanStoreLine('agent', 1) }));
  assert.ok(!prompts()[0].body.includes('register an account'), 'the note is not in the prompt');
  const unlisted = parse(await mcp.client.callTool(TOOL, { rp_id: 'rp-z.test' }));
  assert.equal(unlisted.state, 'not_requestable', JSON.stringify(unlisted));

  // Malformed calls are errors, with a ProtocolError.
  for (const args of [{}, { rp_id: 'rp-a.test', action: 'sign' }, { rp_id: 'rp-a.test', extra: 1 }, { rp_id: 'rp-a.test', wait_seconds: 121 }]) {
    const bad = await mcp.client.callTool(TOOL, args);
    assert.equal(bad.isError, true, `${JSON.stringify(args)}: ${toolText(bad)}`);
    const error = parse(bad);
    assert.equal(error.code, 'malformed_message', JSON.stringify(error));
    assert.ok(error.message && error.recommended_action, JSON.stringify(error));
  }
  assert.equal(prompts().length, 1, 'a malformed call asks nothing');

  // Playwright's tools work through the relay, in the browser the same principal session now launches; the registration
  // consumes the approved token (no page was waiting when it was approved).
  const nav = await mcp.client.callTool('browser_navigate', { url: `${rp.origin}/raw` }, 120000);
  assert.ok(!nav.isError, toolText(nav));
  const registered = evalJson(await mcp.client.callTool('browser_evaluate', {
    function: `async () => { await new Promise(r => { const t = setInterval(() => { if (window.e2e) { clearInterval(t); r(); } }, 50); }); return JSON.stringify(await window.e2e.register({ username: 'mona', userVerification: 'preferred', timeout: 30000 })); }`,
  }));
  assert.equal(registered.ok, true, `the token approved through the tool is consumed by the browser's registration: ${JSON.stringify(registered)}`);
  assert.equal(rp.registrations.filter(r => r.username === 'mona' && r.ok).length, 1, 'the RP verified it');
  assert.equal(prompts().length, 1, 'no second prompt');
  assertVerifiedAssertion(rp, evalJson(await mcp.client.callTool('browser_evaluate', { function: authenticateFn('mona') })), { username: 'mona' });
  assert.equal(prompts().length, 1, 'the registration grant signs in without a prompt');
  // The npx log is the run's: one server for the adapter without the flag, one for the adapter with it.
  assert.equal(mcp.npxCalls().length, 2, 'one Playwright MCP server per adapter');
  assert.ok(mcp.npxCalls().every(argv => !argv.includes('--with-access-tool')), `the flag is the wrapper's, not the server's: ${JSON.stringify(mcp.npxCalls())}`);
  let audit = await stack.daemon.audit();
  assert.equal(policyEvents(audit, 'pre_approval.issued').length, 1);
  assert.equal(policyEvents(audit, 'pre_approval.consumed').length, 1);
  assert.deepEqual(escalationEvents(audit, 'requested').map(e => [e.rp_id, e.action, e.source]), [['rp-a.test', 'register', 'pre_request']]);

  // ---- the daemon restarts under the same stdio session: the tool fails fast while it is down and works afterwards.
  await stack.daemon.stop('SIGTERM');
  const t0 = Date.now();
  const down = await mcp.client.callTool(TOOL, { rp_id: 'rp-b.test', wait_seconds: 0 }, 60000);
  assert.equal(down.isError, true, `the tool fails while the daemon is down: ${toolText(down).slice(0, 300)}`);
  assert.ok(Date.now() - t0 < 20000, `the failure was quick: ${Date.now() - t0} ms`);
  assert.match(toolText(down), /passless daemon unavailable|no longer valid|not running|session/i, toolText(down));
  assert.equal(mcp.client.child.exitCode, null, 'the wrapper outlives the daemon');
  fs.rmSync(path.join(stack.env.dirs.run, 'agent'), { recursive: true, force: true });
  stack.daemon = await stack.startDaemon(stack.profiles);

  const again = parse(await mcp.client.callTool(TOOL, { rp_id: 'rp-b.test', wait_seconds: 30 }, 120000));
  assert.equal(again.state, 'approved', `the tool works again on the same stdio session: ${JSON.stringify(again)}`);
  assert.equal(mcp.client.child.pid, wrapperPid, 'the same wrapper process');
  assert.equal(prompts().length, 2);
  assert.equal(prompts()[1].summary, SIGN_IN_SUMMARY);
  assert.equal(prompts()[1].body, preRequestSignInBody({ profile: 'agent', site: 'rp-b.test' }));
  assert.deepEqual(grantsStore(stack, 'agent').grants.map(g => [g.rp_id, g.kind, g.source]).sort(),
    [['rp-a.test', 'registration', 'pre_request'], ['rp-b.test', 'escalation', 'pre_request']].sort(), JSON.stringify(grantsStore(stack, 'agent').grants));
  // Playwright's tools still work through the relay in the new session.
  const nav2 = await mcp.client.callTool('browser_navigate', { url: `${rp.origin}/sw` }, 120000);
  assert.ok(!nav2.isError, toolText(nav2));
});
