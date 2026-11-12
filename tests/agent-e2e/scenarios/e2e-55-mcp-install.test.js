'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { execFile } = require('node:child_process');

const { scenario, assert } = require('../lib/scenario');
const { assertVerifiedAssertion, assertAgentAllowed, assertNoNotification, policyEvents, HUMAN_CTAP_LOG } = require('../lib/helpers');
const { toolText, evalJson, authenticateFn, NPX_SHIM } = require('../lib/adapters');
const { McpClient } = require('../lib/mcp-client');
const { HARNESS_ROOT } = require('../lib/paths');

const profiles = { agent: { mode: 'same-user', rules: [{ rp: 'rp-a.test', authenticate: 'allow', register: 'deny' }] } };

const run = (bin, args, { env, cwd }) => new Promise(resolve => {
  execFile(bin, args, { env, cwd, timeout: 60000, maxBuffer: 8 * 1024 * 1024 }, (error, stdout, stderr) => {
    resolve({ code: error ? (error.code ?? 1) : 0, stdout, stderr });
  });
});

// Catalogue E2E-55: switching a plain Playwright MCP to Passless with `passless agent mcp install`, and adding the entry where there is none. A project `.mcp.json` in the
// shape real configs have (`pnpm dlx @playwright/mcp@<pin> --browser chromium --headless --isolated --viewport-size ...`) launches a
// browser of its own, so `doctor --agents` warns. `install --yes` rewrites the entry (pin kept as `--package`, `--isolated` and
// `--viewport-size` passed through, `--browser` and `--headless` dropped), after which the doctor is happy and the entry, started
// exactly as written, signs in at the harness RP through the managed browser: agent-path audit record, no human prompt, no
// human authenticator traffic.
// Port-only: the adapters refuse a pipe-mode profile (ADR 0014 section 4.3; E2E-53).
scenario({ id: 'E2E-55', title: 'agent mcp install: a plain Playwright MCP entry is rewritten and signs in through the agent policy', ci: true, timeoutMs: 240000 }, async ctx => {
  const stack = await ctx.stack({ rps: { a: { host: 'rp-a.test' } }, profiles });
  const rp = stack.rp.a;
  await stack.seedHuman(rp, 'alice');
  const { bin, cliEnv } = stack.daemon;

  // The @playwright/mcp version the harness caches (the npx stand-in runs it whatever the pin says; the pin must still reach npx).
  const version = JSON.parse(fs.readFileSync(path.join(HARNESS_ROOT, 'node_modules', '@playwright', 'mcp', 'package.json'), 'utf8')).version;
  const pin = `@playwright/mcp@${version}`;

  const project = path.join(stack.env.dirs.work, 'project');
  fs.mkdirSync(project, { recursive: true });
  const mcpFile = path.join(project, '.mcp.json');
  const original = JSON.stringify({
    mcpServers: {
      playwright: { command: 'pnpm', args: ['dlx', pin, '--browser', 'chromium', '--headless', '--isolated', '--viewport-size', '1440,900'] },
      other: { command: 'bash', args: ['other.sh'] },
    },
  }, null, 2) + '\n';
  fs.writeFileSync(mcpFile, original);

  const doctor = async (cwd = project) => {
    const r = await run(bin, ['doctor', '--agents', '--output', 'json'], { env: cliEnv, cwd });
    const checks = JSON.parse(r.stdout).data.checks;
    return checks.filter(c => c.name.startsWith('mcp_client'));
  };

  // 1. The doctor warns (a warning, not a failure) and names the exact fix.
  const before = await doctor();
  assert.equal(before.length, 1, JSON.stringify(before));
  assert.equal(before[0].name, 'mcp_client: claude-code/project/playwright');
  assert.equal(before[0].passed, true, 'a warning is not a failure');
  assert.match(before[0].message, /^warning: /);
  assert.match(before[0].message, /passkeys from this MCP reach your human authenticator, not the agent policy/);
  assert.ok(before[0].message.includes(`passless agent mcp install --client claude-code --project ${fs.realpathSync(project)} --profile agent --yes`), before[0].message);

  // 2. A dry run prints the diff and changes nothing.
  const install = ['agent', 'mcp', 'install', '--client', 'claude-code', '--project', project, '--profile', 'agent', '--passless-path', fs.realpathSync(bin)];
  const dry = await run(bin, install, { env: cliEnv, cwd: project });
  assert.equal(dry.code, 0, dry.stderr);
  assert.match(dry.stdout, /^\+\+\+ b\//m, 'a unified diff');
  assert.match(dry.stdout, /Dry run: nothing was changed/);
  assert.match(dry.stdout, /dropped `--headless`: headed or headless comes from the Passless profile/);
  assert.equal(fs.readFileSync(mcpFile, 'utf8'), original, 'the dry run changed the file');

  // 3. --yes rewrites it, after a backup.
  const applied = await run(bin, [...install, '--yes'], { env: cliEnv, cwd: project });
  assert.equal(applied.code, 0, applied.stderr + applied.stdout);
  const written = JSON.parse(fs.readFileSync(mcpFile, 'utf8'));
  const entry = written.mcpServers.playwright;
  assert.equal(entry.command, fs.realpathSync(bin), 'the absolute path of passless');
  assert.deepEqual(entry.args, ['agent', 'mcp', 'playwright', '--profile', 'agent', '--package', pin, '--', '--isolated', '--viewport-size', '1440,900']);
  assert.deepEqual(written.mcpServers.other, { command: 'bash', args: ['other.sh'] }, 'other entries are untouched');
  const backups = fs.readdirSync(project).filter(n => n.startsWith('.mcp.json.passless-backup-'));
  assert.equal(backups.length, 1, fs.readdirSync(project).join(', '));
  assert.match(backups[0], /-\d{8}T\d{6}Z$/);
  assert.equal(fs.readFileSync(path.join(project, backups[0]), 'utf8'), original, 'the backup is the original');

  // Idempotent.
  const again = await run(bin, [...install, '--yes'], { env: cliEnv, cwd: project });
  assert.equal(again.code, 0, again.stderr);
  assert.match(again.stdout, /already uses Passless/);
  assert.equal(fs.readdirSync(project).filter(n => n.includes('passless-backup-')).length, 1, 'no second backup');

  // 4. The doctor is happy now.
  const after = await doctor();
  assert.equal(after.length, 1, JSON.stringify(after));
  assert.equal(after[0].passed, true);
  assert.ok(!after[0].message.startsWith('warning:'), after[0].message);
  assert.match(after[0].message, /runs through Passless \(profile agent\)/);

  // 4b. A project with no Playwright MCP at all gets a new `playwright` entry (a dry run first, then --yes), with the same command
  // and args shape the rewrite produces; the file did not exist, so there is no backup. A second run changes nothing.
  const fresh = path.join(stack.env.dirs.work, 'project-new');
  fs.mkdirSync(fresh, { recursive: true });
  const freshFile = path.join(fresh, '.mcp.json');
  const add = ['agent', 'mcp', 'install', '--client', 'claude-code', '--project', fresh, '--profile', 'agent', '--passless-path', fs.realpathSync(bin)];
  const addDry = await run(bin, add, { env: cliEnv, cwd: fresh });
  assert.equal(addDry.code, 0, addDry.stderr);
  assert.match(addDry.stdout, /adding `playwright` \(mcpServers\.playwright\)/);
  assert.match(addDry.stdout, /Dry run: nothing was changed/);
  assert.ok(!fs.existsSync(freshFile), 'the dry run created the file');
  const addYes = await run(bin, [...add, '--yes'], { env: cliEnv, cwd: fresh });
  assert.equal(addYes.code, 0, addYes.stderr + addYes.stdout);
  assert.deepEqual(JSON.parse(fs.readFileSync(freshFile, 'utf8')), {
    mcpServers: { playwright: { type: 'stdio', command: fs.realpathSync(bin), args: ['agent', 'mcp', 'playwright', '--profile', 'agent'] } },
  });
  assert.deepEqual(fs.readdirSync(fresh), ['.mcp.json'], 'a new file has no backup');
  const addAgain = await run(bin, [...add, '--yes'], { env: cliEnv, cwd: fresh });
  assert.equal(addAgain.code, 0, addAgain.stderr);
  assert.match(addAgain.stdout, /already uses Passless/);
  const freshDoctor = await doctor(fresh);
  assert.equal(freshDoctor.length, 1, JSON.stringify(freshDoctor));
  assert.match(freshDoctor[0].message, /runs through Passless \(profile agent\)/);
  // Another server named `playwright` is never replaced.
  const foreign = path.join(stack.env.dirs.work, 'project-foreign');
  fs.mkdirSync(foreign, { recursive: true });
  const foreignText = JSON.stringify({ mcpServers: { playwright: { type: 'http', url: 'https://mcp.invalid/' } } }) + '\n';
  fs.writeFileSync(path.join(foreign, '.mcp.json'), foreignText);
  const refused = await run(bin, ['agent', 'mcp', 'install', '--client', 'claude-code', '--project', foreign, '--profile', 'agent', '--passless-path', fs.realpathSync(bin), '--yes'], { env: cliEnv, cwd: foreign });
  assert.notEqual(refused.code, 0, 'a foreign `playwright` server must be refused');
  assert.match(refused.stderr, /already exists and is not a Playwright MCP server/);
  assert.equal(fs.readFileSync(path.join(foreign, '.mcp.json'), 'utf8'), foreignText);

  // 5. The entry, started exactly as written, is an MCP stdio server that signs in through the agent policy. `npx` is the harness's
  // stand-in, found on the client's PATH as a real configuration finds it.
  const shimDir = path.join(stack.env.dirs.work, 'npx-on-path');
  fs.mkdirSync(shimDir, { recursive: true });
  fs.symlinkSync(NPX_SHIM, path.join(shimDir, 'npx'));
  const humanLogBefore = stack.daemon.log().length;
  const mcp = McpClient.start({ command: entry.command, args: entry.args, env: { ...cliEnv, PATH: `${shimDir}:${cliEnv.PATH}` }, cwd: project });
  stack.adapters.push({ close: () => mcp.close() });
  const init = await mcp.initialize();
  assert.ok(init.serverInfo, 'the rewritten entry speaks MCP on stdio');
  const tools = (await mcp.listTools()).map(t => t.name);
  assert.ok(tools.includes('browser_navigate') && tools.includes('browser_evaluate'), `the same Playwright MCP tools: ${tools.join(', ')}`);

  const nav = await mcp.callTool('browser_navigate', { url: `${rp.origin}/sw` }, 120000);
  assert.ok(!nav.isError, toolText(nav));
  const result = assertVerifiedAssertion(rp, evalJson(await mcp.callTool('browser_evaluate', { function: authenticateFn('alice') })), { username: 'alice' });
  assert.ok(result.counter >= 1);
  // --viewport-size reached the server: the isolated context has the user's viewport.
  const width = evalJson(await mcp.callTool('browser_evaluate', { function: '() => JSON.stringify(window.innerWidth)' }));
  assert.equal(width, 1440, 'the user\'s --viewport-size was passed through');

  // The agent path signed it: agent policy audit record, and no human prompt or human authenticator traffic.
  const [allow] = await assertAgentAllowed(stack, { rpId: 'rp-a.test', n: 1 });
  assert.equal(allow.user_presence, 'agent');
  assert.equal(allow.user_verification, 'agent');
  assertNoNotification(stack);
  assert.doesNotMatch(stack.daemon.log().slice(humanLogBefore), HUMAN_CTAP_LOG, 'the human authenticator handled a request');
  assert.equal(policyEvents(await stack.daemon.audit(), 'policy.deny').length, 0);

  // What npx received: the pinned package and the passed-through flags; the dropped ones never reached @playwright/mcp.
  const log = path.join(stack.env.dirs.logs, 'npx.jsonl');
  const calls = fs.readFileSync(log, 'utf8').split('\n').filter(Boolean).map(l => JSON.parse(l));
  assert.equal(calls.length, 1, JSON.stringify(calls));
  const [argv] = calls;
  assert.deepEqual(argv.slice(0, 2), ['--yes', pin]);
  assert.ok(argv.includes('--isolated') && argv.includes('--viewport-size'), JSON.stringify(argv));
  for (const dropped of ['--browser', '--headless', '--executable-path']) assert.ok(!argv.includes(dropped), `${dropped} reached @playwright/mcp: ${JSON.stringify(argv)}`);
  assert.match(argv[argv.indexOf('--cdp-endpoint') + 1], /^http:\/\/127\.0\.0\.1:\d+$/, 'the attached browser is the managed one');
});
