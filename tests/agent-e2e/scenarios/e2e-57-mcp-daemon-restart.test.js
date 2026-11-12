'use strict';
const fs = require('node:fs');
const path = require('node:path');

const { scenario, assert } = require('../lib/scenario');
const { assertVerifiedAssertion, assertAgentAllowed, auditEvents, waitFor } = require('../lib/helpers');
const { processesMentioning, descendants } = require('../lib/env');
const { toolText, evalJson, authenticateFn, browserProcesses } = require('../lib/adapters');

const profiles = { agent: { mode: 'same-user', rules: [{ rp: 'rp-a.test', authenticate: 'allow', register: 'deny' }] } };
/** A browser tool call while the daemon is down must fail within this bound, never wait out a connect timeout. */
const FAST_MS = 10000;

const readLink = p => { try { return fs.readlinkSync(p); } catch { return null; } };

/** Every process that holds `target` (a `pipe:[inode]` or `socket:[inode]` link; Node's stdio pipes are socketpairs) on one of its descriptors. */
function holdersOf(target) {
  const out = [];
  for (const d of fs.readdirSync('/proc')) {
    if (!/^\d+$/.test(d)) continue;
    let fds = [];
    try { fds = fs.readdirSync(`/proc/${d}/fd`); } catch { continue; }
    if (fds.some(fd => readLink(`/proc/${d}/fd/${fd}`) === target)) out.push(Number(d));
  }
  return out;
}

/**
 * The processes that hold the MCP client's stdio pipes. The fix this scenario guards: they are all the wrapper the client
 * spawned or its descendants (the Playwright MCP server), never a process the daemon started (a principal session in the
 * daemon's cgroup dies with the daemon, and the client's MCP connection with it).
 */
function stdioHolders(wrapperPid) {
  const stdin = readLink(`/proc/${wrapperPid}/fd/0`);
  const stdout = readLink(`/proc/${wrapperPid}/fd/1`);
  assert.match(String(stdin), /^(pipe|socket):/, `the wrapper's stdin is the client's pipe: ${stdin}`);
  assert.match(String(stdout), /^(pipe|socket):/, `the wrapper's stdout is the client's pipe: ${stdout}`);
  // The client's own end of each pipe is held by this test process.
  const holders = new Set([...holdersOf(stdin), ...holdersOf(stdout)]);
  holders.delete(process.pid);
  return [...holders];
}

/** `passless agent mcp-session-broker` processes of this run: the principal sessions the wrapper keeps. */
function brokers(stack) {
  const cmdline = pid => { try { return fs.readFileSync(`/proc/${pid}/cmdline`, 'utf8').split('\0'); } catch { return []; } };
  return processesMentioning('mcp-session-broker')
    .filter(pid => { const argv = cmdline(pid); return argv[0] === stack.daemon.bin && argv.includes('mcp-session-broker'); });
}

const leaseLaunches = audit => auditEvents(audit).filter(e => e.kind === 'browser_lease.launch' && e.profile_id === 'agent');
/** The principal (session) each grant of the profile was issued to: one per session that signed in. */
const grantPrincipals = audit => auditEvents(audit).filter(e => e.kind === 'grant.request' && e.profile_id === 'agent').map(e => e.principal);

/** Sign in through the MCP server: navigate to the RP and authenticate; returns the RP's record of the assertion. */
async function signIn(mcp, rp, what) {
  const nav = await mcp.client.callTool('browser_navigate', { url: `${rp.origin}/sw` }, 120000);
  assert.ok(!nav.isError, `${what}: browser_navigate: ${toolText(nav).slice(0, 600)}`);
  return assertVerifiedAssertion(rp, evalJson(await mcp.client.callTool('browser_evaluate', { function: authenticateFn('alice') })), { username: 'alice' });
}

// Catalogue E2E-57: `passless agent mcp playwright` survives a daemon restart. MCP clients such as opencode's shared server
// never restart an MCP server that exited, so the stdio connection must outlive the daemon: the wrapper the client spawned
// keeps it (with the Playwright MCP server as its own child) and re-establishes its principal session through the admin
// socket, exactly as at start, on the next browser tool call.
// 1. sign in through the wrapper; 2. stop the harness's own daemon (never passless.service): the session and its browser end
// with it; 3. a browser tool call fails fast with a clear error while the MCP stdio session stays open; 4. restart the daemon;
// 5. sign in again over the SAME stdio session: a new principal session and lease from the new daemon, and the same
// Playwright MCP process (npx ran once). Two cycles: SIGTERM (what `systemctl stop` sends; the daemon exits at once and its
// children die with it) and SIGINT (the daemon's graceful shutdown, which closes and audits the lease: the old lease is
// revoked in the audit). Finally stdin EOF tears everything down: the wrapper, the Playwright MCP server, the principal
// session and its browser.
// Port-only: Playwright MCP needs a CDP endpoint, which a pipe-mode profile refuses (ADR 0014 §4.3; the refusal is E2E-53).
scenario({ id: 'E2E-57', title: 'agent mcp playwright survives a daemon restart on the same MCP stdio session', ci: true, timeoutMs: 300000 }, async ctx => {
  const stack = await ctx.stack({ rps: { a: { host: 'rp-a.test' } }, profiles });
  const rp = stack.rp.a;
  await stack.seedHuman(rp, 'alice');

  const mcp = stack.adapter('playwright', { profile: 'agent' });
  const wrapperPid = mcp.client.child.pid;
  const init = await mcp.client.initialize();
  ctx.t.diagnostic(`MCP server: ${JSON.stringify(init.serverInfo)}`);

  // 1. Sign in.
  let last = await signIn(mcp, rp, 'first sign-in');
  await assertAgentAllowed(stack, { rpId: 'rp-a.test', n: 1 });

  const owned = new Set([wrapperPid, ...descendants(wrapperPid)]);
  const holders = stdioHolders(wrapperPid);
  assert.deepEqual(holders.filter(pid => !owned.has(pid)), [], `only the wrapper and its descendants hold the MCP stdio (holders ${holders.join(', ')}; owned ${[...owned].join(', ')})`);

  const seenBrokers = [];
  for (const signal of ['SIGTERM', 'SIGINT']) {
    const [broker, ...more] = brokers(stack);
    assert.ok(broker && !more.length, `${signal}: one principal session (the broker) runs for the wrapper: ${brokers(stack).join(', ')}`);
    assert.ok(!seenBrokers.includes(broker), `${signal}: a session process of its own`);
    seenBrokers.push(broker);
    const before = await stack.daemon.audit();
    const leasesBefore = leaseLaunches(before).map(e => e.lease_id);
    const principalsBefore = grantPrincipals(before);
    const liveLease = leasesBefore[leasesBefore.length - 1];

    // 2. Stop the daemon (the harness's private one): its session and browser end with it.
    await stack.daemon.stop(signal);
    await waitFor(`${signal}: the browser and the principal session to end with the daemon`,
      () => browserProcesses(stack, processesMentioning).length === 0 && brokers(stack).length === 0, { timeoutMs: 20000, intervalMs: 200 });

    // 3. The MCP stdio session stays open, and a browser tool call fails fast with a clear error.
    assert.equal(mcp.client.child.exitCode, null, `${signal}: the wrapper exited with the daemon: ${mcp.client.stderr.slice(-600)}`);
    assert.equal(mcp.client.child.signalCode, null, `${signal}: the wrapper was killed with the daemon: ${mcp.client.stderr.slice(-600)}`);
    const tools = (await mcp.client.listTools()).map(t => t.name);
    assert.ok(tools.includes('browser_navigate'), `${signal}: tools/list still answers: ${tools.join(', ')}`);
    for (let i = 0; i < 2; i++) {
      const t0 = Date.now();
      const down = await mcp.client.callTool('browser_navigate', { url: `${rp.origin}/sw` }, 60000);
      const took = Date.now() - t0;
      assert.equal(down.isError, true, `${signal}: a browser tool call must fail while the daemon is down: ${toolText(down).slice(0, 400)}`);
      assert.ok(took < FAST_MS, `${signal}: the failure took ${took} ms`);
      assert.match(toolText(down), /passless daemon unavailable, retrying/, `${signal}: a clear error: ${toolText(down).slice(0, 600)}`);
      if (i === 0) ctx.t.diagnostic(`${signal}: tool error while the daemon is down (${took} ms): ${toolText(down).split('\n').slice(0, 4).join(' | ')}`);
    }
    assert.equal(mcp.client.child.exitCode, null, `${signal}: the wrapper is still running after the failed calls`);

    // 4. Restart the daemon.
    fs.rmSync(path.join(stack.env.dirs.run, 'agent'), { recursive: true, force: true });
    stack.daemon = await stack.startDaemon(stack.profiles);

    // 5. Sign in again over the same stdio session.
    const again = await signIn(mcp, rp, `${signal}: sign-in after the restart`);
    assert.ok(again.counter > last.counter, `${signal}: counter increases`);
    last = again;
    assert.equal(mcp.client.child.pid, wrapperPid, `${signal}: the same wrapper process`);
    assert.equal(mcp.npxCalls().length, 1, `${signal}: the Playwright MCP server was never restarted: ${JSON.stringify(mcp.npxCalls())}`);

    const audit = await stack.daemon.audit();
    const leases = leaseLaunches(audit).map(e => e.lease_id);
    const principals = grantPrincipals(audit);
    assert.equal(leases.length, leasesBefore.length + 1, `${signal}: a new lease from the new daemon: ${JSON.stringify(leases)}`);
    assert.ok(!leasesBefore.includes(leases[leases.length - 1]), `${signal}: a fresh lease, not an old one`);
    assert.equal(principals.length, principalsBefore.length + 1, `${signal}: the new daemon granted a new principal session: ${JSON.stringify(principals)}`);
    assert.ok(!principalsBefore.includes(principals[principals.length - 1]), `${signal}: a fresh principal session, not an old one`);
    if (signal === 'SIGINT') {
      // The graceful shutdown closed the lease the stopped daemon had handed out.
      const revoked = auditEvents(audit).filter(e => e.kind === 'browser_lease.revoke' && e.lease_id === liveLease);
      assert.equal(revoked.length, 1, `${signal}: the old lease was revoked when its daemon stopped: ${JSON.stringify(auditEvents(audit).filter(e => /lease|daemon/.test(e.kind)))}`);
    }
  }

  // stdin EOF tears everything down: the wrapper and the Playwright MCP server exit, the principal session ends and the
  // daemon closes its browser and lease.
  const leases = leaseLaunches(await stack.daemon.audit()).map(e => e.lease_id);
  const tree = [wrapperPid, ...descendants(wrapperPid)];
  const exited = new Promise(resolve => {
    if (mcp.client.child.exitCode !== null || mcp.client.child.signalCode !== null) resolve();
    else mcp.client.child.once('exit', resolve);
  });
  mcp.client.child.stdin.end();
  await Promise.race([exited, new Promise((_, reject) => setTimeout(() => reject(new Error(`the wrapper did not exit on stdin EOF: ${mcp.client.stderr.slice(-600)}`)), 30000))]);
  const alive = pid => { try { process.kill(pid, 0); return true; } catch (e) { return e.code === 'EPERM'; } };
  await waitFor('the wrapper tree, the principal session and the browser to be gone',
    () => tree.every(pid => !alive(pid)) && brokers(stack).length === 0 && browserProcesses(stack, processesMentioning).length === 0,
    { timeoutMs: 30000, intervalMs: 200 });
  const newLease = leases[leases.length - 1];
  await waitFor('the new lease to be closed in the audit', async () =>
    auditEvents(await stack.daemon.audit()).some(e => /^browser_lease\.(revoke|cleanup)$/.test(e.kind) && e.lease_id === newLease), { timeoutMs: 30000, intervalMs: 500 });
});

/** The live principal sessions of `profile`, as the daemon lists them. */
async function sessionsOf(stack, profile) {
  return (await stack.daemon.adminJson('principals', 'list', '--profile', profile)).sessions.map(s => s.session_id);
}

// E2E-57/ttl: `max_session_ttl` caps each principal session, not the MCP server. When the wrapper's session expires (the
// daemon records why, `SessionEnd` = expired), the next browser tool call launches a new session through the admin socket,
// with a new lease, over the same stdio session; nothing of the expired one is reused, and its lease is closed. A
// deliberate end is final: `agent-admin principals revoke` ends the wrapper (and its Playwright MCP server).
// Port-only: Playwright MCP needs a CDP endpoint, which a pipe-mode profile refuses (ADR 0014 §4.3; the refusal is E2E-53).
const TTL_SECS = 20;
scenario({ id: 'E2E-57/ttl', title: 'agent mcp playwright renews an expired session; a revoked one ends it', ci: true, timeoutMs: 240000 }, async ctx => {
  const stack = await ctx.stack({
    rps: { a: { host: 'rp-a.test' } },
    profiles: { agent: { ...profiles.agent, max_session_ttl: TTL_SECS } },
  });
  const rp = stack.rp.a;
  await stack.seedHuman(rp, 'alice');

  const mcp = stack.adapter('playwright', { profile: 'agent' });
  const wrapperPid = mcp.client.child.pid;
  await mcp.client.initialize();
  const first = await signIn(mcp, rp, 'first sign-in');
  const [firstBroker] = brokers(stack);
  const [firstSession] = await sessionsOf(stack, 'agent');
  const [firstLease] = leaseLaunches(await stack.daemon.audit()).map(e => e.lease_id);
  assert.ok(firstBroker && firstSession && firstLease, 'a session, its broker and its lease');

  // Wait past the TTL: the daemon ends the session and its browser; the wrapper stays.
  await waitFor('the session to expire', async () => brokers(stack).length === 0 && (await sessionsOf(stack, 'agent')).length === 0
    && browserProcesses(stack, processesMentioning).length === 0, { timeoutMs: (TTL_SECS + 30) * 1000, intervalMs: 500 });
  await new Promise(r => setTimeout(r, 1500)); // the wrapper notices within a poll interval
  assert.equal(mcp.client.child.exitCode, null, `the wrapper exited on expiry: ${mcp.client.stderr.slice(-600)}`);

  // The next sign-in renews: a new session (through the admin socket), a new broker, a new lease.
  const again = await signIn(mcp, rp, 'sign-in after the expiry');
  assert.ok(again.counter > first.counter, 'counter increases');
  const [renewedSession, ...more] = await sessionsOf(stack, 'agent');
  assert.ok(renewedSession && !more.length && renewedSession !== firstSession, `a new principal session: ${renewedSession}`);
  const [renewedBroker] = brokers(stack);
  assert.ok(renewedBroker && renewedBroker !== firstBroker, 'a new broker process');
  const audit = await stack.daemon.audit();
  const leases = leaseLaunches(audit).map(e => e.lease_id);
  assert.equal(leases.length, 2, `a new lease: ${JSON.stringify(leases)}`);
  assert.notEqual(leases[1], firstLease, 'not the expired lease');
  assert.ok(auditEvents(audit).some(e => /^browser_lease\.(revoke|expire|cleanup)$/.test(e.kind) && e.lease_id === firstLease),
    `the expired session's lease is closed: ${JSON.stringify(auditEvents(audit).filter(e => /lease/.test(e.kind)))}`);
  assert.equal(mcp.npxCalls().length, 1, 'the same Playwright MCP server');
  assert.equal(mcp.client.child.pid, wrapperPid);

  // A revocation is final: the wrapper exits and is not renewed.
  const exited = new Promise(resolve => mcp.client.child.once('exit', (code, signal) => resolve({ code, signal })));
  await stack.daemon.adminJson('principals', 'revoke', renewedSession, '--confirm');
  const exit = await Promise.race([exited, new Promise(r => setTimeout(() => r(null), 20000))]);
  assert.ok(exit, `the wrapper did not exit after the revocation: ${mcp.client.stderr.slice(-600)}`);
  assert.notEqual(exit.code, 0, `a revoked session is an error exit: ${JSON.stringify(exit)}`);
  assert.match(mcp.client.stderr, /principal session \(revoked\); it is not re-established/, mcp.client.stderr.slice(-600));
  await waitFor('no session, broker or browser left', async () => brokers(stack).length === 0 && (await sessionsOf(stack, 'agent')).length === 0
    && browserProcesses(stack, processesMentioning).length === 0, { timeoutMs: 20000, intervalMs: 300 });
  assert.equal(leaseLaunches(await stack.daemon.audit()).length, 2, 'no session was launched after the revocation');
});
