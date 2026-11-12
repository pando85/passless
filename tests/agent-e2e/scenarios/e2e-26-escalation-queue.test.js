'use strict';
const { scenario, assert } = require('../lib/scenario');
const { escalationEvents, grantedRuleEvents, assertInterceptionActive } = require('../lib/helpers');
const { requestProfile, start, settle, waitForEscalation } = require('../lib/escalation');

// One prompt per profile at a time; other keys queue FIFO (1 active + up to 8 queued, the next is `escalation_queue_full`).
//
// What this scenario proves: four RPs of one session park at once (the per-session waiter cap is 4, see E2E-48), the daemon
// shows ONE notification at a time in arrival order, the next only after the previous was answered, and all four complete.
//
// What it cannot prove end to end: the queue bound itself. Overflowing 1 active + 8 queued needs 10 distinct keys, which
// needs at least three bearer sessions of one profile (4 waiters each). The harness launches a browser through
// `agent-admin browser launch`, which returns the profile's existing live lease (one bearer session per profile; defect
// B1, which killed `browser_scope = "session"` browsers, is fixed in P10, but several principal sessions need the P10b
// `passless agent browser` path). The bound and the FIFO order are covered
// by the coordinator unit tests (`escalation.rs`: queue overflow, FIFO, dequeue); the caps that E2E can reach are in E2E-48.
const HOSTS = ['rp-a.test', 'rp-b.test', 'rp-c.test', 'rp-d.test'];

scenario({ id: 'E2E-26', exposeModes: ['port', 'pipe'], title: 'queued escalations prompt one at a time in arrival order and all complete', timeoutMs: 240000 }, async ctx => {
  const stack = await ctx.stack({
    rps: Object.fromEntries('abcd'.split('').map(c => [c, { host: `rp-${c}.test` }])),
    profiles: { agent: requestProfile(HOSTS) },
    notify: { script: Array(4).fill('approve:1500') },
  });
  for (const c of 'abcd') await stack.seedHuman(stack.rp[c], 'alice');
  const b = await stack.open('agent', `${stack.rp.a.origin}/raw`);
  assertInterceptionActive(b);
  const pages = [b.page];
  for (const c of 'bcd') {
    const p = await b.context.newPage();
    await p.goto(`${stack.rp[c].origin}/raw`);
    pages.push(p);
  }

  // Start in order; each is admitted before the next starts, so the arrival order is known.
  const keys = [];
  for (let i = 0; i < 4; i++) {
    keys.push(await start(pages[i], 'authenticate', { username: 'alice', timeout: 120000 }));
    await waitForEscalation(stack, 'requested', i + 1);
  }
  const results = await Promise.all(pages.map((p, i) => settle(p, keys[i])));
  results.forEach((r, i) => assert.equal(r.ok, true, `${HOSTS[i]}: ${JSON.stringify(r)}`));

  const notes = stack.notify.notifications();
  assert.deepEqual(notes.map(n => n.body.match(/^Site: (\S+)/m)[1]), HOSTS, 'prompts come in arrival order');
  const trace = stack.notify.events().filter(e => e.event === 'Notify' || e.event === 'ActionInvoked').map(e => `${e.event === 'Notify' ? 'N' : 'A'}${e.id}`);
  assert.deepEqual(trace, notes.flatMap(n => [`N${n.id}`, `A${n.id}`]), 'one prompt at a time: each notification is answered before the next is shown');
  const audit = await stack.daemon.audit();
  assert.deepEqual(escalationEvents(audit, 'approved').map(e => e.rp_id), HOSTS);
  assert.deepEqual(grantedRuleEvents(audit, 'add').map(e => e.rp_id), HOSTS);
});
