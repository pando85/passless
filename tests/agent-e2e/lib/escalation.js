'use strict';
// Shared pieces of the P7 escalation scenarios (E2E-20/escalation, 21, 23 to 31, 43, 44, 48 to 50).

const { execFile } = require('node:child_process');
const os = require('node:os');
const assert = require('node:assert/strict');

const { waitFor, auditEvents, escalationEvents } = require('./helpers');

/** A same-user profile whose listed RPs all carry `request` for authenticate (and `register` as given). */
function requestProfile(hosts, { register = 'deny', mode = 'same-user', max_session_ttl } = {}) {
  const p = { mode, rules: hosts.map(rp => ({ rp, authenticate: 'request', register })) };
  if (max_session_ttl) p.max_session_ttl = max_session_ttl;
  return p;
}

/** Start a background ceremony in `page` (window.e2e.start); returns its key. The page must already have `window.e2e`. */
async function start(page, kind, opts = {}) {
  await page.waitForFunction(() => window.e2e, null, { timeout: 15000 });
  return page.evaluate(([k, o]) => window.e2e.start(k, o), [kind, { timeout: 60000, ...opts }]);
}

/** The ceremony's final result (waits for it). */
const settle = (page, key) => page.evaluate(k => window.e2e.result(k), key);
/** `{settled, result, elapsedMs}` without waiting. */
const peek = (page, key) => page.evaluate(k => window.e2e.peek(k), key);
const abort = (page, key) => page.evaluate(k => window.e2e.abort(k), key);

/** Run one ceremony to its result. */
async function run(page, kind, opts = {}) {
  const key = await start(page, kind, opts);
  return settle(page, key);
}

/** Wait for an audit record matching `pred` (the audit export is the daemon's view, so it is the clock for "has the daemon seen it"). */
async function waitForAudit(stack, what, pred, opts = {}) {
  return waitFor(what, async () => {
    const events = auditEvents(await stack.daemon.audit());
    return pred(events) ? events : null;
  }, opts);
}

/** Wait until the daemon wrote `n` `escalation.<kind>` events. */
const waitForEscalation = (stack, kind, n = 1, opts = {}) =>
  waitFor(`${n} escalation.${kind} audit event(s)`, async () => escalationEvents(await stack.daemon.audit(), kind).length >= n, opts);

/** Send a (spoofed) signal on the harness's private session bus; resolves with the dbus-send exit code. */
function dbusSendSignal(stack, args) {
  return new Promise(resolve => {
    execFile('dbus-send', ['--session', '--type=signal', ...args], { env: stack.env.env, timeout: 10000 }, error => resolve(error ? (error.code ?? 1) : 0));
  });
}

const sleep = ms => new Promise(r => setTimeout(r, ms));

/** The registration prompt's summary (ADR 0014 amendment section 5.1): it says this is not a sign-in. */
const REGISTER_SUMMARY = 'Passless: CREATE A NEW PASSKEY? (not a sign-in)';

/**
 * The registration prompt's body, every line daemon-derived. `siteRule` is `exact` ("your rule for this site") or
 * `wildcard` ("NOT on your list; matched by the * rule"); `stored` is the "Stored in" line including the store-count clause.
 */
function registrationBody({ site, origin = `https://${site}`, siteRule = 'exact', stored, principal = os.userInfo().username }) {
  const rule = siteRule === 'wildcard' ? 'NOT on your list; matched by the * rule' : 'your rule for this site';
  return `Action: create a new passkey and register it at this site\nSite: ${site} (${rule})\nOrigin: ${origin}\nStored in: ${stored}\n` +
    `Approving allows this one registration, then lets the agent sign in here without asking.\nRequested by: a page now, principal user ${principal}`;
}

/** "Stored in" of a same-user profile (the human's own store) with `count` passkeys already held for the site. */
const humanStoreLine = (profile, count) =>
  `YOUR passkey store (same-user profile "${profile}"), ${count === 0 ? 'which holds no passkey for this site yet' : `which already holds ${count} passkey${count === 1 ? '' : 's'} for this site`}`;

/** A registration prompt's actions: exactly "Register once" and "Deny" (`register_once:<nonce>`, `deny:<nonce>`), never "Allow always". Returns the nonce. */
function assertRegistrationActions(n) {
  assert.equal(n.actions.length, 4, `actions: ${JSON.stringify(n.actions)}`);
  assert.deepEqual(n.actions.filter((_, j) => j % 2 === 1), ['Register once', 'Deny'], `actions: ${JSON.stringify(n.actions)}`);
  const nonce = (/^register_once:([0-9a-f]{32})$/.exec(n.actions[0]) || [])[1];
  assert.ok(nonce, `register key: ${n.actions[0]}`);
  assert.equal(n.actions[2], `deny:${nonce}`);
  assert.equal(n.expire_timeout, 0, 'the notification does not expire by itself');
  return nonce;
}

module.exports = { REGISTER_SUMMARY, registrationBody, humanStoreLine, assertRegistrationActions, requestProfile, start, settle, peek, abort, run, waitForAudit, waitForEscalation, dbusSendSignal, sleep };
