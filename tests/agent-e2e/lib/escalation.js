'use strict';
// Shared pieces of the P7 escalation scenarios (E2E-20/escalation, 21, 23 to 31, 43, 44, 48 to 50).

const { execFile } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const assert = require('node:assert/strict');

const { REPO_ROOT } = require('./paths');

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

// The two lines a pre-request prompt adds (ADR 0014 amendment sections 5.1 and 5.3), read from the daemon's source so that
// the text exists once: `ORIGIN_NONE_YET` and `REQUESTED_IN_ADVANCE` in cmd/passless/src/agent/escalation_prompt.rs.
const PROMPT_SOURCE = path.join(REPO_ROOT, 'cmd', 'passless', 'src', 'agent', 'escalation_prompt.rs');
function promptConst(name) {
  const m = new RegExp(`pub const ${name}: &str = "([^"]*)";`).exec(fs.readFileSync(PROMPT_SOURCE, 'utf8'));
  if (!m) throw new Error(`${name} not found in ${PROMPT_SOURCE}`);
  return m[1];
}
const ORIGIN_NONE_YET = promptConst('ORIGIN_NONE_YET');
const REQUESTED_IN_ADVANCE = promptConst('REQUESTED_IN_ADVANCE');

/** The sign-in prompt's summary and the body of a pre-request one: seven lines, "Origin: none yet" and who asked. */
const SIGN_IN_SUMMARY = 'Passless: agent sign-in request';
function preRequestSignInBody({ profile, site, mode = 'same-user', principal = os.userInfo().username }) {
  return `Profile: ${profile} (${mode})\nPrincipal user: ${principal}\nAction: sign in with a passkey\nSite: ${site} (any page under this site)\n` +
    `Origin: ${ORIGIN_NONE_YET}\nRequested by: ${REQUESTED_IN_ADVANCE}\n"Allow always" is saved permanently.`;
}

/** The registration prompt's body for a pre-request: no origin yet, and asked in advance (`registrationBody` is the ceremony form). */
function preRequestRegistrationBody({ site, siteRule = 'exact', stored, principal = os.userInfo().username }) {
  const rule = siteRule === 'wildcard' ? 'NOT on your list; matched by the * rule' : 'your rule for this site';
  return `Action: create a new passkey and register it at this site\nSite: ${site} (${rule})\nOrigin: ${ORIGIN_NONE_YET}\nStored in: ${stored}\n` +
    `Approving allows this one registration, then lets the agent sign in here without asking.\nRequested by: ${REQUESTED_IN_ADVANCE}, principal user ${principal}`;
}

module.exports = { ORIGIN_NONE_YET, REQUESTED_IN_ADVANCE, SIGN_IN_SUMMARY, preRequestSignInBody, preRequestRegistrationBody, REGISTER_SUMMARY, registrationBody, humanStoreLine, assertRegistrationActions, requestProfile, start, settle, peek, abort, run, waitForAudit, waitForEscalation, dbusSendSignal, sleep };
