'use strict';
// Scenario registration with matrix expansion, CI tagging and phase-tagged expected failures.
//
//   scenario({ id: 'E2E-01', title: '...', ci: true, xfailUntil: 'P4', xfailReason: '...' }, async ctx => { ... })
//
// - A scenario runs once per matrix variant (browser x headless/headed), see browser.matrix().
// - `ci: true` marks the CI subset (catalogue "C"). AGENT_E2E_MATRIX=ci runs only those.
//   AGENT_E2E_FILTER (comma list of ids or numbers, e.g. "E2E-01,6") overrides the CI selection.
// - `xfailUntil: 'Pn'` + `xfailReason` + `xfailMatch` (a RegExp, required): a failure whose message matches is
//   reported as XFAIL (the test does not fail the run); any OTHER failure is a FAIL; an unexpected pass is
//   XPASS and FAILS the run, so stale tags get removed. `xfailOn: variant => bool` limits the tag to some variants.
// - SKIP (missing browser, no DISPLAY, ...) fails the run unless AGENT_E2E_ALLOW_SKIP=1 (see lib/report.js).
// - Results are appended as JSON lines to $AGENT_E2E_RESULTS (consumed by lib/report.js).

const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const { test } = require('node:test');

const { matrix } = require('./browser');
const { busNames } = require('./env');
const { createStack, closeStack, saveFailureArtifacts } = require('./stack');
const { ARTIFACTS_DIR } = require('./paths');

function selected(meta) {
  const filter = (process.env.AGENT_E2E_FILTER || '').split(',').map(s => s.trim()).filter(Boolean);
  if (filter.length) {
    const num = meta.id.replace(/^E2E-/, '');
    return filter.some(f => f === meta.id || f === num || f.replace(/^E2E-/, '').replace(/^0+/, '') === num.replace(/^0+/, ''));
  }
  const m = process.env.AGENT_E2E_MATRIX || 'ci';
  return m === 'full' || meta.ci === true;
}

function record(entry) {
  const file = process.env.AGENT_E2E_RESULTS;
  if (file) fs.appendFileSync(file, JSON.stringify(entry) + '\n');
}

const firstLine = e => String((e && e.message) || e).split('\n').find(l => l.trim()) || '';

function scenario(meta, body) {
  if (meta.xfailUntil && !(meta.xfailMatch instanceof RegExp)) {
    throw new Error(`${meta.id}: xfailUntil requires an xfailMatch RegExp describing the expected failure`);
  }
  if (!selected(meta)) return;
  const { variants } = matrix();
  for (const variant of variants) {
    const name = `${meta.id} ${meta.title} [${variant.name}]`;
    const base = { id: meta.id, title: meta.title, variant: variant.name, ci: !!meta.ci };
    if (variant.skip) {
      record({ ...base, status: 'SKIP', reason: variant.skip });
      test(name, { skip: variant.skip }, () => {});
      continue;
    }
    const xfail = meta.xfailUntil && (!meta.xfailOn || meta.xfailOn(variant)) ? { until: meta.xfailUntil, reason: meta.xfailReason || '' } : null;

    test(name, { timeout: meta.timeoutMs || 180000 }, async t => {
      const stacks = [];
      const ctx = {
        t, assert, variant, meta,
        /** Create a stack; it is closed (and its artifacts kept on failure) automatically. */
        async stack(o) {
          const s = await createStack(`${meta.id}-${variant.name}`.replace(/[^\w.-]+/g, '_'), variant, o);
          stacks.push(s);
          return s;
        },
      };
      let error = null;
      try { await body(ctx); } catch (e) { error = e; }
      for (const s of stacks) {
        try {
          const unexpected = busNames(s.env.env).filter(n => n !== 'org.freedesktop.DBus' && n !== 'org.freedesktop.Notifications');
          if (unexpected.length && !error) error = new Error(`unexpected services on the private bus: ${unexpected.join(', ')}`);
        } catch (e) { if (!error) error = new Error(`could not inspect the private bus: ${e.message}`); }
        if (error) {
          const dest = path.join(ARTIFACTS_DIR, `${meta.id}-${variant.name}`.replace(/[^\w.-]+/g, '_'));
          try { await saveFailureArtifacts(s, dest, { error: String(error && error.stack || error) }); } catch { /* best effort */ }
        }
        await closeStack(s, !!error);
        const leaks = s.env.cleanup();
        if (leaks.length && !error) error = new Error(`leaked processes after cleanup: ${leaks.join(', ')}`);
      }
      if (xfail) {
        if (error && !meta.xfailMatch.test(String((error && error.message) || error))) {
          record({ ...base, status: 'FAIL', error: `unexpected failure (expected ${meta.xfailMatch}): ${firstLine(error)}` });
          throw error;
        }
        if (error) {
          record({ ...base, status: 'XFAIL', until: xfail.until, reason: xfail.reason, error: firstLine(error) });
          t.todo(`XFAIL until ${xfail.until}: ${xfail.reason} | ${firstLine(error)}`);
          return;
        }
        record({ ...base, status: 'XPASS', until: xfail.until, reason: xfail.reason });
        assert.fail(`XPASS: ${meta.id} [${variant.name}] passed but is tagged xfailUntil ${xfail.until} (${xfail.reason}); remove the tag`);
      }
      if (error) {
        record({ ...base, status: 'FAIL', error: firstLine(error) });
        throw error;
      }
      record({ ...base, status: 'PASS' });
    });
  }
}

/** A harness self-check (no matrix); recorded like a scenario so a failure or skip cannot look green. */
function smoke(id, title, fn, { timeoutMs = 120000 } = {}) {
  const filter = (process.env.AGENT_E2E_FILTER || '').trim();
  if (filter) return; // explicit scenario selection
  test(`${id} ${title}`, { timeout: timeoutMs }, async () => {
    const base = { id, title, variant: 'harness', ci: true };
    try { await fn(); } catch (e) { record({ ...base, status: 'FAIL', error: firstLine(e) }); throw e; }
    record({ ...base, status: 'PASS' });
  });
}

module.exports = { scenario, smoke, assert, record };
