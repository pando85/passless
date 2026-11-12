'use strict';
// The ADR 0014 section 12 audit field lists, read from the daemon's source so there is ONE canonical list:
// `SECTION_12_OPERATION_FIELDS` and `SECTION_12_OTHER_RECORD_FIELDS` in `cmd/passless/src/agent/audit_events.rs`. The Rust
// unit tests check every record type against these lists; the E2E scenarios check the records a real browser ceremony
// produced against the same lists, so a field added to section 12 (or dropped from the code) fails both.

const fs = require('node:fs');
const path = require('node:path');

const { REPO_ROOT } = require('./paths');

const SOURCE = path.join(REPO_ROOT, 'cmd', 'passless', 'src', 'agent', 'audit_events.rs');

/** The text between the `[` after `name` and the `];` that closes the const. */
function constBody(source, name) {
  const start = source.indexOf(`const ${name}`);
  if (start < 0) throw new Error(`${name} not found in ${SOURCE}`);
  const open = source.indexOf('= &[', start);
  const close = source.indexOf('\n];', open);
  if (open < 0 || close < 0) throw new Error(`${name} is not a slice literal in ${SOURCE}`);
  return stripComments(source.slice(open + 4, close));
}

// `//` comments are dropped first, so a quoted word in a comment is never taken for a field.
const stripComments = text => text.replace(/\/\/[^\n]*/g, '');
const strings = text => [...stripComments(text).matchAll(/"([^"]+)"/g)].map(m => m[1]);

let cache = null;

/**
 * `{operation: [field, ...], operationKinds: [kind, ...], other: {kind: [field, ...]}}`.
 * `operation` is carried by every record of `operationKinds` (`policy.allow`, `policy.deny`, `policy.replay_served`,
 * `operation.terminal`); `other` lists the escalation, granted-rule, session-grant and browser-lease records.
 */
function section12() {
  if (cache) return cache;
  const source = fs.readFileSync(SOURCE, 'utf8');
  const operation = strings(constBody(source, 'SECTION_12_OPERATION_FIELDS: &[&str]'));
  const operationKinds = strings(constBody(source, 'SECTION_12_OPERATION_KINDS: &[&str]'));
  const other = {};
  for (const m of constBody(source, 'SECTION_12_OTHER_RECORD_FIELDS: &[(&str, &[&str])]').matchAll(/\(\s*"([^"]+)"\s*,\s*&\[([^\]]*)\]/g)) {
    other[m[1]] = strings(m[2]);
  }
  if (!operation.length || !operationKinds.length || !Object.keys(other).length) throw new Error('the section 12 field lists are empty');
  cache = { operation, operationKinds, other };
  return cache;
}

/** Fields of `fields` that `record` does not carry (a null value counts as carried: every key is always written). */
const missingFields = (record, fields) => fields.filter(f => !(f in record));

module.exports = { section12, missingFields };
