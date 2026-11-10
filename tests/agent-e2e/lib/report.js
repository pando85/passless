'use strict';
// Summarise $AGENT_E2E_RESULTS (JSON lines written by lib/scenario.js).
//   node lib/report.js <results.jsonl> [--markdown]
// Exit status 1 when: any scenario FAILed or XPASSed (a stale xfail tag); nothing ran at all; any SKIP unless
// AGENT_E2E_ALLOW_SKIP=1 (a skipped CI scenario must never look green); or an id in AGENT_E2E_FILTER matched no scenario.

const fs = require('node:fs');

const file = process.argv[2];
const markdown = process.argv.includes('--markdown');
const rows = fs.existsSync(file || '') ? fs.readFileSync(file, 'utf8').split('\n').filter(Boolean).map(l => JSON.parse(l)) : [];

const ids = [...new Set(rows.map(r => r.id))].sort();
const variants = [...new Set(rows.map(r => r.variant))].sort();
const cell = (id, v) => rows.find(r => r.id === id && r.variant === v);
const counts = {};
for (const r of rows) counts[r.status] = (counts[r.status] || 0) + 1;

if (markdown) {
  console.log(`| Scenario | ${variants.join(' | ')} |`);
  console.log(`|---|${variants.map(() => '---').join('|')}|`);
  for (const id of ids) {
    const title = rows.find(r => r.id === id).title;
    console.log(`| ${id} ${title} | ${variants.map(v => { const c = cell(id, v); return c ? c.status : '-'; }).join(' | ')} |`);
  }
} else {
  const w = Math.max(8, ...variants.map(v => v.length)) + 2;
  console.log('\nAgent E2E summary');
  console.log(`${'scenario'.padEnd(10)}${variants.map(v => v.padEnd(w)).join('')}`);
  for (const id of ids) console.log(`${id.padEnd(10)}${variants.map(v => ((cell(id, v) || {}).status || '-').padEnd(w)).join('')}`);
  for (const r of rows.filter(r => r.status !== 'PASS')) {
    const why = r.status === 'XFAIL' ? `until ${r.until}: ${r.error || r.reason}` : (r.error || r.reason || '');
    console.log(`  ${r.status.padEnd(5)} ${r.id} [${r.variant}] ${why}`.slice(0, 260));
  }
}
console.log(`\n${Object.entries(counts).map(([k, v]) => `${k}=${v}`).join(' ')}`);
const problems = [];
if (rows.length === 0) problems.push('no scenario ran');
if ((counts.SKIP || 0) > 0 && process.env.AGENT_E2E_ALLOW_SKIP !== '1') problems.push(`${counts.SKIP} scenario(s) skipped (set AGENT_E2E_ALLOW_SKIP=1 to allow)`);
for (const f of (process.env.AGENT_E2E_FILTER || '').split(',').map(x => x.trim()).filter(Boolean)) {
  const num = f.replace(/^E2E-/, '').replace(/^0+/, '');
  if (!rows.some(r => r.id.replace(/^E2E-/, '').replace(/^0+/, '') === num)) problems.push(`filter ${f} matched no scenario`);
}
for (const p of problems) console.log(`PROBLEM: ${p}`);
process.exit((counts.FAIL || 0) + (counts.XPASS || 0) + problems.length > 0 ? 1 : 0);
