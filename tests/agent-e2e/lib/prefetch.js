'use strict';
// Download the browsers selected by the environment into the harness cache (run.sh holds a lock around
// this, so concurrent runs do not race on the cache) and fail early when a selected browser is unusable.
const { matrix } = require('./browser');

const m = matrix();
for (const v of m.variants) {
  if (v.skip) console.error(`prefetch: ${v.name} unavailable: ${v.skip}`);
  else console.error(`prefetch: ${v.name}: ${v.browser.version}`);
}
