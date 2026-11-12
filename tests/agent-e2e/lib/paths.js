'use strict';
const path = require('node:path');

const REPO_ROOT = path.resolve(__dirname, '..', '..', '..');
const HARNESS_ROOT = path.resolve(__dirname, '..');
// Gitignored (`/target/` in the root .gitignore).
const CACHE_DIR = process.env.AGENT_E2E_CACHE_DIR || path.join(REPO_ROOT, 'target', 'agent-e2e-cache');
// Dedicated cargo target dir for the binaries under test. A shared target dir is clobbered by
// other builds that use different feature sets (the `agent` feature is off by default).
const BIN_TARGET_DIR = process.env.AGENT_E2E_TARGET_DIR || path.join(REPO_ROOT, 'target', 'agent-e2e-bin');
const ARTIFACTS_DIR = process.env.AGENT_E2E_ARTIFACTS_DIR || path.join(REPO_ROOT, 'target', 'agent-e2e-artifacts');

module.exports = { REPO_ROOT, HARNESS_ROOT, CACHE_DIR, BIN_TARGET_DIR, ARTIFACTS_DIR };
