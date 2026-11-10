'use strict';
// Q3: can the extension be enabled in incognito WITHOUT user interaction?
//   (a) primary OTR profile (browser started with --incognito)
//   (b) OTR contexts made by CDP Target.createBrowserContext (== Playwright browser.newContext() over connectOverCDP)
// Seeding attempts: edit the profile's Preferences (extensions.settings.<id>.incognito=true) with and without the
// protection MACs, between two launches of the same profile. Probes in each context: MAIN-world content script marker,
// and whether a WebAuthn get() reaches the proxy extension (onGetRequest) or hangs (native path).
const fs = require('fs');
const L = require('./lib');
const { say, eventsOf, sleep } = L;
const PORT = new URL(L.CTRL_BASE).port;
const A = 'http://rp-a.localhost:' + PORT;
const MANIFEST = { content_scripts: [{ matches: ['http://*/*'], js: ['cs.js'], run_at: 'document_start', world: 'MAIN', all_frames: true }] };

function seed(prof, variant) {
  const f = prof + '/Default/Preferences';
  const j = JSON.parse(fs.readFileSync(f, 'utf8'));
  const e = j.extensions.settings[L.EXT_ID];
  const before = e.incognito;
  e.incognito = true;
  if (variant === 'prefs-nomacs') delete j.protection;
  fs.writeFileSync(f, JSON.stringify(j));
  return 'incognito before=' + before + ' now=true' + (variant === 'prefs-nomacs' ? ' (protection block deleted)' : ' (MACs left stale)');
}
const readPref = (prof) => { try { const j = JSON.parse(fs.readFileSync(prof + '/Default/Preferences', 'utf8')); return j.extensions.settings[L.EXT_ID].incognito; } catch (e) { return 'n/a (not flushed yet)'; } };

async function probe(st, page, label) {
  let cs;
  try { cs = await page.evaluate(() => document.documentElement.getAttribute('data-spike-cs')); } catch (e) { cs = 'ERR ' + String(e).split('\n')[0]; }
  const t = Date.now();
  const r = await page.evaluate(() => window.__get({}, 7000, { signal: AbortSignal.timeout(6000) })).catch((e) => ({ err: 'EVAL ' + String(e).split('\n')[0] }));
  await sleep(300);
  say('   ', label, '| content-script ran:', cs === '1', '| get() ->', r.ok ? 'credential via proxy' : JSON.stringify(r), '| proxy onGetRequest events:', eventsOf(st, 'onGetRequest', t).length);
}

async function phase(conf, st, tmpDir, title, incognito, pre) {
  say('  -- ' + title + (incognito ? ' [--incognito]' : ''));
  st.events.length = 0; st.cfg = { mode: 'ok' };
  const h = await L.launch(conf, { tmpDir, preProfile: pre, manifestPatch: MANIFEST, args: incognito ? ['--incognito'] : [], startUrl: incognito ? A + '/' : undefined });
  try {
    say('   attach:', await L.waitAttached(st), '| worker chrome.extension.isAllowedIncognitoAccess():', await h.cdp.evalInWorker('new Promise(r=>chrome.extension.isAllowedIncognitoAccess(r))'), '| pref now:', readPref(h.prof));
    const bctxs = await h.cdp.send('Target.getBrowserContexts');
    const pages = (await h.cdp.targets()).filter((t) => t.type === 'page');
    say('   target browserContextIds of pages:', pages.map((p) => (p.browserContextId || '').slice(0, 6) + ':' + p.url.slice(0, 24)), '| non-default contexts listed:', bctxs.browserContextIds.length);
    const ctx0 = h.browser.contexts()[0];
    if (incognito) {
      const pg = ctx0.pages().find((p) => p.url().startsWith(A)) || ctx0.pages()[0];
      await pg.addInitScript(L.PAGE_HELPERS); await pg.reload({ waitUntil: 'load' });
      await probe(st, pg, '(a) primary OTR window page');
    } else {
      const pg = await L.pageWithHelpers(ctx0, A + '/');
      await probe(st, pg, 'default profile page (control)');
    }
    // (b) CDP-created context (what Playwright browser.newContext() does)
    const nctx = await h.browser.newContext();
    const np = await L.pageWithHelpers(nctx, A + '/');
    await probe(st, np, '(b) Target.createBrowserContext page (Playwright newContext)');
    await nctx.close();
  } finally { await h.stop({ graceful: true, keep: true }); }
}

L.forEachConfig('Q3', async (h0, st, label) => {
  await h0.stop(); // forEachConfig launched one for us; we manage our own profiles below
  const conf = L.CONFIGS.find((c) => c.browser + '/' + c.mode === label);
  const run = async (name, fn) => { const tmp = fs.mkdtempSync(L.TMP_ROOT + '/q3-'); say('\n [scenario ' + name + ']'); try { await fn(tmp); } catch (e) { say('   FATAL', String(e && e.stack || e).split('\n').slice(0, 3).join(' | ')); } finally { if (!process.env.KEEP) fs.rmSync(tmp, { recursive: true, force: true }); } };
  const prof = (tmp) => fs.readdirSync(tmp).length ? tmp + '/profile' : null;
  await run('unseeded', async (tmp) => { await phase(conf, st, tmp, 'normal launch', false); await phase(conf, st, tmp, 'second launch', true); });
  for (const variant of ['prefs', 'prefs-nomacs']) {
    await run('seeded:' + variant, async (tmp) => {
      await phase(conf, st, tmp, 'profile creation launch', false);
      say('   SEED:', seed(tmp + '/profile', variant));
      await phase(conf, st, tmp, 'relaunch with seeded profile', false);
      await phase(conf, st, tmp, 'relaunch with seeded profile', true);
    });
  }
  // Can the daemon seed a FRESH profile (no prior launch)? Write a minimal Preferences before the very first start.
  await run('seeded-before-first-launch', async (tmp) => {
    const pre = (prof) => { fs.mkdirSync(prof + '/Default', { recursive: true }); fs.writeFileSync(prof + '/Default/Preferences', JSON.stringify({ extensions: { settings: { [L.EXT_ID]: { incognito: true } } } })); };
    await phase(conf, st, tmp, 'FIRST launch of a profile pre-seeded with only {extensions.settings.<id>.incognito:true}', false, pre);
    await phase(conf, st, tmp, 'relaunch (is the seed kept?)', true);
  });
});
