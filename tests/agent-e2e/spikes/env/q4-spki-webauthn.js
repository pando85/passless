// Q4: does --ignore-certificate-errors-spki-list allow WebAuthn on https://rp-a.test, and are localhost/rp-a.localhost usable?
// Run: xvfb-run -a node q4-spki-webauthn.js     (headless variant runs too, no display needed)
const L = require('./lib');
(async () => {
  const exe = process.env.SPIKE_BROWSER || '/usr/bin/chromium';
  const c = L.makeCert(['rp-a.test'], 'rpa');
  const s1 = await L.serve(18443, c); const s2 = await L.serve(18080, null);
  console.log('browser', exe, 'spki', c.spki);
  const variants = [
    ['spki-list', ['--ignore-certificate-errors-spki-list=' + c.spki]],
    ['no-cert-flag', []],
    ['ignore-all', ['--ignore-certificate-errors']],
  ];
  for (const headless of [false, true]) for (const [vn, extra] of variants) {
    const h = await L.launch({ exe, headless, tag: 'q4', args: ['--host-resolver-rules=MAP rp-a.test 127.0.0.1', ...extra] });
    try {
      const ctx = h.browser.contexts()[0]; const p = await ctx.newPage();
      const tag = `[${headless ? 'headless' : 'headed'} ${vn}]`;
      let nav; try { const r = await p.goto('https://rp-a.test:18443/', { waitUntil: 'load', timeout: 8000 }); nav = 'loaded status ' + (r && r.status()); } catch (e) { nav = 'NAV FAIL ' + String(e).split('\n')[0]; }
      console.log(tag, 'https://rp-a.test:18443', nav);
      if (nav.startsWith('loaded')) {
        console.log(tag, ' create rpId=rp-a.test:', L.fmt(await L.probeCreate(p, 'rp-a.test')));
        console.log(tag, ' get    rpId=rp-a.test:', L.fmt(await L.probeGet(p, 'rp-a.test')));
      }
      if (vn === 'spki-list') {
        for (const [url, rp] of [['http://localhost:18080/', 'localhost'], ['http://rp-a.localhost:18080/', 'rp-a.localhost'], ['http://rp-a.test:18080/', 'rp-a.test']]) {
          let n2; try { await p.goto(url, { waitUntil: 'load', timeout: 8000 }); n2 = 'loaded'; } catch (e) { n2 = 'NAV FAIL ' + String(e).split('\n')[0]; }
          if (n2 === 'loaded') console.log(tag, url, 'create rpId=' + rp + ':', L.fmt(await L.probeCreate(p, rp)));
          else console.log(tag, url, n2);
        }
      }
    } finally { h.kill(); }
  }
  s1.close(); s2.close(); process.exit(0);
})().catch(e => { console.error(e); process.exit(1); });
