// Q7: does any switch/feature/policy stop a NON-intercepted WebAuthn request from reaching the HID (UHID) authenticator?
// Needs a running hermetic passless (./passless-test-instance.sh start). Verdict per variant is read from the passless STORE
// (credential files written) and from the page outcome; other agents' passless instances may also exist, so the store is the truth.
// Run: xvfb-run -a node q7-hid-transport.js [variantName ...]
const L = require('./lib');
const store = L.path.join(L.SCRATCH, 'store');
const count = () => { try { return Number(L.execFileSync('sh', ['-c', `find ${store} -type f -name '*.bin' | wc -l`]).toString()); } catch (e) { return -1; } };
// Variants: name -> {args, env, cdpVirtualAuth}. Extra command-line candidates can be added with Q7_CANDIDATES="--a=b;--c=d".
const VARIANTS = {
  baseline: {},
  'disable-features=SecurityKeyHidInterfacesAreFido': { args: ['--disable-features=SecurityKeyHidInterfacesAreFido'] },
  'disable-blink-features=WebAuth': { args: ['--disable-blink-features=WebAuth'] },
  'disable-features=WebAuthentication,WebAuthenticationAPI,WebAuthenticationPasskeyUpgrade': { args: ['--disable-features=WebAuthentication,WebAuthenticationAPI,WebAuthenticationPasskeyUpgrade'] },
  'CDP WebAuthn.enable + virtual authenticator': { cdpVirtualAuth: true },
  'CDP virtual authenticator, then WebAuthn.disable': { cdpVirtualAuth: true, cdpDisableAfter: true },
};
(process.env.Q7_CANDIDATES || '').split(';').filter(Boolean).forEach(c => VARIANTS[c] = { args: c.split(' ') });
(async () => {
  const exe = process.env.SPIKE_BROWSER || '/usr/bin/chromium';
  const srv = await L.serve(18080, null);
  const only = process.argv.slice(2);
  for (const [name, v] of Object.entries(VARIANTS)) {
    if (only.length && !only.includes(name)) continue;
    for (const headless of [false, true]) {
      const before = count();
      const h = await L.launch({ exe, headless, tag: 'q7', args: v.args || [], env: v.env ? v.env() : {} });
      try {
        const p = await h.browser.contexts()[0].newPage(); await p.goto('http://localhost:18080/');
        if (v.cdpVirtualAuth) { const cdp = await p.context().newCDPSession(p); await cdp.send('WebAuthn.enable');
          await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'usb', hasResidentKey: true, hasUserVerification: true, isUserVerified: true } }); }
        const r = await L.probeCreate(p, 'localhost', 12000);
        console.log(`[${name}] ${headless ? 'headless' : 'headed'} => ${L.fmt(r)} | store credentials ${before} -> ${count()}`);
      } catch (e) { console.log(`[${name}] ERROR ${String(e).split('\n')[0]}`); } finally { h.kill(); }
    }
  }
  srv.close(); process.exit(0);
})().catch(e => { console.error(e); process.exit(1); });
