// Q5: which browser builds load an unpacked MV3 extension via --load-extension? Records version/UA for detection.
// Run: xvfb-run -a node q5-browser-matrix.js   (CfT is installed under $SPIKE_SCRATCH/cft; see RESULTS-env.md)
const L = require('./lib');
const { execFileSync } = require('child_process');
const glob = (d, re) => { try { return execFileSync('find', [d, '-type', 'f', '-regex', re]).toString().trim().split('\n')[0] || null; } catch (e) { return null; } };
(async () => {
  const ext = L.path.join(__dirname, 'ext-min');
  const cft = L.path.join(L.SCRATCH, 'cft');
  const B = {
    'chromium(distro)': '/usr/bin/chromium',
    'chrome-stable(branded)': '/usr/bin/google-chrome-stable',
    'chrome-for-testing': glob(cft, '.*/chrome-linux64/chrome'),
    'chrome-headless-shell(CfT)': glob(cft, '.*/chrome-headless-shell'),
  };
  for (const e of ['microsoft-edge', 'brave', 'brave-browser']) { try { B[e] = execFileSync('which', [e]).toString().trim(); } catch (x) { console.log(e, 'NOT INSTALLED (skipped)'); } }
  const srv = await L.serve(18080, null);
  for (const [name, exe] of Object.entries(B)) {
    if (!exe) { console.log(name, 'missing'); continue; }
    let ver = ''; try { ver = execFileSync(exe, ['--version']).toString().trim(); } catch (e) { ver = 'ERR'; }
    const shell = /headless-shell/.test(exe);
    for (const mode of shell ? ['headless-shell'] : ['headed', 'headless=new']) {
      const withExcept = [true, false];
      for (const exc of withExcept) {
        let h;
        try {
          h = await L.launch({ exe, headless: mode === 'headless=new', tag: 'q5', args: ['--load-extension=' + ext, ...(exc ? ['--disable-extensions-except=' + ext] : [])] });
          await L.sleep(1500);
          const bs = await h.browser.newBrowserCDPSession();
          const { targetInfos } = await bs.send('Target.getTargets');
          const sw = targetInfos.filter(t => t.url.startsWith('chrome-extension://'));
          const p = await h.browser.contexts()[0].newPage(); await p.goto('http://localhost:18080/'); await L.sleep(500);
          const attr = await p.evaluate(() => document.documentElement.getAttribute('data-env-spike'));
          const v = await bs.send('Browser.getVersion');
          console.log(`${name} | ${mode} | except=${exc} | sw-targets=${sw.length} | content-script-injected=${attr === '1'} | product="${v.product}" | UA="${v.userAgent}"`);
        } catch (e) { console.log(`${name} | ${mode} | except=${exc} | ERROR ${String(e).split('\n')[0].slice(0, 200)}`); }
        finally { if (h) h.kill(); }
      }
    }
    console.log(`  --version: ${ver}`);
  }
  srv.close(); process.exit(0);
})().catch(e => { console.error(e); process.exit(1); });
