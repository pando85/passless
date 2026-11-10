// Q7 evidence: which /dev/hidraw* nodes does an extension-less Chromium open during a WebAuthn create? (strace -f -e trace=openat)
// Run: xvfb-run -a node q7-strace.js    (needs ./passless-test-instance.sh start)
const L = require('./lib');
(async () => {
  const exe = process.env.SPIKE_BROWSER || '/usr/bin/chromium';
  const srv = await L.serve(18080, null);
  const out = L.path.join(L.SCRATCH, 'strace.out'); try { L.fs.unlinkSync(out); } catch (e) {}
  const h = await L.launch({ exe, headless: false, tag: 'q7s', prefix: ['strace', '-f', '-qq', '-e', 'trace=openat', '-o', out] });
  try {
    const p = await h.browser.contexts()[0].newPage(); await p.goto('http://localhost:18080/');
    console.log(L.fmt(await L.probeCreate(p, 'localhost', 12000)));
  } finally { h.kill(); }
  await L.sleep(500);
  const lines = L.fs.readFileSync(out, 'utf8').split('\n').filter(l => /\/dev\/hidraw/.test(l));
  console.log('hidraw openat lines:', lines.length); console.log(lines.slice(0, 8).map(l => l.replace(/^\d+\s+/, '').slice(0, 150)).join('\n'));
  srv.close(); process.exit(0);
})().catch(e => { console.error(e); process.exit(1); });
