// Q8: bwrap with a private /dev (no hidraw/uhid) around Chromium, headed and --headless=new.
// Verifies: it launches (with Chromium's own sandbox, no --no-sandbox), a non-intercepted WebAuthn create no longer reaches passless,
// and the Chromium sandbox layers are active. Needs ./passless-test-instance.sh start. Run: xvfb-run -a node q8-bwrap.js
const L = require('./lib');
const BWRAP = ['bwrap', '--dev-bind', '/', '/', '--dev', '/dev', '--die-with-parent'];
const store = L.path.join(L.SCRATCH, 'store');
const count = () => Number(L.execFileSync('sh', ['-c', `find ${store} -type f -name '*.bin' | wc -l`]).toString());
const rd = f => { try { return L.fs.readFileSync(f, 'utf8'); } catch (e) { return ''; } };
(async () => {
  const exe = process.env.SPIKE_BROWSER || '/usr/bin/chromium';
  const srv = await L.serve(18080, null);
  console.log('userns:', L.execFileSync('sh', ['-c', 'unshare -U true && echo "unshare -U: OK"']).toString().trim(), '| bwrap', L.execFileSync('bwrap', ['--version']).toString().trim());
  console.log('private /dev:', L.execFileSync('bwrap', [...BWRAP.slice(1), 'sh', '-c', 'ls /dev | tr "\\n" " "; ls /dev/hidraw* /dev/uhid 2>&1 | head -2']).toString().trim().replace(/\n/g, ' | '));
  for (const [label, extra, headless] of [
    ['bwrap, headed, Chromium sandbox ON', [], false],
    ['bwrap, headless=new, Chromium sandbox ON', [], true],
    ['NO bwrap (control), headed', null, false],
  ]) {
    const before = count(); let h;
    try {
      h = await L.launch({ exe, headless, tag: 'q8', prefix: extra === null ? [] : BWRAP });
      const p = await h.browser.contexts()[0].newPage(); await p.goto('http://localhost:18080/');
      await L.sleep(1000);
      const procs = L.execFileSync('pgrep', ['-g', String(h.proc.pid)]).toString().split('\n').filter(Boolean).map(Number);
      const info = procs.map(pid => ({ pid, status: rd(`/proc/${pid}/status`), cmd: (() => { const c = rd(`/proc/${pid}/cmdline`).split('\0').join(' '); const m = c.match(/--type=(\S+)/); return m ? '--type=' + m[1] : (/^(bwrap|\S*chrom)/.test(c) && !/^bwrap/.test(c) ? 'browser' : 'other'); })(), userns: (() => { try { return L.fs.readlinkSync(`/proc/${pid}/ns/user`); } catch (e) { return '?'; } })(), pidns: (() => { try { return L.fs.readlinkSync(`/proc/${pid}/ns/pid`); } catch (e) { return '?'; } })() }));
      const sb = info.filter(i => /^--type=(renderer|gpu-process|utility|zygote)/.test(i.cmd)).map(i => `${i.cmd.replace('--type=', '')}:Seccomp=${(i.status.match(/Seccomp:\s*(\d)/) || [])[1]}`);
      const browser = info.find(i => i.cmd === 'browser');
      const rend = info.find(i => /renderer/.test(i.cmd));
      console.log('  procs by type:', JSON.stringify(info.reduce((a, i) => (a[i.cmd] = (a[i.cmd] || 0) + 1, a), {})));
      console.log(`\n== ${label}`);
      console.log(`  browser NoNewPrivs=${(browser.status.match(/NoNewPrivs:\s*(\d)/) || [])[1]} userns=${browser.userns}; renderer userns=${rend && rend.userns} (differs=${rend && rend.userns !== browser.userns}) ; renderer pidns differs=${rend && rend.pidns !== browser.pidns}`);
      console.log('  seccomp per child:', sb.join(' '));
      const r = await L.probeCreate(p, 'localhost', 10000);
      console.log('  create:', L.fmt(r), '| store credentials', before, '->', count());
    } catch (e) { console.log(`\n== ${label}\n  ERROR ${String(e).split('\n')[0].slice(0, 300)}`); } finally { if (h) h.kill(); }
  }
  // strace inside bwrap: does Chromium even try /dev/hidraw*, and what does it get?
  const out = L.path.join(L.SCRATCH, 'strace-bwrap.out'); try { L.fs.unlinkSync(out); } catch (e) {}
  const h2 = await L.launch({ exe, headless: false, tag: 'q8s', prefix: [...BWRAP, 'strace', '-f', '-qq', '-e', 'trace=openat', '-o', out] });
  try { const p = await h2.browser.contexts()[0].newPage(); await p.goto('http://localhost:18080/'); await L.probeCreate(p, 'localhost', 6000); } finally { h2.kill(); }
  await L.sleep(500);
  console.log('\nstrace inside bwrap, /dev/hidraw opens:', L.fs.readFileSync(out, 'utf8').split('\n').filter(l => /\/dev\/hidraw/.test(l)).map(l => l.replace(/^\d+\s+/, '').slice(0, 120)).join(' | ') || '(none)');
  srv.close(); process.exit(0);
})().catch(e => { console.error(e); process.exit(1); });
