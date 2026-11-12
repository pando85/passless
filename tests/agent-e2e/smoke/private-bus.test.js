'use strict';
// The session bus must be the minimal private one from run.sh: only the bus itself (and, while one of our
// scenarios runs, notify-double) may be on it, and nothing may be activatable. Proves that no real session
// service (xdg portals, gvfs, a11y, notification daemons) can be started on it.

const { execFileSync } = require('node:child_process');

const { smoke, assert } = require('../lib/scenario');
const { assertPrivateBus } = require('../lib/env');

const call = method => execFileSync('dbus-send', ['--session', '--print-reply', '--dest=org.freedesktop.DBus', '/org/freedesktop/DBus',
  `org.freedesktop.DBus.${method}`], { encoding: 'utf8' }).split('\n').filter(l => /string "/.test(l)).map(l => l.match(/string "(.*)"/)[1]);

smoke('SMOKE-02', 'private session bus is minimal (no activatable or running real services)', async () => {
  assertPrivateBus();
  const names = call('ListNames');
  console.log('private bus names:', JSON.stringify(names), 'activatable:', JSON.stringify(call('ListActivatableNames')));
  const unexpected = names.filter(n => !n.startsWith(':') && n !== 'org.freedesktop.DBus' && n !== 'org.freedesktop.Notifications');
  assert.deepEqual(unexpected, [], `unexpected names on the private bus: ${unexpected.join(', ')}`);
  const activatable = call('ListActivatableNames').filter(n => n !== 'org.freedesktop.DBus');
  assert.deepEqual(activatable, [], `activatable services on the private bus: ${activatable.join(', ')}`);
});
