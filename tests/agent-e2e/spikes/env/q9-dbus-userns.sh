#!/usr/bin/env bash
# Q9 (unprivileged evidence): how does a private dbus-daemon --session judge clients whose namespace-local uid (0) differs from their kernel uid (1000)?
# Run: ./q9-dbus-userns.sh     (hermetic: private bus via dbus-run-session; never touches the real session bus)
set -u
exec dbus-run-session -- bash -c '
A=$DBUS_SESSION_BUS_ADDRESS; echo "private bus: $A"
echo "== control: plain uid $(id -u) client"
busctl --address="$A" call org.freedesktop.DBus / org.freedesktop.DBus GetConnectionUnixUser s org.freedesktop.DBus 2>&1 | head -2
echo "== client in userns mapped root->$(id -u) (unshare -r): getuid() inside = 0, kernel uid = $(id -u)"
unshare -r bash -c "id -u; busctl --address=\"$A\" call org.freedesktop.DBus / org.freedesktop.DBus GetConnectionUnixUser s org.freedesktop.DBus 2>&1 | head -2"
echo "== raw EXTERNAL handshake from the userns client claiming each uid (hex-encoded decimal)"
python3 - "$A" <<PY
import socket,sys,os,subprocess,binascii
addr=sys.argv[1]; path=addr.split("path=")[1].split(",")[0]
def attempt(claim):
    s=socket.socket(socket.AF_UNIX); s.connect(path); s.send(b"\0")
    s.send(b"AUTH EXTERNAL "+binascii.hexlify(str(claim).encode())+b"\r\n"); r=s.recv(100); return r.strip()
print("claim uid=%d (my kernel uid, from init ns): %r" % (os.getuid(), attempt(os.getuid())))
print("claim uid=0: %r" % attempt(0))
print("claim uid=1:  %r" % attempt(1))
PY
echo "== libdbus client (dbus-send) inside unshare -r sends its ns uid 0 in AUTH:"
unshare -r dbus-send --address="$A" --print-reply --dest=org.freedesktop.DBus / org.freedesktop.DBus.GetId 2>&1 | head -2
echo "== same raw handshake from inside unshare -r (kernel uid 1000, ns uid 0)"
unshare -r python3 - "$A" <<PY
import socket,sys,os,binascii
path=sys.argv[1].split("path=")[1].split(",")[0]
def attempt(claim):
    s=socket.socket(socket.AF_UNIX); s.connect(path); s.send(b"\0")
    s.send(b"AUTH EXTERNAL "+binascii.hexlify(str(claim).encode())+b"\r\n"); return s.recv(100).strip()
print("ns getuid()=%d; claim 0 (ns uid): %r" % (os.getuid(), attempt(0)))
print("claim 1000 (kernel uid):        %r" % attempt(1000))
PY
'
