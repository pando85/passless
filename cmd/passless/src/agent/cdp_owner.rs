//! Who owns a port-mode browser's CDP listener (ADR 0014 section 4.3).
//!
//! The daemon hands a port-mode agent the browser's `ws://127.0.0.1:<port>/devtools/browser/<id>`
//! endpoint, which carries full authority over the browser. It must therefore be the endpoint of the
//! browser the daemon launched, never whatever answers on that port. With a fixed
//! `browser_cdp_port`, another local process may hold `127.0.0.1:<port>` first (a developer's own
//! Chromium started with `--remote-debugging-port`, Firefox with `--remote-debugging-port`, or an
//! attacker of any UID); Chromium then silently listens on `[::1]:<port>` instead, and an
//! unverified `/json/version` request to `127.0.0.1:<port>` reaches the other process.
//!
//! This module answers that question from the kernel's socket tables: every listener that a
//! connection to `127.0.0.1:<port>` can reach (`/proc/net/tcp{,6}`) must be held by the launched
//! browser's own process tree (`socket:[inode]` among its `/proc/<pid>/fd` entries). It works for
//! a browser under bwrap (no PID or network namespace) and as another UID (the daemon is root
//! then, so it can read every descriptor table); a tree it cannot fully inspect never counts as
//! proof. It also names the holder of an occupied port for the launch error and the doctor.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, TcpListener};

/// The address of a listening TCP socket on the port in question, as far as reaching it through
/// `127.0.0.1` is concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ListenAddr {
    /// `127.0.0.1`, `0.0.0.0`, `[::ffff:127.0.0.1]`, `[::ffff:0.0.0.0]`, or `[::]` (which takes
    /// IPv4 connections unless `IPV6_V6ONLY` is set; counted, as that cannot be seen from here).
    ReachesIpv4Loopback,
    /// `[::1]`: where Chromium falls back to when its `127.0.0.1` bind fails.
    Ipv6Loopback,
    /// Any other address; never reached through `127.0.0.1`.
    Other,
}

/// One listening socket from `/proc/net/tcp` or `/proc/net/tcp6`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Listener {
    pub addr: ListenAddr,
    pub uid: u32,
    pub inode: u64,
}

const TCP_LISTEN: &str = "0A";

/// The listening sockets on `port` in one `/proc/net/tcp` (`v6 = false`) or `/proc/net/tcp6`
/// table. Malformed lines are skipped.
pub(crate) fn parse_listeners(table: &str, v6: bool, port: u16) -> Vec<Listener> {
    table
        .lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 10 || fields[3] != TCP_LISTEN {
                return None;
            }
            let (addr_hex, port_hex) = fields[1].split_once(':')?;
            if u16::from_str_radix(port_hex, 16).ok()? != port {
                return None;
            }
            let addr = if v6 {
                classify_v6(parse_v6(addr_hex)?)
            } else {
                classify_v4(parse_v4(addr_hex)?)
            };
            Some(Listener {
                addr,
                uid: fields[7].parse().ok()?,
                inode: fields[9].parse().ok()?,
            })
        })
        .collect()
}

/// The kernel prints each 32-bit word of the address as the hex of its in-memory (network order)
/// bytes read as a native integer, so `to_ne_bytes` recovers them on either endianness.
fn parse_v4(hex: &str) -> Option<Ipv4Addr> {
    if hex.len() != 8 {
        return None;
    }
    Some(Ipv4Addr::from(
        u32::from_str_radix(hex, 16).ok()?.to_ne_bytes(),
    ))
}

fn parse_v6(hex: &str) -> Option<Ipv6Addr> {
    if hex.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for (i, chunk) in bytes.chunks_mut(4).enumerate() {
        let word = u32::from_str_radix(hex.get(i * 8..i * 8 + 8)?, 16).ok()?;
        chunk.copy_from_slice(&word.to_ne_bytes());
    }
    Some(Ipv6Addr::from(bytes))
}

fn classify_v4(addr: Ipv4Addr) -> ListenAddr {
    if addr == Ipv4Addr::LOCALHOST || addr.is_unspecified() {
        ListenAddr::ReachesIpv4Loopback
    } else {
        ListenAddr::Other
    }
}

fn classify_v6(addr: Ipv6Addr) -> ListenAddr {
    if addr.is_unspecified() {
        ListenAddr::ReachesIpv4Loopback
    } else if addr == Ipv6Addr::LOCALHOST {
        ListenAddr::Ipv6Loopback
    } else if let Some(v4) = addr.to_ipv4_mapped() {
        classify_v4(v4)
    } else {
        ListenAddr::Other
    }
}

/// Every listener on `port` in this network namespace (the browser's: bwrap does not unshare it).
fn listeners_on(port: u16) -> io::Result<Vec<Listener>> {
    let mut out = parse_listeners(&fs::read_to_string("/proc/net/tcp")?, false, port);
    // A kernel without IPv6 has no tcp6 table.
    if let Ok(table) = fs::read_to_string("/proc/net/tcp6") {
        out.extend(parse_listeners(&table, true, port));
    }
    Ok(out)
}

/// The parent PID in a `/proc/<pid>/stat` line (the field after the state, past the last `)` of
/// the command name, which may itself contain parentheses and spaces).
fn parse_ppid(stat: &str) -> Option<u32> {
    let rest = &stat[stat.rfind(')')? + 1..];
    rest.split_whitespace().nth(1)?.parse().ok()
}

fn numeric_proc_entries() -> Vec<u32> {
    fs::read_dir("/proc")
        .map(|entries| {
            entries
                .flatten()
                .filter_map(|e| e.file_name().to_str()?.parse().ok())
                .collect()
        })
        .unwrap_or_default()
}

/// `root` and all its descendants, by parent PID. bwrap shares the PID namespace, so the browser
/// and its helpers appear here under their real PIDs.
pub(crate) fn process_tree(root: u32) -> Vec<u32> {
    let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
    for pid in numeric_proc_entries() {
        if let Some(ppid) = fs::read_to_string(format!("/proc/{pid}/stat"))
            .ok()
            .as_deref()
            .and_then(parse_ppid)
        {
            children.entry(ppid).or_default().push(pid);
        }
    }
    let mut tree = vec![root];
    let mut i = 0;
    while i < tree.len() {
        if let Some(kids) = children.get(&tree[i]) {
            tree.extend(kids.iter().copied().filter(|k| *k != root));
        }
        i += 1;
    }
    tree
}

/// The socket inodes among `pid`'s descriptors. `Ok(None)` when the process is gone; an error when
/// its descriptor table cannot be read (another UID without privilege, a non-dumpable process).
fn socket_inodes_of(pid: u32) -> io::Result<Option<HashSet<u64>>> {
    let entries = match fs::read_dir(format!("/proc/{pid}/fd")) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut inodes = HashSet::new();
    for entry in entries.flatten() {
        if let Ok(target) = fs::read_link(entry.path())
            && let Some(inode) = target
                .to_str()
                .and_then(|t| t.strip_prefix("socket:["))
                .and_then(|t| t.strip_suffix(']'))
                .and_then(|t| t.parse().ok())
        {
            inodes.insert(inode);
        }
    }
    Ok(Some(inodes))
}

/// The socket inodes held by the processes in `pids`, and whether every descriptor table could be
/// read.
fn socket_inodes_of_all(pids: &[u32]) -> (HashSet<u64>, bool) {
    let mut all = HashSet::new();
    let mut complete = true;
    for pid in pids {
        match socket_inodes_of(*pid) {
            Ok(Some(inodes)) => all.extend(inodes),
            Ok(None) => {}
            Err(_) => complete = false,
        }
    }
    (all, complete)
}

/// A process name for an error message: `/proc/<pid>/comm` is chosen by that process, so only
/// printable ASCII survives, and not much of it.
fn process_name(pid: u32) -> String {
    let comm = fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
    let name: String = comm
        .trim()
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(32)
        .collect();
    if name.is_empty() {
        "unknown".to_string()
    } else {
        name
    }
}

/// Who holds a listening socket, for a message: `firefox, pid 64598`, or its UID when no
/// process holding it is visible to this user.
pub(crate) fn describe_holder(listener: &Listener) -> String {
    match holder_pid(listener.inode) {
        Some(pid) => format!("{}, pid {pid}", process_name(pid)),
        None if listener.uid == nix::unistd::geteuid().as_raw() => {
            format!("a process of uid {}", listener.uid)
        }
        None => format!(
            "a process of uid {} that this user cannot inspect",
            listener.uid
        ),
    }
}

/// The first visible process whose descriptors include the socket `inode`.
fn holder_pid(inode: u64) -> Option<u32> {
    numeric_proc_entries().into_iter().find(|pid| {
        socket_inodes_of(*pid)
            .ok()
            .flatten()
            .is_some_and(|inodes| inodes.contains(&inode))
    })
}

/// The process that would hold `127.0.0.1:<port>` against a new listener, described, or `None`
/// when the port is free there. Used by the doctor, which must not bind anything.
pub fn port_holder(port: u16) -> Option<PortHolder> {
    let listeners = listeners_on(port).ok()?;
    let listener = listeners
        .iter()
        .find(|l| l.addr == ListenAddr::ReachesIpv4Loopback)?;
    Some(PortHolder {
        description: describe_holder(listener),
        pid: holder_pid(listener.inode),
    })
}

/// A process listening where a browser's CDP endpoint would.
#[derive(Debug, Clone)]
pub struct PortHolder {
    /// `firefox, pid 64598`, or the UID when no process is visible.
    pub description: String,
    pub pid: Option<u32>,
}

/// Refuses a fixed CDP port that something already holds on `127.0.0.1`, before the browser is
/// started: Chromium would not fail but fall back to `[::1]`. The probe binds the address itself
/// (and lets go at once), so it also catches a holder that is not listening yet. `Err` carries
/// who holds it. A holder that appears between this probe and the browser's own bind is caught by
/// the ownership check after the launch ([`ownership`]).
pub fn ensure_port_free(port: u16) -> Result<(), String> {
    match TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)) {
        Ok(_probe) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::AddrInUse => {
            let holder = listeners_on(port)
                .ok()
                .and_then(|listeners| {
                    listeners
                        .into_iter()
                        .find(|l| l.addr == ListenAddr::ReachesIpv4Loopback)
                })
                .map(|l| describe_holder(&l))
                .unwrap_or_else(|| "held by a socket that is not listening".to_string());
            Err(holder)
        }
        Err(e) => Err(format!("cannot be bound: {e}")),
    }
}

/// Who answers a connection to `127.0.0.1:<port>`, relative to the browser rooted at `root_pid`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Ownership {
    /// Nothing listens there yet.
    NotListening,
    /// Nothing listens there, but the browser listens on `[::1]:<port>`: its `127.0.0.1` bind
    /// failed, and something may take `127.0.0.1:<port>` at any time.
    Ipv6Fallback,
    /// Every listener reachable there is held by the browser's process tree (their inodes,
    /// sorted).
    Owned(Vec<u64>),
    /// Something else listens there (who, for the message).
    Foreign(String),
    /// A listener there is not among the browser's descriptors, but some of those could not be
    /// read; no proof either way.
    Unverifiable(String),
}

/// The ownership of `127.0.0.1:<port>` for the browser rooted at `root_pid` (the launched child:
/// the browser, or bwrap and the browser below it), which runs as `browser_uid`.
pub(crate) fn ownership(root_pid: u32, port: u16, browser_uid: u32) -> Ownership {
    let listeners = match listeners_on(port) {
        Ok(listeners) => listeners,
        Err(e) => return Ownership::Unverifiable(format!("cannot read /proc/net/tcp: {e}")),
    };
    ownership_of(&listeners, browser_uid, &|| {
        socket_inodes_of_all(&process_tree(root_pid))
    })
}

/// [`ownership`] over given listeners; `tree_sockets` returns the socket inodes of the browser's
/// process tree and whether that list is complete.
pub(crate) fn ownership_of(
    listeners: &[Listener],
    browser_uid: u32,
    tree_sockets: &dyn Fn() -> (HashSet<u64>, bool),
) -> Ownership {
    let reachable: Vec<&Listener> = listeners
        .iter()
        .filter(|l| l.addr == ListenAddr::ReachesIpv4Loopback)
        .collect();
    // A socket's UID is its creator's; the browser's sockets carry the browser's UID even under
    // bwrap (whose user namespace maps it to itself). Any other UID is someone else's at once.
    if let Some(other) = reachable.iter().find(|l| l.uid != browser_uid) {
        return Ownership::Foreign(describe_holder(other));
    }
    let ipv6_loopback: Vec<&Listener> = listeners
        .iter()
        .filter(|l| l.addr == ListenAddr::Ipv6Loopback && l.uid == browser_uid)
        .collect();
    if reachable.is_empty() && ipv6_loopback.is_empty() {
        return Ownership::NotListening;
    }
    let (held, complete) = tree_sockets();
    if reachable.is_empty() {
        return if ipv6_loopback.iter().any(|l| held.contains(&l.inode)) {
            Ownership::Ipv6Fallback
        } else {
            Ownership::NotListening
        };
    }
    match reachable.iter().find(|l| !held.contains(&l.inode)) {
        None => {
            let mut inodes: Vec<u64> = reachable.iter().map(|l| l.inode).collect();
            inodes.sort_unstable();
            Ownership::Owned(inodes)
        }
        Some(other) if complete => Ownership::Foreign(describe_holder(other)),
        Some(other) => Ownership::Unverifiable(format!(
            "the listener (socket inode {}, uid {}) is not among the descriptors of the \
             browser's processes this daemon could read",
            other.inode, other.uid
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 0100007F:9A5D 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 111 1 0000000000000000 100 0 0 10 0\n\
   1: 00000000:9A5D 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1001        0 112 1 0000000000000000 100 0 0 10 0\n\
   2: 0100007F:9A5D 0100007F:C000 01 00000000:00000000 00:00000000 00000000  1000        0 113 1 0000000000000000 100 0 0 10 0\n\
   3: 0500A8C0:9A5D 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 114 1 0000000000000000 100 0 0 10 0\n\
   4: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 115 1 0000000000000000 100 0 0 10 0\n\
   5: garbage\n";

    const TCP6: &str = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 00000000000000000000000001000000:9A5D 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 211 1 0000000000000000 100 0 0 10 0\n\
   1: 00000000000000000000000000000000:9A5D 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 212 1 0000000000000000 100 0 0 10 0\n\
   2: 0000000000000000FFFF00000100007F:9A5D 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 213 1 0000000000000000 100 0 0 10 0\n";

    #[cfg(target_endian = "little")]
    #[test]
    fn listeners_are_parsed_and_classified() {
        let v4 = parse_listeners(TCP, false, 39517);
        assert_eq!(
            v4,
            vec![
                Listener {
                    addr: ListenAddr::ReachesIpv4Loopback,
                    uid: 1000,
                    inode: 111
                },
                Listener {
                    addr: ListenAddr::ReachesIpv4Loopback,
                    uid: 1001,
                    inode: 112
                },
                Listener {
                    addr: ListenAddr::Other,
                    uid: 1000,
                    inode: 114
                },
            ],
            "only LISTEN sockets on the port; 192.168.0.5 is not reached through 127.0.0.1"
        );
        let v6 = parse_listeners(TCP6, true, 39517);
        assert_eq!(
            v6.iter().map(|l| (l.addr, l.inode)).collect::<Vec<_>>(),
            vec![
                (ListenAddr::Ipv6Loopback, 211),
                (ListenAddr::ReachesIpv4Loopback, 212),
                (ListenAddr::ReachesIpv4Loopback, 213),
            ]
        );
        assert!(parse_listeners(TCP, false, 8081).is_empty());
    }

    #[test]
    fn the_parent_pid_survives_parentheses_in_the_command_name() {
        assert_eq!(parse_ppid("42 (a) b) (c) S 7 42 42 0"), Some(7));
        assert_eq!(parse_ppid("garbage"), None);
    }

    fn listener(addr: ListenAddr, uid: u32, inode: u64) -> Listener {
        Listener { addr, uid, inode }
    }

    #[test]
    fn ownership_needs_every_reachable_listener_in_the_browser_tree() {
        let ours = |inodes: &[u64], complete: bool| {
            let set: HashSet<u64> = inodes.iter().copied().collect();
            move || (set.clone(), complete)
        };
        let v4 = listener(ListenAddr::ReachesIpv4Loopback, 1000, 7);

        assert_eq!(
            ownership_of(&[], 1000, &ours(&[], true)),
            Ownership::NotListening
        );
        assert_eq!(
            ownership_of(&[v4], 1000, &ours(&[7], true)),
            Ownership::Owned(vec![7])
        );
        // Not among the browser's descriptors: someone else's, even with the same UID.
        assert!(matches!(
            ownership_of(&[v4], 1000, &ours(&[9], true)),
            Ownership::Foreign(_)
        ));
        // ... unless part of the tree could not be read: then there is no proof either way.
        assert!(matches!(
            ownership_of(&[v4], 1000, &ours(&[9], false)),
            Ownership::Unverifiable(_)
        ));
        // Another UID is foreign without looking at descriptors.
        assert!(matches!(
            ownership_of(&[v4], 1001, &|| panic!("not needed")),
            Ownership::Foreign(_)
        ));
        // The browser plus a second listener (an `[::]` socket of another process): foreign.
        let any6 = listener(ListenAddr::ReachesIpv4Loopback, 1000, 8);
        assert!(matches!(
            ownership_of(&[v4, any6], 1000, &ours(&[7], true)),
            Ownership::Foreign(_)
        ));
        // The browser fell back to [::1]; a [::1] listener of someone else is no fallback.
        let lo6 = listener(ListenAddr::Ipv6Loopback, 1000, 5);
        assert_eq!(
            ownership_of(&[lo6], 1000, &ours(&[5], true)),
            Ownership::Ipv6Fallback
        );
        assert_eq!(
            ownership_of(&[lo6], 1000, &ours(&[], true)),
            Ownership::NotListening
        );
        // A listener on another address is irrelevant.
        let other = listener(ListenAddr::Other, 1001, 4);
        assert_eq!(
            ownership_of(&[other, v4], 1000, &ours(&[7], true)),
            Ownership::Owned(vec![7])
        );
    }

    #[test]
    fn a_held_port_is_refused_and_its_holder_named() {
        let held = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = held.local_addr().unwrap().port();
        let holder = ensure_port_free(port).unwrap_err();
        assert!(
            holder.contains(&format!("pid {}", std::process::id())),
            "{holder}"
        );
        let doctor = port_holder(port).expect("the doctor sees the holder");
        assert_eq!(doctor.pid, Some(std::process::id()));
        drop(held);
        assert!(ensure_port_free(port).is_ok());
        assert!(port_holder(port).is_none());
    }

    #[test]
    fn the_process_tree_contains_the_root_and_its_descendants() {
        let mut child = std::process::Command::new("/bin/sh")
            .args(["-c", "sleep 30 & wait"])
            .spawn()
            .unwrap();
        let root = child.id();
        let mut tree = Vec::new();
        for _ in 0..50 {
            tree = process_tree(root);
            if tree.len() >= 2 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        for pid in tree.iter().skip(1) {
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(*pid as i32),
                nix::sys::signal::Signal::SIGKILL,
            );
        }
        let _ = child.kill();
        let _ = child.wait();
        assert_eq!(tree[0], root);
        assert!(tree.len() >= 2, "{tree:?}");
        assert!(!tree.contains(&std::process::id()));
    }
}
