# agent-uhid-feasibility

Phase 0 disposable native UHID feasibility probe for Passless.

This is a **standalone Rust binary** that directly uses the Linux UHID kernel
interface to validate device identity control, sysfs discovery, hidraw mapping,
concurrent lifecycle, and permission probes — without depending on
`soft-fido2-transport` or any production Passless code.

## Build

```bash
cd tools/agent-uhid-feasibility
cargo build
```

## Commands

| Command | Description |
|---------|-------------|
| `env` | Probe environment: UHID module, `/dev/uhid`, hidraw permissions |
| `discover` | List all HID devices via sysfs |
| `discover <uniq>` | Find device by uniq field |
| `hidraw-map` | List all hidraw nodes with identity info |
| `hidraw-map <uniq>` | Resolve hidraw path for a given uniq |
| `perm` | Probe `/dev/uhid` permissions |
| `perm <path>` | Probe permissions on specific path |
| `create <name> <uniq> <vendor> <product> <version>` | Create UHID device (hex IDs) |
| `cycle <count>` | Rapid sequential create-destroy cycles |
| `concurrent <count>` | Concurrent create-destroy cycles |
| `cleanup` | Scan for leftover probe devices in sysfs |

## What this probes

1. **Deterministic identity**: name, phys, uniq, vendor, product, version are
   set via UHID CREATE2 and verified through sysfs.
2. **Sysfs discovery**: Devices are found by walking `/sys/bus/hid/devices/`
   and reading `name`, `phys`, `uniq`, `vendor`, `product` attributes.
3. **Order-independent hidraw mapping**: hidraw nodes are discovered by
   traversing the device's sysfs subtree, not by enumeration order.
4. **Concurrent create-destroy**: Multiple threads create/destroy devices
   simultaneously to validate race-free lifecycle management.
5. **Permission-open probes**: Checks `/dev/uhid` and `/dev/hidraw*`
   permissions, ownership, and open-read-write capability.
6. **Lifecycle cleanup**: Scans sysfs for leftover probe devices.

## Tests

```bash
cargo test
```

Unit tests validate struct layouts, default values, and non-kernel logic.
Integration tests that require `/dev/uhid` are gated behind existence checks.

## Evidence Template

After running experiments, fill in results below:

```
## Evidence: UHID Feasibility Probe

Date: YYYY-MM-DD
Kernel: $(uname -r)
User: $(whoami)
/dev/uhid perms: $(stat -c '%a %U:%G' /dev/uhid 2>/dev/null || echo "N/A")

### Environment
- UHID module loaded: [ ]
- /dev/uhid exists: [ ]
- /dev/uhid R/W open: [ ]
- hidraw devices present: [count]

### Identity Control
- Deterministic name set via CREATE2: [ ]
- Deterministic phys set via CREATE2: [ ]
- Deterministic uniq set via CREATE2: [ ]
- Deterministic vendor/product/version: [ ]
- Identity visible in sysfs after create: [ ]

### Sysfs Discovery
- Device found by uniq: [ ]
- Device found by name: [ ]
- vendor/product readable from sysfs: [ ]

### Hidraw Mapping
- hidraw node discovered via sysfs walk: [ ]
- Mapping is order-independent: [ ]
- hidraw node matches expected device: [ ]

### Concurrent Lifecycle
- N concurrent create-destroy cycles: [pass/fail]
- No leftover devices after cleanup: [ ]
- Destroy on Drop works: [ ]

### Permission Probes
- /dev/uhid readable: [ ]
- /dev/uhid writable: [ ]
- /dev/uhid open R/W: [ ]
- hidraw nodes accessible: [ ]

### Unresolved Gate Items
- [list any items that could not be validated and why]
```

## Prerequisites

- Linux kernel with `uhid` module loaded (`modprobe uhid`)
- Read/write access to `/dev/uhid` (typically `fido` group, mode `0660`)
- sysfs mounted at `/sys`
