# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Passless is a software FIDO2 authenticator emulator written in Rust. It creates a virtual FIDO2 security token that operates through the UHID (Userspace HID) kernel interface, allowing systems to authenticate using FIDO2/WebAuthn without physical hardware tokens.

**Key characteristics:**
- Uses the `keylib` crate for FIDO2/CTAP protocol implementation
- Operates as a platform authenticator with resident key (passkey) support
- Supports multiple storage backends: local filesystem and password-store (pass)
- Implements security hardening (mlock, core dump prevention)
- Desktop notifications for user verification prompts

## Development Commands

### Building
```bash
# Standard build
cargo build

# Release build
cargo build --release

# Full release with vendoring (for distribution)
make release
```

### Testing
```bash
# Run unit tests
cargo test

# Run unit tests with linting
make test

# Run E2E tests (requires authenticator to be running or will auto-start)
make test-e2e
```

The E2E tests use environment variables:
- `PASSLESS_E2E_AUTO_ACCEPT_UV=1` - Auto-accept user verification (debug builds only)
- `PASSLESS_LOCAL_PATH=/tmp/passless/fido2` - Use temporary storage

### Linting and Formatting
```bash
# Format code
cargo fmt
# or
make fmt

# Check formatting
make fmt-check

# Run clippy
cargo clippy --all-targets --all-features -- -D warnings
# or
make clippy

# Auto-fix clippy issues
make clippy-fix

# Run all lints
make lint

# Auto-fix all lints
make lint-fix
```

### Pre-commit Hooks
```bash
# Install hooks
make pre-commit-install

# Run hooks manually
make pre-commit
```

### Running the Authenticator

The authenticator requires UHID kernel module and proper permissions:
```bash
# As root, setup UHID access
modprobe uhid
groupadd fido 2>/dev/null || true
usermod -a -G fido $USER
echo 'KERNEL=="uhid", GROUP="fido", MODE="0660"' > /etc/udev/rules.d/90-uinput.rules
udevadm control --reload-rules && udevadm trigger

# Run authenticator
cargo run

# With verbose logging
cargo run -- --verbose

# With custom backend
cargo run -- --backend-type pass
cargo run -- --backend-type local --local-path /tmp/passless
```

## Architecture

### Core Components

**Main Loop** (`src/main.rs:22-86`):
- Runs in `run_with_service()` function
- Reads CTAPHID packets from UHID device in 64-byte chunks
- Processes CBOR commands through `AuthenticatorService`
- Sends response packets back through UHID
- Periodically cleans up expired credential cache (every 5 seconds)

**AuthenticatorService** (`src/authenticator.rs`):
- Orchestrates FIDO2 operations using dependency-injected `CredentialStorage`
- Builds callbacks for credential operations (read, write, delete, iterate)
- Handles user presence/verification through notifications
- Wraps `keylib::Authenticator` with storage backend integration

**Storage Abstraction** (`src/storage/mod.rs`):
- `CredentialStorage` trait defines interface for all backends
- Key methods: `read_first()`, `read_next()`, `read()`, `write()`, `delete()`, `select_users()`
- Supports iteration with filtering (by ID, RP, or hash)
- Cache cleanup method for security (removes sensitive data from memory)

**Storage Implementations**:
- `LocalStorageAdapter` (`src/storage/local.rs`): JSON files in local directory with in-memory caching
- `PassStorageAdapter` (`src/storage/pass.rs`): Encrypted storage using password-store/GPG

**CTAP Command Handlers** (`src/commands/`):
- `credential_mgmt.rs`: Implements credential management subcommands (enumerate, delete)
- `custom.rs`: Wraps credential management as custom CTAP commands (0x0a standard, 0x41 Yubikey-compatible)
- Commands use storage backend directly for operations

**Configuration** (`src/config.rs`):
- `AppConfig`: Main config structure with backend selection
- `BackendConfig`: Enum for Local vs Pass backend
- `SecurityConfig`: Memory locking, core dump prevention
- CLI args merged with TOML config (CLI takes precedence)
- Default config location: `~/.config/passless/config.toml`

**Security Hardening** (`src/config.rs:74-113`):
- `mlockall()`: Locks all memory to prevent swapping credentials to disk
- `setrlimit(RLIMIT_CORE, 0)`: Disables core dumps
- `prctl(PR_SET_DUMPABLE, 0)`: Prevents process dumping
- Applied during startup, failures logged as warnings

### Authenticator Configuration

The authenticator is configured as a FIDO 2.1 platform authenticator with:
- AAGUID: `66:69:64:6F:2E:70:61:73:73:6C:65:73:73:2E:72:73` ("fido.passless.rs")
- Resident keys (rk=true) for discoverable credentials/passkeys
- User verification support (uv=true, always_uv=true)
- Platform authenticator mode (plat=true)
- PIN UV auth token support
- Credential management enabled (standard 0x0a + Yubikey 0x41 commands)
- Max 100 resident credentials
- Supported extensions: credProtect

### Key Data Flow

**Registration Flow**:
1. Host sends MakeCredential request via UHID
2. CTAPHID layer assembles packets
3. AuthenticatorService processes CBOR request
4. User presence callback shows notification
5. Keylib generates credential
6. Write callback stores credential via CredentialStorage
7. Response sent back through UHID

**Authentication Flow**:
1. Host sends GetAssertion request
2. Select callback retrieves users for RP ID
3. Read callbacks retrieve matching credentials
4. User presence callback confirms authentication
5. Keylib signs assertion
6. Response returned to host

**Credential Management**:
1. Custom command (0x0a or 0x41) received
2. Subcommand router in `credential_mgmt.rs`
3. Direct storage backend calls for enumerate/delete operations
4. Metadata encoded in CBOR and returned

### Testing Structure

**Unit Tests**:
- Located in `#[cfg(test)]` modules within source files
- Test storage adapters, service creation, basic operations

**E2E Tests** (`tests/e2e_webauthn.rs`):
- Requires running authenticator instance
- Tests real WebAuthn registration/assertion flows
- Use `make test-e2e` which auto-starts authenticator if needed
- Run with `--test-threads=1 --ignored --nocapture`

## Important Patterns

### Adding a New Storage Backend

1. Create module in `src/storage/`
2. Implement `CredentialStorage` trait
3. Add variant to `BackendConfig` enum in `src/config.rs`
4. Add CLI args struct with `#[derive(Args)]`
5. Update `main.rs` match statement for backend initialization
6. Consider if `disable_user_verification()` should return true

### Adding New CTAP Commands

1. Define command handler in `src/commands/`
2. Create handler function matching `CustomCommandHandler` signature
3. Use `create_command_with_handler()` or similar builder
4. Add to `custom_commands` vec in `build_authenticator_config()`
5. Access storage via `Arc<Mutex<S>>` parameter if needed

### Environment Variables

Configuration can be set via environment variables:
- `PASSLESS_CONFIG`: Path to config file
- `PASSLESS_BACKEND_TYPE`: "local" or "pass"
- `PASSLESS_LOCAL_PATH`: Local storage directory
- `PASSLESS_PASS_STORE_PATH`: Password store path
- `PASSLESS_PASS_PATH`: Relative path in password store (default: "fido2")
- `PASSLESS_PASS_GPG_BACKEND`: "gpgme" or "gnupg-bin"
- `PASSLESS_USE_MLOCK`: Enable memory locking (default: true)
- `PASSLESS_DISABLE_CORE_DUMPS`: Disable core dumps (default: true)
- `PASSLESS_NO_NEW_PRIVS`: Set no new privileges (default: true)
- `PASSLESS_LOG_LEVEL`: Log level filter
- `PASSLESS_LOG_STYLE`: Log style
- `PASSLESS_E2E_AUTO_ACCEPT_UV`: Auto-accept UV in E2E tests (debug only)

## CI/CD

The project uses GitHub Actions (`.github/workflows/rust.yml`):
- **fmt**: Checks code formatting with `cargo fmt --check`
- **clippy**: Runs clippy with `--deny warnings`
- **build**: Builds and tests on Ubuntu 22.04 (for older glibc compatibility)
- **release**: On tags, creates release artifacts with vendored dependencies

Release process:
1. Update version in `Cargo.toml`
2. Run `make update-changelog` to generate changelog
3. Tag with `v*` pattern
4. CI builds, runs tests, publishes to crates.io, creates GitHub release
