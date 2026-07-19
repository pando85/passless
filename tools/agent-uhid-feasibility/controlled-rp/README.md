# Controlled RP — WebAuthn Test Harness

Standards-based WebAuthn Relying Party for testing stock Chromium/Firefox against the Passless virtual authenticator via UHID. Uses `@simplewebauthn/server` v13.3.0 for full cryptographic verification: attestation/authenticator data parsing, RP ID hash, UP/UV flags, signature verification, challenge/origin binding, and monotonic signature counter.

No browser extensions or proxies required.

## Prerequisites

- Node.js 18+
- A running Passless authenticator instance (UHID device)
- Stock Chromium or Firefox

## Quick Start

```bash
cd tools/agent-uhid-feasibility/controlled-rp

# Install dependencies (first time only)
npm install

# Start the RP server (HTTP on localhost is a secure context)
npm start
# or directly:
node server.js

# Custom port:
PORT=9090 node server.js

# Open in browser
# Chromium:
chromium --user-data-dir=/tmp/passless-browser-test http://localhost:8443
# Firefox:
firefox --profile /tmp/passless-ff-test http://localhost:8443
```

## HTTPS Mode (optional)

```bash
# Generate self-signed certificate
bash gen_cert.sh

# Start with HTTPS (update server.js EXPECTED_ORIGIN if using non-default port)
node server.js --https
```

## Running Tests

```bash
npm test
# or directly:
node --test tests/test_server.js
```

## Test Procedure

1. **Start Passless authenticator** (in a separate terminal):
   ```bash
   cargo run
   ```

2. **Start the RP server**:
   ```bash
   npm start
   ```

3. **Open browser** to `http://localhost:8443`

4. **Register**: Click "Register Passkey" — browser invokes stock `navigator.credentials.create()`

5. **Authenticate**: Click "Authenticate" — browser invokes stock `navigator.credentials.get()`

6. **Check results**: The log panel shows full verification details including AAGUID, attestation format, device type, counter values, and user verification status

## Verification Scope

Full standards-based verification via `@simplewebauthn/server`:
- **Registration**: Attestation object parsing (CBOR), authenticator data extraction, RP ID hash validation, COSE public key extraction, UP/UV flag checks, challenge/origin binding, credential storage (id, publicKey, counter, transports)
- **Authentication**: Authenticator data parsing, RP ID hash validation, UP/UV flag checks, signature verification against stored public key, challenge/origin binding, monotonic signature counter enforcement (replay protection)

## API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/` | GET | WebAuthn test UI |
| `/api/status` | GET | Server status and credential count |
| `/api/register/begin` | POST | Generate registration options |
| `/api/register/finish` | POST | Verify registration response (full crypto) |
| `/api/authenticate/begin` | POST | Generate authentication options |
| `/api/authenticate/finish` | POST | Verify assertion response (full crypto) |

## Configuration

| Variable | Default | Description |
|---|---|---|
| `PORT` | `8443` | Server port |
| `HOST` | `127.0.0.1` | Bind address |
