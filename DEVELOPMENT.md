# Development

## Testing the TPM backend (swtpm)

Quick, minimal steps to run a software TPM for testing locally. Copy-paste these in a terminal.

Prerequisites

- Install the `swtpm` package from your distribution (e.g. `sudo apt install swtpm` or
  `sudo pacman -S swtpm`).

Create a runtime directory and a character device to bind swtpm to:

```bash
rm -rf /tmp/swtpm-state /tmp/tpm-store
mkdir -p /tmp/swtpm-state /tmp/tpm-store

# Start the software TPM and attach it to the char device:
swtpm socket \
  --tpm2 \
  --tpmstate dir=/tmp/swtpm-state \
  --server type=tcp,port=2321 \
  --ctrl type=tcp,port=2322 \
  --flags not-need-init,startup-clear \
  --log level=20
```

Run passless pointing at the TPM device. The TCTI string must be a valid TCTI spec (examples:
`device:/dev/tpm0`, `device:path=~/.local/run/mytpm0`, `tabrmd:` or `swtpm:`).

```bash
cargo run -- --backend-type tpm --tpm-tcti "swtpm:host=localhost,port=2321" --tpm-path /tmp/tpm-store -v
```
