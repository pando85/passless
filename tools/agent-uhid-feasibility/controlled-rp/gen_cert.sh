#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_DIR="${SCRIPT_DIR}/certs"

mkdir -p "${CERTS_DIR}"

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout "${CERTS_DIR}/key.pem" \
  -out "${CERTS_DIR}/cert.pem" \
  -days 365 -nodes \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  2>/dev/null

echo "Certificates generated in ${CERTS_DIR}/"
echo "  cert.pem - self-signed certificate"
echo "  key.pem  - private key"
echo ""
echo "To use HTTPS: python3 server.py --https"
echo ""
echo "Note: For HTTPS, browsers will show a certificate warning."
echo "  Chrome: type 'thisisunsafe' to bypass"
echo "  Firefox: Advanced -> Accept the Risk"
