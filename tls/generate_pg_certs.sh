#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT_DIR="${SCRIPT_DIR}/../postgres-tls"
mkdir -p "$OUT_DIR"
umask 077

CA_KEY="$SCRIPT_DIR/ca.key"
CA_CRT="$SCRIPT_DIR/ca.crt"

if [ ! -f "$CA_KEY" ] || [ ! -f "$CA_CRT" ]; then
  echo "Missing CA. Run tls/generate_certs.sh first." >&2
  exit 1
fi

echo "Generating Postgres server key and CSR..."
openssl genrsa -out "$OUT_DIR/server.key" 2048 >/dev/null 2>&1
openssl req -new -key "$OUT_DIR/server.key" -out "$OUT_DIR/server.csr" \
  -subj "/C=US/ST=State/L=City/O=Vivified/CN=postgres" >/dev/null 2>&1

cat > "$OUT_DIR/server.ext" << 'EOF'
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = postgres
IP.1 = 127.0.0.1
EOF

echo "Signing Postgres server certificate with CA..."
openssl x509 -req -in "$OUT_DIR/server.csr" -CA "$CA_CRT" -CAkey "$CA_KEY" -CAcreateserial \
  -out "$OUT_DIR/server.crt" -days 365 -sha256 -extfile "$OUT_DIR/server.ext" >/dev/null 2>&1

chmod 600 "$OUT_DIR/server.key"
chmod 644 "$OUT_DIR/server.crt"
echo "Postgres TLS certs generated in $OUT_DIR"

