#!/bin/bash
set -euo pipefail

# Development-only certificate generator
# DO NOT COMMIT GENERATED KEYS/CERTS TO VCS

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CERT_DIR="$SCRIPT_DIR"

umask 077

echo "Generating development CA..."
openssl genrsa -out "$CERT_DIR/ca.key" 4096 >/dev/null 2>&1
openssl req -x509 -new -nodes -key "$CERT_DIR/ca.key" -sha256 -days 365 -out "$CERT_DIR/ca.crt" \
  -subj "/C=US/ST=State/L=City/O=Vivified/CN=Vivified-CA" >/dev/null 2>&1

echo "Generating core server certificate..."
openssl genrsa -out "$CERT_DIR/core.key" 2048 >/dev/null 2>&1
openssl req -new -key "$CERT_DIR/core.key" -out "$CERT_DIR/core.csr" \
  -subj "/C=US/ST=State/L=City/O=Vivified/CN=vivified-core" >/dev/null 2>&1

cat > "$CERT_DIR/core.ext" << 'EOF'
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = vivified-core
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF

openssl x509 -req -in "$CERT_DIR/core.csr" -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
  -out "$CERT_DIR/core.crt" -days 365 -sha256 -extfile "$CERT_DIR/core.ext" >/dev/null 2>&1

echo "Generating plugin certificates..."
for plugin in user-management email-gateway prometheus; do
  openssl genrsa -out "$CERT_DIR/${plugin}.key" 2048 >/dev/null 2>&1
  openssl req -new -key "$CERT_DIR/${plugin}.key" -out "$CERT_DIR/${plugin}.csr" \
    -subj "/C=US/ST=State/L=City/O=Vivified/CN=${plugin}" >/dev/null 2>&1
  openssl x509 -req -in "$CERT_DIR/${plugin}.csr" -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" \
    -CAcreateserial -out "$CERT_DIR/${plugin}.crt" -days 365 -sha256 >/dev/null 2>&1
done

chmod 600 "$CERT_DIR"/*.key
chmod 644 "$CERT_DIR"/*.crt

echo "Certificates generated in $CERT_DIR"

