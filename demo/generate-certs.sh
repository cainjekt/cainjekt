#!/usr/bin/env bash
set -euo pipefail

CA_KEY=/tmp/cainjekt-demo-ca.key
CA_CRT=/tmp/cainjekt-demo-ca.crt
SERVER_EXT=/tmp/cainjekt-demo-server.ext
SERVER_KEY=/tmp/cainjekt-demo-server.key
SERVER_CSR=/tmp/cainjekt-demo-server.csr
SERVER_CRT=/tmp/cainjekt-demo-server.crt
SERIAL=/tmp/cainjekt-demo-ca.srl

rm -f "$CA_KEY" "$CA_CRT" "$SERVER_EXT" "$SERVER_KEY" "$SERVER_CSR" "$SERVER_CRT" "$SERIAL" || true

openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes \
  -subj '/CN=cainjekt-demo-root' \
  -keyout "$CA_KEY" \
  -out "$CA_CRT" >/dev/null 2>&1

cat > "$SERVER_EXT" <<'EXT'
subjectAltName=DNS:https-server,DNS:https-server.cainjekt-demo,DNS:https-server.cainjekt-demo.svc,DNS:https-server.cainjekt-demo.svc.cluster.local
extendedKeyUsage=serverAuth
EXT

openssl req -new -newkey rsa:2048 -nodes \
  -subj '/CN=https-server.cainjekt-demo.svc.cluster.local' \
  -keyout "$SERVER_KEY" \
  -out "$SERVER_CSR" >/dev/null 2>&1

openssl x509 -req \
  -in "$SERVER_CSR" \
  -CA "$CA_CRT" \
  -CAkey "$CA_KEY" \
  -CAcreateserial \
  -out "$SERVER_CRT" \
  -days 365 \
  -sha256 \
  -extfile "$SERVER_EXT" >/dev/null 2>&1

echo "Certificates are generated!"
echo "  CA certificate: ${CA_CRT}"
echo "  Server certificate: ${SERVER_KEY}"
echo "  Server key: ${SERVER_CRT}"

