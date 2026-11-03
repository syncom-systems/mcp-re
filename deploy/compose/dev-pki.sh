#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Throwaway key material for EVALUATING the compose deployment. Not for production.
#
#   ./dev-pki.sh            create ./secrets/ (refuses to overwrite an existing one)
#   ./dev-pki.sh client     re-issue the 1-hour evaluation client certificate
#
# Creates a private CA, a server certificate for the compose service name, a response
# signing seed, and one evaluation client (certificate and request-signing key) whose
# public key is listed in trust.json.
#
#   secrets/server/   what the proxy reads; mounted read-only. Mode 0600: the proxy refuses a
#                     key file that is group- or world-readable, so the container runs as the
#                     files' owner (MCP_RE_UID / MCP_RE_GID in .env).
#   secrets/client/   the CA key and the evaluation client's keys; never mounted.
#
# In production these come from your own CA, KMS and trust anchors. The proxy's
# --max-client-cert-lifetime bounds how long a client certificate may live, which is why
# the evaluation client certificate lasts one hour. One CA signs both the server and the
# client certificates here; production keeps those roles apart.
set -euo pipefail
cd "$(dirname "$0")"
SRV=secrets/server
CLI=secrets/client
SERVER_NAME="${MCP_RE_SERVER_NAME:-mcp-re-proxy}"
umask 077

b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }

issue_client() {
  # `openssl x509 -days` counts whole days; `openssl ca` takes dates, so it can issue one hour.
  local work start end
  work="$(mktemp -d)"
  : > "$work/index.txt"; echo 1000 > "$work/serial"
  cat > "$work/ca.cnf" <<CNF
[ca]
default_ca = c
[c]
database = $work/index.txt
new_certs_dir = $work
serial = $work/serial
default_md = sha256
policy = p
[p]
commonName = supplied
[ext]
subjectAltName = URI:spiffe://$SERVER_NAME/client/evaluation
extendedKeyUsage = clientAuth
CNF
  openssl ecparam -name prime256v1 -genkey -noout -out "$CLI/client-tls.key"
  openssl req -new -key "$CLI/client-tls.key" -subj "/CN=evaluation-client" -out "$work/client.csr"
  start="$(date -u -d '-1 minute' +%Y%m%d%H%M%SZ 2>/dev/null || date -u -v-1M +%Y%m%d%H%M%SZ)"
  end="$(date -u -d '+59 minutes' +%Y%m%d%H%M%SZ 2>/dev/null || date -u -v+59M +%Y%m%d%H%M%SZ)"
  openssl ca -batch -config "$work/ca.cnf" -cert "$SRV/client-ca.pem" -keyfile "$CLI/ca.key" \
    -in "$work/client.csr" -out "$CLI/client-tls.pem" -notext -extensions ext \
    -startdate "$start" -enddate "$end" >/dev/null 2>&1
  rm -rf "$work"
  echo "evaluation client certificate valid until $end"
}

if [[ "${1:-}" == client ]]; then
  [[ -f "$SRV/client-ca.pem" ]] || { echo "dev-pki: run ./dev-pki.sh first" >&2; exit 1; }
  issue_client
  exit 0
fi
[[ ! -e secrets ]] || { echo "dev-pki: ./secrets already exists; remove it to start over" >&2; exit 1; }
mkdir -p "$SRV" "$CLI"

openssl ecparam -name prime256v1 -genkey -noout -out "$CLI/ca.key"
openssl req -x509 -new -key "$CLI/ca.key" -days 30 -subj "/CN=MCP-RE evaluation CA" -out "$SRV/client-ca.pem"

openssl ecparam -name prime256v1 -genkey -noout -out "$SRV/server-key.pem"
openssl req -new -key "$SRV/server-key.pem" -subj "/CN=$SERVER_NAME" -out "$CLI/server.csr"
openssl x509 -req -in "$CLI/server.csr" -CA "$SRV/client-ca.pem" -CAkey "$CLI/ca.key" \
  -CAserial "$CLI/ca.srl" -CAcreateserial -days 30 -out "$SRV/server-chain.pem" \
  -extfile <(printf 'subjectAltName=DNS:%s,DNS:localhost\nextendedKeyUsage=serverAuth\n' "$SERVER_NAME") 2>/dev/null
rm -f "$CLI/server.csr" "$CLI/ca.srl"

head -c 32 /dev/urandom | b64url > "$SRV/signing.seed"

openssl genpkey -algorithm ed25519 -out "$CLI/client-signing.key"
pub="$(openssl pkey -in "$CLI/client-signing.key" -pubout -outform DER | tail -c 32 | b64url)"
printf '[{"signer":"spiffe://%s/client/evaluation","key_id":"evaluation-1","public_key":"%s"}]\n' \
  "$SERVER_NAME" "$pub" > "$SRV/trust.json"

issue_client

chmod 0700 "$SRV" "$CLI"
chmod 0600 "$SRV"/* "$CLI"/*
echo "created ./secrets — evaluation only."
echo "The proxy refuses key files that are group- or world-readable, so they stay 0600 and the"
echo "container must run as their owner. Put these in .env:"
echo "  MCP_RE_UID=$(id -u)"
echo "  MCP_RE_GID=$(id -g)"
