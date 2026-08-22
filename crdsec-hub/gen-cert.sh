#!/bin/bash

# Generates a local test CA and an ECDSA (P-256) leaf cert signed by it,
# for local testing only - populates ./tls/ so nginx can start. Not for
# production; a real deployment wants a real CA-issued cert there instead
# (e.g. via ACME, see nashcom-labs/lego).
#
# Everything, including the CA private key, lives in tls/ - which is
# bind-mounted into the nginx container (see docker-compose.yml). Fine
# for local testing; a production CA key should not be handled this way.
# Distribute tls/ca.crt (not ca.key) to remote crdsectl agents' trust
# stores so they can validate this hub's leaf cert.
#
# The CA (key + cert) is only ever generated once and reused on later
# runs - regenerating it would invalidate every agent that already
# trusts the old ca.crt. The leaf (key + cert) is always regenerated
# fresh each run, since only this hub itself needs to trust it.

set -e

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
TLS_DIR="${SCRIPT_DIR}/tls"
ENV_FILE="${SCRIPT_DIR}/.env"

if [ -r "$ENV_FILE" ]; then
  # shellcheck disable=SC1090
  . "$ENV_FILE"
fi

# Must match docker-compose.yml's nginx "hostname:" (also driven by
# HUB_HOST) and crdsec-hub.sh's own HUB_HOST - all three need to agree
# for TLS hostname verification to actually pass. Assumes a DNS name, not
# an IP - if you set HUB_HOST to a raw IP, add it as an IP: SAN by hand.
HUB_HOST="${HUB_HOST:-localhost}"

CA_DAYS="${CA_DAYS:-3650}"
LEAF_DAYS="${LEAF_DAYS:-365}"

mkdir -p "$TLS_DIR"

# CA - only created if missing, so re-running this script doesn't
# invalidate agents that already trust the existing ca.crt.
if [ -e "${TLS_DIR}/ca.key" ] && [ -e "${TLS_DIR}/ca.crt" ]; then
  echo "Existing CA found at ${TLS_DIR}/ca.key + ca.crt - reusing it."
  ca_created="no"
else
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "${TLS_DIR}/ca.key"
  openssl req -x509 -new -key "${TLS_DIR}/ca.key" -days "$CA_DAYS" -out "${TLS_DIR}/ca.crt" \
    -subj "/CN=crdsec-hub CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"
  ca_created="yes"
fi

# Leaf, signed by the CA - always regenerated fresh (key and cert both)
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "${TLS_DIR}/tls.key"

CSR=$(mktemp)
openssl req -new -key "${TLS_DIR}/tls.key" -out "$CSR" \
  -subj "/CN=${HUB_HOST}" \
  -addext "subjectAltName=DNS:${HUB_HOST},DNS:localhost,IP:127.0.0.1"

openssl x509 -req -in "$CSR" \
  -CA "${TLS_DIR}/ca.crt" -CAkey "${TLS_DIR}/ca.key" -CAcreateserial \
  -out "${TLS_DIR}/tls.crt" -days "$LEAF_DAYS" -copy_extensions copyall

rm -f "$CSR"

chmod 600 "${TLS_DIR}/ca.key" "${TLS_DIR}/tls.key"

if [ "$ca_created" = "yes" ]; then
  echo "Wrote ${TLS_DIR}/ca.key + ca.crt (CA, keep ca.key private)."
else
  echo "Reused existing ${TLS_DIR}/ca.key + ca.crt (CA)."
fi
echo "Wrote ${TLS_DIR}/tls.key + tls.crt (leaf, signed by the CA above)."
echo "Distribute ${TLS_DIR}/ca.crt to remote crdsectl agents' trust stores."
