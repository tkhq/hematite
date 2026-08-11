#!/usr/bin/env bash
# Mint a throwaway MITM CA and create the Secret the chart's
# tls.existingSecret expects. Dev/CI only — bring an operator-managed CA
# for real deployments. Key is PKCS#8 ECDSA P-256, the only format
# hematite's certificate library accepts.
#
#   gen-ca.sh <secret-name> [extra kubectl args, e.g. -n sandbox]
set -euo pipefail
SECRET=${1:?usage: gen-ca.sh <secret-name> [kubectl args...]}
shift
dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT

openssl ecparam -name prime256v1 -genkey -noout -out "$dir/ca.sec1.key"
openssl pkcs8 -topk8 -nocrypt -in "$dir/ca.sec1.key" -out "$dir/ca.key"
openssl req -x509 -new -nodes -key "$dir/ca.key" -sha256 -days 30 \
  -subj "/CN=hematite dev CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign,digitalSignature" \
  -out "$dir/ca.crt"

kubectl create secret generic "$SECRET" \
  --from-file=ca.crt="$dir/ca.crt" \
  --from-file=ca.key="$dir/ca.key" \
  "$@"
