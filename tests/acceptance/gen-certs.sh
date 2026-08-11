#!/usr/bin/env bash
# Generate the test CA (used both to mint client-facing MITM leaves and to
# sign the echo upstream's leaf) and the echo upstream leaf. One CA keeps
# trust management simple: the client trusts it, hematite mints under it, and
# it is baked into hematite's system roots for upstream verification.
set -euo pipefail
cd "$(dirname "$0")"

# The file-source secret the acceptance config swaps in (gitignored).
mkdir -p secrets
printf 'internal-real-token' > secrets/internal-token

mkdir -p certs
cd certs

if [[ -f ca.crt && "${1:-}" != "--force" ]]; then
  echo "certs already present (use --force to regenerate)"; exit 0
fi

# CA. rcgen needs a PKCS#8 key, so convert from openssl's SEC1 output.
openssl ecparam -name prime256v1 -genkey -noout -out ca.sec1.key
openssl pkcs8 -topk8 -nocrypt -in ca.sec1.key -out ca.key
rm -f ca.sec1.key
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 \
  -subj "/CN=hematite acceptance CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign,digitalSignature" \
  -out ca.crt

# Echo upstream leaf, valid for the hostnames the upstream stands in for.
openssl ecparam -name prime256v1 -genkey -noout -out echo.key
openssl req -new -key echo.key -subj "/CN=upstream" -out echo.csr
cat > echo.ext <<'EXT'
subjectAltName=DNS:httpbin.org,DNS:echo,DNS:localhost
extendedKeyUsage=serverAuth
EXT
openssl x509 -req -in echo.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days 3650 -sha256 -extfile echo.ext -out echo.crt
cat echo.crt ca.crt > echo.fullchain.crt
rm -f echo.csr echo.ext ca.srl

echo "generated: ca.crt ca.key echo.crt echo.key echo.fullchain.crt"
