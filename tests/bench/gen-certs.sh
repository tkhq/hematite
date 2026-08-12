#!/usr/bin/env bash
# Generate the bench CA, the shared upstream leaf, and the 1KB perf body.
# One CA: the loadgen trusts it, both proxies mint MITM leaves under it, and
# both proxies trust it for the upstream dial via SSL_CERT_FILE.
set -euo pipefail
cd "$(dirname "$0")"

mkdir -p www results
printf '{"pad":"%s"}\n' "$(head -c 1000 /dev/zero | tr '\0' 'x')" > www/1k.json

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
  -subj "/CN=hematite bench CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign,digitalSignature" \
  -out ca.crt

# One leaf shared by both upstreams.
openssl ecparam -name prime256v1 -genkey -noout -out echo.key
openssl req -new -key echo.key -subj "/CN=bench upstream" -out echo.csr
cat > echo.ext <<'EXT'
subjectAltName=DNS:upstream.test,DNS:denied.test,DNS:stream.test,DNS:localhost
extendedKeyUsage=serverAuth
EXT
openssl x509 -req -in echo.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days 3650 -sha256 -extfile echo.ext -out echo.crt
cat echo.crt ca.crt > echo.fullchain.crt
rm -f echo.csr echo.ext ca.srl
echo "generated: ca.crt ca.key echo.crt echo.key echo.fullchain.crt"
