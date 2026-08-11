#!/usr/bin/env bash
# The acceptance client: runs the Appendix A steps against the running
# proxy. Exits non-zero on the first failure. DNS is pointed at hematite, so
# every hostname is intercepted to the proxy; --cacert trusts the MITM CA.
set -uo pipefail

CA=${CA:-/certs/ca.crt}
fail=0

# Discover the proxy's IP via Docker's embedded DNS (retry while hematite
# starts), then repoint our own resolver at it so every subsequent lookup is
# intercepted by hematite.
PROXY=""
for _ in $(seq 1 30); do
  PROXY=$(getent hosts hematite | awk '{print $1}' | head -1)
  [ -n "$PROXY" ] && break
  sleep 1
done
if [ -z "$PROXY" ]; then echo "cannot resolve hematite"; exit 1; fi
echo "proxy at $PROXY; switching resolver"
echo "nameserver $PROXY" > /etc/resolv.conf

step() { echo; echo "=== step $1: $2 ==="; }
ok()   { echo "  ok: $1"; }
bad()  { echo "  FAIL: $1"; fail=1; }

# Wait for the proxy's TLS listener to accept connections.
for _ in $(seq 1 30); do
  curl -sS --cacert "$CA" https://httpbin.org/get >/dev/null 2>&1 && break
  sleep 1
done

step 1 "allowlisted GET -> 200"
code=$(curl -s -o /tmp/s1 -w '%{http_code}' --cacert "$CA" https://httpbin.org/get)
[ "$code" = 200 ] && ok "200" || bad "expected 200, got $code"

step 2 "non-allowlisted host -> 403"
code=$(curl -s -o /dev/null -w '%{http_code}' --cacert "$CA" https://example.com/)
[ "$code" = 403 ] && ok "403" || bad "expected 403, got $code"

step 3 "secret swap: upstream sees the real key"
body=$(curl -s --cacert "$CA" -H 'Authorization: Bearer proxy-openai-abc123' https://httpbin.org/headers)
echo "$body" | grep -q 'sk-real-acceptance' && ok "real key at upstream" || bad "swap did not happen: $body"
echo "$body" | grep -q 'proxy-openai-abc123' && bad "proxy token leaked upstream" || ok "no proxy token upstream"

step 4 "require:true, no token -> 403"
code=$(curl -s -o /dev/null -w '%{http_code}' --cacert "$CA" https://httpbin.org/headers)
[ "$code" = 403 ] && ok "403" || bad "expected 403, got $code"

step 5 "disallowed header stripped"
body=$(curl -s --cacert "$CA" -H 'X-Tracking: 1' https://httpbin.org/get)
echo "$body" | grep -qi 'x-tracking' && bad "tracking header reached upstream" || ok "stripped"

step 6 "DNS precedence (static > passthrough > intercept)"
static=$(dig +short @"$PROXY" db.internal.corp A | head -1)
[ "$static" = "10.0.0.9" ] && ok "static 10.0.0.9" || bad "static got '$static'"
intercept=$(dig +short @"$PROXY" anything.example A | head -1)
[ "$intercept" = "$PROXY" ] && ok "intercept -> proxy" || bad "intercept got '$intercept'"
# Passthrough: *.iana.org is forwarded to the upstream resolver (1.1.1.1),
# so the answer is a real public IP, never the proxy IP.
passthru=$(dig +short @"$PROXY" www.iana.org A | grep -E '^[0-9]+\.' | head -1)
if [ -n "$passthru" ] && [ "$passthru" != "$PROXY" ]; then
  ok "passthrough -> $passthru"
else
  bad "passthrough got '$passthru' (expected a forwarded public IP)"
fi

step 7 "CONNECT tunnel -> MITM'd 200"
code=$(curl -s -o /dev/null -w '%{http_code}' -x http://"$PROXY":8080 --cacert "$CA" https://httpbin.org/get)
[ "$code" = 200 ] && ok "tunnel 200" || bad "expected 200, got $code"

step 8 "allowlisted host resolving to metadata -> guard 502"
code=$(curl -s -o /dev/null -w '%{http_code}' --cacert "$CA" https://imds-test.local/)
[ "$code" = 502 ] && ok "guard 502" || bad "expected 502, got $code"

step 9 "management reload"
code=$(curl -s -o /dev/null -w '%{http_code}' -XPOST -H "Authorization: Bearer ${MGMT_TOKEN:-reload-token}" http://"$PROXY":9092/v1/reload)
[ "$code" = 200 ] && ok "reload 200" || bad "expected 200, got $code"
code=$(curl -s -o /dev/null -w '%{http_code}' -XPOST -H 'Authorization: Bearer wrong' http://"$PROXY":9092/v1/reload)
[ "$code" = 401 ] && ok "bad token 401" || bad "expected 401, got $code"

echo
if [ "$fail" = 0 ]; then echo "ACCEPTANCE: PASS"; else echo "ACCEPTANCE: FAIL"; fi
exit $fail
