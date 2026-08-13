#!/usr/bin/env bash
# Conformance suite: identical scenarios against one proxy. Scenarios a
# proxy has no feature for score N/A (capability map in targets.sh).
# Usage: conformance.sh <proxy>
# For hematite, run.sh recreates the service with HEMATITE_CONFIG=hematite-conf.yaml first.
set -uo pipefail
cd "$(dirname "$0")"
. ./targets.sh
if [[ $# -ne 1 ]]; then
  echo "Usage: conformance.sh <proxy>" >&2
  exit 2
fi
T=$1
P="http://$T:8080"
mkdir -p results
R="results/conformance-$T.jsonl"
: > "$R"

rec() {
  jq -n --arg id "$1" --arg name "$2" --arg result "$3" --arg detail "$4" \
    '{id:$id,name:$name,result:$result,detail:$detail}' >> "$R"
}

lcurl() {
  docker compose exec -T loadgen curl -sS -m 10 -x "$P" --cacert /certs/ca.crt "$@" 2>&1
}

code=$(lcurl -o /dev/null -w '%{http_code}' https://upstream.test/1k.json)
if [[ "$code" == "200" ]]; then rec 1 "allowlisted host reaches upstream" PASS "http $code"
else rec 1 "allowlisted host reaches upstream" FAIL "got: $code"; fi

code=$(lcurl -o /dev/null -w '%{http_code}' https://denied.test/1k.json)
if [[ "$code" != "200" ]]; then rec 2 "non-allowlisted host is blocked" PASS "got: $code"
else rec 2 "non-allowlisted host is blocked" FAIL "request succeeded"; fi

if target_can "$T" swap; then
  auth=$(lcurl -H "Authorization: Bearer proxy-bench-token-123" https://upstream.test/echo | jq -r .authorization 2>/dev/null)
  if [[ "$auth" == "Bearer sk-bench-real-key-do-not-log" ]]; then rec 3 "proxy token swapped for real secret at boundary" PASS "upstream saw real key"
  else rec 3 "proxy token swapped for real secret at boundary" FAIL "upstream saw: $auth"; fi
else
  rec 3 "proxy token swapped for real secret at boundary" "N/A" "no secret-injection feature"
fi

if target_can "$T" guard; then
  code=$(lcurl -o /dev/null -w '%{http_code}' https://imds-test.local/)
  if [[ "$code" != "200" ]]; then rec 5 "allowlisted host resolving to IMDS is refused" PASS "got: $code"
  else rec 5 "allowlisted host resolving to IMDS is refused" FAIL "request succeeded"; fi
else
  rec 5 "allowlisted host resolving to IMDS is refused" "N/A" "no resolved-IP guard; an in-fixture result would be a network artifact, not policy"
fi

if target_can "$T" strip; then
  evil=$(lcurl -H "X-Evil-Header: pwn" https://upstream.test/echo | jq -r .x_evil_header 2>/dev/null)
  if [[ -z "$evil" || "$evil" == "null" ]]; then
    rec 6 "disallowed header does not reach upstream" PASS "header stripped"
  else
    rec 6 "disallowed header does not reach upstream" FAIL "upstream saw: $evil"
  fi
else
  rec 6 "disallowed header does not reach upstream" "N/A" "no header-allowlist feature"
fi

detail=$(docker compose exec -T loadgen python3 /scripts/stream_client.py sse "$T:8080" 2>&1)
if [[ $? -eq 0 ]]; then rec 7 "SSE passthrough is unbuffered" PASS "$detail"
else rec 7 "SSE passthrough is unbuffered" FAIL "$detail"; fi

detail=$(docker compose exec -T loadgen python3 /scripts/stream_client.py ws "$T:8080" 2>&1)
if [[ $? -eq 0 ]]; then rec 8 "WebSocket echo round-trip" PASS "$detail"
else rec 8 "WebSocket echo round-trip" FAIL "$detail"; fi

# Containment last: no real secret anywhere in this proxy's output so far.
# Only meaningful for proxies that hold the real secret at all.
if target_can "$T" swap; then
  leaks=$(docker compose logs "$T" 2>&1 | grep -c "sk-bench-real-key-do-not-log" || true)
  if [[ "$leaks" == "0" ]]; then rec 4 "real secret never appears in proxy logs" PASS "0 occurrences"
  else rec 4 "real secret never appears in proxy logs" FAIL "$leaks occurrences"; fi
else
  rec 4 "real secret never appears in proxy logs" "N/A" "proxy never holds the real secret"
fi

# Scenario FAILs are product findings (data for the scorecard), not
# harness errors — the suite succeeds when it measured everything.
fails=$(jq -s '[.[] | select(.result == "FAIL")] | length' "$R")
recs=$(jq -s 'length' "$R")
echo "conformance($T): $recs scenarios recorded, $fails FAIL findings"
[[ "$recs" == "8" ]] || exit 1
