#!/usr/bin/env bash
# Fast chart checks: helm lint plus grep assertions over `helm template`
# output. No cluster needed; this is CI's fast path for the chart.
set -euo pipefail
cd "$(dirname "$0")/../.."

CHART=deploy/chart/hematite
VALUES=tests/k3s/values.yaml

assert() { # assert <pattern> <description>
  if ! grep -q -- "$1" <<<"$out"; then
    echo "FAIL: rendered output missing: $2 (pattern: $1)"; exit 1
  fi
  echo "ok: $2"
}

out=$(helm template hematite "$CHART" -f "$VALUES")

assert 'clusterIP: 10.43.200.2'        "Service pins the values clusterIP"
assert 'HEMATITE_DNS_PROXY_IP'          "DNS proxy_ip env override present"
assert 'value: "10.43.200.2"'           "proxy_ip env equals the Service clusterIP"
assert 'checksum/config'                "config checksum annotation rolls the Deployment"
assert 'mountPath: /etc/hematite/hematite.yaml' "config mounted at the canonical path"
assert 'protocol: UDP'                  "DNS service port is UDP"

helm lint "$CHART" -f "$VALUES"
echo "chart render checks: PASS"
