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
assert 'HEMATITE_TLS_CA_CERT'           "TLS cert path env override present"
assert 'mountPath: /etc/hematite/tls'   "TLS secret mounted at the canonical path"
assert 'secretName: hematite-tls'       "TLS volume uses tls.existingSecret"
assert 'HEMATITE_MANAGEMENT_API_KEY'    "management API key env present"
assert 'name: hematite-mgmt'            "management key sourced from management.existingSecret"
assert 'name: OPENAI_API_KEY'           "values.env passthrough renders"

assert 'kind: NetworkPolicy'  "egress lockdown renders when enabled"
assert 'app: accept-client'   "lockdown selects the configured client pods"
assert 'k8s-app: kube-dns'    "lockdown allows cluster DNS (bootstrap resolution)"

# Off by default: the chart's own values must NOT render a NetworkPolicy.
if helm template hematite "$CHART" | grep -q 'kind: NetworkPolicy'; then
  echo "FAIL: NetworkPolicy rendered with default values (must be opt-in)"; exit 1
fi
echo "ok: lockdown is off by default"

# dns.enabled without a pinned clusterIP must refuse to render.
if helm template hematite "$CHART" -f "$VALUES" --set service.clusterIP="" >/dev/null 2>&1; then
  echo "FAIL: expected render error when service.dns.enabled without service.clusterIP"; exit 1
fi
echo "ok: dns.enabled without clusterIP is a render error"

helm lint "$CHART" -f "$VALUES"
echo "chart render checks: PASS"
