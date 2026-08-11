#!/usr/bin/env bash
# In-cluster client: the full acceptance suite, then the k8s-only
# NetworkPolicy assertion. CA and MGMT_TOKEN come from the Job env.
set -uo pipefail

# Wait briefly for the kube-router network policy controller to program
# iptables rules for this pod before the acceptance suite starts.
sleep 10

bash /scripts/run.sh
accept=$?

echo
echo "=== step 10: NetworkPolicy bypass -> blocked ==="
# Dial the echo upstream's Service IP directly, skipping hematite. The
# egress lockdown must make this fail (-k: trust isn't the question).
if curl -s -o /dev/null --max-time 5 -k "https://${ECHO_IP}/get"; then
  echo "  FAIL: direct dial to upstream succeeded (lockdown not enforcing)"
  exit 1
fi
echo "  ok: direct dial blocked"

exit "$accept"
