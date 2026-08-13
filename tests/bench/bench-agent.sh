#!/usr/bin/env bash
# Agent-traffic suite: realistic AI-agent sessions (SSE chat + tool bursts +
# denied requests) through baseline/hematite/iron via agentbench. Emits
# results/agent-<target>.json plus timestamped docker-stats samples so the
# report can attribute CPU/RSS to the steady vs burst phase.
set -uo pipefail
cd "$(dirname "$0")"
mkdir -p results

if [[ "${QUICK:-}" == "1" ]]; then
  export AGENT_STEADY_SECS=20 AGENT_BURST_SECS=10 AGENT_STEADY_RATE_PER_MIN=30
  export AGENT_SSE_CHUNKS_MIN=40 AGENT_SSE_CHUNKS_MAX=120
fi

# sample_ts <container-id> <outfile> — 1/s docker stats with epoch-ms.
sample_ts() {
  : > "results/$2"
  while true; do
    local line ts
    line=$(docker stats --no-stream --format '{{.CPUPerc}} {{.MemUsage}}' "$1" 2>/dev/null) || break
    ts=$(($(date +%s) * 1000))
    echo "$line" | awk -v ts="$ts" '{cpu=$1; sub(/%/,"",cpu); mem=$2;
          if (mem ~ /GiB/)      {sub(/GiB/,"",mem); mem*=1024}
          else if (mem ~ /KiB/) {sub(/KiB/,"",mem); mem/=1024}
          else                  {sub(/MiB/,"",mem)}
          printf "{\"ts\":%s,\"cpu_pct\":%s,\"mem_mib\":%s}\n", ts, cpu, mem}' >> "results/$2"
  done
}

CUR_SAMPLER=""
cleanup() {
  if [[ -n "$CUR_SAMPLER" ]]; then
    kill "$CUR_SAMPLER" 2>/dev/null
    wait "$CUR_SAMPLER" 2>/dev/null
  fi
  return 0
}
trap cleanup EXIT

# Wait for the mock LLM upstream.
llm_ready=0
for _ in $(seq 1 30); do
  if docker compose exec -T loadgen curl -s -o /dev/null -m 2 \
       --cacert /certs/ca.crt https://llm.test/tool; then
    llm_ready=1; break
  fi
  sleep 1
done
if [[ "$llm_ready" != 1 ]]; then
  echo "agent suite: llm.test never became ready" >&2
  exit 1
fi

. ./targets.sh
fail=0
for t in baseline $PROXY_TARGETS; do
  proxy=""
  cid=""
  if [[ "$t" != baseline ]]; then
    proxy="http://$t:8080"
    cid=$(docker compose ps -q "$t")
  fi
  echo "=== agent suite: $t ==="
  if [[ -n "$cid" ]]; then
    sample_ts "$cid" "stats-agent-$t.jsonl" &
    CUR_SAMPLER=$!
  fi
  if ! docker compose exec -T \
      -e AGENT_STEADY_SECS -e AGENT_BURST_SECS -e AGENT_STEADY_RATE_PER_MIN \
      -e AGENT_SSE_CHUNKS_MIN -e AGENT_SSE_CHUNKS_MAX \
      loadgen agentbench attack --target "$t" --proxy "$proxy" \
        --ca /certs/ca.crt --out "/results/agent-$t.json"; then
    echo "agent suite: attack failed for $t" >&2
    fail=1
  fi
  if [[ -n "$CUR_SAMPLER" ]]; then
    kill "$CUR_SAMPLER" 2>/dev/null || true
    wait "$CUR_SAMPLER" 2>/dev/null || true
    CUR_SAMPLER=""
  fi
done

# Structural check: every produced file has both phases.
for t in baseline $PROXY_TARGETS; do
  if ! jq -e '.steady.classes.chat.count >= 1 and .burst.classes.chat.count >= 1' \
      "results/agent-$t.json" >/dev/null 2>&1; then
    echo "agent suite: results/agent-$t.json missing or incomplete" >&2
    fail=1
  fi
done

echo "agent suite done"
exit "$fail"
