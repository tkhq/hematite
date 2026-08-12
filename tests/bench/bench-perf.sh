#!/usr/bin/env bash
# Perf suite: vegeta over the CONNECT tunnel against baseline (direct),
# hematite, and iron. Two kinds per target: fixed-rate latency and max
# throughput. docker stats sampled ~1/s for the proxy under test.
set -euo pipefail
cd "$(dirname "$0")"

DUR=${DUR:-30s}; RATE=${RATE:-400}; WORKERS=${WORKERS:-64}; ITER=${ITER:-3}
if [[ "${QUICK:-}" == "1" ]]; then DUR=3s; RATE=50; WORKERS=8; ITER=1; fi
mkdir -p results

# attack <proxy-url-or-empty> <outfile> <vegeta rate args...>
attack() {
  local proxy=$1 out=$2; shift 2
  docker compose exec -T -e HTTPS_PROXY="$proxy" loadgen sh -c \
    "printf 'GET https://upstream.test/1k.json\nAuthorization: Bearer proxy-bench-token-123\n' | \
     vegeta attack -duration $DUR -http2=false -root-certs /certs/ca.crt $* | \
     vegeta report -type json" > "results/$out"
}

# sample <container-id> <outfile> — loops until killed
sample() {
  : > "results/$2"
  while true; do
    docker stats --no-stream --format '{{.CPUPerc}} {{.MemUsage}}' "$1" | \
      awk '{cpu=$1; sub(/%/,"",cpu); mem=$2;
            if (mem ~ /GiB/)      {sub(/GiB/,"",mem); mem*=1024}
            else if (mem ~ /KiB/) {sub(/KiB/,"",mem); mem/=1024}
            else                  {sub(/MiB/,"",mem)}
            printf "{\"cpu_pct\":%s,\"mem_mib\":%s}\n", cpu, mem}' >> "results/$2"
  done
}

# measured <target> <proxy-url-or-empty>
measured() {
  local target=$1 proxy=$2 cid=""
  [[ "$target" != baseline ]] && cid=$(docker compose ps -q "$target")
  # warmup (untimed, not sampled) — save/restore DUR around the override
  local saved_dur=$DUR
  DUR=3s attack "$proxy" "warmup-$target.json" -rate 50 >/dev/null 2>&1 || true
  DUR=$saved_dur
  for i in $(seq 1 "$ITER"); do
    for kind in fixed max; do
      local rate_args="-rate $RATE"
      [[ "$kind" == max ]] && rate_args="-rate 0 -max-workers $WORKERS"
      local spid=""
      if [[ -n "$cid" ]]; then sample "$cid" "stats-$target-$kind-$i.jsonl" & spid=$!; fi
      attack "$proxy" "perf-$target-$kind-$i.json" $rate_args
      if [[ -n "$spid" ]]; then kill "$spid" 2>/dev/null || true; wait "$spid" 2>/dev/null || true; fi
    done
  done
}

measured baseline ""
measured hematite "http://hematite:8080"
measured iron     "http://iron:8080"
rm -f results/warmup-*.json
echo "perf suite done"
