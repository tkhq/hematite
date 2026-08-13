#!/usr/bin/env bash
# One-command benchmark: hematite vs iron-proxy.
# Usage: ./run.sh [all|perf|footprint|agent|conformance]   QUICK=1 for a smoke run.
#
# Hardware signing token unavailable in CI; commits use -c commit.gpgsign=false.
set -uo pipefail
cd "$(dirname "$0")"
SUITE=${1:-all}

./gen-certs.sh
mkdir -p results

# Write suite status line-by-line inside runsuite so values survive across
# subshells (a "| while read" loop would get its own bash copy of STATUS).
: > results/suite-status.txt

runsuite() { # runsuite <name> <command...>
  local name=$1; shift
  echo "=== suite: $name ==="
  "$@"
  local rc=$?
  if [[ $rc -eq 0 ]]; then
    echo "$name: ok" >> results/suite-status.txt
  else
    echo "$name: ERRORED" >> results/suite-status.txt
  fi
}

docker compose build
docker compose up -d --force-recreate   # perf config; clean logs for containment

wait_ready() { # wait_ready <proxy>
  local i
  for i in $(seq 1 60); do
    if docker compose exec -T loadgen curl -s -o /dev/null -m 2 \
         -x "http://$1:8080" --cacert /certs/ca.crt \
         https://upstream.test/1k.json; then
      return 0
    fi
    sleep 1
  done
  echo "ERROR: $1 never became ready" >&2
  return 1
}
wait_ready hematite && wait_ready iron || { docker compose logs; exit 1; }

if [[ "$SUITE" == all || "$SUITE" == footprint ]]; then
  runsuite footprint ./bench-footprint.sh
fi
if [[ "$SUITE" == all || "$SUITE" == perf ]]; then
  runsuite perf ./bench-perf.sh
fi
if [[ "$SUITE" == all || "$SUITE" == agent ]]; then
  runsuite agent ./bench-agent.sh
fi
if [[ "$SUITE" == all || "$SUITE" == conformance ]]; then
  docker compose logs hematite > results/hematite-preconf.log 2>&1
  HEMATITE_CONFIG=hematite-conf.yaml docker compose up -d --force-recreate hematite
  if ! wait_ready hematite; then
    echo "ERROR: hematite did not become ready after config reload; skipping conformance suites" >&2
    echo "conformance-hematite: ERRORED" >> results/suite-status.txt
    echo "conformance-iron: ERRORED"     >> results/suite-status.txt
  else
    runsuite conformance-hematite ./conformance.sh hematite
    runsuite conformance-iron     ./conformance.sh iron
  fi
fi

docker compose logs hematite > results/hematite.log 2>&1
docker compose logs iron     > results/iron.log 2>&1
{ uname -a; docker --version; echo "cpus: $(getconf _NPROCESSORS_ONLN)"; } > results/host-info.txt

# Belt-and-braces containment across everything captured this run.
if grep -rq "sk-bench-real-key-do-not-log" results/*.log 2>/dev/null; then
  echo "WARNING: real secret found in captured proxy logs" | tee results/containment-warning.txt
fi

./render-report.sh "$SUITE"

docker compose down

if grep -q ERRORED results/suite-status.txt 2>/dev/null; then
  echo "one or more suites ERRORED (see results/suite-status.txt)"; exit 1
fi
echo "done: tests/bench/results/REPORT.md"
