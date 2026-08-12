#!/usr/bin/env bash
# Render results/*.json into results/REPORT.md.
set -euo pipefail
cd "$(dirname "$0")"
SUITE=${1:-all}
OUT=results/REPORT.md

# med <target> <kind> <jq-expr>: median across iteration files of a vegeta metric
med() {
  jq -s "map($3) | sort | .[(length/2|floor)]" results/perf-"$1"-"$2"-*.json 2>/dev/null || echo null
}

# stat_agg <target> <field> <agg>: aggregate across all stats files for a target
stat_agg() {
  cat results/stats-"$1"-*.jsonl 2>/dev/null \
    | jq -s "map(.$2) | if length==0 then null else ($3) end" 2>/dev/null || echo null
}

# fmt_num <value> <format>: printf-format a jq number, printing '-' if null
fmt_num() {
  local val=$1 fmt=$2
  if [[ "$val" == "null" || -z "$val" ]]; then
    echo -n "-"
  else
    # shellcheck disable=SC2059
    printf "$fmt" "$val"
  fi
}

{
  echo "# hematite vs iron-proxy — benchmark report"
  echo
  echo "> Numbers from docker-compose on a developer host support **relative**"
  echo "> comparison between the two proxies only; they are not publishable"
  echo "> absolute figures."
  echo
  echo "## Environment"
  echo '```'
  cat results/host-info.txt 2>/dev/null || echo "(host-info not recorded)"
  echo "iron-proxy image: ironsh/iron-proxy:0.49.0"
  echo "hematite: built from $(git rev-parse --short HEAD 2>/dev/null || echo 'local source')"
  echo '```'
  echo
  echo "## Suite status"
  echo '```'
  cat results/suite-status.txt 2>/dev/null || echo "(no status recorded)"
  echo '```'

  if [[ "$SUITE" == all || "$SUITE" == perf ]]; then
    echo
    echo "## Performance (medians over iterations; latency in ms)"
    echo
    echo "| target | p50 | p90 | p99 | max RPS | success | CPU% mean | CPU% max | RSS MiB mean | RSS MiB max |"
    echo "|---|---|---|---|---|---|---|---|---|---|"
    for t in baseline hematite iron; do
      p50=$(med "$t" fixed '.latencies."50th"/1e6')
      p90=$(med "$t" fixed '.latencies."90th"/1e6')
      p99=$(med "$t" fixed '.latencies."99th"/1e6')
      rps=$(med "$t" max  '.throughput')
      okr=$(med "$t" fixed '.success')
      if [[ "$t" == baseline ]]; then
        cpum="null"; cpux="null"; memm="null"; memx="null"
      else
        cpum=$(stat_agg "$t" cpu_pct 'add/length')
        cpux=$(stat_agg "$t" cpu_pct 'max')
        memm=$(stat_agg "$t" mem_mib 'add/length')
        memx=$(stat_agg "$t" mem_mib 'max')
      fi
      # Format each column; guard against null/empty when a suite errored.
      c_p50=$(fmt_num "$p50" "%.2f")
      c_p90=$(fmt_num "$p90" "%.2f")
      c_p99=$(fmt_num "$p99" "%.2f")
      c_rps=$(fmt_num "$rps" "%.0f")
      c_okr=$(fmt_num "$okr" "%s")
      c_cpum=$(fmt_num "$cpum" "%.1f")
      c_cpux=$(fmt_num "$cpux" "%.1f")
      c_memm=$(fmt_num "$memm" "%.1f")
      c_memx=$(fmt_num "$memx" "%.1f")
      echo "| $t | $c_p50 | $c_p90 | $c_p99 | $c_rps | $c_okr | $c_cpum | $c_cpux | $c_memm | $c_memx |"
    done
    echo
    base99=$(med baseline fixed '.latencies."99th"/1e6')
    for t in hematite iron; do
      t99=$(med "$t" fixed '.latencies."99th"/1e6')
      if [[ "$base99" == "null" || "$t99" == "null" ]]; then
        echo "- **$t p99 overhead vs baseline:** - (perf data unavailable)"
      else
        overhead=$(jq -n "$t99 - $base99 | .*100 | round | ./100")
        echo "- **$t p99 overhead vs baseline:** ${overhead} ms"
      fi
    done
  fi

  if [[ "$SUITE" == all || "$SUITE" == footprint ]]; then
    echo
    echo "## Operational footprint"
    echo
    echo "| target | image MB | binary MB | cold start ms | idle RSS MiB |"
    echo "|---|---|---|---|---|"
    if [[ -f results/footprint.json ]]; then
      jq -r '.[] | "| \(.target) | \(.image_bytes/1e6|round) | \(.binary_bytes/1e6*100|round/100) | \(.cold_start_ms) | \(.idle_rss_mib) |"' \
        results/footprint.json
    else
      echo "| (footprint ERRORED) | | | | |"
    fi
  fi

  if [[ "$SUITE" == all || "$SUITE" == conformance ]]; then
    echo
    echo "## Security conformance"
    echo
    echo "| # | scenario | hematite | iron-proxy |"
    echo "|---|---|---|---|"
    for id in 1 2 3 4 5 6 7 8; do
      name=$(jq -rs --arg id "$id" '.[] | select(.id==$id) | .name' \
               results/conformance-hematite.jsonl 2>/dev/null | head -1)
      h=$(jq -rs --arg id "$id" '.[] | select(.id==$id) | .result' \
               results/conformance-hematite.jsonl 2>/dev/null | head -1)
      i=$(jq -rs --arg id "$id" '.[] | select(.id==$id) | .result' \
               results/conformance-iron.jsonl 2>/dev/null | head -1)
      echo "| $id | ${name:-?} | ${h:-?} | ${i:-?} |"
    done
    echo
    echo "Details per scenario are in \`results/conformance-*.jsonl\`."
  fi

  echo
  echo "## Configs under test (verbatim)"
  for f in configs/hematite.yaml configs/hematite-conf.yaml configs/iron.yaml; do
    echo
    echo "### $f"
    echo '```yaml'
    cat "$f" 2>/dev/null || echo "(not found)"
    echo '```'
  done
} > "$OUT"
echo "wrote $OUT"
