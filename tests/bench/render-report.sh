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

# stat_agg <target> <field> <agg>: aggregate across the PERF suite's stats
# files only (fixed + max kinds) — agent-suite samples live in
# stats-agent-*.jsonl and are reported per phase in their own section.
stat_agg() {
  cat results/stats-"$1"-fixed-*.jsonl results/stats-"$1"-max-*.jsonl 2>/dev/null \
    | jq -s "map(.$2) | if length==0 then null else ($3) end" 2>/dev/null || echo null
}

# agent_val <target> <phase> <class> <field>
agent_val() {
  jq -r ".$2.classes.\"$3\".$4 // \"null\"" "results/agent-$1.json" 2>/dev/null || echo null
}

# agent_stat <target> <phase> <field> <agg>: docker-stats aggregate windowed
# to the phase's [start, end] epoch range.
agent_stat() {
  local t=$1 phase=$2 field=$3 agg=$4 s e
  s=$(jq -r ".$phase.start_epoch_ms // empty" "results/agent-$t.json" 2>/dev/null)
  e=$(jq -r ".$phase.end_epoch_ms // empty" "results/agent-$t.json" 2>/dev/null)
  if [[ -z "$s" || -z "$e" ]]; then echo null; return; fi
  jq -s --argjson s "$s" --argjson e "$e" \
    "map(select(.ts >= \$s and .ts <= \$e) | .$field) | if length==0 then null else ($agg) end" \
    "results/stats-agent-$t.jsonl" 2>/dev/null || echo null
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

  if [[ "$SUITE" == all || "$SUITE" == agent ]]; then
    echo
    echo "## Agent workload (realistic AI-agent sessions)"
    echo
    if [[ -f results/agent-baseline.json ]]; then
      jq -r '.profile |
        "Sessions: chat POST (\(.chat_body_bytes_min/1024|round)-\(.chat_body_bytes_max/1024|round)KB body, secret swap) with SSE response streamed at \(1000/.sse_interval_ms|round) chunks/s for \(.sse_chunks_min*.sse_interval_ms/1000)-\(.sse_chunks_max*.sse_interval_ms/1000)s, then \(.tool_calls_per_session) parallel tool GETs; \(.denied_probability*100|round)% of sessions also hit a denied host. Open-loop Poisson arrivals: steady \(.steady_secs)s @ \(.steady_sessions_per_min)/min, then burst \(.burst_secs)s @ \(.burst_multiplier)x."' \
        results/agent-baseline.json
      echo
      for phase in steady burst; do
        echo "### ${phase} phase"
        echo
        echo "| metric | baseline | hematite | iron-proxy |"
        echo "|---|---|---|---|"
        row() { # row <label> <class> <field> <fmt>
          local label=$1 class=$2 field=$3 fmt=$4 vals=""
          for t in baseline hematite iron; do
            vals="$vals | $(fmt_num "$(agent_val "$t" "$phase" "$class" "$field")" "$fmt")"
          done
          echo "| $label$vals |"
        }
        row "sessions launched (chat count)" chat count "%.0f"
        row "chat total p50 ms" chat p50_ms "%.0f"
        row "chat total p99 ms" chat p99_ms "%.0f"
        row "TTFT p50 ms" chat_ttft p50_ms "%.1f"
        row "TTFT p99 ms" chat_ttft p99_ms "%.1f"
        row "SSE max-stall p99 ms" chat_stall p99_ms "%.1f"
        row "tool call p50 ms" tool p50_ms "%.2f"
        row "tool call p99 ms" tool p99_ms "%.2f"
        row "denied-request p50 ms" denied p50_ms "%.2f"
        row "chat errors" chat errors "%.0f"
        row "tool errors" tool errors "%.0f"
        row "denied errors" denied errors "%.0f"
        # Proxy resource use windowed to this phase.
        cpu_h=$(agent_stat hematite "$phase" cpu_pct 'add/length')
        cpu_i=$(agent_stat iron "$phase" cpu_pct 'add/length')
        mem_h=$(agent_stat hematite "$phase" mem_mib 'max')
        mem_i=$(agent_stat iron "$phase" mem_mib 'max')
        echo "| proxy CPU% mean | - | $(fmt_num "$cpu_h" "%.1f") | $(fmt_num "$cpu_i" "%.1f") |"
        echo "| proxy RSS MiB max | - | $(fmt_num "$mem_h" "%.1f") | $(fmt_num "$mem_i" "%.1f") |"
        echo
      done
      echo "Notes: TTFT = time to first SSE chunk; max-stall = worst gap"
      echo "between consecutive SSE chunks in a session (streaming smoothness"
      echo "through the proxy). Denied-request latency is the time to a"
      echo "definitive policy refusal (N/A for baseline: no policy). The mock"
      echo "LLM paces chunks server-side, so chat totals mostly measure the"
      echo "stream duration; TTFT, stalls, and tool latency carry the signal."
    else
      echo "(agent suite ERRORED or not run)"
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
