#!/usr/bin/env bash
# Footprint suite: image size, binary size, cold start (container StartedAt
# -> first successful proxied 200), idle RSS after 10s of no traffic.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p results

bin_path() {
  case "$1" in
    hematite) echo /usr/local/bin/hematite ;;
    iron)     echo /usr/local/bin/iron-proxy ;;
  esac
}

tmp=results/footprint-rows.jsonl
: > "$tmp"

for t in hematite iron; do
  cid=$(docker compose ps -q "$t")
  img=$(docker inspect -f '{{.Image}}' "$cid")
  image_bytes=$(docker image inspect -f '{{.Size}}' "$img")
  binary_bytes=$(docker compose exec -T "$t" sh -c "stat -c %s $(bin_path "$t")" | tr -d '[:space:]')

  # Cold start: poller (in-network, 10ms resolution) races the restart.
  docker compose exec -T loadgen python3 /scripts/poll.py "$t:8080" > "results/cold-$t.txt" &
  poller=$!
  sleep 0.5
  docker compose restart "$t" >/dev/null
  wait "$poller"
  first_ok_ms=$(tr -d '[:space:]' < "results/cold-$t.txt")
  cid=$(docker compose ps -q "$t")
  started=$(docker inspect -f '{{.State.StartedAt}}' "$cid")
  started_ms=$(python3 - "$started" <<'PY'
import datetime, sys
s = sys.argv[1].rstrip("Z")
head, _, frac = s.partition(".")
dt = datetime.datetime.fromisoformat(f"{head}.{(frac + '000000')[:6]}+00:00")
print(int(dt.timestamp() * 1000))
PY
)
  cold_start_ms=$((first_ok_ms - started_ms))

  sleep 10   # idle settle
  idle_rss_mib=$(docker stats --no-stream --format '{{.MemUsage}}' "$cid" | \
    awk '{mem=$1;
          if (mem ~ /GiB/)      {sub(/GiB/,"",mem); mem*=1024}
          else if (mem ~ /KiB/) {sub(/KiB/,"",mem); mem/=1024}
          else                  {sub(/MiB/,"",mem)}
          print mem}')

  jq -n --arg t "$t" --argjson img "$image_bytes" --argjson bin "$binary_bytes" \
        --argjson cold "$cold_start_ms" --argjson idle "$idle_rss_mib" \
        '{target:$t,image_bytes:$img,binary_bytes:$bin,cold_start_ms:$cold,idle_rss_mib:$idle}' >> "$tmp"
done

jq -s . "$tmp" > results/footprint.json
rm -f "$tmp" results/cold-*.txt
echo "footprint suite done"
cat results/footprint.json
