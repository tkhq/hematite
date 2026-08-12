# tests/bench — hematite vs iron-proxy

A docker-compose harness that compares hematite (built from this tree)
against iron-proxy (`ironsh/iron-proxy:0.49.0`) on three axes: MITM'd-HTTPS
performance via CONNECT, operational footprint, and security conformance.
Design doc: `docs/superpowers/specs/2026-08-12-bench-vs-iron-proxy-design.md`.

## Run

    ./run.sh              # full run (~10 min), writes results/REPORT.md
    QUICK=1 ./run.sh      # smoke run (~2 min), same report shape
    ./run.sh perf         # one suite: perf | footprint | conformance

Knobs (perf suite): `DUR` (30s), `RATE` (400/s fixed-rate run), `WORKERS`
(64, max-throughput run), `ITER` (3).

## What the numbers mean

- Perf targets: `baseline` is loadgen to upstream direct; the proxies add a
  CONNECT tunnel + TLS MITM + allowlist + secret swap. The headline metric
  is overhead vs baseline, not absolute RPS.
- All runs force HTTP/1.1 (`-http2=false`) so both proxies see the same
  client protocol.
- Conformance scenario 6 (header stripping) is N/A for iron-proxy: it has
  no `header_allowlist` transform. hematite runs that suite with
  `configs/hematite-conf.yaml`; perf uses the minimal equivalent configs.
- Results from a laptop are honest for relative comparison only.

## Layout

- `run.sh` — orchestrator; `bench-perf.sh`, `bench-footprint.sh`,
  `conformance.sh` — suites; `render-report.sh` — report renderer.
- `configs/` — the three proxy configs (printed verbatim in the report).
- `scripts/` — in-container Python clients (cold-start poller, SSE/WS).
- `results/` — gitignored output: JSON, logs, REPORT.md.

## Notes

- Hardware signing token is unavailable in the CI environment that runs this
  harness; commits use `git -c commit.gpgsign=false commit`.
- The containment check (`sk-bench-real-key-do-not-log`) verifies the real
  secret never leaks into captured proxy logs. A failure writes
  `results/containment-warning.txt`.
