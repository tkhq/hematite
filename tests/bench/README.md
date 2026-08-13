# tests/bench — hematite vs iron-proxy

A docker-compose harness that compares hematite (built from this tree)
against iron-proxy (`ironsh/iron-proxy:0.49.0`) on four axes: MITM'd-HTTPS
performance via CONNECT, a realistic AI-agent workload, operational
footprint, and security conformance.
Results and tradeoffs are written up in [COMPARISON.md](COMPARISON.md).
Design doc: `docs/superpowers/specs/2026-08-12-bench-vs-iron-proxy-design.md`.

## Run

    ./run.sh              # full run (~20 min), writes results/REPORT.md
    QUICK=1 ./run.sh      # smoke run (~4 min), same report shape
    ./run.sh perf         # one suite: perf | footprint | agent | conformance

Knobs (perf suite): `DUR` (30s), `RATE` (400/s fixed-rate run), `WORKERS`
(64, max-throughput run), `ITER` (3). Agent suite: `AGENT_STEADY_SECS`
(90), `AGENT_STEADY_RATE_PER_MIN` (30), `AGENT_BURST_SECS` (30),
`AGENT_BURST_MULT` (10), plus body/chunk shape vars in
`agentbench/src/main.rs`.

## Agent workload

`tests/bench/agentbench` (a standalone Rust crate, one binary, two modes)
models what these proxies actually front. `agentbench serve` is a mock LLM
API on `llm.test` (SSE chat streaming at a fixed token cadence + a tool
endpoint). `agentbench attack` replays agent sessions with open-loop
Poisson arrivals: an 8-32KB chat POST carrying the proxy token (secret
swap on every call) whose SSE response is consumed chunk by chunk, then a
burst of 6 parallel tool GETs; 10% of sessions also hit a denied host. A
steady phase is followed by a 10x burst. Reported per phase and class:
p50/p99, TTFT (time to first SSE chunk), worst inter-chunk stall, denied-
request refusal latency, error counts, and phase-windowed proxy CPU/RSS.
Open-loop arrival means a slow proxy queues sessions rather than
throttling the generator, which is what keeps p99 honest.

## What the numbers mean

- Perf targets: `baseline` is loadgen to upstream direct; the proxies add a
  CONNECT tunnel + TLS MITM + allowlist + secret swap. The headline metric
  is overhead vs baseline, not absolute RPS.
- All runs force HTTP/1.1 (`-http2=false`) so both proxies see the same
  client protocol.
- Conformance scenario 6 (header stripping) is N/A for iron-proxy: it has
  no `header_allowlist` transform. hematite runs that suite with
  `configs/hematite-conf.yaml`; perf uses the minimal equivalent configs.
- hematite's config runs a management listener and DNS server that iron-proxy
  lacks, so hematite's idle RSS carries extra product surface; the core perf
  comparison (allowlist + secrets transforms) is equivalent.
- Results from a laptop are honest for relative comparison only.

## Layout

- `run.sh` — orchestrator; `bench-perf.sh`, `bench-footprint.sh`,
  `bench-agent.sh`, `conformance.sh` — suites; `render-report.sh` — report
  renderer.
- `agentbench/` — Rust crate for the agent workload (mock LLM upstream +
  session generator); deliberately outside the hematite workspace.
- `configs/` — the three proxy configs (printed verbatim in the report).
- `scripts/` — in-container Python clients (cold-start poller, SSE/WS).
- `results/` — gitignored output: JSON, logs, REPORT.md.

## Notes

- Hardware signing token is unavailable in the CI environment that runs this
  harness; commits use `git -c commit.gpgsign=false commit`.
- The containment check (`sk-bench-real-key-do-not-log`) verifies the real
  secret never leaks into captured proxy logs. A failure writes
  `results/containment-warning.txt`.
