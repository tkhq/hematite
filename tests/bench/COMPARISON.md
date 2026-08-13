# Egress-proxy comparison: hematite, iron-proxy, Squid, mitmproxy, smokescreen

*Data from the 2026-08-13 full run of this harness (`./run.sh`) on an M-series
Mac (18 cores, Docker Desktop), hematite built from this tree. Proxy versions:
iron-proxy 0.49.0, Squid 6.14 (ssl-bump), mitmproxy 11.1.3, smokescreen
v0.0.4. All numbers support relative comparison between the proxies; none are
publishable absolutes. Configs and the raw report are generated into
`results/` by every run.*

## What these tools do

All five sit between an untrusted workload (a CI job, an AI agent, a sandbox)
and the internet, and enforce a default-deny allowlist. They split into two
classes:

- **MITM proxies** terminate TLS with a CA the workload trusts, inspect and
  transform the inner traffic, and re-encrypt toward the upstream: hematite,
  iron-proxy, Squid (ssl-bump), mitmproxy.
- **Blind tunnels** check the CONNECT target and then pass encrypted bytes
  through untouched: smokescreen. This class cannot inspect or modify
  traffic, so it does less work per byte by design. Compare it as a
  different tradeoff, not as a faster equivalent.

Only hematite and iron-proxy do boundary secret injection: the workload holds
a worthless proxy token, and the proxy swaps in the real credential on the
way out. For the other three, a compromised workload that holds a real API
key can exfiltrate it; the allowlist is the only line of defense.

## The scorecard

Security conformance, from `conformance.sh` (PASS = correct behavior
observed; N/A = the proxy has no such feature):

| # | scenario | hematite | iron-proxy | Squid | mitmproxy | smokescreen |
|---|---|---|---|---|---|---|
| 1 | allowlisted host reaches upstream | PASS | PASS | PASS | PASS | PASS |
| 2 | non-allowlisted host is blocked | PASS | PASS | PASS | PASS | PASS |
| 3 | proxy token swapped for real secret | PASS | PASS | N/A | N/A | N/A |
| 4 | real secret never appears in proxy logs | PASS | PASS | N/A | N/A | N/A |
| 5 | allowlisted host that resolves to IMDS is refused | PASS | PASS | N/A | N/A | PASS |
| 6 | disallowed header does not reach upstream | PASS | N/A | N/A | N/A | N/A |
| 7 | SSE passthrough is unbuffered | PASS | PASS | PASS | **FAIL** | PASS |
| 8 | WebSocket round-trip | PASS | PASS | **FAIL** | PASS | PASS |

The two FAILs are real product behavior, reproduced across runs:

- **Squid cannot proxy a WebSocket through a bumped connection.** The upgrade
  dies with `502 ERR_INVALID_RESP`. Agent workloads that hold long-lived
  WebSocket sessions do not work through Squid ssl-bump.
- **mitmproxy buffers streaming responses by default.** The first SSE byte
  arrives when the stream ends. In the agent workload below, time-to-first-
  token through mitmproxy was the full stream duration (seconds), versus
  ~45 ms for every other proxy. Streaming LLM traffic is unusable through a
  default mitmproxy.

The N/A columns are the feature gap: no proxy except hematite and iron-proxy
can keep real credentials out of the sandbox, and only hematite,
iron-proxy, and smokescreen re-check where an allowlisted hostname actually
resolves (the SSRF/DNS-rebinding guard). Header allowlisting exists only in
hematite.

## Performance

Two workloads. First, uniform load: 1 KB HTTPS GETs through each proxy's
CONNECT tunnel (vegeta, medians over three 30 s runs):

| target | p50 | p99 | max RPS | CPU% mean | RSS max |
|---|---|---|---|---|---|
| no proxy | 0.26 ms | 0.51 ms | 5,213 | - | - |
| hematite | 0.35 ms | 0.94 ms | 5,820* | 20 | 14 MiB |
| iron-proxy | 0.38 ms | 0.97 ms | 2,630 | 56 | 272 MiB |
| Squid | 0.37 ms | 0.77 ms | 6,269* | 28 | 246 MiB |
| mitmproxy | 0.93 ms | 2.01 ms | 1,683 | 62 | 72 MiB |
| smokescreen | 0.31 ms | 0.66 ms | 5,175* | 12 | 81 MiB |

\* At or above the fixture's own ceiling (~5.2k RPS, a single-worker nginx):
these three do not bottleneck below the test rig; differences between them at
that line are noise. iron-proxy and mitmproxy cap well below it.

On this workload Squid posts the best MITM p99. Uniform keep-alive GETs are
Squid's home turf, and the number is honest. It is also the least
representative workload for the traffic these proxies front, which is why
the harness has a second one.

Second, the agent workload: open-loop sessions that mirror real AI-agent
traffic: an 8–32 KB chat POST (with secret swap where supported), an SSE
response consumed token-by-token, a burst of six parallel tool calls on
fresh connections, and an occasional denied request. Steady phase, then a
10x burst. Selected results (steady / burst):

| metric | no proxy | hematite | iron-proxy | Squid | mitmproxy | smokescreen |
|---|---|---|---|---|---|---|
| tool call p50 (fresh conn) | 43 ms | **44 / 45 ms** | 89 / 88 ms | 61 / 58 ms | 68 / 62 ms | 46 / 46 ms |
| time-to-first-token p50 | 42 ms | 43 ms | 44 ms | 50 ms | **7,858 ms** | 44 ms |
| worst SSE stall p99 | 34 ms | 41 / 42 ms | 37 / 38 ms | 38 / 45 ms | (buffered) | 34 / 38 ms |
| errors (all classes, both phases) | 0 | 0 | 0 | 0 | 0 | 0 |
| RSS max under load | - | **11 MiB** | 110 MiB | 243 MiB | 98 MiB | 32 MiB |

Fresh-connection latency is where agent traffic lives (tool fan-out, short
sessions), and it inverts the uniform-GET table: hematite matches the
no-proxy floor, Squid and mitmproxy add ~15–25 ms per connection, iron-proxy
adds ~45 ms. Every proxy survived the 10x burst with zero errors.

There is a ~43 ms floor on the tool-call and first-token absolutes that
belongs to the fixture, not the proxies; it is constant across targets, so
the deltas are meaningful.

## Operational footprint

| target | binary | image | cold start | idle RSS |
|---|---|---|---|---|
| hematite | 12.9 MB | 36 MB | 53 ms | **1.4 MiB** |
| iron-proxy | 48.6 MB | 20 MB | 104 ms | 10 MiB |
| Squid | 7.6 MB | 71 MB | 107 ms | 159 MiB |
| mitmproxy | (Python dist) | 101 MB | 254 ms | 51 MiB |
| smokescreen | 13.4 MB | 12 MB | 59 ms | 4.8 MiB |

## Tradeoffs, per proxy

**Squid** is the fastest MITM proxy on uniform load and the most battle-
tested codebase here. Against that: no secret injection, no resolved-IP
guard, no header policy, broken WebSockets under ssl-bump, ~160 MiB idle,
and its policy lives in an ACL language that this harness's 25-line config
took several attempts to get right (inner bumped requests need their own
`http_access` rule, an easy silent mistake).

**iron-proxy** is the closest feature match to hematite: secret injection,
IMDS guard, DNS interception, streaming support. In this harness it adds
~45 ms to every fresh connection and runs at 5–10x hematite's memory and
2–3x its CPU; its policy is enforced by disciplined code rather than by
types or executable vectors.

**mitmproxy** is a debugging tool, and it shows: the richest inspection
ecosystem, but default response buffering that breaks streaming, the
slowest data path, and policy that lives in Python you write yourself.
Right tool for interactive analysis; wrong tool for a production boundary.

**smokescreen** is the minimal, honest non-MITM option: smallest image,
near-zero overhead, a real private-range guard. It cannot see inside the
tunnel, so no secret handling, no header policy, no per-request audit of
inner traffic. If you only need destination control, it is a good choice,
and a useful reminder that everything the MITM proxies add costs something.

**hematite** is the only column with no N/A and no FAIL: it carries every
traffic class correctly (SSE unbuffered, WebSockets, secret swap, IMDS
guard, header allowlisting) while staying within noise of the fastest MITM
proxy on latency, matching the no-proxy floor on fresh connections, and
running in 1.4 MiB idle / 11 MiB under load, an order of magnitude below
the incumbents. Its distinguishing property is not on the scorecard: the
security invariants (secrets cannot be logged, no dial without a policy
decision, every request audits) are enforced by the type system and by
executable test vectors, not by review discipline. Two known soft spots,
found by this harness and tracked as follow-ups: its worst-case SSE
inter-chunk stall is a few ms higher than iron-proxy's (~41 vs ~37 ms p99),
and its MITM leaf advertises h2 unconditionally (worked around in the h2
Host-header fix on this branch).

## Why hematite

Pick by what the boundary must do:

- Destination control only → smokescreen.
- Interactive traffic inspection → mitmproxy.
- Plain MITM caching/filtering, no agents, no secrets → Squid.
- **Credentials must never enter the sandbox, agent traffic (streaming,
  WebSockets, tool fan-out) must work, and the boundary should be more
  trustworthy than the workload it guards → hematite.** iron-proxy makes the
  same promises; hematite keeps them with less latency, an order of
  magnitude less memory, and invariants a compiler checks.

## Reproduce

```
cd tests/bench
./run.sh            # ~35 min, writes results/REPORT.md
QUICK=1 ./run.sh    # ~10 min smoke run
```

Fairness rules: every proxy gets the same CA, semantically equivalent
configs (printed verbatim in the report), the same warmup and load, and a
pinned version. Scenario FAILs are recorded as findings, never silently
downgraded. Known limits: laptop/Docker numbers are relative only; the
harness and configs were written by the hematite authors (mitigated by
publishing everything); Go's GC headroom inflates iron-proxy's RSS numbers
relative to its true need.
