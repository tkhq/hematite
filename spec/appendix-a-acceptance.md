# Appendix A — Acceptance Test (normative for L3)

The single scenario that means "hematite works." It is the Phase-1 artifact
that made the spec falsifiable, and it MUST be wired as the executable
integration test (`tests/acceptance/`) — docker-compose with three services:
`hematite`, an echo upstream standing in for `httpbin.org`, and a `client`
whose DNS points at the proxy. Config: Appendix B. The test asserts both the
client-observed behavior and the emitted audit records (validated against
`spec/schema/audit-record.schema.json`).

| # | Step | Expected |
|---|------|----------|
| 1 | `GET https://httpbin.org/get` (allowlisted) | 200; record `action: allow` with the full five-trace request list (`allowlist`, `annotate`, `body_capture`, `secrets`, `header_allowlist`), every verdict `continue` |
| 2 | `GET https://example.com/` | 403; record `action: reject`, `rejected_by: allowlist`, WARN |
| 3 | `GET https://httpbin.org/headers` with `Authorization: Bearer proxy-openai-abc123` | Upstream sees `Bearer sk-real…`; record annotates `swapped: [{secret: OPENAI_API_KEY, locations: ["header:Authorization"]}]` |
| 4 | Same host, secrets `require: true`, request without the proxy token | 403; `rejected_by: secrets` |
| 5 | `GET https://httpbin.org/get` with header `X-Tracking: 1` (not in `header_allowlist`; path chosen so the `require: true` secret rule does not match) | Upstream does not receive it; `stripped_headers: ["X-Tracking"]` |
| 6 | `dig` against the proxy DNS: `db.internal.corp` (static record *inside* the passthrough zone), `ns.internal.corp` (passthrough, resolvable by the harness resolver), `anything.example` | `10.0.0.9` (static beats passthrough) / the harness resolver's answer / `proxy_ip` — the three precedence tiers in order |
| 7 | `curl -x http://proxy:8080` CONNECT to the allowlisted host | MITM'd, transformed, 200; record has `tunnel.target` |
| 8 | Allowlisted hostname whose A record is `169.254.169.254` | 502; `action: reject`, `rejected_by: guard`, `guard: {denied_addr, prefix}` |
| 9 | Rewrite the config file to add example.com, `POST /v1/reload` (exec'd inside the hematite container — management binds loopback) → repeat step 2 → 200. Rewrite to a broken config, reload → 422, and step 2 still 200 on the surviving config | Atomic swap; fail-closed on bad config |
| 10 | Sweep all records emitted above | Each validates against the JSON Schema; `grep` for the real secret value across all logs finds nothing |

Pass criterion: all ten, in one run, from a clean start.
