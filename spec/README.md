# hematite specification v0.1 (draft)

hematite is a default-deny egress boundary for untrusted workloads, whose
security invariants are enforced by the type system and by executable test
vectors — not by review discipline. Concept note: [`../CONCEPT.md`](../CONCEPT.md).

## Reading order (parts depend only on earlier parts)

| Part | Title | Level |
|------|-------|-------|
| [00](00-preliminaries.md) | Preliminaries — terms, conformance levels, global invariants | — |
| [01](01-decision-model.md) | Decision model — RequestSummary, Verdict, Trace, buffered body | L0 |
| [02](02-matching.md) | Matching — rules, globs, CIDRs, header patterns | L0 |
| [03](03-pipeline.md) | Pipeline — transform contract, ordering, short-circuit | L0 |
| [04](04-transforms.md) | Built-in transforms — allowlist, annotate, secrets, header_allowlist, body_capture | L0/L3 |
| [05](05-listeners.md) | Listeners — HTTP, TLS MITM, tunnel (CONNECT/SOCKS5), streaming | L1/L2 |
| [06](06-dns.md) | DNS server — precedence, interception | L2 |
| [07](07-upstream.md) | Upstream dialing — the guard, header hygiene | L1 |
| [08](08-audit.md) | Audit log — schema, secret safety | L0/L1 |
| [09](09-config.md) | Configuration — schema, validation, atomic reload | L1 |
| [10](10-non-goals.md) | Non-goals and the extension roadmap | — |

## Appendices

- [A — Acceptance test](appendix-a-acceptance.md) (the falsifiable target; runs as `tests/acceptance/`)
- [B — Worked example config](appendix-b-worked-example.md)
- [C — Test vectors](appendix-c-test-vectors.md) (normative; data files in `vectors/`)
- [D — Threat model mapping](appendix-d-threat-model.md)
- [E — Rust crate map](appendix-e-crate-map.md)
- [F — Extension sketch: X-postgres](appendix-f-x-postgres.md) (informative)
- [G — Extension sketch: X-mcp](appendix-g-x-mcp.md) (informative)
- [H — Other extension candidates](appendix-h-other-candidates.md) (informative: judge, response retry, SNI-only, control plane)
- [`schema/audit-record.schema.json`](schema/audit-record.schema.json) — normative audit schema

## Status

v0.1: decisions drafted from the Phase-1 concept note; derived from a
first-principles study of iron-proxy's data plane (compatibility is a
non-goal, Part 00 §6). Pending before v0.2: vector data files extracted from
Appendix C, the conformance runner, and the plain-language pass.
